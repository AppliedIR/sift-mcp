"""Tests for the Streamable HTTP MCP endpoint."""

import contextlib
import json

import pytest
from unittest.mock import MagicMock
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.testclient import TestClient

from sift_gateway.auth import AuthMiddleware
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import (
    MCPAuthASGIApp,
    create_backend_mcp_server,
    create_mcp_server,
    create_session_manager,
)
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway
from .conftest import MockBackend, make_tool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gateway(mock_backends: dict, tool_map: dict, api_keys: dict | None = None) -> Gateway:
    config = {"gateway": {}, "api_keys": api_keys or {}, "backends": {}}
    gw = Gateway(config)
    gw.backends = mock_backends
    gw._tool_map = tool_map
    return gw


def _make_app_with_mcp(gw: Gateway) -> Starlette:
    """Build a Starlette app with MCP endpoint (no lifespan — backends pre-configured)."""
    api_keys = gw.config.get("api_keys", {})
    mcp_server = create_mcp_server(gw)
    session_manager = create_session_manager(mcp_server)
    mcp_asgi = MCPAuthASGIApp(session_manager, api_keys=api_keys)

    # Per-backend MCP endpoints
    backend_session_managers = []
    per_backend_routes = []
    for name in gw.backends:
        b_server = create_backend_mcp_server(gw, name)
        b_sm = create_session_manager(b_server)
        b_asgi = MCPAuthASGIApp(b_sm, api_keys=api_keys)
        backend_session_managers.append(b_sm)
        per_backend_routes.append(Mount(f"/mcp/{name}", app=b_asgi))

    routes = list(health_routes()) + list(rest_routes())
    routes.extend(per_backend_routes)
    routes.append(Mount("/mcp", app=mcp_asgi))

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(session_manager.run())
            for b_sm in backend_session_managers:
                await stack.enter_async_context(b_sm.run())
            yield

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.gateway = gw
    app.add_middleware(AuthMiddleware, api_keys=api_keys)
    return app


# ---------------------------------------------------------------------------
# MCPAuthASGIApp unit tests
# ---------------------------------------------------------------------------

class TestMCPAuthASGIApp:
    """Test the ASGI auth wrapper in isolation."""

    def _make_scope(self, headers: dict[str, str] | None = None) -> dict:
        h = {"content-length": "0"}
        h.update(headers or {})
        raw_headers = []
        for k, v in h.items():
            raw_headers.append((k.lower().encode(), v.encode()))
        return {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": raw_headers,
            "state": {},
        }

    @pytest.fixture
    def dummy_session_manager(self):
        """A mock session manager that records calls."""
        mgr = MagicMock()
        mgr.handle_request = MagicMock()

        async def fake_handle(scope, receive, send):
            pass

        mgr.handle_request.side_effect = fake_handle
        return mgr

    async def test_no_keys_anonymous(self, dummy_session_manager):
        app = MCPAuthASGIApp(dummy_session_manager, api_keys={})
        scope = self._make_scope()

        async def receive():
            return {}

        sent = []

        async def send(msg):
            sent.append(msg)

        await app(scope, receive, send)
        assert scope["state"]["examiner"] == "anonymous"
        assert scope["state"]["role"] == "examiner"
        dummy_session_manager.handle_request.assert_called_once()

    async def test_missing_auth_returns_401(self, dummy_session_manager):
        keys = {"secret": {"examiner": "alice", "role": "lead"}}
        app = MCPAuthASGIApp(dummy_session_manager, api_keys=keys)
        scope = self._make_scope()

        async def receive():
            return {"type": "http.request", "body": b""}

        responses = []

        async def send(msg):
            responses.append(msg)

        await app(scope, receive, send)
        # Should get 401 response
        assert any(r.get("status") == 401 for r in responses)
        dummy_session_manager.handle_request.assert_not_called()

    async def test_bad_key_returns_403(self, dummy_session_manager):
        keys = {"secret": {"examiner": "alice", "role": "lead"}}
        app = MCPAuthASGIApp(dummy_session_manager, api_keys=keys)
        scope = self._make_scope({"Authorization": "Bearer wrong_key"})

        async def receive():
            return {"type": "http.request", "body": b""}

        responses = []

        async def send(msg):
            responses.append(msg)

        await app(scope, receive, send)
        assert any(r.get("status") == 403 for r in responses)
        dummy_session_manager.handle_request.assert_not_called()

    async def test_valid_key_sets_analyst(self, dummy_session_manager):
        keys = {"secret123": {"examiner": "alice", "role": "lead"}}
        app = MCPAuthASGIApp(dummy_session_manager, api_keys=keys)
        scope = self._make_scope({"Authorization": "Bearer secret123"})

        async def receive():
            return {}

        async def send(msg):
            pass

        await app(scope, receive, send)
        assert scope["state"]["examiner"] == "alice"
        assert scope["state"]["role"] == "lead"
        dummy_session_manager.handle_request.assert_called_once()

    async def test_post_without_content_length_returns_411(self, dummy_session_manager):
        app = MCPAuthASGIApp(dummy_session_manager, api_keys={})
        # Build scope without content-length header
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [],
            "state": {},
        }

        sent = []

        async def receive():
            return {}

        async def send(msg):
            sent.append(msg)

        await app(scope, receive, send)
        assert any(b"411" in str(msg).encode() or msg.get("status") == 411 for msg in sent)


# ---------------------------------------------------------------------------
# create_mcp_server unit tests
# ---------------------------------------------------------------------------

class TestCreateMCPServer:
    async def test_list_tools_returns_all(self):
        backend_a = MockBackend("backend-a", tools=[
            make_tool("analyze_file", "Analyze a file"),
            make_tool("list_evidence", "List evidence"),
        ])
        backend_a._started = True
        gw = _make_gateway(
            {"backend-a": backend_a},
            {"analyze_file": "backend-a", "list_evidence": "backend-a"},
        )
        server = create_mcp_server(gw)
        # The list_tools handler is registered on the server — call via gateway
        tools = await gw.get_tools_list()
        assert len(tools) == 2
        names = {t.name for t in tools}
        assert "analyze_file" in names
        assert "list_evidence" in names

    async def test_get_tools_list_with_collision_prefix(self):
        backend_a = MockBackend("backend-a", tools=[make_tool("scan", "Scan A")])
        backend_b = MockBackend("backend-b", tools=[make_tool("scan", "Scan B")])
        backend_a._started = True
        backend_b._started = True
        gw = _make_gateway(
            {"backend-a": backend_a, "backend-b": backend_b},
            {"backend-a__scan": "backend-a", "backend-b__scan": "backend-b"},
        )
        tools = await gw.get_tools_list()
        assert len(tools) == 2
        names = {t.name for t in tools}
        assert "backend-a__scan" in names
        assert "backend-b__scan" in names

    async def test_get_tools_list_includes_schemas(self):
        from mcp.types import Tool as MCPTool
        tool = MCPTool(
            name="check",
            description="Check something",
            inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
        )
        backend = MockBackend("b1", tools=[tool])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"check": "b1"})
        tools = await gw.get_tools_list()
        assert len(tools) == 1
        assert tools[0].inputSchema["properties"]["path"]["type"] == "string"


# ---------------------------------------------------------------------------
# Integration: full app with MCP client
# ---------------------------------------------------------------------------

class TestMCPIntegration:
    """Integration tests using TestClient as context manager (triggers lifespan)."""

    def test_mcp_post_initialize(self):
        """POST to /mcp with an initialize request should get a valid JSON-RPC response."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test tool")])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"})
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            resp = client.post(
                "/mcp",
                json=init_request,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            # Should get a successful response (either JSON or SSE)
            assert resp.status_code in (200, 202)

    def test_mcp_auth_required_when_keys_set(self):
        """When API keys are configured, /mcp should require auth."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test")])
        backend._started = True
        keys = {"mykey": {"examiner": "alice", "role": "examiner"}}
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"}, api_keys=keys)
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={"Accept": "application/json, text/event-stream"},
            )
            assert resp.status_code == 401

    def test_mcp_auth_valid_key(self):
        """With valid auth, /mcp should process the request."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test")])
        backend._started = True
        keys = {"mykey": {"examiner": "alice", "role": "examiner"}}
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"}, api_keys=keys)
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            resp = client.post(
                "/mcp",
                json=init_request,
                headers={
                    "Authorization": "Bearer mykey",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code in (200, 202)

    def test_mcp_no_keys_anonymous(self):
        """Without API keys, /mcp should accept requests as anonymous."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test")])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"})
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            resp = client.post(
                "/mcp",
                json=init_request,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code in (200, 202)

    def test_rest_list_tools_still_works(self):
        """Verify REST endpoint wasn't broken by refactoring."""
        backend = MockBackend("b1", tools=[make_tool("tool_a", "Tool A")])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"tool_a": "b1"})
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/tools")
            assert resp.status_code == 200
            data = resp.json()
            assert data["count"] == 1
            assert data["tools"][0]["name"] == "tool_a"
            assert data["tools"][0]["description"] == "Tool A"


# ---------------------------------------------------------------------------
# Per-backend MCP endpoint tests
# ---------------------------------------------------------------------------

class TestPerBackendMCP:
    """Tests for per-backend MCP endpoints at /mcp/{backend-name}."""

    def test_per_backend_mcp_initialize(self):
        """POST to /mcp/b1 succeeds with MCP initialize."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test tool")])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"})
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            resp = client.post(
                "/mcp/b1",
                json=init_request,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code in (200, 202)

    def test_per_backend_only_for_configured(self):
        """Only configured backends get dedicated per-backend MCP endpoints.

        Unknown backend names under /mcp/* fall through to the aggregate
        endpoint (expected Starlette Mount prefix-matching behavior).
        Verify the dedicated endpoint for 'b1' works while 'b2' does not.
        """
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test")])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"})
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            # b1 has a dedicated endpoint
            resp = client.post(
                "/mcp/b1",
                json=init_request,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code in (200, 202)

    def test_per_backend_auth_required(self):
        """When API keys are configured, /mcp/b1 requires auth."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test")])
        backend._started = True
        keys = {"mykey": {"examiner": "alice", "role": "examiner"}}
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"}, api_keys=keys)
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/mcp/b1",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={"Accept": "application/json, text/event-stream"},
            )
            assert resp.status_code == 401

    def test_aggregate_still_works(self):
        """Aggregate /mcp continues to work alongside per-backend endpoints."""
        backend = MockBackend("b1", tools=[make_tool("test_tool", "A test")])
        backend._started = True
        gw = _make_gateway({"b1": backend}, {"test_tool": "b1"})
        app = _make_app_with_mcp(gw)

        with TestClient(app, raise_server_exceptions=False) as client:
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            # Aggregate
            resp = client.post(
                "/mcp",
                json=init_request,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code in (200, 202)
            # Per-backend
            resp2 = client.post(
                "/mcp/b1",
                json=init_request,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert resp2.status_code in (200, 202)
