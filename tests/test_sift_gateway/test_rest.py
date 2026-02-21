"""Tests for REST API routes."""

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from sift_gateway.auth import AuthMiddleware
from sift_gateway.health import health_routes
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway
from .conftest import MockBackend, make_tool


def _make_test_app(gateway: Gateway) -> Starlette:
    """Build a Starlette app WITHOUT lifespan (backends are pre-configured)."""
    routes = []
    routes.extend(health_routes())
    routes.extend(rest_routes())

    app = Starlette(routes=routes)
    app.state.gateway = gateway

    api_keys = gateway.config.get("api_keys", {})
    app.add_middleware(AuthMiddleware, api_keys=api_keys)
    return app


def _make_test_gateway(mock_backends: dict, tool_map: dict = None) -> Gateway:
    """Create a Gateway with pre-injected mock backends (no real config needed)."""
    config = {"gateway": {}, "api_keys": {}, "backends": {}}
    gw = Gateway(config)
    gw.backends = mock_backends
    if tool_map:
        gw._tool_map = tool_map
    return gw


class TestListTools:
    def test_list_all_tools(self, mock_backends):
        tool_map = {
            "analyze_file": "backend-a",
            "list_evidence": "backend-a",
            "search_intel": "backend-b",
            "check_hash": "backend-b",
        }
        gw = _make_test_gateway(mock_backends, tool_map)
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/tools")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 4
        names = {t["name"] for t in data["tools"]}
        assert "analyze_file" in names
        assert "search_intel" in names

    def test_filter_by_backend(self, mock_backends):
        tool_map = {
            "analyze_file": "backend-a",
            "list_evidence": "backend-a",
            "search_intel": "backend-b",
        }
        gw = _make_test_gateway(mock_backends, tool_map)
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/tools?backend=backend-a")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        assert all(t["backend"] == "backend-a" for t in data["tools"])

    def test_filter_nonexistent_backend(self, mock_backends):
        gw = _make_test_gateway(mock_backends, {"t1": "backend-a"})
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/tools?backend=no-such")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


class TestCallTool:
    def test_call_existing_tool(self, mock_backends):
        for b in mock_backends.values():
            b._started = True
        gw = _make_test_gateway(mock_backends, {"analyze_file": "backend-a"})
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/tools/analyze_file", json={"arguments": {"path": "/data/img.E01"}})
        assert resp.status_code == 200
        data = resp.json()
        assert data["tool"] == "analyze_file"
        assert data["backend"] == "backend-a"
        assert len(data["result"]) > 0

    def test_call_nonexistent_tool_returns_404(self, mock_backends):
        gw = _make_test_gateway(mock_backends, {})
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/tools/no_such_tool", json={"arguments": {}})
        assert resp.status_code == 404
        assert "not found" in resp.json()["error"].lower()

    def test_call_with_invalid_json(self, mock_backends):
        gw = _make_test_gateway(mock_backends, {"t1": "backend-a"})
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/tools/t1",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400


class TestAnalystInjection:
    def test_analyst_injected_for_forensic_mcp(self):
        """When API key resolves to an analyst, forensic-mcp record tools get analyst_override."""
        forensic = MockBackend("forensic-mcp", tools=[
            make_tool("record_finding", "Record a finding"),
        ])
        forensic._started = True
        config = {
            "gateway": {},
            "api_keys": {"key1": {"analyst": "alice", "role": "lead"}},
            "backends": {},
        }
        gw = Gateway(config)
        gw.backends = {"forensic-mcp": forensic}
        gw._tool_map = {"record_finding": "forensic-mcp"}

        app = _make_test_app(gw)
        # Override config to include api_keys
        gw.config = config
        app = Starlette(routes=list(health_routes()) + list(rest_routes()))
        app.state.gateway = gw
        app.add_middleware(AuthMiddleware, api_keys=config["api_keys"])

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/tools/record_finding",
            json={"arguments": {"finding": {"title": "test"}}},
            headers={"Authorization": "Bearer key1"},
        )
        assert resp.status_code == 200
        # Check that the backend received analyst_override
        assert len(forensic._call_log) == 1
        assert forensic._call_log[0]["arguments"]["analyst_override"] == "alice"

    def test_no_injection_for_non_forensic_backend(self):
        """Non-forensic-mcp backends should NOT get analyst_override injected."""
        other = MockBackend("sift-mcp", tools=[
            make_tool("run_command", "Run a command"),
        ])
        other._started = True
        config = {
            "gateway": {},
            "api_keys": {"key1": {"analyst": "alice", "role": "lead"}},
            "backends": {},
        }
        gw = Gateway(config)
        gw.backends = {"sift-mcp": other}
        gw._tool_map = {"run_command": "sift-mcp"}
        gw.config = config

        app = Starlette(routes=list(health_routes()) + list(rest_routes()))
        app.state.gateway = gw
        app.add_middleware(AuthMiddleware, api_keys=config["api_keys"])

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/tools/run_command",
            json={"arguments": {"cmd": "ls"}},
            headers={"Authorization": "Bearer key1"},
        )
        assert resp.status_code == 200
        assert "analyst_override" not in other._call_log[0]["arguments"]


class TestBodySizeLimit:
    def test_oversized_body_returns_413(self, mock_backends):
        """Request body exceeding _MAX_REQUEST_BYTES returns 413."""
        for b in mock_backends.values():
            b._started = True
        gw = _make_test_gateway(mock_backends, {"analyze_file": "backend-a"})
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)

        # _MAX_REQUEST_BYTES is 10 * 1024 * 1024 (10 MB). Send 11 MB.
        oversized_body = b"x" * (11 * 1024 * 1024)
        resp = client.post(
            "/api/v1/tools/analyze_file",
            content=oversized_body,
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 413
        assert "too large" in resp.json()["error"].lower()

    def test_body_at_limit_is_accepted_or_parsed(self, mock_backends):
        """A body exactly at the limit should not be rejected as too large.

        It may fail JSON parsing (since it is not valid JSON), but the 413
        should NOT be triggered.
        """
        for b in mock_backends.values():
            b._started = True
        gw = _make_test_gateway(mock_backends, {"analyze_file": "backend-a"})
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)

        # Exactly 10 MB — not valid JSON, so expect 400 (bad JSON), not 413
        body_at_limit = b"x" * (10 * 1024 * 1024)
        resp = client.post(
            "/api/v1/tools/analyze_file",
            content=body_at_limit,
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400  # Bad JSON, but NOT 413


class TestListBackends:
    def test_list_backends(self, mock_backends):
        for b in mock_backends.values():
            b._started = True
        gw = _make_test_gateway(mock_backends)
        app = _make_test_app(gw)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/backends")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        names = {b["name"] for b in data["backends"]}
        assert "backend-a" in names
        assert "backend-b" in names
