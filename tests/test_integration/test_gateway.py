"""Integration test: MCP JSON-RPC through the gateway to a real sift-mcp backend.

Sends a proper MCP tools/call message to /mcp/sift-mcp, which routes through
the gateway's per-backend endpoint to real tool execution.

Evidence at /cases/integration-test/evidence/. Skips when absent.
"""

from __future__ import annotations

import contextlib
import json
import time

import pytest

pytestmark = pytest.mark.integration


def _gateway_deps_available() -> bool:
    """Check if gateway dependencies are importable."""
    try:
        from sift_gateway.server import Gateway  # noqa: F401
        from starlette.testclient import TestClient  # noqa: F401
        return True
    except ImportError:
        return False


class TestGatewayThrough:
    """MCP JSON-RPC to /mcp/sift-mcp → real sift-mcp → real fls → response."""

    @pytest.fixture(autouse=True)
    def _check_deps(self):
        if not _gateway_deps_available():
            pytest.skip("Gateway dependencies not installed")

    def test_mcp_tool_call_through_gateway(self, evidence_dir, monkeypatch, tmp_path):
        """Full round-trip: HTTP → gateway → sift-mcp backend → real fls → response."""
        from mcp.types import Tool, TextContent

        from sift_gateway.backends.base import MCPBackend
        from sift_gateway.health import health_routes
        from sift_gateway.mcp_endpoint import (
            MCPAuthASGIApp,
            create_backend_mcp_server,
            create_mcp_server,
            create_session_manager,
        )
        from sift_gateway.rest import rest_routes
        from sift_gateway.server import Gateway
        from starlette.applications import Starlette
        from starlette.routing import Mount
        from starlette.testclient import TestClient

        monkeypatch.setenv("AIIR_EXAMINER", "gateway-test")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "audit").mkdir(exist_ok=True)

        # A backend that delegates to real sift-mcp tool execution
        class RealSiftBackend(MCPBackend):
            def __init__(self):
                super().__init__("sift-mcp", {"type": "stdio", "enabled": True})

            async def start(self):
                self._started = True

            async def stop(self):
                self._started = False

            async def list_tools(self):
                return [
                    Tool(
                        name="run_command",
                        description="Execute a catalog-approved forensic tool",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "command": {"type": "array", "items": {"type": "string"}},
                                "purpose": {"type": "string"},
                                "timeout": {"type": "integer"},
                                "save_output": {"type": "boolean"},
                            },
                            "required": ["command", "purpose"],
                        },
                    )
                ]

            async def call_tool(self, name, arguments):
                if name != "run_command":
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]

                from sift_mcp.audit import AuditWriter
                from sift_mcp.catalog import clear_catalog_cache, get_tool_def
                from sift_mcp.response import build_response
                from sift_mcp.tools.generic import run_command

                clear_catalog_cache()
                audit = AuditWriter(mcp_name="sift-mcp")
                evidence_id = audit._next_evidence_id()

                command = arguments["command"]
                purpose = arguments.get("purpose", "")
                timeout = arguments.get("timeout") or None

                start = time.monotonic()
                exec_result = run_command(command, purpose=purpose, timeout=timeout)
                elapsed = time.monotonic() - start

                binary = command[0].split("/")[-1]
                td = get_tool_def(binary)
                fk_name = td.knowledge_name if td else binary

                response = build_response(
                    tool_name="run_command",
                    success=exec_result["exit_code"] == 0,
                    data=exec_result,
                    evidence_id=evidence_id,
                    output_format="text",
                    elapsed_seconds=elapsed,
                    exit_code=exec_result["exit_code"],
                    command=command,
                    fk_tool_name=fk_name,
                )

                clear_catalog_cache()
                return [TextContent(type="text", text=json.dumps(response))]

            async def health_check(self):
                return {"status": "ok" if self._started else "stopped"}

        # Build gateway with real backend
        config = {"gateway": {}, "api_keys": {}, "backends": {}}
        gw = Gateway(config)
        backend = RealSiftBackend()
        backend._started = True
        gw.backends = {"sift-mcp": backend}
        gw._tool_map = {"run_command": "sift-mcp"}

        # Build Starlette app with MCP endpoints
        mcp_server = create_mcp_server(gw)
        session_manager = create_session_manager(mcp_server)
        mcp_asgi = MCPAuthASGIApp(session_manager, api_keys={})

        b_server = create_backend_mcp_server(gw, "sift-mcp")
        b_sm = create_session_manager(b_server)
        b_asgi = MCPAuthASGIApp(b_sm, api_keys={})

        routes = list(health_routes()) + list(rest_routes())
        routes.append(Mount("/mcp/sift-mcp", app=b_asgi))
        routes.append(Mount("/mcp", app=mcp_asgi))

        @contextlib.asynccontextmanager
        async def lifespan(app):
            async with contextlib.AsyncExitStack() as stack:
                await stack.enter_async_context(session_manager.run())
                await stack.enter_async_context(b_sm.run())
                yield

        app = Starlette(routes=routes, lifespan=lifespan)
        app.state.gateway = gw

        image_path = str(evidence_dir / "base-dc-cdrive.E01")

        with TestClient(app, raise_server_exceptions=False) as client:
            # Step 1: Initialize MCP session
            init_resp = client.post(
                "/mcp/sift-mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "integration-test", "version": "1.0"},
                    },
                },
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert init_resp.status_code in (200, 202), (
                f"Initialize failed: {init_resp.status_code} {init_resp.text}"
            )

            # Extract session ID from response headers for session continuity
            session_id = init_resp.headers.get("mcp-session-id", "")

            # Step 2: Send initialized notification
            headers = {
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
            if session_id:
                headers["mcp-session-id"] = session_id

            notif_resp = client.post(
                "/mcp/sift-mcp",
                json={
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
                headers=headers,
            )
            # Notifications may return 200 or 202 (accepted)
            assert notif_resp.status_code in (200, 202, 204)

            # Step 3: Call tools/call with a real fls command
            # E01 is a partition image (C: volume only), so fls -o 0 reads NTFS directly
            call_resp = client.post(
                "/mcp/sift-mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "run_command",
                        "arguments": {
                            "command": ["fls", "-o", "0", image_path],
                            "purpose": "gateway integration test",
                        },
                    },
                },
                headers=headers,
            )
            assert call_resp.status_code in (200, 202), (
                f"tools/call failed: {call_resp.status_code} {call_resp.text}"
            )

            # Parse the response — may be JSON or SSE
            body = call_resp.text
            if body.startswith("event:") or body.startswith("data:"):
                # SSE format: extract the data payload
                for line in body.splitlines():
                    if line.startswith("data: "):
                        payload = json.loads(line[6:])
                        break
                else:
                    pytest.fail(f"No data line found in SSE response:\n{body}")
            else:
                payload = json.loads(body)

            # Validate the JSON-RPC result contains tool output
            assert "result" in payload or "content" in payload.get("result", {}), (
                f"Missing result in response: {json.dumps(payload, indent=2)}"
            )

            # The result.content should contain a TextContent with our fls output
            result = payload.get("result", payload)
            content_items = result.get("content", [])
            assert len(content_items) >= 1, f"No content items: {result}"

            # Parse the inner text (which is our JSON envelope)
            text_data = content_items[0].get("text", "")
            envelope = json.loads(text_data)

            # Validate envelope fields from real tool execution
            assert envelope["success"] is True
            assert envelope["tool"] == "run_command"
            assert "$MFT" in envelope["data"]["stdout"]
            assert "Users" in envelope["data"]["stdout"]
            assert envelope["evidence_id"].startswith("sift-")
            assert "discipline_reminder" in envelope
