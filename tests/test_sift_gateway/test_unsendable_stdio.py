"""A lone surrogate sent to a stdio backend (here through the gateway's
own handlers) is refused by name and audited on both routes:
the aggregate route (Gateway.call_tool) and the per-backend route, which
doesn't pass Gateway.call_tool. The backend keeps working. Before, the call
failed with CancelledError and every later call to that backend failed the
same way, while its health still read ok.

A real StdioMCPBackend runs a stdio MCP server. This file imports nothing
the change added, so it runs against the code before it.
"""

from __future__ import annotations

import asyncio
import sys

import mcp.types as types
import pytest
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.server import Gateway

SERVER = """\
from mcp.server.fastmcp import FastMCP
m = FastMCP("probe", log_level="WARNING")
@m.tool(structured_output=False)
async def echo(x: object = None) -> str:
    return "got " + ascii(x)[:60]
m.run(transport="stdio")
"""


@pytest.fixture
async def stdio_gateway(tmp_path):
    """A gateway whose one backend, sift-mcp, is a real stdio MCP server."""
    script = tmp_path / "server.py"
    script.write_text(SERVER)
    backend = StdioMCPBackend(
        "sift-mcp", {"type": "stdio", "command": sys.executable, "args": [str(script)]}
    )
    await backend.start()
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {"sift-mcp": backend}
    gw._tool_map = {"echo": "sift-mcp"}
    refused = []

    async def audit_refusal(backend_name, tool, arguments, exc, examiner=None):
        refused.append((backend_name, tool, str(exc)))

    gw.audit_refusal = audit_refusal
    gw.refused = refused
    try:
        yield gw
    finally:
        await backend.stop()


async def _echo(gw: Gateway, route: str, x):
    server = (
        create_backend_mcp_server(gw, "sift-mcp")
        if route == "per-backend"
        else create_mcp_server(gw)
    )
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name="echo", arguments={"x": x}),
    )
    handler = server.request_handlers[types.CallToolRequest]
    result = (await asyncio.wait_for(handler(request), 20)).root  # never a hang
    return result.isError, result.content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["per-backend", "aggregate"])
async def test_a_stdio_backend_refuses_it_by_name_and_keeps_working(
    stdio_gateway, route
):
    gw = stdio_gateway
    assert await _echo(gw, route, "fine") == (False, "got 'fine'")
    is_error, text = await _echo(gw, route, "a\ud800b")
    assert is_error is True
    assert "sift-mcp: echo wasn't sent: its argument 'x' holds a lone surrogate" in text
    assert [(b, t) for b, t, _ in gw.refused] == [("sift-mcp", "echo")]
    # the next normal calls, on either route, still work
    assert await _echo(gw, route, "fine") == (False, "got 'fine'")
    assert await _echo(gw, "aggregate", "after") == (False, "got 'after'")
    assert (await gw.backends["sift-mcp"].health_check())["status"] == "ok"
