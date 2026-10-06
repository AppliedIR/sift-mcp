"""A backend tool's error result reaches gateway clients as an MCP error.

The backends keep the ``isError`` flag with the content, and both the
per-backend and the aggregate endpoint return it. Successful results are
returned exactly as before.
"""

import sys
import textwrap
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp import types
from mcp.types import CallToolResult, TextContent, Tool
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.server import Gateway

FAILED = [TextContent(type="text", text="explicit failure")]
OK = [TextContent(type="text", text='{"ok": true}')]


def _stub(backend, is_error: bool):
    backend._started = True
    backend._tools_cache = [Tool(name="check", inputSchema={"type": "object"})]
    backend._session = MagicMock()
    backend._session.call_tool = AsyncMock(
        return_value=CallToolResult(
            content=FAILED if is_error else OK, isError=is_error
        )
    )
    return backend


def _backend(kind: str, is_error: bool):
    if kind == "stdio":
        return _stub(StdioMCPBackend("stdbk", {"command": "true"}), is_error)
    return _stub(HttpMCPBackend("httpbk", {"url": "http://127.0.0.1:9/mcp"}), is_error)


def _gateway(backend) -> Gateway:
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {backend.name: backend}
    gw._tool_map = {f"{backend.name}__check": backend.name}
    gw._audit = MagicMock()
    return gw


async def _call(server, name: str) -> CallToolResult:
    handler = server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments={}),
    )
    return (await handler(request)).root


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["stdio", "http"])
@pytest.mark.parametrize("is_error", [True, False])
async def test_a_backend_keeps_the_error_flag_with_the_content(kind, is_error):
    result = await _backend(kind, is_error).call_tool("check", {})
    assert list(result) == (FAILED if is_error else OK)
    assert getattr(result, "is_error", False) is is_error


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["stdio", "http"])
@pytest.mark.parametrize("endpoint", ["per-backend", "aggregate"])
async def test_a_backend_error_reaches_the_client_as_an_error(kind, endpoint):
    backend = _backend(kind, True)
    gw = _gateway(backend)
    if endpoint == "per-backend":
        result = await _call(create_backend_mcp_server(gw, backend.name), "check")
    else:
        result = await _call(create_mcp_server(gw), f"{backend.name}__check")
    assert result.isError is True
    assert [c.text for c in result.content] == ["explicit failure"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["stdio", "http"])
@pytest.mark.parametrize("endpoint", ["per-backend", "aggregate"])
async def test_a_successful_call_is_not_flagged(kind, endpoint):
    backend = _backend(kind, False)
    gw = _gateway(backend)
    if endpoint == "per-backend":
        result = await _call(create_backend_mcp_server(gw, backend.name), "check")
    else:
        result = await _call(create_mcp_server(gw), f"{backend.name}__check")
    assert result.isError is False
    assert [c.text for c in result.content] == ['{"ok": true}']


SERVER = textwrap.dedent(
    """
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("error-flag-test")


    @mcp.tool(structured_output=False)
    def ok_text() -> str:
        return "hello"


    @mcp.tool(structured_output=False)
    def boom() -> str:
        raise TypeError("an unexpected keyword argument")


    mcp.run()
    """
)


@pytest.mark.asyncio
async def test_a_tool_that_raises_in_a_real_stdio_backend_is_an_error(tmp_path):
    script = tmp_path / "server.py"
    script.write_text(SERVER)
    backend = StdioMCPBackend(
        "real", {"command": sys.executable, "args": [str(script)]}
    )
    gw = _gateway(backend)
    server = create_backend_mcp_server(gw, "real")
    await backend.start()
    try:
        failed = await _call(server, "boom")
        ok = await _call(server, "ok_text")
    finally:
        # Closed in the task that opened it; stop() closes it in another task.
        await backend._exit_stack.aclose()
    assert failed.isError is True
    assert "an unexpected keyword argument" in failed.content[0].text
    assert ok.isError is False
    assert [c.text for c in ok.content] == ["hello"]


@pytest.mark.parametrize("is_error", [True, False])
def test_the_rest_body_is_unchanged(is_error):
    from sift_gateway.rest import rest_routes
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.testclient import TestClient

    gw = _gateway(_backend("stdio", is_error))
    app = Starlette(routes=rest_routes())
    app.state.gateway = gw
    resp = TestClient(app).post("/api/v1/tools/stdbk__check", json={"arguments": {}})
    expected = {
        "tool": "stdbk__check",
        "backend": "stdbk",
        "result": [c.model_dump() for c in (FAILED if is_error else OK)],
    }
    assert resp.status_code == 200
    assert resp.content == JSONResponse(expected).body
