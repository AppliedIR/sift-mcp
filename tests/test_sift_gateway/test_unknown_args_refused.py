"""An argument name a stdio backend's tool doesn't declare is refused by name
on both MCP routes, and a backend that restarts with a new parameter has it
accepted on the same Server objects, with no client re-list.

A real StdioMCPBackend runs a small FastMCP server that closes its tools with
sift_common's helper. Its tools return a dict: a str-returning tool fails on
the per-backend route for a reason unrelated to arguments.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys

import mcp.types as types
import pytest
from sift_gateway import server as gateway_server
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.server import Gateway

SERVER = """\
import os, sys
import sift_common
from mcp.server.fastmcp import FastMCP
open(sys.argv[1], "w").write(str(os.getpid()))
m = FastMCP("probe", log_level="WARNING")
@m.tool()
def count(query: str{extra}) -> dict:
    return {{"query": query}}
getattr(sift_common, "close_tool_arguments", lambda server: None)(m)
m.run(transport="stdio")
"""
V1 = SERVER.format(extra="")
V2 = SERVER.format(extra=', since: str = ""')  # the new build adds a parameter
ROUTES = ["aggregate", "per-backend"]


def _backend(tmp_path, source: str, tag: str) -> StdioMCPBackend:
    script = tmp_path / f"server_{tag}.py"
    script.write_text(source)
    pid = tmp_path / f"pid_{tag}"
    return StdioMCPBackend(
        "probe",
        {"type": "stdio", "command": sys.executable, "args": [str(script), str(pid)]},
    )


@pytest.fixture
async def gw(tmp_path):
    """A gateway over one started stdio backend, its tool map built, and its
    two MCP-route Servers."""
    backend = _backend(tmp_path, V1, "v1")
    await backend.start()
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {"probe": backend}
    await gw._build_tool_map()
    gw.routes = {
        "aggregate": create_mcp_server(gw),
        "per-backend": create_backend_mcp_server(gw, "probe"),
    }
    try:
        yield gw
    finally:
        for b in gw.backends.values():
            await b.stop()


async def _call(gw: Gateway, route: str, arguments: dict) -> tuple[bool, str]:
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name="count", arguments=arguments),
    )
    handler = gw.routes[route].request_handlers[types.CallToolRequest]
    result = (await asyncio.wait_for(handler(request), 20)).root  # never a hang
    return result.isError, result.content[0].text


def _refused_by_schema(name: str) -> str:
    return (
        "Input validation error: Additional properties are not allowed"
        f" ('{name}' was unexpected)"
    )


@pytest.mark.parametrize("route", ROUTES)
async def test_an_undeclared_name_is_refused_by_name(gw, route):
    assert await _call(gw, route, {"query": "q"}) == (False, '{\n  "query": "q"\n}')
    is_error, text = await _call(gw, route, {"query": "q", "time_to": "2000"})
    assert is_error is True
    assert text == _refused_by_schema("time_to")


async def test_behind_the_placeholder_schema_the_backend_refuses_it(gw):
    """The backend isn't listing, so the aggregate route publishes the open
    placeholder; the backend's own argument model refuses the name."""
    await gw.backends["probe"].stop()
    gw._tool_cache = {}
    server = gw.routes["aggregate"]
    await server.request_handlers[types.ListToolsRequest](
        types.ListToolsRequest(method="tools/list")
    )
    placeholder = {"type": "object", "properties": {}}
    assert server._tool_cache["count"].inputSchema == placeholder
    is_error, text = await _call(gw, "aggregate", {"query": "q", "time_to": "2000"})
    assert is_error is True
    assert "time_to" in text and "Extra inputs are not permitted" in text


async def test_a_replaced_backend_s_new_name_is_accepted_without_a_relist(gw, tmp_path):
    for route in ROUTES:  # each Server has cached the first build's schema
        assert (await _call(gw, route, {"query": "q", "since": "x"}))[0] is True
    await gw.backends["probe"].stop()
    replacement = _backend(tmp_path, V2, "v2")
    await replacement.start()
    gw.backends["probe"] = replacement
    await gw._build_tool_map()
    for route in ROUTES:
        is_error, text = await _call(gw, route, {"query": "q", "since": "x"})
        assert is_error is False, (route, text)


async def test_after_a_crash_the_new_build_s_name_is_accepted_after_the_rebuild(
    gw, tmp_path, monkeypatch
):
    for route in ROUTES:
        assert (await _call(gw, route, {"query": "q"}))[0] is False
    backend = gw.backends["probe"]
    os.kill(int((tmp_path / "pid_v1").read_text()), signal.SIGKILL)
    (tmp_path / "server_v1.py").write_text(V2)  # the new build, in its place
    # a ping sent while the pipe closes waits out its timeout as busy; the
    # next check finds the child gone
    for _ in range(2):
        if (await backend.health_check())["status"] != "busy":
            break
    assert backend.started is False
    for route in ROUTES:  # the disclosed window: refused by name until rebuilt
        assert await _call(gw, route, {"query": "q", "since": "x"}) == (
            True,
            _refused_by_schema("since"),
        )
    monkeypatch.setattr(gateway_server, "_LATE_START_SECONDS", 0.05)
    checker = asyncio.create_task(gw._late_start_checker())
    try:
        for _ in range(400):
            cached = gw._tool_cache.get("count")
            if backend.started and cached and "since" in str(cached.inputSchema):
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("the late-start check never rebuilt the tool map")
    finally:
        checker.cancel()
        await asyncio.gather(checker, return_exceptions=True)
    for route in ROUTES:
        is_error, text = await _call(gw, route, {"query": "q", "since": "x"})
        assert is_error is False, (route, text)
