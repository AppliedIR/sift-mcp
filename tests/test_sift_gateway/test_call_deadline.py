"""A tool call past its backend's deadline gives the client one named text on
every route, and leaves the backend and the call alone.

The gateway had a timer of its own racing the backend's, and each route said
something else when one fired: "unexpected failure … (TimeoutError)" on the
per-backend endpoint, "timed out after 300s" on the aggregate one, a 500 on
REST. None said the call might still be running. The backend's deadline is
now the only one, and every route returns the text it names.

The backends are real, each on a stand-in child process (stdio, or streamable
HTTP on loopback) whose `slow` tool outlasts the deadline.
"""

from __future__ import annotations

import ast
import inspect
import logging
import os
import subprocess
import sys
import textwrap
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp import types
from sift_gateway.backends import http_backend, stdio_backend
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway
from starlette.applications import Starlette

DEADLINE = 0.5

STANDIN = textwrap.dedent(
    """\
    import asyncio, os, socket, sys
    from mcp.server.fastmcp import FastMCP
    m = FastMCP("standin")

    @m.tool()
    async def slow(seconds: float) -> str:
        await asyncio.sleep(seconds)
        return "slow done"

    @m.tool()
    def ping() -> str:
        return f"pid {os.getpid()}"

    if sys.argv[1] == "stdio":
        m.run()
    else:
        import uvicorn
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)  # a connection now waits for uvicorn, never refused
        print(sock.getsockname()[1], flush=True)
        app = m.streamable_http_app()
        uvicorn.Server(uvicorn.Config(app, log_level="warning")).run(sockets=[sock])
    """
)

TEXT = (
    "Backend standin: slow gave no answer in 0.5s; it wasn't sent again, as it "
    "may still be running or waiting to start. Check the case audit before "
    "running it again."
)


@pytest.fixture
def standin(tmp_path):
    path = tmp_path / "standin.py"
    path.write_text(STANDIN)
    return path


@pytest.fixture
async def gateway(request, standin, monkeypatch):
    kind = request.param
    remote = None
    if kind == "stdio":
        args = ["-I", str(standin), "stdio"]
        config = {"type": "stdio", "command": sys.executable, "args": args}
        monkeypatch.setattr(stdio_backend, "_TOOL_CALL_TIMEOUT", DEADLINE)
    else:
        remote = subprocess.Popen(
            [sys.executable, "-I", str(standin), "http"], stdout=subprocess.PIPE
        )
        port = int(remote.stdout.readline())
        config = {"type": "http", "url": f"http://127.0.0.1:{port}/mcp"}
        monkeypatch.setattr(http_backend, "_TOOL_CALL_TIMEOUT", DEADLINE)
    gw = Gateway({"backends": {"standin": config}})
    gw._notify_backend_case = AsyncMock()
    await gw.start()
    try:
        yield gw
    finally:
        await gw.stop()
        if remote is not None:
            remote.terminate()
            remote.wait(10)


async def _mcp(server, name: str, arguments: dict) -> str:
    handler = server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    )
    result = (await handler(request)).root
    assert result.isError is True
    return result.content[0].text


async def _rest(gw, name: str, arguments: dict) -> str:
    app = Starlette(routes=list(rest_routes()))
    app.state.gateway = gw
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        response = await c.post(
            f"/api/v1/tools/{name}", json={"arguments": arguments}, timeout=30
        )
    body = response.json()
    assert (response.status_code, body.get("error_type")) == (504, "CallTimeout")
    return body["error"]


ROUTES = {
    "per-backend": lambda gw, args: _mcp(
        create_backend_mcp_server(gw, "standin"), "slow", args
    ),
    "aggregate": lambda gw, args: _mcp(create_mcp_server(gw), "slow", args),
    "REST": lambda gw, args: _rest(gw, "slow", args),
}


async def _pid(backend) -> int:
    return int((await backend.call_tool("ping", {}))[0].text.split()[-1])


@pytest.mark.parametrize("route", sorted(ROUTES))
@pytest.mark.parametrize("gateway", ["stdio", "http"], indirect=True)
async def test_a_call_past_the_deadline_gives_the_named_text_and_leaves_the_call(
    gateway, route, caplog
):
    backend = gateway.backends["standin"]
    pid = await _pid(backend)
    generation = getattr(backend, "_generation", None)
    caplog.set_level(logging.DEBUG)

    text = await ROUTES[route](gateway, {"seconds": 3})

    assert text == TEXT
    named = [r for r in caplog.records if TEXT in r.getMessage()]
    assert len(named) == 1, [r.getMessage() for r in caplog.records]
    assert not [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.ERROR and r not in named
    ]
    # not reset: the same child, still running, answers the next call
    assert backend.started is True
    assert getattr(backend, "_generation", None) == generation
    os.kill(pid, 0)
    assert await _pid(backend) == pid


def _timers(node) -> list[str]:
    """A timer of call_tool's own: a wait_for, or a catch of the timeout."""
    if isinstance(node, ast.Call):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in ("wait_for", "timeout", "timeout_at"):
            return [ast.unparse(node)]
    if isinstance(node, ast.ExceptHandler) and node.type is not None:
        types_ = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        return [
            f"except {ast.unparse(t)}"
            for t in types_
            if ast.unparse(t) in ("asyncio.TimeoutError", "TimeoutError")
        ]
    return []


def test_the_gateway_keeps_no_timer_of_its_own_on_a_tool_call():
    tree = ast.parse(textwrap.dedent(inspect.getsource(Gateway.call_tool)))
    assert [t for node in ast.walk(tree) for t in _timers(node)] == []
