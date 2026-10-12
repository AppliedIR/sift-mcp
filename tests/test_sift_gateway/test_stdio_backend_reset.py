"""A stdio backend whose child dies is restarted on the next call, and its
health asks the child (stdio-backend-reset-065).

At db9ddef only ConnectionError/OSError reset the backend: after the child
died every later call failed with ClosedResourceError until the gateway
restarted, and health read "ok" from the tool cache. A timeout is never "the
child is gone" (on 3.12 TimeoutError is an OSError): a health check during a
long call reports busy and leaves the backend, and the call, alone.

The backend runs a real stand-in stdio server (its tools answer with their
pid); the child is killed with SIGKILL, or exits mid-call.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import textwrap
from unittest.mock import AsyncMock

import pytest
from sift_gateway.backends.base import in_own_task
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.server import Gateway

SERVER = textwrap.dedent(
    """\
    import os, time
    from mcp.server.fastmcp import FastMCP
    m = FastMCP("standin")

    @m.tool()
    def ping() -> str:
        return f"pid {os.getpid()}"

    @m.tool()
    def slow(seconds: float) -> str:  # sync: it holds the child's loop
        time.sleep(seconds)
        return f"slow done in pid {os.getpid()}"

    @m.tool()
    def die() -> str:  # the child exits while the call is in flight
        time.sleep(0.3)
        os._exit(1)

    @m.tool()
    def err() -> str:
        raise ValueError("a tool's own error")

    m.run()
    """
)


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "standin.py"
    path.write_text(SERVER)
    return {"type": "stdio", "command": sys.executable, "args": ["-I", str(path)]}


@pytest.fixture
async def backend(config):
    b = StdioMCPBackend("standin", config)
    await in_own_task(b.start())
    await b.list_tools()  # as the gateway's tool map does after a start
    yield b
    if b.started:
        await b.stop()


def _text(result) -> str:
    return result[0].text  # a ToolResult is the content list


async def _pid(b) -> int:
    return int(_text(await b.call_tool("ping", {})).split()[-1])


async def _kill(b) -> int:
    pid = await _pid(b)
    os.kill(pid, signal.SIGKILL)
    await asyncio.sleep(0.5)
    return pid


async def test_r1_a_call_after_the_child_died_fails_and_resets(backend):
    await _kill(backend)
    with pytest.raises(Exception):
        await backend.call_tool("ping", {})
    assert backend.started is False  # was True: every later call failed too


async def test_r1b_a_child_that_dies_mid_call_costs_one_failed_call(backend):
    with pytest.raises(Exception):
        await backend.call_tool("die", {})
    assert backend.started is False  # an McpError "Connection closed" is gone too
    await in_own_task(backend.start())  # the gateway's lazy restart
    assert "pid" in _text(await backend.call_tool("ping", {}))


async def test_r2_the_gateway_restarts_it_on_the_next_call(config):
    gw = Gateway({"backends": {"standin": config}})
    gw._notify_backend_case = AsyncMock()
    await gw.start()
    try:
        backend = gw.backends["standin"]
        old = await _kill(backend)
        with pytest.raises(Exception):
            await gw.call_tool("ping", {})
        result = await gw.call_tool("ping", {})
        new = int(_text(result).split()[-1])
        assert new != old
    finally:
        await gw.stop()


async def test_r3_health_after_the_child_died_isnt_ok_and_names_the_error(backend):
    await _kill(backend)
    health = await backend.health_check()
    assert health["status"] == "error" and health["error"], (
        health
    )  # was "ok", from the cache
    assert backend.started is False
    assert (await backend.health_check())["status"] == "stopped"


async def test_r4_a_tools_own_error_leaves_the_backend(backend):
    pid = await _pid(backend)
    result = await backend.call_tool("err", {})
    assert result.is_error
    assert backend.started is True and await _pid(backend) == pid


async def test_r5_a_healthy_backend_is_ok(backend):
    health = await backend.health_check()
    assert health == {"status": "ok", "type": "stdio", "tools": 4}


async def test_r6_health_during_a_long_call_is_busy_and_the_call_completes(backend):
    """A sync tool holds the child past the 5 s ping: busy, never a reset
    (on 3.12 the timeout is an OSError, which once cleaned it up)."""
    pid = await _pid(backend)
    call = asyncio.ensure_future(backend.call_tool("slow", {"seconds": 6.5}))
    await asyncio.sleep(0.5)
    health = await backend.health_check()
    assert health["status"] == "busy" and "ping" in health["error"], health
    assert backend.started is True
    assert _text(await call) == f"slow done in pid {pid}"
    assert (await backend.health_check())["status"] == "ok"


async def test_r4b_a_call_that_times_out_leaves_the_backend(backend, monkeypatch):
    """A timeout is never "gone" (on 3.12 it's an OSError): the busy child stays."""
    from sift_gateway.backends import stdio_backend

    pid = await _pid(backend)
    monkeypatch.setattr(stdio_backend, "_TOOL_CALL_TIMEOUT", 0.5)
    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        await backend.call_tool("slow", {"seconds": 2})
    assert backend.started is True
    monkeypatch.setattr(stdio_backend, "_TOOL_CALL_TIMEOUT", 30)
    assert await _pid(backend) == pid


async def test_r4c_an_mcp_error_other_than_connection_closed_leaves_the_backend(
    backend, monkeypatch
):
    from mcp.shared.exceptions import McpError
    from mcp.types import ErrorData

    async def refused(*a, **k):
        raise McpError(ErrorData(code=-32602, message="Invalid params"))

    monkeypatch.setattr(backend._session, "call_tool", refused)
    with pytest.raises(McpError):
        await backend.call_tool("ping", {})
    assert backend.started is True


async def test_r7_two_overlapping_failures_and_a_restart_keep_the_new_session(backend):
    """Two failed requests clean up the same session while a third restarts
    the backend: a cleanup that finishes after the restart never clears the
    new session (codex on 09d10b3)."""
    old_pid = await _pid(backend)
    old_stack = backend._exit_stack
    gates, closes = [asyncio.Event(), asyncio.Event()], []

    class HeldClose:  # the session's close, suspended until its gate opens
        async def aclose(self):
            gate = gates[min(len(closes), 1)]
            closes.append(gate)
            await gate.wait()

    backend._exit_stack = HeldClose()
    first = asyncio.ensure_future(backend._safe_cleanup(context="first failure"))
    second = asyncio.ensure_future(backend._safe_cleanup(context="second failure"))
    await asyncio.sleep(0.1)
    gates[0].set()
    await asyncio.sleep(0.1)
    assert backend.started is False
    await in_own_task(backend.start())  # the next request restarts it
    new = backend._session
    gates[1].set()
    await asyncio.gather(first, second)
    assert backend.started is True and backend._session is new
    assert await _pid(backend) != old_pid
    assert len(closes) == 1  # the session was closed once
    os.kill(old_pid, signal.SIGKILL)  # the stand-in's first child
    try:
        await in_own_task(old_stack.aclose())
    except BaseException:  # noqa: BLE001 - its own task's scopes: cleanup only
        pass


async def test_r8_an_old_sessions_late_failure_never_resets_the_replacement(backend):
    """Codex's ordering on c594912: two calls pending on the old session; the
    first fails, a request restarts the backend, then the second fails. The
    second is the old child's failure: the replacement stays and answers."""
    import anyio

    old_pid = await _pid(backend)
    gates = [asyncio.Event(), asyncio.Event()]
    held = []

    async def held_call(name, arguments):  # the old session's calls, failing on cue
        gate = gates[len(held)]
        held.append(gate)
        await gate.wait()
        raise anyio.ClosedResourceError()

    backend._session.call_tool = held_call
    first = asyncio.ensure_future(backend.call_tool("ping", {}))
    second = asyncio.ensure_future(backend.call_tool("ping", {}))
    await asyncio.sleep(0.1)
    gates[0].set()
    with pytest.raises(anyio.ClosedResourceError):
        await first
    assert backend.started is False  # the current session's failure: reset
    await in_own_task(backend.start())  # the next request restarts it
    new = backend._session
    gates[1].set()
    with pytest.raises(anyio.ClosedResourceError):
        await second  # it still fails: it ran on the old child
    assert backend.started is True and backend._session is new
    assert await _pid(backend) != old_pid


async def test_r9_an_old_failure_during_the_replacements_start_never_resets_it(
    backend, monkeypatch
):
    """Codex's ordering on a705586: the replacement is published while its
    initialize is still awaited, and an old call fails meanwhile. The old
    call's generation is already stale, so the replacement survives."""
    import anyio
    from sift_gateway.backends import stdio_backend

    old_pid = await _pid(backend)
    failing, initializing = asyncio.Event(), asyncio.Event()

    async def held_call(name, arguments):  # an old session's call, failing on cue
        await failing.wait()
        raise anyio.ClosedResourceError()

    backend._session.call_tool = held_call
    old_call = asyncio.ensure_future(backend.call_tool("ping", {}))
    await asyncio.sleep(0.1)
    await backend._safe_cleanup(context="the old child died")  # a first failure
    real_initialize = stdio_backend.ClientSession.initialize

    async def held_initialize(self):
        await initializing.wait()
        return await real_initialize(self)

    monkeypatch.setattr(stdio_backend.ClientSession, "initialize", held_initialize)
    restart = asyncio.ensure_future(in_own_task(backend.start()))
    await asyncio.sleep(0.5)  # the replacement is published, its initialize held
    failing.set()
    with pytest.raises(anyio.ClosedResourceError):
        await old_call
    initializing.set()
    await restart
    assert backend.started is True
    assert await _pid(backend) != old_pid
