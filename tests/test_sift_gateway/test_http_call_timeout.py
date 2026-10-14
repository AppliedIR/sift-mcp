"""A tool call to an HTTP backend is sent again only when the remote refused
its session before running anything ("session terminated" / "session not
found"); a call that outlives the call timeout, or whose connection is lost
after it was sent, is never sent again.

From Python 3.11 a TimeoutError is an OSError, so the reconnect-and-retry
meant for a dropped connection also caught a timed-out call: a wintools
command still running on the guest was started a second time. And a dropped
connection was retried whatever the remote had done: a second call's
reconnect tore down the first call's session, which then sent the first call
again. A lost connection now fails once, by name, saying the call may have run.

The backend is real; its session is a stand-in that counts the calls it was
sent, and a reconnect hands back the same stand-in.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from anyio import BrokenResourceError, ClosedResourceError
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData
from sift_gateway.backends import http_backend
from sift_gateway.backends.http_backend import HttpMCPBackend


class _Session:
    def __init__(self, first_call):
        self.calls = 0
        self.first_call = first_call

    async def send_ping(self):
        return None

    async def call_tool(self, name, arguments):
        self.calls += 1
        if self.calls == 1:
            await self.first_call()
        return SimpleNamespace(content=["done"], isError=False)


def _backend(monkeypatch, first_call):
    backend = HttpMCPBackend(
        "wintools", {"type": "http", "url": "http://127.0.0.1:1/mcp"}
    )
    session = _Session(first_call)
    backend._started, backend._session = True, session
    reconnects = []

    async def reconnect(reason):
        reconnects.append(reason)
        backend._session = session

    monkeypatch.setattr(backend, "_reconnect", reconnect)
    return backend, session, reconnects


@pytest.mark.asyncio
async def test_a_call_past_the_timeout_runs_once_and_fails_by_name(monkeypatch):
    monkeypatch.setattr(http_backend, "_TOOL_CALL_TIMEOUT", 0.2)

    async def slow():
        await asyncio.sleep(5)  # a command still running on the guest

    backend, session, reconnects = _backend(monkeypatch, slow)
    with pytest.raises(asyncio.TimeoutError) as e:
        await backend.call_tool("run_windows_command", {"command": "x"})
    assert (session.calls, reconnects) == (1, [])
    assert "run_windows_command gave no answer in 0.2s; it wasn't sent again" in str(
        e.value
    )


LOST = {  # a connection lost after the call went out
    "connection reset": ConnectionError("connection reset by peer"),
    "an OSError": OSError(104, "Connection reset by peer"),
    "closed resource": ClosedResourceError(),
    "broken resource": BrokenResourceError(),
    "stream ended, by its text": RuntimeError("stream ended unexpectedly"),
}


@pytest.mark.parametrize("label", sorted(LOST))
@pytest.mark.asyncio
async def test_a_lost_connection_is_never_sent_again_and_says_it_may_have_run(
    monkeypatch, label
):
    async def lost():
        raise LOST[label]

    backend, session, reconnects = _backend(monkeypatch, lost)
    with pytest.raises(RuntimeError) as e:
        await backend.call_tool("run_windows_command", {"command": "x"})
    assert (session.calls, reconnects) == (1, []), label
    assert "the connection was lost during run_windows_command" in str(e.value)
    assert "the call may have run on the guest; check before re-running" in str(e.value)


def _refused_session():
    """What the MCP client raises when the remote 404s a request on a session
    it doesn't know, before running it."""
    return McpError(ErrorData(code=32600, message="Session terminated"))


@pytest.mark.asyncio
async def test_a_session_the_remote_refused_is_sent_again_once(monkeypatch):
    async def refused():
        raise _refused_session()  # the remote ran nothing

    backend, session, reconnects = _backend(monkeypatch, refused)
    result = await backend.call_tool("run_windows_command", {"command": "x"})
    assert (list(result), session.calls, len(reconnects)) == (["done"], 2, 1)


@pytest.mark.asyncio
async def test_a_session_refused_twice_is_not_sent_a_third_time(monkeypatch):
    backend, session, reconnects = _backend(monkeypatch, None)

    async def always(name, arguments):
        session.calls += 1
        raise _refused_session()

    session.call_tool = always
    with pytest.raises(McpError, match="Session terminated"):
        await backend.call_tool("run_windows_command", {"command": "x"})
    assert (session.calls, len(reconnects)) == (2, 1)


@pytest.mark.asyncio
async def test_a_tool_error_is_not_sent_again(monkeypatch):
    async def bad():
        raise ValueError("invalid arguments")

    backend, session, reconnects = _backend(monkeypatch, bad)
    with pytest.raises(ValueError, match="invalid arguments"):
        await backend.call_tool("run_windows_command", {"command": "x"})
    assert (session.calls, reconnects) == (1, [])


SAYS_SESSION = {  # raised after the tool ran, or by the tool: never sent again
    "a result that fails validation, quoting the output": RuntimeError(
        "Invalid structured content returned by tool run_windows_command: "
        "{'status': 'session terminated'} is not of type 'integer'"
    ),
    "a tool error saying it": McpError(
        ErrorData(code=-32603, message="session not found")
    ),
    "the right text with another code": McpError(
        ErrorData(code=-32600, message="Session terminated")
    ),
    "the old text match": RuntimeError("Session terminated"),
}


@pytest.mark.parametrize("label", sorted(SAYS_SESSION))
@pytest.mark.asyncio
async def test_text_that_only_says_session_terminated_is_never_sent_again(
    monkeypatch, label
):
    async def after_it_ran():
        raise SAYS_SESSION[label]

    backend, session, reconnects = _backend(monkeypatch, after_it_ran)
    with pytest.raises(Exception):
        await backend.call_tool("run_windows_command", {"command": "x"})
    assert (session.calls, reconnects) == (1, []), label
