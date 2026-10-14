"""An HTTP backend whose remote ended the session (a wintools restart, a guest
revert) is reconnected by heal(), which each call and the gateway's 30 s
checker run, so /health reads ok again with no tool call. A ping that times
out while a call is running is left alone: a busy remote can be slow to
answer, and a reconnect would end the running call's session.

The backend is real; its session is a stand-in, and a reconnect is counted.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from anyio import ClosedResourceError
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData
from sift_gateway.backends import http_backend
from sift_gateway.backends.http_backend import HttpMCPBackend


class _Session:
    def __init__(self, ping):
        self.ping, self.calls = ping, 0
        self.release = asyncio.Event()

    async def send_ping(self):
        await self.ping()

    async def call_tool(self, name, arguments):
        self.calls += 1
        if name == "slow":
            await self.release.wait()
        return SimpleNamespace(content=[name], isError=False)


async def _answers():
    return None


async def _ended():
    raise RuntimeError("Session terminated")


async def _silent():
    await asyncio.sleep(3600)


def _backend(monkeypatch, ping):
    monkeypatch.setattr(http_backend, "_PING_TIMEOUT", 0.2)
    backend = HttpMCPBackend(
        "wintools", {"type": "http", "url": "http://127.0.0.1:1/mcp"}
    )
    session = _Session(ping)
    backend._started, backend._session = True, session
    reconnects = []

    async def reconnect(reason):
        reconnects.append(reason)
        session.ping = _answers  # the new session answers

    monkeypatch.setattr(backend, "_reconnect", reconnect)
    return backend, session, reconnects


@pytest.mark.asyncio
async def test_a_session_the_remote_ended_is_reconnected_once(monkeypatch):
    backend, _, reconnects = _backend(monkeypatch, _ended)
    for _ in range(3):
        await backend.heal()
    assert reconnects == ["RuntimeError: Session terminated"]
    assert (await backend.health_check())["status"] == "ok"


@pytest.mark.asyncio
async def test_a_backend_that_answers_is_never_reconnected(monkeypatch):
    backend, _, reconnects = _backend(monkeypatch, _answers)
    for _ in range(3):
        await backend.heal()
    assert reconnects == []


@pytest.mark.asyncio
async def test_a_ping_timeout_reconnects_only_when_no_call_is_running(monkeypatch):
    backend, _, reconnects = _backend(monkeypatch, _silent)
    backend._in_flight = 1
    await backend.heal()
    assert reconnects == []
    backend._in_flight = 0
    await backend.heal()
    assert reconnects == ["no answer to a ping in 0s"]


@pytest.mark.asyncio
async def test_a_call_made_while_another_runs_on_a_slow_remote_is_sent_on_the_same_session(
    monkeypatch,
):
    backend, session, reconnects = _backend(monkeypatch, _answers)
    first = asyncio.ensure_future(backend.call_tool("slow", {}))
    while session.calls == 0:
        await asyncio.sleep(0.01)
    session.ping = _silent  # busy with the first call
    second = await backend.call_tool("get_share_info", {})
    assert list(second) == ["get_share_info"] and reconnects == []
    session.release.set()
    assert list(await first) == ["slow"]
    assert (session.calls, backend._in_flight) == (2, 0)


@pytest.mark.asyncio
async def test_a_session_ended_while_a_call_runs_is_still_reconnected(monkeypatch):
    backend, _, reconnects = _backend(monkeypatch, _ended)
    backend._in_flight = 1
    await backend.heal()
    assert reconnects == ["RuntimeError: Session terminated"]


@pytest.mark.asyncio
async def test_a_failed_call_is_no_longer_counted_as_running(monkeypatch):
    backend, session, _ = _backend(monkeypatch, _answers)

    async def refused(name, arguments):
        raise ValueError("bad arguments")

    session.call_tool = refused
    with pytest.raises(ValueError):
        await backend.call_tool("get_share_info", {})
    assert backend._in_flight == 0


class _Live:
    """A session whose calls and pings wait on events, and whose waiting
    call fails once the session is torn down."""

    def __init__(self, ping, call):
        self.ping, self.call = ping, call
        self.closed = asyncio.Event()
        self.calls = 0

    async def send_ping(self):
        await self.ping(self)

    async def call_tool(self, name, arguments):
        self.calls += 1
        return await self.call(self)


async def _until(done, closed):
    """Wait for `done`, or fail as a closed session's call does."""
    first = await _first(done.wait(), closed.wait())
    if first == 1:
        raise ClosedResourceError()


async def _first(*aws):
    tasks = [asyncio.ensure_future(a) for a in aws]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    return tasks.index(next(iter(done)))


@pytest.mark.asyncio
async def test_a_call_s_reconnect_during_a_heal_s_ping_is_the_only_one(monkeypatch):
    """codex on 001: a call already sending gets "Session terminated" while
    the checker's heal waits on a ping of the same old session. The heal's
    ping then fails. One reconnect, and the call's retry answers on the
    fresh session, which no second reconnect closes."""
    call_go, ping_go, retry_go = asyncio.Event(), asyncio.Event(), asyncio.Event()
    pings = []

    async def old_ping(s):
        pings.append(s)
        if len(pings) > 1:  # the checker's, after the call's own heal
            await ping_go.wait()
            raise RuntimeError("Session terminated")

    async def old_call(s):
        await call_go.wait()
        raise McpError(ErrorData(code=32600, message="Session terminated"))

    async def new_ping(s):
        return None

    async def new_call(s):
        await _until(retry_go, s.closed)
        return SimpleNamespace(content=["done"], isError=False)

    old, new = _Live(old_ping, old_call), _Live(new_ping, new_call)
    backend = HttpMCPBackend(
        "wintools", {"type": "http", "url": "http://127.0.0.1:1/mcp"}
    )
    backend._started, backend._session = True, old
    spare = _Live(new_ping, new_call)  # what a second reconnect would get
    fresh, reconnects = [new, spare], []

    async def start():
        backend._session, backend._started = fresh.pop(0), True

    async def teardown():
        reconnects.append(backend._session)
        backend._session.closed.set()
        backend._session, backend._started = None, False

    monkeypatch.setattr(backend, "start", start)
    monkeypatch.setattr(backend, "_teardown", teardown)

    call = asyncio.ensure_future(backend.call_tool("run_windows_command", {}))
    while old.calls == 0:
        await asyncio.sleep(0.01)
    checker = asyncio.ensure_future(backend.heal())
    while len(pings) < 2:
        await asyncio.sleep(0.01)
    call_go.set()  # the call's "Session terminated", while the heal pings
    await asyncio.sleep(0.05)
    ping_go.set()  # then the heal's ping fails
    await checker
    await asyncio.sleep(0.05)
    retry_go.set()
    assert list(await asyncio.wait_for(call, 5)) == ["done"]
    assert reconnects == [old] and new.calls == 1
