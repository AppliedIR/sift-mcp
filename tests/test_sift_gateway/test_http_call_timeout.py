"""A tool call to an HTTP backend that outlives the call timeout is never sent
again.

From Python 3.11 a TimeoutError is an OSError, so the reconnect-and-retry
meant for a dropped connection also caught a timed-out call: a wintools
command still running on the guest was started a second time. A timed-out
call now fails once, by name; a dropped connection is still retried once.

The backend is real; its session is a stand-in that counts the calls it was
sent, and a reconnect hands back the same stand-in.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
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


@pytest.mark.asyncio
async def test_a_dropped_connection_is_still_retried_once(monkeypatch):
    async def dropped():
        raise ConnectionError("connection reset by peer")

    backend, session, reconnects = _backend(monkeypatch, dropped)
    result = await backend.call_tool("run_windows_command", {"command": "x"})
    assert (list(result), session.calls, len(reconnects)) == (["done"], 2, 1)
