"""sift-mcp answers while a run is running, and runs one at a time.

FastMCP calls a sync tool on its event loop, so while run_command ran the
server answered nothing, not a discovery call and not the ping: the gateway's
health read it as busy. Each tool now runs in a worker thread. run_command and
check_tools run one at a time, so a later run never overlaps an earlier one,
even one whose caller gave up on it; the other discovery tools wait for
nothing.

The server is the real one, over an in-memory MCP session; the run's command
is held before it runs, until the row lets it go.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from sift_mcp.server import create_server
from sift_mcp.tools import generic

HOLD = 8.0  # the longest a run is held: what a call stuck behind it waits
ANSWER = 5.0  # what "answers" means


class Held:
    """run_command's executor, held until released; each run's start and end."""

    def __init__(self, monkeypatch):
        self.release, self.started, self.spans = threading.Event(), [], []
        real = generic.run_command

        def held(command, **kwargs):
            self.started.append(time.monotonic())
            self.release.wait(HOLD)
            try:
                return real(command, **kwargs)
            finally:
                self.spans.append((self.started[len(self.spans)], time.monotonic()))

        monkeypatch.setattr(generic, "run_command", held)

    async def running(self, n: int = 1):
        deadline = time.monotonic() + HOLD
        while len(self.started) < n and time.monotonic() < deadline:
            await asyncio.sleep(0.05)


def _run(session):
    return asyncio.ensure_future(
        session.call_tool("run_command", {"command": ["date"], "purpose": "test"})
    )


async def _answers_during_a_run(held, session, tool, arguments):
    run = _run(session)
    await held.running()
    start = time.monotonic()
    result = await asyncio.wait_for(session.call_tool(tool, arguments), HOLD * 2)
    took = time.monotonic() - start
    assert held.spans == [], "answered only after the run ended"
    assert took < ANSWER and not result.isError, (took, result)
    held.release.set()
    assert not (await run).isError


async def _ping_with_check_tools_waiting(held, session):
    run = _run(session)
    await held.running()
    check = asyncio.ensure_future(
        session.call_tool("check_tools", {"tool_names": ["fls"]})
    )
    await asyncio.sleep(0.3)
    start = time.monotonic()
    await asyncio.wait_for(session.send_ping(), HOLD * 2)
    assert held.spans == [] and not check.done(), "answered only after the run"
    assert time.monotonic() - start < ANSWER
    held.release.set()
    assert not (await run).isError and not (await check).isError


async def _second_run_after_the_first(held, session):
    first = _run(session)
    await held.running()
    second = _run(session)
    await asyncio.sleep(0.5)
    held.release.set()
    assert not (await first).isError and not (await second).isError
    (_, first_end), (second_start, _) = held.spans
    assert second_start >= first_end


async def _cancelled_caller_keeps_the_limiter(held, session):
    from sift_common import offload  # the one-at-a-time worker thread

    limiter, gate, spans = asyncio.Lock(), threading.Event(), []

    def work(n):
        start = time.monotonic()
        if n == 1:
            gate.wait(HOLD)
        spans.append((start, time.monotonic()))
        return n

    run = offload(work, limiter)
    first = asyncio.ensure_future(run(1))
    await asyncio.sleep(0.2)
    first.cancel()
    start = time.monotonic()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert time.monotonic() - start < 1, "the cancelled caller waited"
    assert limiter.locked(), "released while its thread runs"
    second = asyncio.ensure_future(run(2))
    await asyncio.sleep(0.3)
    assert not second.done() and spans == []
    gate.set()
    assert await asyncio.wait_for(second, ANSWER) == 2
    assert spans[1][0] >= spans[0][1]
    assert not limiter.locked()


ROWS = {
    "get_tool_help answers during a run": lambda h, s: _answers_during_a_run(
        h, s, "get_tool_help", {"tool_name": "no-such-tool"}
    ),
    "list_available_tools answers during a run": lambda h, s: _answers_during_a_run(
        h, s, "list_available_tools", {}
    ),
    "suggest_tools answers during a run": lambda h, s: _answers_during_a_run(
        h, s, "suggest_tools", {"artifact_type": "evtx"}
    ),
    "the ping answers during a run, check_tools waiting": (
        _ping_with_check_tools_waiting
    ),
    "a second run starts after the first ends, and completes": (
        _second_run_after_the_first
    ),
    "a cancelled caller returns, its run keeps the limiter": (
        _cancelled_caller_keeps_the_limiter
    ),
}


@pytest.mark.parametrize("row", sorted(ROWS))
async def test_tools_answer_during_a_run_and_runs_go_one_at_a_time(row, monkeypatch):
    held = Held(monkeypatch)
    try:
        async with create_connected_server_and_client_session(
            create_server()
        ) as session:
            await ROWS[row](held, session)
    finally:
        held.release.set()  # a failed row never leaves a thread held
