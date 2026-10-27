"""One start path for a backend.

Every starter reaches ``ensure_backend_started``: a call (aggregate
``call_tool``, per-backend ``tools/list`` and ``tools/call``) and the
late-start checker's pass. The checker takes a backend's start lock only
when it can without waiting, and once shutdown begins it stops at the first
step where it regains control.

Each row drives the real gateway over fake backends whose start follows a
script and can block until released. The checker's interval wait is a pass
the row runs with ``go()``. Shutdown begins when the stopper task first runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import itertools
import logging
import sys
from unittest.mock import AsyncMock, MagicMock

import anyio
import pytest
from mcp import types as mcp_types
from sift_gateway import server as server_mod
from sift_gateway.backends import http_backend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server
from sift_gateway.server import Gateway

from .conftest import MockBackend, make_tool

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

pytestmark = pytest.mark.timeout(60)

LOGGER = "sift_gateway.server"
SOON = 1.0  # "within 1 s" in every row
SHORT = 0.3  # the start timeouts, cut, for the timed-out start
WHO = contextvars.ContextVar("who", default="test")  # which starter is running

CALLS = ["agg", "list", "call"]
STARTERS = [*CALLS, "checker"]
PAIRS = [(a, b) for a in STARTERS for b in STARTERS if (a, b) != ("checker", "checker")]
PAIR_IDS = [f"{a}-then-{b}" for a, b in PAIRS]
REFUSED = "Backend b didn't start (ConnectionError: refused)."


class _Row:
    """Every column of a row is checked, and a RED row names each failed one."""

    def __init__(self):
        self.failed: list[str] = []

    def check(self, column: str, ok, seen=None) -> None:
        if not ok:
            self.failed.append(f"{column}: {seen!r}")

    def done(self) -> None:
        assert not self.failed, "\n".join(self.failed)


async def until(check, what: str, within: float = SOON) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while not check():
        if loop.time() > deadline:
            raise AssertionError(f"not within {within}s: {what}")
        await asyncio.sleep(0.005)


async def settles(check, within: float = SOON) -> bool:
    with contextlib.suppress(AssertionError):
        await until(check, "", within)
        return True
    return False


def outcome(task: asyncio.Task):
    if not task.done():
        return "pending"
    if task.cancelled():
        return "cancelled"
    return task.exception() or task.result()


class Passes:
    """``server.anyio`` for the checker: each interval wait ends on ``go()``."""

    def __init__(self):
        self.waits = 0
        self.waiting = asyncio.Event()
        self._next: asyncio.Future | None = None

    async def sleep(self, _seconds) -> None:
        self.waits += 1
        self._next = asyncio.get_running_loop().create_future()
        self.waiting.set()
        try:
            await self._next
        finally:
            self.waiting.clear()

    def go(self) -> int:
        """End the wait; the count of waits so far (a pass ended once it grows)."""
        n = self.waits
        if self._next is not None and not self._next.done():
            self._next.set_result(None)
        return n

    def __getattr__(self, name):
        return getattr(anyio, name)


class ShortWaits:
    """``server.asyncio`` with the start timeouts (the path's 60 s, and the
    checker's own 30 s where it has one) cut to SHORT."""

    async def wait_for(self, aw, timeout):
        return await asyncio.wait_for(aw, SHORT if timeout in (30.0, 60.0) else timeout)

    def __getattr__(self, name):
        return getattr(asyncio, name)


class Gated(MockBackend):
    """A stdio-like backend whose starts follow ``script``, one step each:
    "ok", "block" (until released), "raise", "block-raise" or "cancel".
    It keeps the real early return once started, and counts starts in
    flight inside ``start()``."""

    def __init__(self, name: str, script=()):
        super().__init__(name, tools=[make_tool(f"{name}_tool")])
        self.script = list(script)
        self.starts = 0
        self.inside = 0
        self.most = 0
        self.who: list[str] = []
        self.saw_cancel = False
        self.entered = asyncio.Event()
        self.go_on = asyncio.Event()

    def release(self) -> None:
        self.go_on.set()

    async def start(self) -> None:
        if self._started:
            return
        step = self.script.pop(0) if self.script else "ok"
        self.starts += 1
        self.who.append(WHO.get())
        self.inside += 1
        self.most = max(self.most, self.inside)
        self.entered.set()
        try:
            if step == "cancel":
                raise asyncio.CancelledError
            if step in ("block", "block-raise"):
                try:
                    await self.go_on.wait()
                except asyncio.CancelledError:
                    self.saw_cancel = True
                    raise
            if step in ("raise", "block-raise"):
                raise ConnectionError("refused")
            self._started = True
        finally:
            self.inside -= 1

    async def call_tool(self, name: str, arguments: dict) -> list:
        return [mcp_types.TextContent(type="text", text="ok")]


class FakeSession:
    def __init__(self, link: Link):
        self.link = link

    async def send_ping(self):
        if self.link.ping is not None:
            await self.link.ping()


class Link(HttpMCPBackend):
    """wintools-mcp over HTTP: the real start, heal and reconnect, with a
    fake connect in the runner that follows ``script`` ("ok" or "block")."""

    def __init__(self, script=()):
        url = "http://127.0.0.1:9/mcp"
        super().__init__("wintools-mcp", {"type": "http", "url": url, "enabled": True})
        self.script = list(script)
        self.connects = 0
        self.inside = 0
        self.most = 0
        self.who: list[str] = []
        self.saw_cancel = False
        self.runners: list[asyncio.Task] = []
        self.entered = asyncio.Event()
        self.go_on = asyncio.Event()
        self.list_blocks = False
        self.listing = asyncio.Event()
        self.list_gate = asyncio.Event()
        self.pinging = asyncio.Event()
        self.ping = None  # an async callable the session's ping awaits
        self.heals = 0

    def release(self) -> None:
        self.go_on.set()
        self.list_gate.set()

    async def _run(self, url, headers, ready, stop) -> None:
        me = asyncio.current_task()
        self.runners.append(me)
        step = self.script.pop(0) if self.script else "ok"
        self.connects += 1
        self.who.append(WHO.get())
        self.inside += 1
        self.most = max(self.most, self.inside)
        self.entered.set()
        try:
            try:
                if step == "block":
                    await self.go_on.wait()
            except asyncio.CancelledError:
                self.saw_cancel = True
                raise
            finally:
                self.inside -= 1
            self._session = FakeSession(self)
            self._tools_cache = [make_tool("wintools-mcp_tool")]
            self._started = True
            self.last_error = None
            if not ready.done():
                ready.set_result(None)
            await stop.wait()
        except BaseException as exc:  # as the real runner: handed to start()
            if not ready.done():
                ready.set_exception(http_backend._StartFailed(self._why(exc)))
        finally:
            if self._runner is me:
                self._runner = None
                self._session = None
                self._started = False

    async def list_tools(self):
        if self.list_blocks:
            self.listing.set()
            await self.list_gate.wait()
        return await super().list_tools()

    async def heal(self) -> None:
        self.heals += 1
        await super().heal()

    async def call_tool(self, name: str, arguments: dict) -> list:
        return [mcp_types.TextContent(type="text", text="ok")]


class SpyLock(asyncio.Lock):
    """A start lock that records who made each acquire that missed the fast
    path (the caller joined the waiters). ``hook`` runs once, inside the
    checker's first call of ``locked()``, the busy test's first read."""

    def __init__(self):
        super().__init__()
        self.slow: list[str] = []
        self.hook = None
        self.fired = False
        self.ran_at_return = None

    async def acquire(self):
        waiters = self._waiters
        if self._locked or (waiters and not all(w.cancelled() for w in waiters)):
            self.slow.append(WHO.get())
        return await super().acquire()

    def locked(self) -> bool:
        if self.hook is not None and not self.fired and WHO.get() == "checker":
            self.fired = True
            ran = self.hook()
            busy = super().locked()
            self.ran_at_return = ran()
            return busy
        return super().locked()


class CaseSync:
    """``gw._notify_backend_case``: counts entries, and blocks when told."""

    def __init__(self):
        self.entries = 0
        self.blocks = False
        self.entered = asyncio.Event()
        self.gate = asyncio.Event()

    async def __call__(self, backend) -> None:
        self.entries += 1
        self.entered.set()
        if self.blocks:
            await self.gate.wait()


class Rig:
    def __init__(self, caplog, monkeypatch):
        self.caplog = caplog
        self.passes = Passes()
        self.tasks: list[asyncio.Task] = []
        self.backends: list = []
        self.syncs: list[CaseSync] = []
        monkeypatch.setattr(server_mod, "anyio", self.passes)

    def gateway(self, *backends) -> Gateway:
        gw = Gateway({"backends": {}})
        gw._audit = MagicMock()
        gw.case_at_start = AsyncMock(return_value="")
        gw.record_pending_hashes = AsyncMock()
        gw._notify_backend_case = CaseSync()
        self.syncs.append(gw._notify_backend_case)
        for backend in backends:
            gw.backends[backend.name] = backend
            gw._start_locks[backend.name] = SpyLock()
            gw._tool_map[f"{backend.name}_tool"] = backend.name
            self.backends.append(backend)
        return gw

    def spawn(self, who: str, fn, *args) -> asyncio.Task:
        async def body():
            WHO.set(who)
            return await fn(*args)

        task = asyncio.ensure_future(body())
        self.tasks.append(task)
        return task

    def checker(self, gw: Gateway) -> asyncio.Task:
        return self.spawn("checker", gw._late_start_checker)

    async def waiting(self) -> None:
        await until(self.passes.waiting.is_set, "the checker waits for its pass")

    async def one_pass(self) -> bool:
        """Run one pass: whether it ended (the checker waits again) within 1 s."""
        await self.waiting()
        n = self.passes.go()
        return await settles(lambda: self.passes.waits > n)

    def mark(self) -> int:
        return len(self.caplog.records)

    def lines(self, since: int = 0) -> list[str]:
        records = self.caplog.records[since:]
        return [r.getMessage() for r in records if r.name == LOGGER]

    async def close(self) -> None:
        for _ in range(50):
            for backend in self.backends:
                backend.release()
            for sync in self.syncs:
                sync.gate.set()
            runners = [t for b in self.backends for t in getattr(b, "runners", [])]
            pending = [t for t in [*self.tasks, *runners] if not t.done()]
            if not pending:
                break
            for task in pending:
                task.cancel()
            await asyncio.wait(pending, timeout=0.2)


@pytest.fixture
async def rig(caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger=LOGGER)
    r = Rig(caplog, monkeypatch)
    yield r
    await r.close()


async def reach(gw: Gateway, route: str, name: str) -> str:
    """One request for ``name``'s tool on ``route``: "ok", or the error text."""
    tool = f"{name}_tool"
    try:
        if route == "agg":
            await gw.call_tool(tool, {})
            return "ok"
        server = create_backend_mcp_server(gw, name)
        if route == "list":
            request = mcp_types.ListToolsRequest(method="tools/list")
            await server.request_handlers[mcp_types.ListToolsRequest](request)
            return "ok"
        server._tool_cache[tool] = make_tool(tool)  # no listing on a cache miss
        params = mcp_types.CallToolRequestParams(name=tool, arguments={})
        request = mcp_types.CallToolRequest(method="tools/call", params=params)
        result = (
            await server.request_handlers[mcp_types.CallToolRequest](request)
        ).root
        if result.isError:
            return " ".join(c.text for c in result.content)
        return "ok"
    except Exception as exc:
        return str(exc)


def checker_lines(lines: list[str], name: str) -> list[str]:
    """The checker's starter lines for ``name``."""
    done = (
        f"Late-started backend: {name}",
        f"Tool map rebuilt after late-starting: {name}",
    )
    failed = f"Late-start failed for {name}: "
    return [line for line in lines if line in done or line.startswith(failed)]


def lazy(lines: list[str], name: str) -> int:
    return lines.count(f"Lazy-starting backend: {name}")


def started_lines(name: str) -> list[str]:
    return [
        f"Late-started backend: {name}",
        f"Tool map rebuilt after late-starting: {name}",
    ]


# --- two starters on one backend ---------------------------------------------


async def begin(rig: Rig, gw: Gateway, starter: str, name: str):
    """Start ``starter`` on ``name``: a call's task, or the pass's wait count."""
    if starter == "checker":
        return rig.passes.go()
    return rig.spawn("call", reach, gw, starter, name)


async def overlap(rig: Rig, gw: Gateway, b: Gated, second: str):
    """Begin the second starter while the first's start is in flight, and let
    it get as far as it goes: a call queued on the lock (or starting), the
    checker's pass ended (or starting)."""
    lock = gw._start_locks[b.name]
    if second == "checker":
        n = await begin(rig, gw, "checker", b.name)
        await settles(lambda: rig.passes.waits > n or b.starts > 1)
        return None
    task = await begin(rig, gw, second, b.name)
    await settles(lambda: "call" in lock.slow or b.starts > 1)
    return task


@pytest.mark.parametrize(("first", "second"), PAIRS, ids=PAIR_IDS)
async def test_two_starters_make_one_start(rig, first, second):
    row = _Row()
    b = Gated("b", ["block"])
    gw = rig.gateway(b)
    if "checker" in (first, second):
        rig.checker(gw)
        await rig.waiting()
    head = await begin(rig, gw, first, "b")
    row.check("first start entered", await settles(b.entered.is_set), b.starts)
    tail = await overlap(rig, gw, b, second)
    since = rig.passes.waits
    b.release()
    calls = [t for t in (head, tail) if isinstance(t, asyncio.Task)]
    if calls:
        await asyncio.wait(calls, timeout=SOON)
    if first == "checker":
        await settles(lambda: rig.passes.waits > since)
    lines = rig.lines()
    row.check("starts in flight at most 1", b.most == 1, b.most)
    row.check("one start", b.starts == 1, b.starts)
    row.check(
        "every call ok",
        all(outcome(t) == "ok" for t in calls),
        [outcome(t) for t in calls],
    )
    row.check("Lazy-starting lines", lazy(lines, "b") == (first != "checker"), lines)
    want = started_lines("b") if first == "checker" else []
    row.check("checker lines", checker_lines(lines, "b") == want, lines)
    row.check("a call sets last_tool_call", b.last_tool_call > 0, b.last_tool_call)
    row.done()


@pytest.mark.parametrize("starter", STARTERS)
async def test_only_a_call_counts_as_a_tool_call(rig, starter):
    row = _Row()
    b = Gated("b")
    gw = rig.gateway(b)
    if starter == "checker":
        rig.checker(gw)
        row.check("pass ended", await rig.one_pass(), rig.passes.waits)
    else:
        row.check("reply", await reach(gw, starter, "b") == "ok", None)
    row.check("started", b.started, b.starts)
    if starter == "checker":
        row.check("last_tool_call unchanged", b.last_tool_call == 0.0, b.last_tool_call)
    else:
        row.check("last_tool_call set", b.last_tool_call > 0, b.last_tool_call)
    row.done()


async def test_g2_the_checker_alone_starts_a_backend_once(rig):
    row = _Row()
    b = Gated("b")
    gw = rig.gateway(b)
    rig.checker(gw)
    row.check("pass ended", await rig.one_pass(), rig.passes.waits)
    lines = rig.lines()
    row.check("one start", b.starts == 1, b.starts)
    row.check("checker lines", checker_lines(lines, "b") == started_lines("b"), lines)
    row.check("no Lazy-starting", lazy(lines, "b") == 0, lines)
    row.check("last_tool_call unchanged", b.last_tool_call == 0.0, b.last_tool_call)
    row.done()


async def test_g3_a_failed_checker_start_is_retried_on_the_next_pass(rig):
    row = _Row()
    b = Gated("b", ["raise", "ok"])
    gw = rig.gateway(b)
    rig.checker(gw)
    row.check("pass 1 ended", await rig.one_pass(), rig.passes.waits)
    lines = rig.lines()
    failed = [x for x in checker_lines(lines, "b") if x.startswith("Late-start failed")]
    row.check("pass 1: one failure line", len(failed) == 1 and b.starts == 1, lines)
    row.check("pass 2 ended", await rig.one_pass(), rig.passes.waits)
    lines = rig.lines()
    row.check("pass 2: one more start", b.starts == 2, b.starts)
    row.check("pass 2: started", "Late-started backend: b" in lines, lines)
    row.done()


async def test_a_failed_checker_start_logs_the_paths_reason(rig):
    b = Gated("b", ["raise"])
    gw = rig.gateway(b)
    rig.checker(gw)
    assert await rig.one_pass()
    assert checker_lines(rig.lines(), "b") == [f"Late-start failed for b: {REFUSED}"]


# --- the busy test: the checker never waits for another starter -------------


async def busy_rig(rig: Rig):
    busy = Gated("busy", ["block"] * 3)
    nxt = Gated("next")
    gw = rig.gateway(busy, nxt)
    rig.checker(gw)
    await rig.waiting()
    return gw, busy, nxt, gw._start_locks["busy"]


async def busy_columns(row: _Row, rig: Rig, busy, nxt, lock, since: int) -> None:
    reached = await settles(lambda: nxt.starts == 1)
    row.check("the pass reached the next backend within 1 s", reached, nxt.starts)
    row.check(
        "the checker never joined the waiters", "checker" not in lock.slow, lock.slow
    )
    row.check(
        "nothing logged for the busy one",
        checker_lines(rig.lines(since), "busy") == [],
        rig.lines(since),
    )
    row.check("busy: starts in flight at most 1", busy.most == 1, busy.most)


async def test_h1_a_a_call_starting_and_a_call_queued(rig):
    row = _Row()
    gw, busy, nxt, lock = await busy_rig(rig)
    rig.spawn("call", reach, gw, "agg", "busy")
    await until(busy.entered.is_set, "call 1 starts")
    rig.spawn("call", reach, gw, "agg", "busy")
    await until(lambda: "call" in lock.slow, "call 2 queued")
    since = rig.mark()
    rig.passes.go()
    await busy_columns(row, rig, busy, nxt, lock, since)
    row.done()


async def test_h1_b_released_to_a_queued_call_that_hasnt_run(rig):
    row = _Row()
    gw, busy, nxt, lock = await busy_rig(rig)
    await lock.acquire()
    rig.spawn("call", reach, gw, "agg", "busy")
    await until(lambda: "call" in lock.slow, "the call queued")
    since = rig.mark()
    rig.passes.go()  # the checker runs before the woken call
    lock.release()
    await busy_columns(row, rig, busy, nxt, lock, since)
    row.done()


async def test_h1_c_a_cancelled_head_waiter_and_a_live_one_behind_it(rig):
    row = _Row()
    gw, busy, nxt, lock = await busy_rig(rig)
    await lock.acquire()
    head = rig.spawn("call", reach, gw, "agg", "busy")
    await until(lambda: lock.slow.count("call") == 1, "the head waiter queued")
    rig.spawn("call", reach, gw, "agg", "busy")
    await until(lambda: lock.slow.count("call") == 2, "a live waiter behind it")
    since = rig.mark()
    rig.passes.go()
    head.cancel()
    lock.release()  # wakes no one: the head waiter is cancelled
    await busy_columns(row, rig, busy, nxt, lock, since)
    row.done()


async def test_h1_d_a_call_scheduled_during_the_busy_test_waits_for_the_checker(rig):
    row = _Row()
    b = Gated("b", ["block"])
    gw = rig.gateway(b)
    lock = gw._start_locks["b"]
    ran: list[bool] = []
    calls: list[asyncio.Task] = []

    async def call():
        ran.append(True)
        return await reach(gw, "agg", "b")

    def hook():  # in the checker's locked(): the call's task made, not yet run
        calls.append(rig.spawn("call", call))
        return lambda: bool(ran)

    lock.hook = hook
    rig.checker(gw)
    await rig.waiting()
    rig.passes.go()
    await settles(b.entered.is_set)
    await settles(lambda: "call" in lock.slow)
    row.check("the hook in locked() fired", lock.fired, lock.fired)
    row.check(
        "the call hadn't run when the busy test returned",
        lock.ran_at_return is False,
        lock.ran_at_return,
    )
    row.check(
        "the checker took the lock on the fast path",
        "checker" not in lock.slow,
        lock.slow,
    )
    row.check("the call waits for the checker's start", "call" in lock.slow, lock.slow)
    b.release()
    if calls:
        await asyncio.wait(calls, timeout=SOON)
    lines = rig.lines()
    row.check(
        "the call's reply",
        [outcome(t) for t in calls] == ["ok"],
        [outcome(t) for t in calls],
    )
    row.check("one start", b.starts == 1 and b.most == 1, (b.starts, b.most))
    row.check("no Lazy-starting", lazy(lines, "b") == 0, lines)
    row.done()


# --- HTTP: the checker and a call on an HttpMCPBackend ----------------------


async def test_http_the_checker_alone_connects_once(rig):
    row = _Row()
    link = Link()
    gw = rig.gateway(link)
    rig.checker(gw)
    row.check("pass ended", await rig.one_pass(), rig.passes.waits)
    lines = rig.lines()
    row.check("one connect", link.connects == 1 and link.started, link.connects)
    row.check(
        "checker lines",
        checker_lines(lines, "wintools-mcp") == started_lines("wintools-mcp"),
        lines,
    )
    row.check("healed", link.heals == 1, link.heals)
    row.check(
        "case sync",
        gw._notify_backend_case.entries == 1,
        gw._notify_backend_case.entries,
    )
    row.check(
        "last_tool_call unchanged", link.last_tool_call == 0.0, link.last_tool_call
    )
    row.done()


@pytest.mark.parametrize("first", ["agg", "checker"])
async def test_http_the_checker_and_a_call_connect_once(rig, first):
    row = _Row()
    link = Link(["block"])
    gw = rig.gateway(link)
    lock = gw._start_locks["wintools-mcp"]
    rig.checker(gw)
    await rig.waiting()
    call = None
    if first == "checker":
        rig.passes.go()
        await until(link.entered.is_set, "the checker connects")
        call = rig.spawn("call", reach, gw, "agg", "wintools-mcp")
        await settles(lambda: "call" in lock.slow or link.connects > 1)
    else:
        call = rig.spawn("call", reach, gw, "agg", "wintools-mcp")
        await until(link.entered.is_set, "the call connects")
        n = rig.passes.go()
        await settles(lambda: rig.passes.waits > n or link.connects > 1)
    link.release()
    await asyncio.wait({call}, timeout=SOON)
    row.check("connects in flight at most 1", link.most == 1, link.most)
    row.check("one connect", link.connects == 1, link.connects)
    row.check("the call's reply", outcome(call) == "ok", outcome(call))
    row.done()


# --- a start that fails, under each pair -------------------------------------

MODES = ["raise", "timeout", "cancel"]
FIRST_STEP = {"raise": "block-raise", "timeout": "block", "cancel": "block"}
CHECKER_LINE = {
    "raise": f"Late-start failed for b: {REFUSED}",
    "timeout": "Late-start failed for b: Backend b didn't start (TimeoutError).",
    "cancel": "Late-start failed for b: ",
}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("first", "second"), PAIRS, ids=PAIR_IDS)
async def test_after_a_failed_start_the_next_starter_makes_its_own(
    rig, monkeypatch, first, second, mode
):
    row = _Row()
    if mode == "timeout":
        monkeypatch.setattr(server_mod, "asyncio", ShortWaits())
    b = Gated("b", [FIRST_STEP[mode]])
    gw = rig.gateway(b)
    checker = None
    if "checker" in (first, second):
        checker = rig.checker(gw)
        await rig.waiting()
    head = await begin(rig, gw, first, "b")
    row.check("first start entered", await settles(b.entered.is_set), b.starts)
    tail = await overlap(rig, gw, b, second)
    # the first start fails
    if mode == "raise":
        b.release()
    elif mode == "cancel":
        (checker if first == "checker" else head).cancel()
    if first == "checker":
        failed = await settles(
            lambda: any(x.startswith("Late-start failed for b: ") for x in rig.lines()),
            SOON + SHORT,
        )
        row.check("the checker's start failed", failed, rig.lines())
    else:
        await asyncio.wait({head}, timeout=SOON + SHORT)
        if mode != "cancel":
            row.check(
                "the first call's reply",
                "Backend b didn't start (" in str(outcome(head)),
                outcome(head),
            )
    # the second starter makes its own attempt
    if second == "checker":
        row.check("the next pass ended", await rig.one_pass(), rig.passes.waits)
        row.check(
            "the next pass started it",
            "Late-started backend: b" in rig.lines(),
            rig.lines(),
        )
    else:
        await asyncio.wait({tail}, timeout=SOON)
        row.check("the second call's reply", outcome(tail) == "ok", outcome(tail))
    lines = rig.lines()
    row.check("starts in flight at most 1", b.most == 1, b.most)
    row.check("two starts", b.starts == 2, b.starts)
    calls = (first != "checker") + (second != "checker")
    row.check("Lazy-starting lines", lazy(lines, "b") == calls, lines)
    if first == "checker":
        failed = [x for x in lines if x.startswith("Late-start failed for b: ")]
        row.check("the checker's failure line", failed == [CHECKER_LINE[mode]], failed)
    row.done()


@pytest.mark.parametrize("route", CALLS)
async def test_a_call_behind_a_failed_checker_start_reports_its_own_attempt(rig, route):
    row = _Row()
    b = Gated("b", ["block-raise", "raise"])
    gw = rig.gateway(b)
    lock = gw._start_locks["b"]
    rig.checker(gw)
    await rig.waiting()
    rig.passes.go()
    await until(b.entered.is_set, "the checker starts")
    call = rig.spawn("call", reach, gw, route, "b")
    await settles(lambda: "call" in lock.slow or b.starts > 1)
    b.release()
    await asyncio.wait({call}, timeout=SOON)
    lines = rig.lines()
    row.check(
        "the call's reply carries its own attempt's text",
        REFUSED in str(outcome(call)),
        outcome(call),
    )
    row.check(
        "two starts, one at a time", (b.starts, b.most) == (2, 1), (b.starts, b.most)
    )
    row.check("one Lazy-starting", lazy(lines, "b") == 1, lines)
    row.done()


# --- shutdown ends the checker ------------------------------------------------


class At:
    """What the rows compare after shutdown began, taken as it begins."""

    def __init__(self, rig: Rig, gw: Gateway, link: Link, after: Gated):
        self.mark = rig.mark()
        self.after = after.starts
        self.heals = link.heals
        self.syncs = gw._notify_backend_case.entries


async def shut(rig: Rig, gw: Gateway, task: asyncio.Task, snap):
    """Begin shutdown through the stop method. ``snap()`` runs as the stopper
    starts. Whether the checker was done within 1 s, the snapshot, and the
    stopper's own outcome."""
    taken = []

    async def stopper():
        taken.append(snap())
        await gw.stop_late_start_checker(task)

    stop = rig.spawn("test", stopper)
    done, _ = await asyncio.wait({task}, timeout=SOON)
    if done:
        await asyncio.wait({stop}, timeout=SOON)
    await until(lambda: taken, "the stopper ran")
    return bool(done), taken[0], outcome(stop)


def star_columns(
    row: _Row, rig: Rig, gw: Gateway, link: Link, after: Gated, at: At
) -> None:
    lines = rig.lines(at.mark)
    late = [x for x in lines if x in started_lines("wintools-mcp")]
    sync = gw._notify_backend_case.entries
    row.check(
        "after: no start entered after shutdown began",
        after.starts == at.after,
        (at.after, after.starts),
    )
    row.check(
        "wintools-mcp: no heal after shutdown began",
        link.heals == at.heals,
        (at.heals, link.heals),
    )
    row.check(
        "wintools-mcp: no case sync after shutdown began",
        sync == at.syncs,
        (at.syncs, sync),
    )
    row.check(
        "wintools-mcp: no late-start lines after shutdown began", late == [], late
    )


def blocks_until_cancelled(link: Link, cleanup=None):
    """A start for ``link`` that blocks until cancelled; ``cleanup`` is what
    its cancel raises (the cancel itself when None)."""

    async def start():
        if link._started:
            return
        link.connects += 1
        link.who.append(WHO.get())
        link.entered.set()
        try:
            await link.go_on.wait()
        except asyncio.CancelledError:
            link.saw_cancel = True
            if cleanup is not None:
                raise cleanup from None
            raise

    return start


def completes_when_released(link: Link):
    async def start():
        if link._started:
            return
        link.connects += 1
        link.entered.set()
        await link.go_on.wait()
        link._session = FakeSession(link)
        link._tools_cache = [make_tool("wintools-mcp_tool")]
        link._started = True

    return start


POINTS = [
    "ii-in-start",
    "iv-start-cleanup-raises",
    "v-in-rebuild-after-start",
    "vii-start-done-1-turn",
    "vii-start-done-2-turns",
    "vii-start-done-3-turns",
    "viii-in-heal-reconnect",
    "viii-b-in-heal-ping-group",
    "ix-in-stale-rebuild",
    "x-in-case-sync",
]


async def arrive(rig: Rig, point: str, row: _Row):
    """Bring the checker to ``point`` on wintools-mcp, with a second backend
    after it whose start blocks; the gateway, the checker and both backends."""
    link = Link(["block"] if point == "ii-in-start" else ["ok", "block"])
    after = Gated("after", ["block"])
    gw = rig.gateway(link, after)
    sync = gw._notify_backend_case
    if point.startswith(("viii", "ix", "x")):
        await link.start()  # connected before the pass; the pass heals it
        link.entered.clear()
    if point == "iv-start-cleanup-raises":
        link.start = blocks_until_cancelled(link, OSError("cleanup failed"))
    if point.startswith("vii-"):
        link.start = completes_when_released(link)
    if point == "v-in-rebuild-after-start":
        link.list_blocks = True
    if point == "viii-in-heal-reconnect":

        async def gone():
            raise ConnectionError("gone")

        link.ping = gone
    if point == "viii-b-in-heal-ping-group":

        async def hangs():
            link.pinging.set()
            try:
                await asyncio.get_running_loop().create_future()
            except asyncio.CancelledError:
                raise BaseExceptionGroup(
                    "cancelled", [asyncio.CancelledError()]
                ) from None

        link.ping = hangs
    if point == "ix-in-stale-rebuild":
        link._tool_map_stale = True
        link.list_blocks = True
    if point == "x-in-case-sync":
        sync.blocks = True
    task = rig.checker(gw)
    await rig.waiting()
    rig.passes.go()
    trigger = {
        "v-in-rebuild-after-start": link.listing,
        "viii-b-in-heal-ping-group": link.pinging,
        "ix-in-stale-rebuild": link.listing,
        "x-in-case-sync": sync.entered,
    }.get(point, link.entered)
    row.check("reached the point", await settles(trigger.is_set), point)
    if point == "ii-in-start":
        row.check("the checker is the starter", link.who == ["checker"], link.who)
    if point == "viii-in-heal-reconnect":
        row.check("the reconnect is connecting", link.connects == 2, link.connects)
    if point.startswith("vii-"):
        turns = int(point.split("-")[3])
        link.go_on.set()
        while not link._started:
            await asyncio.sleep(0)
        for _ in range(turns):
            await asyncio.sleep(0)
    return gw, task, link, after


@pytest.mark.parametrize("point", POINTS)
async def test_shutdown_ends_the_checker_at_each_await(rig, point):
    row = _Row()
    gw, task, link, after = await arrive(rig, point, row)
    done, at, stopper = await shut(rig, gw, task, lambda: At(rig, gw, link, after))
    row.check("the checker done within 1 s", done, outcome(task))
    row.check("the stop method returned", stopper is None, stopper)
    star_columns(row, rig, gw, link, after, at)
    if point == "ii-in-start":
        row.check(
            "the fake saw the cancel",
            await settles(lambda: link.saw_cancel),
            link.saw_cancel,
        )
    row.done()


async def test_vi_shutdown_ends_the_interval_wait(rig):
    row = _Row()
    link = Link()
    gw = rig.gateway(link)
    await link.start()
    task = rig.checker(gw)
    await rig.waiting()
    done, _, stopper = await shut(rig, gw, task, lambda: None)
    row.check("the checker done within 1 s", done, outcome(task))
    row.check("the stop method returned", stopper is None, stopper)
    row.done()


async def test_i_shutdown_while_a_calls_start_holds_the_lock(rig):
    row = _Row()
    b = Gated("b", ["block"])
    gw = rig.gateway(b)
    task = rig.checker(gw)
    await rig.waiting()
    call = rig.spawn("call", gw.ensure_backend_started, "b")
    await until(b.entered.is_set, "the call starts")
    row.check("the pass ended", await rig.one_pass(), rig.passes.waits)
    done, _, stopper = await shut(rig, gw, task, lambda: None)
    row.check("the checker done within 1 s", done, outcome(task))
    row.check("the stop method returned", stopper is None, stopper)
    b.release()
    await asyncio.wait({call}, timeout=SOON)
    row.check(
        "the call's start completed",
        call.done() and not call.cancelled() and call.exception() is None,
        outcome(call),
    )
    row.check("one start", (b.starts, b.most) == (1, 1), (b.starts, b.most))
    row.check("no checker lines", checker_lines(rig.lines(), "b") == [], rig.lines())
    row.done()


async def test_iii_a_cancelled_start_while_running_is_a_failed_start(rig):
    row = _Row()
    b = Gated("b", ["cancel", "ok"])
    gw = rig.gateway(b)
    rig.checker(gw)
    row.check("pass 1 ended", await rig.one_pass(), rig.passes.waits)
    lines = rig.lines()
    row.check(
        "the line, with the cancel's own text",
        checker_lines(lines, "b") == ["Late-start failed for b: "],
        lines,
    )
    row.check("pass 2 ended", await rig.one_pass(), rig.passes.waits)
    row.check(
        "pass 2 started it",
        b.starts == 2 and "Late-started backend: b" in rig.lines(),
        rig.lines(),
    )
    row.done()


class FakeSessionManager:
    def __init__(self, n: int, order: list[str]):
        self.n = n
        self.order = order

    @contextlib.asynccontextmanager
    async def run(self):
        try:
            yield
        finally:
            self.order.append(f"sm{self.n} exit")


async def test_leaving_the_lifespan_stops_the_checker_first(rig, monkeypatch):
    row = _Row()
    order: list[str] = []
    first = Gated("first", ["block"])
    after = Gated("after", ["block"])
    gw = rig.gateway(first, after)
    gw.start = AsyncMock()
    count = itertools.count()
    monkeypatch.setattr(
        server_mod,
        "create_session_manager",
        lambda server: FakeSessionManager(next(count), order),
    )

    async def loader():
        try:
            await asyncio.get_running_loop().create_future()
        except asyncio.CancelledError:
            order.append("loader cancelled")
            raise

    real = gw._late_start_checker

    async def checker():
        WHO.set("checker")
        rig.tasks.append(asyncio.current_task())
        try:
            await real()
        finally:
            order.append("checker done")

    gw._backend_loader = loader
    gw._late_start_checker = checker
    app = gw.create_app()
    leave = asyncio.Event()

    async def drive():
        async with app.router.lifespan_context(app):
            await leave.wait()

    rig.spawn("test", drive)
    await rig.waiting()
    rig.passes.go()
    await until(first.entered.is_set, "the checker starts first")
    at = after.starts
    leave.set()
    done = await settles(lambda: "checker done" in order)
    row.check("the checker done within 1 s", done, order)
    row.check("after: no start entered", after.starts == at, after.starts)
    exits = [i for i, x in enumerate(order) if x.endswith(" exit")]
    own = order.index("checker done") if done else len(order)
    loader_at = (
        order.index("loader cancelled") if "loader cancelled" in order else len(order)
    )
    row.check("done before the loader's cancel", own < loader_at, order)
    row.check(
        "done before the first session manager's exit",
        all(own < i for i in exits),
        order,
    )
    row.done()
