"""A stdio backend's lost connection, a stop by the gateway, a failed start and
the gateway's own failure each reach the client as one named text, on the
per-backend route and the aggregate one.

Before this change a dead child's next call failed with "unexpected failure …
(ClosedResourceError)" or "retry once to trigger reconnect", a death during a
call waited for the 300 s deadline or named an McpError, a child's own error
reply was hidden or reset the backend, a stop during a call left it with no
reply, and a start that failed named nothing (or ended the client's session).

Each row runs real stand-in children (a FastMCP server, and a raw JSON-RPC one
that writes and flushes every reply before anything else) behind a real
Gateway, with an in-memory MCP client on each route. The client's own cap is
CAP seconds, so a call that would wait for the deadline shows up as no reply.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import logging
import os
import signal
import sys
import textwrap
import time
import types
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import anyio
import httpx
import pytest
import sift_gateway
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CONNECTION_CLOSED, ErrorData
from sift_gateway import server as server_mod
from sift_gateway.backends import stdio_backend
from sift_gateway.backends.base import in_own_task
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway
from starlette.applications import Starlette

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup, ExceptionGroup

pytestmark = pytest.mark.timeout(300)

CAP = 10  # the client's own wait for a reply; the backend's deadline is 300 s
ROUTES = ["per-backend", "aggregate"]

STANDIN = textwrap.dedent(
    """\
    import asyncio, os
    from mcp.server.fastmcp import FastMCP
    m = FastMCP("standin")

    @m.tool(structured_output=False)
    def ping() -> str:
        return f"pid {os.getpid()}"

    @m.tool(structured_output=False)
    async def slow(seconds: float) -> str:
        await asyncio.sleep(seconds)
        return f"slow done in pid {os.getpid()}"

    @m.tool(structured_output=False)
    async def ff(seconds: float) -> str:  # bytes that aren't UTF-8, then alive
        await asyncio.sleep(1)
        os.write(1, b"\\xff\\xfe\\n")
        await asyncio.sleep(seconds)
        return "ff done"

    m.run()
    """
)

RAW = textwrap.dedent(
    """\
    import json, os, sys, time
    MODE = sys.argv[1]
    if MODE == "exit":
        sys.exit(0)
    if MODE == "closestdin":
        os.close(0)
        time.sleep(600)
    ERRORS = {
        "err32603": (-32603, "error-reply probe -32603"),
        "err32603x": (-32603, "error-then-exit probe -32603"),
        "err32000": (-32000, "error-reply probe -32000, the child's own"),
    }

    def reply(rid, **msg):
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, **msg}) + "\\n")
        sys.stdout.flush()

    def text(t):
        return {"content": [{"type": "text", "text": t}], "isError": False}

    TOOLS = [{"name": n, "inputSchema": {"type": "object"}} for n in ("ok", "err", "bye")]
    LISTS = []
    for line in sys.stdin:
        if not line.strip():
            continue
        req = json.loads(line)
        if "id" not in req:
            continue
        rid, method = req["id"], req.get("method")
        name = (req.get("params") or {}).get("name")
        if method == "initialize":
            if MODE == "ffinit":
                os.write(1, b"\\xff\\xfe\\n")
            reply(rid, result={
                "protocolVersion": req["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": MODE, "version": "0"},
            })
        elif method == "tools/list" and MODE == "slowlist":
            if len(LISTS) == 1:  # the second listing is slow
                time.sleep(4)
            LISTS.append(1)
            reply(rid, result={"tools": TOOLS})
        elif method == "tools/list" and MODE == "listerr":
            reply(rid, error={"code": -32603, "message": "listing-error probe listing refused"})
        elif method == "tools/list":
            reply(rid, result={"tools": TOOLS})
        elif method == "ping":
            reply(rid, result={})
        elif name == "ok":
            reply(rid, result=text(f"pid {os.getpid()}"))
        elif name == "bye":  # the reply and the child's exit arrive together
            reply(rid, result=text(f"bye from pid {os.getpid()}"))
            os._exit(0)
        elif name == "err":
            code, message = ERRORS[MODE]
            reply(rid, error={"code": code, "message": message})
            if MODE == "err32603x":
                os._exit(0)
        else:
            reply(rid, error={"code": -32601, "message": f"no method {method}"})
    """
)


def _before(tool: str) -> str:
    return (
        f"The gateway lost its connection to backend standin's process before "
        f"{tool} was sent, so {tool} didn't run. The gateway starts the backend "
        "again on the next call."
    )


def _during(tool: str) -> str:
    return (
        f"The gateway lost its connection to backend standin's process while "
        f"{tool} was running. The gateway didn't send it again, and it may have "
        "run in part: check the case audit before running it again. The gateway "
        "starts the backend again on the next call."
    )


def _stopped(tool: str) -> str:
    return (
        "The gateway stopped backend standin (a service stop or restart, an idle "
        f"stop or shutdown) while {tool} was running. The gateway didn't send it "
        "again, and it may have run in part: check the case audit before running "
        "it again."
    )


def _failed(tool: str, text: str) -> str:
    """Both routes print a RuntimeError from a call this way."""
    return f"Error: {tool} failed: {text}"


class _Row:
    """Every column of a row is checked, and a failing row names each failed one."""

    def __init__(self):
        self.failed: list[str] = []

    def check(self, column: str, ok, seen=None) -> None:
        if not ok:
            self.failed.append(f"{column}: {seen!r}")

    def done(self) -> None:
        assert not self.failed, "\n".join(self.failed)


@pytest.fixture
def standin(tmp_path):
    path = tmp_path / "standin.py"
    path.write_text(STANDIN)
    return path


@pytest.fixture
def raw(tmp_path):
    path = tmp_path / "raw.py"
    path.write_text(RAW)
    return path


def _conf(path: Path, *args: str) -> dict:
    return {
        "type": "stdio",
        "command": sys.executable,
        "args": ["-I", str(path), *args],
    }


@pytest.fixture
async def gws():
    """Gateways for a row, each with one backend `standin`; stopped after."""
    made = []

    async def make(conf: dict, *, start: bool = True, gateway: dict | None = None):
        gw = Gateway({"gateway": gateway or {}, "backends": {"standin": conf}})
        gw._notify_backend_case = AsyncMock()
        made.append(gw)
        if start:
            await gw.start()
        return gw

    yield make
    for gw in made:
        await gw.stop()


@contextlib.asynccontextmanager
async def _client(gw, route: str):
    if route == "per-backend":
        server = create_backend_mcp_server(gw, "standin")
    else:
        server = create_mcp_server(gw)
    async with create_connected_server_and_client_session(server) as client:
        yield client


async def _call(client, tool: str, args: dict | None = None, cap: float = CAP):
    """(isError, text, seconds); isError None when no reply came."""
    started = time.monotonic()
    try:
        result = await client.call_tool(
            tool, args or {}, read_timeout_seconds=timedelta(seconds=cap)
        )
    except Exception as exc:  # the client's cap, or its session ended
        return None, f"{type(exc).__name__}: {exc}", time.monotonic() - started
    text = " | ".join(getattr(c, "text", repr(c)) for c in result.content)
    return result.isError, text, time.monotonic() - started


async def _pid(client) -> int | None:
    err, text, _ = await _call(client, "ping")
    if err is False and text.startswith("pid "):
        return int(text.split()[-1])
    return None


async def _answers_ping(client) -> bool:
    try:
        with anyio.fail_after(5):
            await client.send_ping()
        return True
    except Exception:
        return False


def _stat(pid) -> list[str]:
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()
    except OSError:
        return ["gone", "0"]


def _alive(pid: int) -> bool:
    return _stat(pid)[0] not in ("gone", "Z")


def _kids(match: str = "") -> list[int]:
    """This process's live children, whose command line holds `match`."""
    me, out = str(os.getpid()), []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        state, ppid = _stat(entry)[:2]
        if ppid != me or state in ("gone", "Z"):
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode()
        except OSError:
            continue
        if match in cmd:
            out.append(int(entry))
    return sorted(out)


def _fds() -> int:
    return len(os.listdir("/proc/self/fd"))


async def _settles(check, seconds: float = 3) -> bool:
    end = time.monotonic() + seconds
    while not check():
        if time.monotonic() > end:
            return False
        await asyncio.sleep(0.05)
    return True


async def _kill(pid: int, settle: float = 0.5) -> None:
    """SIGKILL; wait until it's gone, then `settle` more."""
    os.kill(pid, signal.SIGKILL)
    await _settles(lambda: not _alive(pid), 5)
    await asyncio.sleep(settle)


def _pending(backend) -> int:
    session = backend._session
    return 0 if session is None else len(session._response_streams)


async def _after(row: _Row, client, backend) -> None:
    """The columns every row records after it."""
    row.check("client answers a ping", await _answers_ping(client))
    row.check("0 pending in the backend session", _pending(backend) == 0)


async def _held(*_args, **_kwargs):
    await asyncio.Event().wait()


# A call after the child died, on either route


@pytest.mark.parametrize("route", ROUTES)
async def test_a_call_after_the_child_died_gets_the_before_send_text(
    gws, standin, route
):
    row, fds = _Row(), _fds()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
        await _kill(old)
        err, text, _ = await _call(client, "ping")
        row.check("call 1 text", text == _failed("ping", _before("ping")), text)
        row.check("call 1 isError", err is True, err)
        row.check("started false", backend.started is False, backend.started)
        row.check("fds back", await _settles(lambda: _fds() == fds), (_fds(), fds))
        new = await _pid(client)
        row.check("call 2 from a new pid", new not in (None, old), (old, new))
        await _after(row, client, backend)
    row.done()


async def test_two_parallel_calls_after_a_death_start_one_child(gws, standin):
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, "per-backend") as client:
        old = await _pid(client)
        await _kill(old)
        (_, one, _), (_, two, _) = await asyncio.gather(
            _call(client, "ping"), _call(client, "ping")
        )
        new = await _pid(client)
        before = _failed("ping", _before("ping"))
        row.check(
            "one call gets the before-send text", before in (one, two), [one, two]
        )
        row.check(
            "the other: before-send or the new pid",
            {one, two} <= {before, f"pid {new}"},
            [one, two, new],
        )
        row.check("call 3 from a new pid", new not in (None, old), (old, new))
        row.check("exactly one new child", _kids(str(standin)) == [new], _kids())
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_a_call_held_past_its_start_gets_the_before_send_text(
    gws, standin, route, monkeypatch
):
    """A call passes the start and waits in the tool-map rebuild; meanwhile its
    child dies and a second call resets the session."""
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    entered, release = asyncio.Event(), asyncio.Event()
    rebuild = gw._build_tool_map

    async def held_rebuild():
        entered.set()
        await release.wait()
        await rebuild()

    async with _client(gw, route) as client:
        # A client lists the tools first; with the SDK's tool cache empty, a
        # call would refresh it through the route's list_tools, not its call
        await client.list_tools()
        await backend.stop()  # the tool map stays: the next call starts it
        monkeypatch.setattr(gw, "_build_tool_map", held_rebuild)
        held = asyncio.ensure_future(_call(client, "ping"))
        await asyncio.wait_for(entered.wait(), 30)
        [child] = _kids(str(standin))
        await _kill(child)
        _, second, _ = await _call(client, "ping")
        row.check("call 2", second == _failed("ping", _before("ping")), second)
        release.set()
        _, text, _ = await held
        row.check("the held call", text == _failed("ping", _before("ping")), text)
        if route == "per-backend":  # the aggregate rebuild dropped the backend
            new = await _pid(client)
            row.check("call 3 from a new pid", new not in (None, child), new)
            row.check("one child", _kids(str(standin)) == [new], _kids())
        await _after(row, client, backend)
    row.done()


def test_no_retry_once_text_in_the_gateway():
    src = Path(sift_gateway.__file__).parent
    hits = [p for p in src.rglob("*.py") if "retry once" in p.read_text()]
    assert hits == []


# The connection is lost during a call


@pytest.mark.parametrize("route", ROUTES)
async def test_a_child_killed_during_a_call_gets_the_during_call_text(
    gws, standin, route
):
    row, fds = _Row(), _fds()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
        call = asyncio.ensure_future(_call(client, "slow", {"seconds": 30}))
        await asyncio.sleep(1)
        os.kill(old, signal.SIGKILL)
        killed = time.monotonic()
        err, text, _ = await call
        took = time.monotonic() - killed
        row.check("text", text == _failed("slow", _during("slow")), text)
        row.check("isError", err is True, err)
        row.check("within 3 s of the kill", took < 3, round(took, 2))
        row.check("started false", backend.started is False, backend.started)
        row.check("fds back", await _settles(lambda: _fds() == fds), (_fds(), fds))
        row.check("not in the gateway", "in the gateway" not in text, text)
        new = await _pid(client)
        row.check("the next call from a new pid", new not in (None, old), new)
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_a_call_that_never_returns_gets_the_during_call_text(gws, standin, route):
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
        backend._session.call_tool = _held
        call = asyncio.ensure_future(_call(client, "slow", {"seconds": 30}))
        await asyncio.sleep(1)
        os.kill(old, signal.SIGKILL)
        killed = time.monotonic()
        _, text, _ = await call
        took = time.monotonic() - killed
        row.check("text", text == _failed("slow", _during("slow")), text)
        row.check("within 3 s of the kill", took < 3, round(took, 2))
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_a_call_judges_by_its_own_session_after_a_restart(
    gws, standin, route, monkeypatch
):
    """Call 1's poll can't see its child's end until call 3 has started a new
    child and returned: call 1 must not take the new child for its own."""
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
        backend._session.call_tool = _held
        gate, first = asyncio.Event(), []
        real = getattr(stdio_backend, "_lost", None)

        def gated(stream):
            task = asyncio.current_task()
            first[:] = first or [task]
            if task is first[0] and not gate.is_set():
                return False
            return real(stream)

        monkeypatch.setattr(stdio_backend, "_lost", gated, raising=False)
        call1 = asyncio.ensure_future(_call(client, "slow", {"seconds": 30}, cap=60))
        await asyncio.sleep(1)
        await _kill(old)
        _, two, _ = await _call(client, "ping")
        row.check("call 2", two == _failed("ping", _before("ping")), two)
        new = await _pid(client)
        row.check("call 3 from a new pid", new not in (None, old), new)
        gate.set()
        _, one, _ = await call1
        row.check("call 1", one == _failed("slow", _during("slow")), one)
        row.check("started true after call 1", backend.started is True)
        row.check("the new pid alive", new is not None and _alive(new), new)
        four = await _pid(client)
        row.check("call 4 by the new pid", four == new, (four, new))
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_bytes_that_arent_utf8_during_a_call_get_the_during_call_text(
    gws, standin, route
):
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
        err, text, took = await _call(client, "ff", {"seconds": 30})
        row.check("text", text == _failed("ff", _during("ff")), text)
        row.check("within 3 s of the write", took < 4, round(took, 2))
        row.check("started false", backend.started is False, backend.started)
        row.check("old pid gone", await _settles(lambda: not _alive(old)), old)
        await _after(row, client, backend)
    row.done()


# A child's own reply


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "mode,message",
    [
        ("err32603", "error-reply probe -32603"),
        ("err32000", "error-reply probe -32000, the child's own"),
    ],
)
async def test_a_childs_error_reply_is_the_backend_error_text(
    gws, raw, route, mode, message
):
    row = _Row()
    gw = await gws(_conf(raw, mode))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        _, ok, _ = await _call(client, "ok")
        err, text, _ = await _call(client, "err")
        want = _failed("err", f"Backend standin answered err with an error: {message}.")
        row.check("text", text == want, text)
        row.check("isError", err is True, err)
        row.check("not in the gateway", "in the gateway" not in text, text)
        row.check("started true", backend.started is True, backend.started)
        _, again, _ = await _call(client, "ok")
        row.check("the same pid answers next", again == ok, (ok, again))
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_an_error_reply_then_exit_is_the_backend_error_text(gws, raw, route):
    row = _Row()
    want = _failed(
        "err",
        "Backend standin answered err with an error: error-then-exit probe -32603.",
    )
    for rep in range(5):
        gw = await gws(_conf(raw, "err32603x"))
        async with _client(gw, route) as client:
            _, text, _ = await _call(client, "err")
            row.check(f"rep {rep} text", text == want, text)
            row.check(f"rep {rep} ping", await _answers_ping(client))
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_a_reply_then_exit_is_the_reply(gws, raw, route):
    row = _Row()
    for rep in range(5):
        gw = await gws(_conf(raw, "replyeof"))
        async with _client(gw, route) as client:
            err, text, _ = await _call(client, "bye")
            row.check(f"rep {rep}", err is False and text.startswith("bye from"), text)
    row.done()


# A failed start


async def _raise_timeout():
    raise TimeoutError()


async def _raise_mcp():
    raise McpError(ErrorData(code=CONNECTION_CLOSED, message="Connection closed"))


async def _raise_group():
    raise ExceptionGroup("unhandled errors in a TaskGroup", [ValueError("start probe")])


START_FAILURES = {
    "exit": (1, None),
    "timeout": (1, _raise_timeout),
    "mcperror": (1, _raise_mcp),
    "group": (1, _raise_group),
    "ffinit": (1, None),
    "true": (40, None),
    "closestdin": (3, None),
}
START_FAILURE_DETAIL = {
    "timeout": "(TimeoutError)",
    "mcperror": "(McpError: Connection closed)",
    "group": "(ExceptionGroup: ",
}


@pytest.mark.parametrize("via", ["per-backend", "aggregate", "tools/list"])
@pytest.mark.parametrize("leg", sorted(START_FAILURES))
async def test_a_failed_start_gets_the_start_failure_text(
    gws, standin, raw, leg, via, monkeypatch, caplog
):
    row = _Row()
    reps, raiser = START_FAILURES[leg]
    if leg == "true":
        conf = {"type": "stdio", "command": "/bin/true", "args": []}
    elif raiser is None:
        conf = _conf(raw, leg)
    else:
        conf = _conf(standin)
    mine = conf["args"][1] if conf["args"] else conf["command"]  # this row's child
    if leg == "closestdin":
        monkeypatch.setattr(stdio_backend, "_INITIALIZE_TIMEOUT", 1)
    gw = await gws(conf, start=False)
    gw._tool_map["ping"] = "standin"
    backend = gw.backends["standin"]
    if raiser is not None:
        monkeypatch.setattr(backend, "start", raiser)
    route = "per-backend" if via == "tools/list" else via
    async with _client(gw, route) as client:
        for rep in range(reps):
            if via == "tools/list":
                try:
                    with anyio.fail_after(CAP + 30):
                        await client.list_tools()
                    text = "tools/list answered"
                except Exception as exc:
                    text = f"{type(exc).__name__}: {exc}"
            else:
                _, text, _ = await _call(client, "ping", cap=CAP + 30)
            want = "Backend standin didn't start " + START_FAILURE_DETAIL.get(leg, "(")
            row.check(f"rep {rep} text", want in text, text)
            row.check(f"rep {rep} not in the gateway", "in the gateway" not in text)
            row.check(f"rep {rep} ping", await _answers_ping(client))
            row.check(f"rep {rep} started false", backend.started is False)
            left = await _settles(lambda: not _kids(mine), 5)
            row.check(f"rep {rep} no child left", left, _kids(mine))
    cancelled = [
        r.getMessage()
        for r in caplog.records
        if r.levelname == "ERROR" and "CancelledError" in r.getMessage()
    ]
    row.check("no ERROR line names a CancelledError", not cancelled, cancelled)
    row.done()


# A start cancelled by its caller, or by its own task group, whose
# close raises a real error


async def _fail_soon():
    await asyncio.sleep(0.1)
    raise OSError(5, "close probe: the transport failed")


def _fake_stdio(close, *, group: bool = False, fail: bool = False):
    """stdio_client's stand-in: nobody answers initialize. Its close raises
    close(). `group` holds the streams in a task group, as stdio_client does,
    and `fail` fails that group soon, as a dead child does."""

    @contextlib.asynccontextmanager
    async def stdio_client(_params):
        _s2c_w, s2c_r = anyio.create_memory_object_stream(10)
        c2s_w, _c2s_r = anyio.create_memory_object_stream(10)
        try:
            if not group:
                yield s2c_r, c2s_w
                return
            async with anyio.create_task_group() as tg:
                if fail:
                    tg.start_soon(_fail_soon)
                yield s2c_r, c2s_w
        finally:
            raise close()

    return stdio_client


def _broken_pipe() -> BaseException:
    return OSError(32, "Broken pipe (the child's stdin, on close)")


def _mixed() -> BaseException:
    return BaseExceptionGroup(
        "close probe", [asyncio.CancelledError(), OSError(32, "close failed")]
    )


async def _under_scope(start, *, own_task: bool = True):
    """The caller is an anyio scope cancelled from outside, as the SDK cancels a
    request's handler; the scope takes its own cancellation. With `own_task`
    False the scope is in start's own task, as the loader's task group is
    (server.py:893-896)."""
    with anyio.CancelScope() as scope:
        asyncio.get_running_loop().call_later(0.3, scope.cancel)
        await (in_own_task(start) if own_task else start)
    caught = scope.cancelled_caught
    return "the caller's scope caught its cancellation" if caught else ""


START_ROUTES = {
    "A": lambda b: b.start(),
    "B": lambda b: in_own_task(b.start()),
    "C": lambda b: asyncio.wait_for(in_own_task(b.start()), 60),
    "scope": lambda b: _under_scope(b.start()),
    "loader scope": lambda b: _under_scope(b.start(), own_task=False),
}


async def _start_outcome(route: str, cancel: bool, caplog) -> tuple[str, list, list]:
    """(what reached the caller, its ERROR "failed to start" lines, the "never
    retrieved" reports) for one start of a backend on `route`."""
    unretrieved = []
    loop = asyncio.get_running_loop()
    before = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: unretrieved.append(ctx["message"]))
    try:
        backend = stdio_backend.StdioMCPBackend("standin", {"command": "x", "args": []})
        outer = asyncio.ensure_future(START_ROUTES[route](backend))
        if cancel:
            await asyncio.sleep(0.3)
            outer.cancel()
        await asyncio.wait({outer}, timeout=CAP)
        if not outer.done():
            outer.cancel()
            got = "no answer"
        elif outer.cancelled():
            got = "CancelledError"
        elif outer.exception() is not None:
            got = f"{type(outer.exception()).__name__}: {outer.exception()}"
        else:
            got = f"returned: {outer.result()}"
        del outer
        for _ in range(3):
            gc.collect()
            await asyncio.sleep(0.05)
    finally:
        loop.set_exception_handler(before)
    failed = [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.ERROR and "failed to start" in r.getMessage()
    ]
    return got, failed, [m for m in unretrieved if "never retrieved" in m]


@pytest.mark.parametrize("route", ["A", "B", "C"])
async def test_a_callers_cancel_is_kept_when_the_close_raises(
    route, monkeypatch, caplog
):
    """The caller cancels a start at 0.3 s, and the transport's close raises a real
    error: the caller still gets its cancellation, with no ERROR line and no
    unretrieved exception."""
    row = _Row()
    monkeypatch.setattr(stdio_backend, "stdio_client", _fake_stdio(_broken_pipe))
    got, failed, unretrieved = await _start_outcome(route, True, caplog)
    row.check("the caller gets CancelledError", got == "CancelledError", got)
    row.check("no ERROR failed to start", not failed, failed)
    row.check("0 never retrieved", not unretrieved, unretrieved)
    row.done()


async def test_a_loader_scope_cancel_is_kept_when_the_close_raises(monkeypatch, caplog):
    """The gateway's shutdown cancels the
    loader's task-group scope in the task that awaits start (server.py:494, 542,
    893-896), and the transport's close raises a real error. That scope is
    outside the guard, so the start's look must not see it: the scope takes its
    cancellation, with no ERROR and no BrokenPipeError."""
    row = _Row()
    fake = _fake_stdio(_broken_pipe, group=True)
    monkeypatch.setattr(stdio_backend, "stdio_client", fake)
    got, failed, unretrieved = await _start_outcome("loader scope", False, caplog)
    want = "returned: the caller's scope caught its cancellation"
    row.check("what reaches the caller", got == want, got)
    row.check("no ERROR failed to start", not failed, failed)
    row.check("0 never retrieved", not unretrieved, unretrieved)
    row.done()


# No row for a caller's cancel that lands just before the start's own task
# group fails: on 3.10 one up to ~1 ms ahead is lost (BrokenPipeError and an
# ERROR line), and 3.12 keeps it, so a row at that edge would be flaky.
MIXED_CLOSES = {  # leg: (fail the group, cancel by the caller, route, what reaches it)
    "own failure": (True, False, "A", "BrokenPipeError: [Errno 32] close failed"),
    "caller A": (False, True, "A", "CancelledError"),
    "caller C": (False, True, "C", "CancelledError"),
    "caller scope": (
        False,
        False,
        "scope",
        "returned: the caller's scope caught its cancellation",
    ),
}


@pytest.mark.parametrize("leg", sorted(MIXED_CLOSES))
async def test_a_close_mixing_a_cancellation_and_an_error(leg, monkeypatch, caplog):
    """The start's close raises a group of a CancelledError and an OSError. A
    start whose own task group failed raises the OSError and logs it as the
    failed start; one its caller cancelled stays a cancellation, with no ERROR."""
    row = _Row()
    fail, cancel, route, want = MIXED_CLOSES[leg]
    fake = _fake_stdio(_mixed, group=True, fail=fail)
    monkeypatch.setattr(stdio_backend, "stdio_client", fake)
    got, failed, unretrieved = await _start_outcome(route, cancel, caplog)
    row.check("what reaches the caller", got == want, got)
    if fail:
        line = "Backend standin failed to start: " + want
        row.check("the ERROR line names the OSError", failed == [line], failed)
    else:
        row.check("no ERROR failed to start", not failed, failed)
    row.check("0 never retrieved", not unretrieved, unretrieved)
    row.done()


async def test_health_leaves_the_session_when_tools_list_fails():
    """health_check's list_tools never resets: a session whose tools/list fails
    with a gone error is reported, and left for the next call to judge."""
    backend = stdio_backend.StdioMCPBackend("standin", {"command": "x", "args": []})
    error = AsyncMock(side_effect=anyio.BrokenResourceError())
    session = types.SimpleNamespace(list_tools=error)
    backend._session, backend._started = session, True
    health = await backend.health_check()
    want = {"status": "error", "type": "stdio", "error": "BrokenResourceError"}
    assert health == want, health
    assert backend._session is session, backend._session
    assert backend.started is True


@pytest.mark.parametrize("route", ROUTES)
async def test_a_call_while_the_loader_replaces_it_is_the_reloading_reply(
    gws, standin, route
):
    gw = await gws(_conf(standin), start=False)
    gw._tool_map["ping"] = "standin"
    gw._pending_backends["standin"] = _conf(standin)
    async with _client(gw, route) as client:
        _, text, _ = await _call(client, "ping")
    assert "Backend standin is reloading; retry shortly" in text, text
    assert "didn't start" not in text, text


# Health and tools/list after a death


async def _health(gw) -> dict:
    app = Starlette(routes=health_routes())
    app.state.gateway = gw
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        return (await c.get("/health", timeout=30)).json()["backends"]["standin"]


@pytest.mark.parametrize("cache", ["kept", "cleared"])
@pytest.mark.parametrize("route", ROUTES)
async def test_health_reports_a_dead_child_and_doesnt_reset_it(
    gws, standin, route, cache, monkeypatch
):
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
        await _kill(old)
        if cache == "cleared":
            backend._tools_cache = None
        for n in (1, 2):
            health = await _health(gw)
            row.check(f"/health {n}", health.get("status") == "error", health)
        row.check("started still true", backend.started is True, backend.started)
        monkeypatch.setattr(server_mod, "_LATE_START_SECONDS", 0.5)
        checker = asyncio.ensure_future(gw._late_start_checker())
        await asyncio.sleep(2)
        await gw.stop_late_start_checker(checker)
        row.check("no new child", _kids(str(standin)) == [], _kids(str(standin)))
        _, text, _ = await _call(client, "ping")
        row.check("call 1", text == _failed("ping", _before("ping")), text)
        new = await _pid(client)
        row.check("call 2 from a new pid", new not in (None, old), new)
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_tools_list_after_a_death_answers_and_the_call_gets_before_send(
    gws, standin, route
):
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        await _kill(await _pid(client))
        names = [t.name for t in (await client.list_tools()).tools]
        row.check("tools/list answers", "ping" in names, names)
        _, text, _ = await _call(client, "ping")
        row.check("the next call", text == _failed("ping", _before("ping")), text)
        await _after(row, client, backend)
    row.done()


# A listing when the child dies


def _listing() -> str:
    return (
        "The gateway lost its connection to backend standin's process while listing "
        "its tools, so no tool ran. The gateway starts the backend again on the next "
        "call."
    )


async def _listed(client, cap: float = CAP):
    """(tool names or None, error text, seconds) for one tools/list."""
    started = time.monotonic()
    try:
        with anyio.fail_after(cap):
            names = [t.name for t in (await client.list_tools()).tools]
        return names, "", time.monotonic() - started
    except Exception as exc:  # the client's cap, or the route's error reply
        return None, f"{type(exc).__name__}: {exc}", time.monotonic() - started


@pytest.mark.parametrize("ask", ["call", "list"])
@pytest.mark.parametrize("route", ROUTES)
async def test_a_listing_the_child_never_answers_ends_with_its_death(
    gws, standin, route, ask
):
    """The child dies while the backend waits for its tools/list, and the reply
    never comes (as on 3.10, when the request's write meets the dead pipe)."""
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, route) as client:
        old = await _pid(client)
    backend._tools_cache = None
    backend._session.list_tools = _held
    async with _client(gw, route) as client:  # a new client's call lists first
        if ask == "call":
            pending = asyncio.ensure_future(_call(client, "ping"))
        else:
            pending = asyncio.ensure_future(_listed(client))
        await asyncio.sleep(1)
        killed = time.monotonic()
        await _kill(old, settle=0)
        seen = await pending
        took = time.monotonic() - killed
        row.check("an answer within 5 s of the kill", took < 5, (round(took, 2), seen))
        if route == "aggregate" and ask == "call":  # its listing skips the failure
            ok = (
                seen[0] is False
                and seen[1].startswith("pid ")
                and seen[1] != f"pid {old}"
            )
        elif route == "aggregate":
            ok = seen[:2] == (["ping", "slow", "ff"], "")
        elif ask == "call":
            ok = seen[:2] == (True, _listing())
        else:
            ok = seen[:2] == (None, f"McpError: {_listing()}")
        row.check("the answer", ok, seen)
        new = await _pid(client)
        row.check("the next call from a new pid", new not in (None, old), new)
        row.check("one child", _kids(str(standin)) == [new], _kids(str(standin)))
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("when", ["before", "during", "deadline"])
async def test_health_when_the_child_dies_at_its_listing(
    gws, standin, when, monkeypatch
):
    """Health's tools/list meets the death: health says error within the
    bound, and leaves the session for the next call to judge, as after any death. deadline:
    the death is first seen at the listing's deadline."""
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    deadline = stdio_backend._TOOL_LIST_TIMEOUT
    async with _client(gw, "per-backend") as client:
        old = await _pid(client)
        backend._tools_cache = None
        backend._session.list_tools = _held
        real, looks = stdio_backend._lost, []
        misses = 2 if when == "deadline" else 1  # health's look, then the send's

        def first_misses(stream):  # health's own looks come just before the death
            looks.append(stream)
            return False if len(looks) <= misses else real(stream)

        if when != "during":
            await _kill(old)
            monkeypatch.setattr(stdio_backend, "_lost", first_misses)
        if when == "deadline":  # the wait's first look is at its deadline
            monkeypatch.setattr(stdio_backend, "_TOOL_LIST_TIMEOUT", 0)
        started = time.monotonic()
        health = asyncio.ensure_future(_health(gw))
        if when == "during":
            await asyncio.sleep(1)
            await _kill(old, settle=0)
        try:
            seen = await asyncio.wait_for(health, CAP)
        except asyncio.TimeoutError:
            seen = None
        took = time.monotonic() - started
        monkeypatch.setattr(stdio_backend, "_lost", real)
        monkeypatch.setattr(stdio_backend, "_TOOL_LIST_TIMEOUT", deadline)
        row.check("health within 5 s", took < 5, round(took, 2))
        row.check("status error", (seen or {}).get("status") == "error", seen)
        row.check("started still true", backend.started is True, backend.started)
        _, text, _ = await _call(client, "ping")
        row.check("call 1", text == _failed("ping", _before("ping")), text)
        new = await _pid(client)
        row.check("call 2 from a new pid", new not in (None, old), new)
        await _after(row, client, backend)
    row.done()


async def test_a_childs_error_reply_to_a_listing_is_as_it_was(gws, raw):
    row = _Row()
    gw = await gws(_conf(raw, "listerr"))
    backend = gw.backends["standin"]
    [child] = _kids(str(raw))
    async with _client(gw, "per-backend") as client:
        seen = await _call(client, "ok")
        row.check(
            "call", seen[:2] == (True, "listing-error probe listing refused"), seen
        )
        listed = await _listed(client)
        row.check(
            "list",
            listed[:2] == (None, "McpError: listing-error probe listing refused"),
            listed,
        )
        row.check("started true", backend.started is True, backend.started)
        row.check("the same child", _kids(str(raw)) == [child], _kids(str(raw)))
        await _after(row, client, backend)
    row.done()


# The gateway's own failure


@pytest.mark.parametrize("route", ROUTES)
async def test_the_gateways_own_failure_is_named(gws, standin, route, monkeypatch):
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]

    async def broken(*_args, **_kwargs):
        raise ValueError("gateway probe")

    monkeypatch.setattr(backend, "call_tool", broken)
    async with _client(gw, route) as client:
        err, text, _ = await _call(client, "ping")
        assert (err, text) == (
            True,
            "Error: ping failed in the gateway (ValueError: gateway probe).",
        )
        assert await _answers_ping(client)


# A stop by the gateway during a call


def _short_reaper_sleep(monkeypatch) -> None:
    """The idle reaper's 60 s sleep is 0.25 s; every other sleep is as it was."""
    proxy = types.ModuleType("asyncio")
    proxy.__dict__.update(asyncio.__dict__)

    async def sleep(delay, result=None):
        return await asyncio.sleep(0.25 if delay == 60 else delay, result)

    proxy.sleep = sleep
    monkeypatch.setattr(server_mod, "asyncio", proxy)


async def _rest(gw, path: str) -> int:
    app = Starlette(routes=list(rest_routes()))
    app.state.gateway = gw
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        return (await c.post(path, timeout=30)).status_code


@pytest.mark.parametrize("how", ["stop", "restart", "reaper"])
@pytest.mark.parametrize("route", ROUTES)
async def test_a_stop_during_a_call_gets_the_stopped_text(
    gws, standin, route, how, monkeypatch
):
    row = _Row()
    idle = {"idle_timeout_seconds": 1} if how == "reaper" else None
    gw = await gws(_conf(standin), gateway=idle)
    backend = gw.backends["standin"]
    stops: list[float] = []
    stop = backend.stop

    async def timed_stop():
        stops.append(time.monotonic())
        await stop()

    monkeypatch.setattr(backend, "stop", timed_stop)
    reaper = None
    async with _client(gw, route) as client:
        old = await _pid(client)
        call = asyncio.ensure_future(_call(client, "slow", {"seconds": 30}))
        if how == "reaper":
            _short_reaper_sleep(monkeypatch)
            reaper = asyncio.ensure_future(gw._idle_reaper())
        else:
            await asyncio.sleep(1)
            status = await _rest(gw, f"/api/v1/services/standin/{how}")
            row.check(f"REST {how}", status == 200, status)
        _, text, _ = await call
        ended = time.monotonic()
        if reaper is not None:
            reaper.cancel()
        row.check("the backend was stopped", stops, stops)
        took = ended - stops[0] if stops else None
        row.check("text", text == _failed("slow", _stopped("slow")), text)
        row.check("within 3 s of the stop", took is not None and took < 3, took)
        row.check("no 'starts the backend again'", "starts the backend" not in text)
        if how == "restart":
            new = await _pid(client)
            row.check("the new pid serves", new not in (None, old), new)
            row.check("the new pid alive", new is not None and _alive(new), new)
            # The mark was the old session's, not the restarted one's
            call = asyncio.ensure_future(_call(client, "slow", {"seconds": 30}))
            await asyncio.sleep(1)
            if new is not None:
                os.kill(new, signal.SIGKILL)
            _, text, _ = await call
            row.check(
                "the restarted session's text",
                text == _failed("slow", _during("slow")),
                text,
            )
        await _after(row, client, backend)
    row.done()


# The listing's other deaths, and a stop


@pytest.mark.parametrize("who", ["health", "call", "list"])
async def test_the_child_dies_while_its_listing_runs(gws, raw, who):
    """The child got tools/list and is killed before it answers: EOF, no hang."""
    row = _Row()
    gw = await gws(_conf(raw, "slowlist"))
    backend = gw.backends["standin"]
    [child] = _kids(str(raw))
    async with _client(gw, "per-backend") as client:
        first = await _call(client, "ok")  # warms this route's own tool cache
        row.check("first", first[:2] == (False, f"pid {child}"), first)
        backend._tools_cache = None
        if who == "health":
            pending = asyncio.ensure_future(_health(gw))
            await asyncio.sleep(1)
            killed = time.monotonic()
            await _kill(child, settle=0)
            try:
                seen = await asyncio.wait_for(pending, CAP)
            except asyncio.TimeoutError:
                seen = None
            took = time.monotonic() - killed
            row.check("health within 5 s", took < 5, round(took, 2))
            row.check("status error", (seen or {}).get("status") == "error", seen)
            row.check("started still true", backend.started is True, backend.started)
            again = await _call(client, "ok")
            row.check("call 1", again[1] == _failed("ok", _before("ok")), again)
            nxt = await _call(client, "ok")
        else:
            async with _client(gw, "per-backend") as c2:  # a new client lists first
                if who == "call":
                    pending = asyncio.ensure_future(_call(c2, "ok"))
                else:
                    pending = asyncio.ensure_future(_listed(c2))
                await asyncio.sleep(1)
                killed = time.monotonic()
                await _kill(child, settle=0)
                seen = await pending
                took = time.monotonic() - killed
                row.check("answer within 5 s", took < 5, round(took, 2))
                if who == "call":
                    ok = seen[:2] == (True, _listing())
                else:
                    ok = seen[:2] == (None, f"McpError: {_listing()}")
                row.check("the listing text", ok, seen)
                nxt = await _call(c2, "ok")
        row.check(
            "next call from a new pid",
            nxt[0] is False and nxt[1] != f"pid {child}",
            nxt,
        )
    row.done()


@pytest.mark.parametrize("ask", ["call", "list"])
async def test_a_listing_on_a_connection_already_lost(gws, standin, ask):
    """The death is known before the listing starts; the tool cache is cold."""
    row = _Row()
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]
    async with _client(gw, "per-backend") as client:
        old = await _pid(client)
        await _kill(old)
        backend._tools_cache = None
    async with _client(gw, "per-backend") as client:  # a new client lists first
        if ask == "call":
            seen = await _call(client, "ping")
            ok = seen[:2] == (True, _listing())
        else:
            seen = await _listed(client)
            ok = seen[:2] == (None, f"McpError: {_listing()}")
        row.check("the listing text", ok, seen)
        row.check("at once", seen[2] < 2, seen)
        new = await _pid(client)
        row.check("next call from a new pid", new not in (None, old), new)
        await _after(row, client, backend)
    row.done()


async def test_a_live_child_slow_to_list_times_out_alive(gws, raw, monkeypatch):
    """A live child slower than the listing deadline: a timeout, not a death."""
    row = _Row()
    gw = await gws(_conf(raw, "slowlist"))
    backend = gw.backends["standin"]
    [child] = _kids(str(raw))
    monkeypatch.setattr(stdio_backend, "_TOOL_LIST_TIMEOUT", 2)
    backend._tools_cache = None
    async with _client(gw, "per-backend") as client:
        seen = await _call(client, "ok")  # lists first: 4 s against 2 s
        row.check("not the listing text", _listing() not in seen[1], seen)
        row.check("the listing timed out", seen[0] is True, seen)
        row.check("started still true", backend.started is True, backend.started)
        await asyncio.sleep(3)  # the late reply comes and goes
        again = await _call(client, "ok")
        row.check("the same child", again[:2] == (False, f"pid {child}"), again)
        row.check("one child", _kids(str(raw)) == [child], _kids(str(raw)))
    row.done()


@pytest.mark.parametrize("how", ["task", "scope"])
async def test_a_callers_cancel_ends_its_listing(gws, raw, how):
    """The caller cancels a listing the child is slow to answer (an asyncio
    task cancel, or an AnyIO cancel scope): the cancel reaches the caller at
    once, no request is left waiting, and the child lists again."""
    row = _Row()
    gw = await gws(_conf(raw, "slowlist"))
    backend = gw.backends["standin"]
    [child] = _kids(str(raw))
    backend._tools_cache = None  # the next listing is the child's slow second
    started = time.monotonic()
    if how == "task":
        pending = asyncio.ensure_future(backend.list_tools())
        await asyncio.sleep(1)
        pending.cancel()
        await asyncio.wait({pending}, timeout=CAP)
        cancelled = pending.cancelled()
    else:
        with anyio.move_on_after(1) as scope:
            await backend.list_tools()
        cancelled = scope.cancelled_caught
    took = time.monotonic() - started
    row.check("the cancel reached the caller", cancelled is True, cancelled)
    row.check("within 2 s", took < 2, round(took, 2))
    row.check("0 pending in the backend session", _pending(backend) == 0)
    names = [t.name for t in await backend.list_tools()]
    row.check("the child lists again", names == ["ok", "err", "bye"], names)
    row.check("one child", _kids(str(raw)) == [child], _kids(str(raw)))
    row.done()


def _stopped_listing() -> str:
    return (
        "The gateway stopped backend standin (a service stop or restart, an idle stop "
        "or shutdown) while listing its tools, so no tool ran."
    )


@pytest.mark.parametrize("form", ["held", "eof"])
@pytest.mark.parametrize("how", ["stop", "restart"])
@pytest.mark.parametrize("ask", ["call", "list"])
async def test_a_stop_during_a_listing_gets_the_stopped_text(gws, raw, ask, how, form):
    """The gateway stops the backend while it lists: no restart promise, as during a call."""
    row = _Row()
    gw = await gws(_conf(raw, "slowlist"))
    backend = gw.backends["standin"]
    [child] = _kids(str(raw))
    backend._tools_cache = None
    if form == "held":  # the reply never comes, as on 3.10
        backend._session.list_tools = _held
    async with _client(gw, "per-backend") as client:
        if ask == "call":
            pending = asyncio.ensure_future(_call(client, "ok"))
        else:
            pending = asyncio.ensure_future(_listed(client))
        await asyncio.sleep(1)
        stopped = time.monotonic()
        status = await _rest(gw, f"/api/v1/services/standin/{how}")
        row.check(f"REST {how}", status == 200, status)
        seen = await pending
        took = time.monotonic() - stopped
        if ask == "call":
            ok = seen[:2] == (True, _stopped_listing())
        else:
            ok = seen[:2] == (None, f"McpError: {_stopped_listing()}")
        row.check("the stopped listing text", ok, seen)
        row.check("within 3 s of the stop", took < 3, round(took, 2))
        if how == "restart":
            nxt = await _call(client, "ok")
            new = nxt[0] is False and nxt[1] != f"pid {child}"
            row.check("next call from a new pid", new, nxt)
    row.done()
