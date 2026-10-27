"""A stdio backend's lost connection, a stop by the gateway, a failed start and
the gateway's own failure each reach the client as one named text, on the
per-backend route and the aggregate one (backend-gone-text R3).

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
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway
from starlette.applications import Starlette

if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup

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
        "err32603": (-32603, "r2c probe -32603"),
        "err32603x": (-32603, "r2cx probe -32603"),
        "err32000": (-32000, "r2c probe -32000, the child's own"),
    }

    def reply(rid, **msg):
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, **msg}) + "\\n")
        sys.stdout.flush()

    def text(t):
        return {"content": [{"type": "text", "text": t}], "isError": False}

    TOOLS = [{"name": n, "inputSchema": {"type": "object"}} for n in ("ok", "err", "bye")]
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
    """Every column of a row is checked, and a RED row names each failed one."""

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


# R1, R6 (aggregate): a call after the child died


@pytest.mark.parametrize("route", ROUTES)
async def test_r1_a_call_after_the_child_died_gets_the_before_send_text(
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


async def test_r1p_two_parallel_calls_after_a_death_start_one_child(gws, standin):
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
async def test_r1n_a_call_held_past_its_start_gets_the_before_send_text(
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


def test_r6_no_retry_once_text_in_the_gateway():
    src = Path(sift_gateway.__file__).parent
    hits = [p for p in src.rglob("*.py") if "retry once" in p.read_text()]
    assert hits == []


# R2, R3, R3b, R2d: the connection is lost during a call


@pytest.mark.parametrize("route", ROUTES)
async def test_r2_a_child_killed_during_a_call_gets_the_during_call_text(
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
async def test_r3_a_call_that_never_returns_gets_the_during_call_text(
    gws, standin, route
):
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
async def test_r3b_a_call_judges_by_its_own_session_after_a_restart(
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
async def test_r2d_bytes_that_arent_utf8_during_a_call_get_the_during_call_text(
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


# R2c, R2c-x, R2w: a child's own reply


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "mode,message",
    [
        ("err32603", "r2c probe -32603"),
        ("err32000", "r2c probe -32000, the child's own"),
    ],
)
async def test_r2c_a_childs_error_reply_is_the_backend_error_text(
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
async def test_r2cx_an_error_reply_then_exit_is_the_backend_error_text(gws, raw, route):
    row = _Row()
    want = _failed(
        "err", "Backend standin answered err with an error: r2cx probe -32603."
    )
    for rep in range(5):
        gw = await gws(_conf(raw, "err32603x"))
        async with _client(gw, route) as client:
            _, text, _ = await _call(client, "err")
            row.check(f"rep {rep} text", text == want, text)
            row.check(f"rep {rep} ping", await _answers_ping(client))
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_r2w_guard_a_reply_then_exit_is_the_reply(gws, raw, route):
    row = _Row()
    for rep in range(5):
        gw = await gws(_conf(raw, "replyeof"))
        async with _client(gw, route) as client:
            err, text, _ = await _call(client, "bye")
            row.check(f"rep {rep}", err is False and text.startswith("bye from"), text)
    row.done()


# R5, R9: a failed start


async def _raise_timeout():
    raise TimeoutError()


async def _raise_mcp():
    raise McpError(ErrorData(code=CONNECTION_CLOSED, message="Connection closed"))


async def _raise_group():
    raise ExceptionGroup("unhandled errors in a TaskGroup", [ValueError("r5 probe")])


R5_LEGS = {
    "exit": (1, None),
    "timeout": (1, _raise_timeout),
    "mcperror": (1, _raise_mcp),
    "group": (1, _raise_group),
    "ffinit": (1, None),
    "true": (40, None),
    "closestdin": (3, None),
}
R5_DETAIL = {
    "timeout": "(TimeoutError)",
    "mcperror": "(McpError: Connection closed)",
    "group": "(ExceptionGroup: ",
}


@pytest.mark.parametrize("via", ["per-backend", "aggregate", "tools/list"])
@pytest.mark.parametrize("leg", sorted(R5_LEGS))
async def test_r5_a_failed_start_gets_the_start_failure_text(
    gws, standin, raw, leg, via, monkeypatch, caplog
):
    row = _Row()
    reps, raiser = R5_LEGS[leg]
    if leg == "true":
        conf = {"type": "stdio", "command": "/bin/true", "args": []}
    elif raiser is None:
        conf = _conf(raw, leg)
    else:
        conf = _conf(standin)
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
            want = "Backend standin didn't start " + R5_DETAIL.get(leg, "(")
            row.check(f"rep {rep} text", want in text, text)
            row.check(f"rep {rep} not in the gateway", "in the gateway" not in text)
            row.check(f"rep {rep} ping", await _answers_ping(client))
            row.check(f"rep {rep} started false", backend.started is False)
            left = await _settles(lambda: not _kids(), 5)
            row.check(f"rep {rep} no child left", left, _kids())
    cancelled = [
        r.getMessage()
        for r in caplog.records
        if r.levelname == "ERROR" and "CancelledError" in r.getMessage()
    ]
    row.check("no ERROR line names a CancelledError", not cancelled, cancelled)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_r9_guard_a_call_while_the_loader_replaces_it_is_the_reloading_reply(
    gws, standin, route
):
    gw = await gws(_conf(standin), start=False)
    gw._tool_map["ping"] = "standin"
    gw._pending_backends["standin"] = _conf(standin)
    async with _client(gw, route) as client:
        _, text, _ = await _call(client, "ping")
    assert "Backend standin is reloading; retry shortly" in text, text
    assert "didn't start" not in text, text


# R7, R7c, R8: health and tools/list after a death


async def _health(gw) -> dict:
    app = Starlette(routes=health_routes())
    app.state.gateway = gw
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        return (await c.get("/health", timeout=30)).json()["backends"]["standin"]


@pytest.mark.parametrize("cache", ["kept", "cleared"])
@pytest.mark.parametrize("route", ROUTES)
async def test_r7_health_reports_a_dead_child_and_doesnt_reset_it(
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
        checker.cancel()
        row.check("no new child", _kids(str(standin)) == [], _kids(str(standin)))
        _, text, _ = await _call(client, "ping")
        row.check("call 1", text == _failed("ping", _before("ping")), text)
        new = await _pid(client)
        row.check("call 2 from a new pid", new not in (None, old), new)
        await _after(row, client, backend)
    row.done()


@pytest.mark.parametrize("route", ROUTES)
async def test_r8_tools_list_after_a_death_answers_and_the_call_gets_before_send(
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


# R10: the gateway's own failure


@pytest.mark.parametrize("route", ROUTES)
async def test_r10_the_gateways_own_failure_is_named(gws, standin, route, monkeypatch):
    gw = await gws(_conf(standin))
    backend = gw.backends["standin"]

    async def broken(*_args, **_kwargs):
        raise ValueError("r10 probe")

    monkeypatch.setattr(backend, "call_tool", broken)
    async with _client(gw, route) as client:
        err, text, _ = await _call(client, "ping")
        assert (err, text) == (
            True,
            "Error: ping failed in the gateway (ValueError: r10 probe).",
        )
        assert await _answers_ping(client)


# R11, R11s: a stop by the gateway during a call


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
async def test_r11_a_stop_during_a_call_gets_the_stopped_text(
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
            # R11s: the mark was the old session's, not the restarted one's
            call = asyncio.ensure_future(_call(client, "slow", {"seconds": 30}))
            await asyncio.sleep(1)
            if new is not None:
                os.kill(new, signal.SIGKILL)
            _, text, _ = await call
            row.check("R11s text", text == _failed("slow", _during("slow")), text)
        await _after(row, client, backend)
    row.done()
