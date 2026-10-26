"""A stdio backend keeps its MCP channel away from the processes it starts.

Each backend runs as the gateway runs it (`python -m <module>`, the channel
on a socket at fd 0 and fd 1). Once it is serving, fd 0 is /dev/null, fd 1 is
fd 2's file, and the channel lives only on descriptors that are closed on exec
and that sys.stdin and sys.stdout read and write. The channel's descriptors
are found by the socket's inode, so a backend can't pass by moving it to
another socket or a pipe. One read-only call per backend shows it still
answers over the moved channel. A backend the gateway starts again after it
died is held to the same lines.
"""

from __future__ import annotations

import asyncio
import json
import os
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import mcp.types as types
import pytest
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server
from sift_gateway.server import Gateway

TIMEOUT = 30.0
O_CLOEXEC = 0o2000000
# Runs the backend as `python -m` does; SIGUSR1 writes which descriptors
# sys.stdin and sys.stdout use at that moment.
LAUNCH = (
    "import json, runpy, signal, sys\n"
    "report, module = sys.argv.pop(1), sys.argv.pop(1)\n"
    "def _report(*_):\n"
    "    with open(report, 'w') as f:\n"
    "        json.dump({'stdin': sys.stdin.fileno(), 'stdout': sys.stdout.fileno()}, f)\n"
    "signal.signal(signal.SIGUSR1, _report)\n"
    "runpy.run_module(module, run_name='__main__', alter_sys=True)\n"
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc/<pid>/fd"
)


def _fds(pid: int) -> dict[int, str]:
    d = f"/proc/{pid}/fd"
    out = {}
    for name in os.listdir(d):
        try:
            out[int(name)] = os.readlink(f"{d}/{name}")
        except OSError:
            pass
    return out


def _cloexec(pid: int, fd: int) -> bool:
    with open(f"/proc/{pid}/fdinfo/{fd}") as f:
        flags = next(ln for ln in f if ln.startswith("flags:"))
    return bool(int(flags.split()[1], 8) & O_CLOEXEC)


def _streams(pid: int, report: Path) -> dict | None:
    """The descriptors sys.stdin and sys.stdout use now (None: no answer)."""
    report.unlink(missing_ok=True)
    os.kill(pid, signal.SIGUSR1)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            return json.loads(report.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
    return None


def _triage_databases(tmp: Path, env: dict) -> None:
    """Empty baseline databases: windows-triage won't start without them."""
    from windows_triage.db.schemas import CONTEXT_SCHEMA, KNOWN_GOOD_SCHEMA

    for name, schema, var in (
        ("known_good.db", KNOWN_GOOD_SCHEMA, "WT_KNOWN_GOOD_DB"),
        ("context.db", CONTEXT_SCHEMA, "WT_CONTEXT_DB"),
    ):
        conn = sqlite3.connect(tmp / name)
        conn.executescript(schema)
        conn.close()
        env[var] = str(tmp / name)
    env["WT_REGISTRY_DB"] = str(tmp / "no_registry.db")


# (module, its arguments as the installer writes them, a read-only tool, setup)
BACKENDS = [
    ("forensic_mcp", ["--deferred-tools"], "get_rules", None),
    ("sift_mcp", [], "list_available_tools", None),
    ("case_mcp", [], "case_list", None),
    ("report_mcp", [], "list_profiles", None),
    ("windows_triage", [], "get_health", _triage_databases),
    ("rag_mcp", [], "list_knowledge_sources", None),
    ("opencti_mcp", [], "get_health", None),
]


class _Backend:
    def __init__(self, module: str, args: list[str], tmp: Path, setup):
        home = tmp / "home"
        (home / ".vhir").mkdir(parents=True)
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("VHIR_", "OPENCTI_", "WT_", "THREATINTEL_"))
        }
        env["HOME"] = str(home)
        if setup:
            setup(tmp, env)
        self.report = tmp / "fds.json"
        self.stderr_path = tmp / "stderr.log"
        # The channel: one socket pair for each direction, as a gateway's
        # transport is a socket. The child's ends are known by inode.
        self.req, child_in = socket.socketpair()
        self.resp, child_out = socket.socketpair()
        self.inodes = {
            "stdin": os.fstat(child_in.fileno()).st_ino,
            "stdout": os.fstat(child_out.fileno()).st_ino,
        }
        with open(self.stderr_path, "wb") as err:
            self.p = subprocess.Popen(
                [sys.executable, "-c", LAUNCH, str(self.report), module, *args],
                stdin=child_in.fileno(),
                stdout=child_out.fileno(),
                stderr=err,
                cwd=tmp,
                env=env,
            )
        child_in.close()
        child_out.close()
        self.buf, self.n = b"", 0

    def stderr(self) -> str:
        return self.stderr_path.read_text(errors="replace")[-4000:]

    def _send(self, obj):
        self.req.sendall((json.dumps(obj) + "\n").encode())

    def rpc(self, method, params, timeout=TIMEOUT):
        self.n += 1
        self._send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if msg.get("id") == self.n:
                    return msg
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.resp], [], [], left)[0]:
                return None
            chunk = self.resp.recv(65536)
            if not chunk:
                return None
            self.buf += chunk

    def start(self):
        hello = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        }
        r = self.rpc("initialize", hello, 60)
        assert r and "result" in r, f"no initialize reply:\n{self.stderr()}"
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def streams(self) -> dict:
        streams = _streams(self.p.pid, self.report)
        assert streams, f"no report of sys.stdin/sys.stdout:\n{self.stderr()}"
        return streams

    def close(self):
        self.p.kill()
        self.p.wait()
        self.req.close()
        self.resp.close()


@pytest.mark.parametrize(
    "module,args,tool,setup", BACKENDS, ids=[b[0] for b in BACKENDS]
)
def test_a_backend_serves_on_a_channel_its_children_cannot_reach(
    tmp_path, module, args, tool, setup
):
    pytest.importorskip(module)
    b = _Backend(module, args, tmp_path, setup)
    try:
        b.start()
        r = b.rpc("tools/call", {"name": tool, "arguments": {}})
        assert r and "result" in r, f"{tool} got no reply: {r}\n{b.stderr()}"
        assert r["result"].get("isError") is False, r
        assert b.p.poll() is None

        fds = _fds(b.p.pid)
        assert fds[0] == "/dev/null"
        assert fds[1] == fds[2]
        assert fds[2] == str(b.stderr_path)
        channel = {
            side: sorted(
                fd for fd, target in fds.items() if target == f"socket:[{ino}]"
            )
            for side, ino in b.inodes.items()
        }
        for side, held in channel.items():
            assert held, f"no descriptor holds the {side} socket: {fds}"
            for fd in held:
                assert fd not in (0, 1), (side, fd)
                assert _cloexec(b.p.pid, fd), f"{side} socket on fd {fd} is inherited"

        streams = b.streams()
        assert streams["stdin"] in channel["stdin"], (streams, channel)
        assert streams["stdout"] in channel["stdout"], (streams, channel)
    finally:
        b.close()


def _objects(pid: int | str) -> dict[int, tuple[int, int]]:
    """Each descriptor of `pid` and the object it refers to (device, inode)."""
    d = f"/proc/{pid}/fd"
    out = {}
    for name in os.listdir(d):
        try:
            st = os.stat(f"{d}/{name}")
        except OSError:
            continue
        out[int(name)] = (st.st_dev, st.st_ino)
    return out


def _running(module: str) -> list[int]:
    """This process's live children that run `module`."""
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            stat = Path(f"/proc/{name}/stat").read_text()
            argv = Path(f"/proc/{name}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        state, ppid = stat.rsplit(")", 1)[1].split()[:2]
        if int(ppid) == os.getpid() and state != "Z" and module.encode() in argv:
            found.append(int(name))
    return found


async def test_a_backend_the_gateway_starts_again_keeps_its_channel_away(
    tmp_path, monkeypatch
):
    """Kill a backend the gateway runs and make two calls: the backend the
    gateway starts again is held to every line a row above checks."""
    for key in list(os.environ):
        if key.startswith("VHIR_"):
            monkeypatch.delenv(key)
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    env = {"HOME": str(home)}
    if os.environ.get("PYTHONPATH"):
        env["PYTHONPATH"] = os.environ["PYTHONPATH"]
    report = tmp_path / "fds.json"
    backend = StdioMCPBackend(
        "report-mcp",
        {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-c", LAUNCH, str(report), "report_mcp"],
            "env": env,
        },
    )
    # in a task of its own, as the gateway starts it: when the backend dies,
    # its session cancels the task that opened it, never the test
    await asyncio.create_task(backend.start())
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {"report-mcp": backend}
    gw._tool_map = {"list_profiles": "report-mcp"}
    handler = create_backend_mcp_server(gw, "report-mcp").request_handlers[
        types.CallToolRequest
    ]

    async def list_profiles() -> types.CallToolResult:
        request = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="list_profiles", arguments={}),
        )
        return (await asyncio.wait_for(handler(request), TIMEOUT)).root

    try:
        [killed] = _running("report_mcp")
        os.kill(killed, signal.SIGKILL)
        deadline = time.monotonic() + 10
        while killed in _running("report_mcp") and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        try:  # a dead backend's first call can fail
            await list_profiles()
        except (Exception, asyncio.CancelledError):
            pass
        before = set(_objects("self").values())
        await list_profiles()  # starts it again
        [pid] = _running("report_mcp")
        assert pid != killed

        fds = _fds(pid)
        assert fds[0] == "/dev/null"
        assert fds[1] == fds[2]
        # the channel: what the gateway opened for the new backend
        opened = set(_objects("self").values()) - before
        channel = sorted(fd for fd, obj in _objects(pid).items() if obj in opened)
        assert channel, f"the gateway holds none of {fds}"
        for fd in channel:
            assert fd not in (0, 1), fd
            assert _cloexec(pid, fd), f"channel on fd {fd} is inherited"
        streams = _streams(pid, report)
        assert streams, "no report of sys.stdin/sys.stdout"
        assert streams["stdin"] in channel, (streams, channel)
        assert streams["stdout"] in channel, (streams, channel)

        result = await list_profiles()
        assert result.isError is False, result
        assert _running("report_mcp") == [pid]
    finally:
        await backend.stop()


# A second call must leave everything as the first left it.
TWICE = (
    "import json, os, sys\n"
    "from sift_common import isolate_stdio_transport\n"
    "def state():\n"
    "    d = '/proc/self/fd'\n"
    "    fds = {}\n"
    "    for n in os.listdir(d):\n"
    "        try:\n"
    "            fds[n] = os.readlink(d + '/' + n)\n"
    "        except OSError:\n"
    "            pass\n"
    "    return {'fds': fds, 'stdin': sys.stdin.fileno(), 'stdout': sys.stdout.fileno()}\n"
    "isolate_stdio_transport()\n"
    "first = state()\n"
    "isolate_stdio_transport()\n"
    "second = state()\n"
    "sys.stdout.write(json.dumps([first, second]))\n"
)


def test_a_second_isolation_changes_nothing():
    p = subprocess.run(
        [sys.executable, "-c", TWICE],
        stdin=subprocess.PIPE,
        capture_output=True,
        timeout=TIMEOUT,
    )
    assert p.returncode == 0, p.stderr
    first, second = json.loads(p.stdout)
    # the listing opens a descriptor of its own, which differs between calls
    for s in (first, second):
        s["fds"] = {n: t for n, t in s["fds"].items() if not t.startswith("/proc/")}
    assert first == second
    assert first["fds"]["0"] == "/dev/null"
    assert first["stdout"] not in (0, 1)
