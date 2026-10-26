"""A stdio backend keeps its MCP channel away from the processes it starts.

Each backend runs as the gateway runs it (`python -m <module>`, the channel
on a socket at fd 0 and fd 1). Once it is serving, fd 0 is /dev/null, fd 1 is
fd 2's file, and the channel lives only on descriptors that are closed on exec
and that sys.stdin and sys.stdout read and write. The channel's descriptors
are found by the socket's inode, so a backend can't pass by moving it to
another socket or a pipe. One read-only call per backend shows it still
answers over the moved channel.
"""

from __future__ import annotations

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

import pytest

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

    def fds(self) -> dict[int, str]:
        d = f"/proc/{self.p.pid}/fd"
        out = {}
        for name in os.listdir(d):
            try:
                out[int(name)] = os.readlink(f"{d}/{name}")
            except OSError:
                pass
        return out

    def cloexec(self, fd: int) -> bool:
        with open(f"/proc/{self.p.pid}/fdinfo/{fd}") as f:
            flags = next(ln for ln in f if ln.startswith("flags:"))
        return bool(int(flags.split()[1], 8) & O_CLOEXEC)

    def streams(self) -> dict:
        """The descriptors sys.stdin and sys.stdout use now."""
        self.report.unlink(missing_ok=True)
        os.kill(self.p.pid, signal.SIGUSR1)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                return json.loads(self.report.read_text())
            except (OSError, ValueError):
                time.sleep(0.05)
        raise AssertionError(f"no report of sys.stdin/sys.stdout:\n{self.stderr()}")

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

        fds = b.fds()
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
                assert b.cloexec(fd), f"{side} socket on fd {fd} is inherited"

        streams = b.streams()
        assert streams["stdin"] in channel["stdin"], (streams, channel)
        assert streams["stdout"] in channel["stdout"], (streams, channel)
    finally:
        b.close()


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
