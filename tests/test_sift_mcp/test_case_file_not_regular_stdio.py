"""A case file that isn't a regular file never stops sift-mcp.

The server runs as the gateway runs it: `python -m sift_mcp` over stdio, the
case chosen through `$HOME/.vhir/active_case`. A sync tool runs on the event
loop's thread, so one call that waits on a FIFO stops every later call, for
every case, until a restart. Each call here has a hard timeout of its own,
and one server serves every call in a test: the wedge belongs to the process.
"""

from __future__ import annotations

import json
import os
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

TIMEOUT = 8.0
WARNING = "Audit write failed — action not recorded"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")


class _Server:
    def __init__(self, home: Path, cwd: Path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
        env["HOME"] = str(home)
        self.p = subprocess.Popen(
            [sys.executable, "-m", "sift_mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
        )
        self.buf, self.n = b"", 0
        assert self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "t", "version": "0"}}, 30)  # fmt: skip
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, obj):
        self.p.stdin.write((json.dumps(obj) + "\n").encode())
        self.p.stdin.flush()

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
            if left <= 0 or not select.select([self.p.stdout], [], [], left)[0]:
                return None
            chunk = os.read(self.p.stdout.fileno(), 65536)
            if not chunk:
                return None
            self.buf += chunk

    def call(self, name, args) -> dict | None:
        """The tool's answer as a dict, or None for no answer in time."""
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        if r is None or "result" not in r:
            return None
        res = r["result"]
        text = next((c.get("text", "") for c in res.get("content") or []), "")
        try:
            body = json.loads(text)
        except ValueError:
            body = {"text": text}
        return {
            "isError": res.get("isError"),
            **(body if isinstance(body, dict) else {}),
        }

    def close(self):
        self.p.kill()
        self.p.wait()


@pytest.fixture
def env(tmp_path):
    home, run = tmp_path / "home", tmp_path / "run"
    (home / ".vhir").mkdir(parents=True)
    run.mkdir()
    server = _Server(home, run)

    def case(name):
        d = tmp_path / "cases" / name
        (d / "audit").mkdir(parents=True)
        (d / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\n")
        (d / "evidence.json").write_text(json.dumps({"files": []}))
        (home / ".vhir" / "active_case").write_text(f"{d}\n")
        return d

    yield server, case
    server.close()


def _ls(d):
    return {"command": ["ls", "-la", str(d)], "purpose": "test", "save_output": True}


def _hostname():
    return {"command": ["hostname"], "purpose": "test", "save_output": True}


def _answered(r) -> bool:
    return (
        r is not None
        and r.get("isError") is False
        and r.get("success") is True
        and (r.get("metadata") or {}).get("exit_code") == 0
    )


def _entries(d):
    log = d / "audit" / "sift-mcp.jsonl"
    if not log.is_file():
        return []
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()]


def _is_fifo(p) -> bool:
    return stat.S_ISFIFO(os.lstat(p).st_mode)


def test_a_fifo_registry_doesnt_stop_the_server(env):
    server, case = env
    c1 = case("fifo-registry")
    (c1 / "evidence.json").unlink()
    os.mkfifo(c1 / "evidence.json")
    r = server.call("run_command", _ls(c1))
    assert _answered(r), r
    (entry,) = _entries(c1)
    assert entry["audit_id"] == r["audit_id"] and "input_registered" not in entry
    assert _is_fifo(c1 / "evidence.json")
    # the same server answers the next case, and a tool that reads no case file
    c2 = case("next-case")
    r2 = server.call("run_command", _ls(c2))
    assert _answered(r2), r2
    assert [e["audit_id"] for e in _entries(c2)] == [r2["audit_id"]]
    assert server.call("list_available_tools", {}) is not None


def test_a_fifo_audit_log_gets_no_entry_and_the_server_goes_on(env):
    server, case = env
    c1 = case("fifo-log")
    os.mkfifo(c1 / "audit" / "sift-mcp.jsonl")
    r = server.call("run_command", _hostname())
    assert _answered(r), r
    assert r["audit_id"] is None and r["warning"] == WARNING
    assert _is_fifo(c1 / "audit" / "sift-mcp.jsonl")
    c2 = case("next-case")
    r2 = server.call("run_command", _ls(c2))
    assert _answered(r2), r2
    assert [e["audit_id"] for e in _entries(c2)] == [r2["audit_id"]]


def test_a_fifo_audit_log_a_reader_holds_gets_nothing(env):
    """The log's open succeeds with a reader there: only the check on the
    open file keeps the entry out of the pipe."""
    server, case = env
    c1 = case("fifo-log-read")
    log = c1 / "audit" / "sift-mcp.jsonl"
    os.mkfifo(log)
    rfd = os.open(log, os.O_RDONLY | os.O_NONBLOCK)
    try:
        r = server.call("run_command", _hostname())
        try:
            got = os.read(rfd, 1 << 20)
        except BlockingIOError:
            got = b""
    finally:
        os.close(rfd)
    assert _answered(r), r
    assert r["audit_id"] is None and r["warning"] == WARNING
    assert got == b"" and _is_fifo(log)


def test_an_audit_log_linked_to_a_device_gets_no_entry(env):
    server, case = env
    c1 = case("devnull-log")
    (c1 / "audit" / "sift-mcp.jsonl").symlink_to("/dev/null")
    r = server.call("run_command", _hostname())
    assert _answered(r), r
    assert r["audit_id"] is None and r["warning"] == WARNING
