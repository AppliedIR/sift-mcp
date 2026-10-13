"""A case data file that isn't a regular file never stops forensic-mcp, and an
audit log it couldn't read never lets a finding grade FULL or DECLARED.

The server runs as the gateway runs it, over stdio, with the case chosen
through `$HOME/.vhir/active_case`. Its tools are sync functions on the event
loop's thread, so one read that waits on a FIFO stops every later call, for
every case. Each call has a hard timeout, and one server serves every call in
a test: a wedge belongs to the process. (The launcher only points the case
lock at a folder of the test's own, as conftest does in-process.)

A log the server can't read (mode 000, or a FIFO another process holds open
with an entry in it) could hold another entry for the cited id, which would
make the trace AMBIGUOUS. So any skipped log caps the artifact at AMBIGUOUS,
with a reason naming each log, in the response and in the stored artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

TIMEOUT = 8.0
SIFT_ID = "sift-rig-20261012-001"
QUOTE = "hello rig line"
SKIP = "an entry there could change sift-rig-20261012-001's trace"
LAUNCH = (
    "import runpy, sys\n"
    "from pathlib import Path\n"
    "from forensic_mcp.case import manager\n"
    "manager.LEDGER_DIR = Path(sys.argv.pop(1))\n"
    "runpy.run_module('forensic_mcp', run_name='__main__', alter_sys=True)\n"
)

pytestmark = [
    pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX"),
    pytest.mark.skipif(os.geteuid() == 0, reason="mode 000 doesn't stop root"),
]


class _Server:
    def __init__(self, home: Path, ledger: Path, cwd: Path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
        env["HOME"] = str(home)
        self.p = subprocess.Popen(
            [sys.executable, "-c", LAUNCH, str(ledger)],
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
        sc = res.get("structuredContent")
        if isinstance(sc, dict):
            return sc.get("result", sc)
        text = next((c.get("text", "") for c in res.get("content") or []), "")
        try:
            return json.loads(text)
        except ValueError:
            return {"text": text}

    def close(self):
        self.p.kill()
        self.p.wait()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def env(tmp_path):
    home, run, ledger = tmp_path / "home", tmp_path / "run", tmp_path / "ledger"
    (home / ".vhir").mkdir(parents=True)
    run.mkdir()
    ledger.mkdir()
    server = _Server(home, ledger, run)
    held: list[int] = []

    def case(name, declared=False):
        """A case whose cited run read a registered x.bin, so the registry
        and the audit logs decide the grade (FULL with nothing else)."""
        d = tmp_path / "cases" / name
        for sub in ("audit", "evidence", "extractions"):
            (d / sub).mkdir(parents=True)
        (d / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\nexaminer: rig\n")
        (d / "findings.json").write_text("[]")
        (d / "timeline.json").write_text("[]")
        x = d / "evidence" / "x.bin"
        x.write_bytes(b"registered evidence bytes\n")
        real, xs = os.path.realpath(x), _sha(x.read_bytes())
        out = d / "extractions" / "out.txt"
        out.write_text(QUOTE + "\n")
        run_entry = {
            "audit_id": SIFT_ID, "ts": "2026-10-12T00:00:00+00:00", "tool": "run_command",
            "mcp": "sift-mcp", "params": {"command": ["cat", real]}, "input_files": [real],
            "input_sha256s": [xs],
            "result_summary": {"output_file": str(out), "output_sha256": _sha(out.read_bytes())},
        }  # fmt: skip
        if declared:
            run_entry["declared"] = True
        (d / "audit" / "sift-mcp.jsonl").write_text(json.dumps(run_entry) + "\n")
        (d / "evidence.json").write_text(
            json.dumps(
                {"files": [{"path": real, "sha256": xs, "registered_by": "examiner"}]}
            )
        )
        (home / ".vhir" / "active_case").write_text(f"{d}\n")
        return d

    def hold(path, payload: bytes):
        """`path` as a FIFO another process holds open, with `payload` in it."""
        path.unlink(missing_ok=True)
        os.mkfifo(path)
        fd = os.open(path, os.O_RDWR)
        os.write(fd, payload)
        held.append(fd)

    yield server, case, hold
    server.close()
    for fd in held:
        os.close(fd)


def _duplicate(d) -> bytes:
    """A second entry for SIFT_ID, from another tool with an unregistered
    input: readable, it makes the trace AMBIGUOUS."""
    other = d / "extractions" / "other.bin"
    other.write_bytes(b"not registered\n")
    e = {"audit_id": SIFT_ID, "ts": "2026-10-12T00:00:02+00:00", "tool": "x",
         "mcp": "wintools-mcp", "input_files": [str(other)],
         "input_sha256s": [_sha(other.read_bytes())]}  # fmt: skip
    return (json.dumps(e) + "\n").encode()


def _record(server) -> dict | None:
    finding = {
        "title": "a finding", "observation": "the run saw " + QUOTE,
        "interpretation": "a test", "confidence": "LOW", "confidence_justification": "a test",
        "type": "finding", "event_timestamp": "2026-01-24T15:00:41Z", "audit_ids": [],
        "alternatives": [{"explanation": "an admin did it", "status": "open"}],
        "challenged": {"outcome": "not_challenged", "reason": "no skeptic in this test"},
    }  # fmt: skip
    art = {"source": "x", "extraction": "cat x", "content": QUOTE, "audit_id": SIFT_ID}
    return server.call("record_finding", {"finding": finding, "artifacts": [art]})


def _graded(r) -> tuple:
    return (
        (r or {}).get("status"),
        (r or {}).get("provenance_grade"),
        (r or {}).get("message"),
    )


def _stored(server) -> tuple:
    """The stored artifact, as get_findings gives it (what the portal and
    `vhir review` show)."""
    r = server.call("get_findings", {})
    (f,) = (r or {}).get("findings") or [{}]
    (a,) = f.get("artifacts") or [{}]
    return (
        a.get("provenance_grade"),
        (a.get("provenance_break") or {}).get("kind"),
        a.get("provenance_reason"),
    )


def _listed(r) -> tuple:
    return (r or {}).get("findings"), (r or {}).get("total")


def _mode000(*paths):
    for p in paths:
        os.chmod(p, 0)


def test_a_skipped_audit_log_caps_the_grade_at_ambiguous_and_names_each_log(env):
    server, case, hold = env
    # one entry for the id: FULL, no message (control)
    case("one-entry")
    assert _graded(_record(server)) == ("STAGED", "FULL", None)
    # the duplicate in a readable log: AMBIGUOUS (control)
    d = case("dup-readable")
    (d / "audit" / "wintools-mcp.jsonl").write_bytes(_duplicate(d))
    assert _graded(_record(server)) == (
        "STAGED", "AMBIGUOUS", f"Finding staged as AMBIGUOUS: {SIFT_ID} is on 2 audit entries"
    )  # fmt: skip
    # the duplicate in a mode-000 log: AMBIGUOUS, naming it, stored so too
    d = case("dup-mode000")
    log = d / "audit" / "wintools-mcp.jsonl"
    log.write_bytes(_duplicate(d))
    _mode000(log)
    why = f"couldn't read audit/wintools-mcp.jsonl (Permission denied): {SKIP}"
    assert _graded(_record(server)) == (
        "STAGED", "AMBIGUOUS", f"Finding staged as AMBIGUOUS: {why}"
    )  # fmt: skip
    assert _stored(server) == ("AMBIGUOUS", "audit-unreadable", why)
    # two mode-000 logs: both named
    d = case("two-mode000")
    log = d / "audit" / "wintools-mcp.jsonl"
    log.write_bytes(_duplicate(d))
    other = d / "audit" / "claude-code.jsonl"
    other.write_text(
        json.dumps({"audit_id": "claude-rig-20261012-001", "tool": "Bash"}) + "\n"
    )
    _mode000(log, other)
    why = (
        "couldn't read audit/claude-code.jsonl (Permission denied), "
        f"audit/wintools-mcp.jsonl (Permission denied): {SKIP}"
    )
    assert _graded(_record(server)) == (
        "STAGED", "AMBIGUOUS", f"Finding staged as AMBIGUOUS: {why}"
    )  # fmt: skip
    assert _stored(server)[:2] == ("AMBIGUOUS", "audit-unreadable")


def test_a_declared_trace_with_a_skipped_log_is_ambiguous_and_keeps_its_own_reason(env):
    server, case, hold = env
    # the duplicate readable: AMBIGUOUS (control)
    d = case("declared-dup-readable", declared=True)
    (d / "audit" / "wintools-mcp.jsonl").write_bytes(_duplicate(d))
    assert _graded(_record(server)) == (
        "STAGED", "AMBIGUOUS", f"Finding staged as AMBIGUOUS: {SIFT_ID} is on 2 audit entries"
    )  # fmt: skip
    # the duplicate in a mode-000 log
    d = case("declared-dup-mode000", declared=True)
    log = d / "audit" / "wintools-mcp.jsonl"
    log.write_bytes(_duplicate(d))
    _mode000(log)
    why = (
        f"declared by the AI: {SIFT_ID} (run_command); "
        f"couldn't read audit/wintools-mcp.jsonl (Permission denied): {SKIP}"
    )
    assert _graded(_record(server)) == (
        "STAGED", "AMBIGUOUS", f"Finding staged as AMBIGUOUS: {why}"
    )  # fmt: skip
    assert _stored(server) == ("AMBIGUOUS", "audit-unreadable", why)


def test_a_duplicate_in_a_held_fifo_log_caps_the_grade_and_the_server_goes_on(env):
    """Last: at the heads this call never returns."""
    server, case, hold = env
    d = case("dup-held-fifo")
    log = d / "audit" / "wintools-mcp.jsonl"
    hold(log, _duplicate(d))
    why = f"couldn't read audit/wintools-mcp.jsonl (not a regular file): {SKIP}"
    assert _graded(_record(server)) == (
        "STAGED", "AMBIGUOUS", f"Finding staged as AMBIGUOUS: {why}"
    )  # fmt: skip
    assert _stored(server) == ("AMBIGUOUS", "audit-unreadable", why)
    assert os.path.exists(log) and not os.path.isfile(log)  # still the FIFO


def test_a_held_fifo_findings_file_is_refused_and_the_next_case_is_served(env):
    """It holds a findings list: nothing of it is taken or written over."""
    server, case, hold = env
    d = case("findings-held-fifo")
    planted = [{"id": "F-planted-001", "status": "DRAFT", "title": "from the pipe"}]
    hold(d / "findings.json", json.dumps(planted).encode())
    cmd = {"command": "ls -la", "purpose": "a test", "output_excerpt": "total 0"}
    finding = {
        "title": "a finding", "observation": "an observation", "interpretation": "a test",
        "confidence": "LOW", "confidence_justification": "a test", "type": "finding",
        "event_timestamp": "2026-01-24T15:00:41Z", "audit_ids": [],
        "challenged": {"outcome": "not_challenged", "reason": "no skeptic in this test"},
    }  # fmt: skip
    r = server.call(
        "record_finding", {"finding": finding, "supporting_commands": [cmd]}
    )
    error = f"Cannot read findings.json: {d / 'findings.json'} is not a regular file"
    assert r == {"error": error}
    assert not os.path.isfile(d / "findings.json")  # still the FIFO
    listed = server.call("get_findings", {})  # an error, not a row
    assert (_listed(listed), listed.get("error")) == (([], 0), error)
    case("next-case")
    assert _listed(server.call("get_findings", {})) == ([], 0)
