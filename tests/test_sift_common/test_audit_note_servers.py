"""What each server answers when its call's entry isn't recorded.

Before a case exists nothing has failed: the reply says so under `audit` and
carries no `warning`, so an AI that stops on an audit failure goes on. A case
that is no longer one, an audit file that can't take the entry, or a pointer
that can't be read is a warning naming its cause. The forensic-mcp, sift-mcp
and case-mcp rows run as the gateway runs them, over stdio; the rest
in-process.
"""

from __future__ import annotations

import errno
import json
import os
import pathlib
import select
import subprocess
import sys
import threading
import time
from pathlib import Path

import case_mcp.server as cms
import forensic_mcp.case.manager as fmanager
import pytest
import report_mcp.server as rms
from sift_common.audit import AuditWriter

NO_CASE = "not recorded: no case was active for this call"
RAN = "The call itself ran; calling it again repeats it."
FAILED = "Audit write failed — not recorded: "

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX files")


def _gone(path) -> str:
    return f"not recorded: {path} is no longer a case (no CASE.yaml). {RAN}"


class _Server:
    def __init__(self, module: str, home: Path, cwd: Path):
        # forensic-mcp as the gateway runs it: reference data as tools
        flags = ["--deferred-tools"] if module == "forensic_mcp" else []
        env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
        env.update(HOME=str(home), VHIR_EXAMINER="tester")
        self.p = subprocess.Popen(
            [sys.executable, "-m", module, *flags],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
        )
        self.buf, self.n = b"", 0
        assert self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "t", "version": "0"}}, 60)  # fmt: skip
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, obj):
        self.p.stdin.write((json.dumps(obj) + "\n").encode())
        self.p.stdin.flush()

    def rpc(self, method, params, timeout=30.0):
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
            chunk = os.read(self.p.stdout.fileno(), 1 << 20)
            if not chunk:
                return None
            self.buf += chunk

    def call(self, name, args) -> dict:
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        assert r is not None and "result" in r, r
        res = r["result"]
        text = next((c.get("text", "") for c in res.get("content") or []), "")
        assert not res.get("isError"), text
        return json.loads(text)

    def close(self):
        self.p.kill()
        self.p.wait()


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (tmp_path / "run").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    for module in (fmanager, cms, rms):
        monkeypatch.setattr(module, "_ACTIVE_CASE_FILE", home / ".vhir" / "active_case")
    return home


@pytest.fixture
def stdio(home, tmp_path):
    servers = []

    def start(module):
        servers.append(_Server(module, home, tmp_path / "run"))
        return servers[-1]

    yield start
    for s in servers:
        s.close()


def _case(tmp_path, name="case-a"):
    case = tmp_path / "cases" / name
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\nname: {name}\nstatus: open\n")
    (case / "evidence.json").write_text('{"files": []}')
    return case


def _point(home, target):
    (home / ".vhir" / "active_case").write_text(f"{target}\n")


def _call(server, tool, /, **args):
    return server._tool_manager._tools[tool].fn(**args)


def _sift():
    from sift_mcp.server import create_server

    return create_server()


def _forensic():
    from forensic_mcp.server import create_server

    return create_server("tools")


def _wrapped(module, cls, mcp, result):
    import importlib

    server = object.__new__(getattr(importlib.import_module(module), cls))
    server._audit = AuditWriter(mcp)
    return server._wrap_response("search", {"q": "x"}, dict(result))


def _py(code):
    return {"command": [sys.executable, "-c", code], "purpose": "test"}


def _no_case(reply):
    assert reply.get("audit") == NO_CASE and "warning" not in reply, reply


# --- no case: nothing failed -------------------------------------------------

STDIO = [
    ("forensic_mcp", "get_investigation_framework", {}),
    ("sift_mcp", "suggest_tools", {"artifact_type": "prefetch"}),
    ("case_mcp", "log_reasoning", {"text": "first thoughts"}),
]


@pytest.mark.parametrize("module,tool,args", STDIO, ids=[m for m, _, _ in STDIO])
def test_no_case_over_stdio_says_so_and_warns_nothing(module, tool, args, stdio):
    _no_case(stdio(module).call(tool, args))


def test_no_case_in_process_says_so_and_warns_nothing(home, tmp_path):
    _case(tmp_path, "case-x")  # named by the call, not active
    _no_case(_call(rms.create_server(), "generate_report", case_id="case-x"))
    _no_case(_wrapped("windows_triage.server", "WindowsTriageServer",
                      "windows-triage-mcp", {"verdict": "UNKNOWN"}))  # fmt: skip
    _no_case(_wrapped("opencti_mcp.server", "OpenCTIMCPServer", "opencti-mcp",
                      {"results": []}))  # fmt: skip


def test_a_case_activated_later_records_without_a_note(home, tmp_path, stdio):
    server = stdio("forensic_mcp")
    _no_case(server.call("get_investigation_framework", {}))
    case = _case(tmp_path)
    _point(home, case)
    for _ in range(2):
        reply = server.call("get_investigation_framework", {})
        assert "audit" not in reply and "warning" not in reply, reply
    tools = [json.loads(x)["tool"] for x in
             (case / "audit" / "forensic-mcp.jsonl").read_text().splitlines()]  # fmt: skip
    assert tools == ["get_investigation_framework"] * 2


def test_a_case_activated_during_a_run_keeps_the_no_case_note(home, tmp_path):
    case = _case(tmp_path)
    pointer = home / ".vhir" / "active_case"
    reply = _call(_sift(), "run_command",
                  **_py(f"open({str(pointer)!r}, 'w').write({str(case)!r})"))  # fmt: skip
    assert reply["success"] is True, reply
    _no_case(reply)


# --- the audit file can't take the entry ------------------------------------


def _todo(tmp_path, home, audit_file):
    case = _case(tmp_path)
    _point(home, case)
    audit_file(case / "audit" / "forensic-mcp.jsonl", case)
    reply = _call(_forensic(), "add_todo", description="check the prefetch")
    assert reply.get("status") == "created", reply
    return reply


def test_a_fifo_audit_file_is_still_an_audit_failure(home, tmp_path):
    reply = _todo(tmp_path, home, lambda log, case: os.mkfifo(log))
    assert reply["warning"].startswith("Audit write failed"), reply


def test_a_fifo_audit_file_names_its_cause(home, tmp_path):
    def held_fifo(log, case):
        os.mkfifo(log)
        held_fifo.fd = os.open(log, os.O_RDONLY | os.O_NONBLOCK)

    try:
        reply = _todo(tmp_path, home, held_fifo)
    finally:
        os.close(held_fifo.fd)
    assert "is not a regular file" in reply["warning"], reply
    reply = _todo(tmp_path / "unheld", home, lambda log, case: os.mkfifo(log))
    assert reply["warning"].startswith(FAILED) and reply["warning"].endswith(RAN)
    assert f"[Errno {errno.ENXIO}]" in reply["warning"], reply


def test_an_audit_path_taken_by_a_file_is_an_audit_failure(home, tmp_path):
    case = _case(tmp_path)
    _point(home, case)
    os.rmdir(case / "audit")
    (case / "audit").write_text("")
    reply = _call(_forensic(), "add_todo", description="check the prefetch")
    assert reply["warning"].startswith("Audit write failed"), reply


def test_an_audit_path_taken_by_a_file_names_its_cause(home, tmp_path):
    case = _case(tmp_path)
    _point(home, case)
    os.rmdir(case / "audit")
    (case / "audit").write_text("")
    reply = _call(_forensic(), "add_todo", description="check the prefetch")
    assert "[Errno 17]" in reply["warning"], reply


# --- log_reasoning: its entry is the call --------------------------------------


@pytest.mark.parametrize("state", ["no_case", "fifo", "case_gone"])
def test_reasoning_not_recorded_says_why(state, home, tmp_path):
    expected = None
    if state == "fifo":
        case = _case(tmp_path)
        _point(home, case)
        os.mkfifo(case / "audit" / "case-mcp.jsonl")
    elif state == "case_gone":
        moved = tmp_path / "cases" / "moved-away"
        _point(home, moved)
        expected = _gone(moved)
    reply = _call(cms.create_server(), "log_reasoning", text="why")
    assert reply["status"] == "not_recorded", reply
    if state == "no_case":
        _no_case(reply)
    elif state == "fifo":
        assert reply["warning"].startswith(FAILED) and reply["warning"].endswith(RAN)
    else:
        assert reply["warning"] == expected and "audit" not in reply, reply


# --- the pointer names a folder that isn't a case -----------------------------

POINTED = [
    ("forensic-mcp", lambda: _call(_forensic(), "get_investigation_framework")),
    ("sift-mcp", lambda: _call(_sift(), "suggest_tools", artifact_type="prefetch")),
    ("case-mcp", lambda: _call(cms.create_server(), "log_reasoning", text="why")),
]


@pytest.mark.parametrize("name,call", POINTED, ids=[n for n, _ in POINTED])
def test_a_pointer_to_a_non_case_is_case_gone(name, call, home, tmp_path):
    folder = tmp_path / "cases" / "not-a-case"
    folder.mkdir(parents=True)
    _point(home, folder)
    reply = call()
    assert reply.get("warning", "").endswith(_gone(folder)), reply
    assert "audit" not in reply and list(folder.iterdir()) == []


def test_a_run_whose_case_moved_before_it_started_says_case_gone(home, tmp_path):
    moved = tmp_path / "cases" / "moved-away"
    _point(home, moved)
    reply = _call(_sift(), "run_command", **_py("print('ran')"))
    assert reply["success"] is True, reply
    assert reply.get("warning") == _gone(moved) and "audit" not in reply, reply


@pytest.mark.parametrize("via", ["pointer", "VHIR_CASE_DIR"])
def test_a_run_whose_case_yaml_is_a_fifo_says_case_gone_at_once(
    via, home, tmp_path, monkeypatch
):
    case = _case(tmp_path)
    (case / "CASE.yaml").unlink()
    os.mkfifo(case / "CASE.yaml")  # no writer: a read would wait forever
    _point(home, case)
    if via == "VHIR_CASE_DIR":
        monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    server = _sift()
    for _ in range(2):
        got: dict = {}
        t = threading.Thread(daemon=True, target=lambda got=got: got.update(
            reply=_call(server, "run_command", command=["/bin/echo", "hi"], purpose="t")))  # fmt: skip
        t.start()
        t.join(5)
        if t.is_alive():
            os.close(
                os.open(case / "CASE.yaml", os.O_WRONLY | os.O_NONBLOCK)
            )  # its EOF
            pytest.fail("the CASE.yaml FIFO was read")
        reply = got["reply"]
        assert reply["success"] is True and reply["data"]["stdout"] == "hi\n", reply
        assert reply.get("warning") == _gone(case) and "audit" not in reply, reply


@pytest.mark.parametrize("via", ["pointer", "VHIR_CASE_DIR"])
def test_an_audit_folder_from_the_environment_moves_only_the_entry(
    via, home, tmp_path, monkeypatch
):
    """The run's folder, its output, the registry link and the case id are
    the case's; only the entry goes to VHIR_AUDIT_DIR."""
    case = _case(tmp_path)
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"x")
    registered = {"files": [{"path": str(evidence), "sha256": "ab" * 32}]}
    (case / "evidence.json").write_text(json.dumps(registered))
    folder = tmp_path / "elsewhere" / "audit"
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(folder))
    monkeypatch.chdir(tmp_path)  # a run without its case writes here, not in the tree
    if via == "pointer":
        _point(home, case)
    else:
        monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    code = "__import__('shutil').copy(__import__('sys').argv[1], 'out.bin')"
    reply = _call(_sift(), "run_command", command=[sys.executable, "-c", code,
                  str(evidence)], purpose="test")  # fmt: skip
    assert reply["success"] is True and "warning" not in reply, reply
    assert "audit" not in reply, reply
    op = case / "extractions" / reply["audit_id"]
    assert (op / "out.bin").read_bytes() == b"x"
    (entry,) = [
        json.loads(x) for x in (folder / "sift-mcp.jsonl").read_text().splitlines()
    ]
    assert (entry["audit_id"], entry["case_id"]) == (reply["audit_id"], "case-a")
    assert entry["input_sha256s"] == ["ab" * 32], entry
    assert [o["path"] for o in entry["outputs"]] == [str(op / "out.bin")], entry
    assert not (case / "audit" / "sift-mcp.jsonl").exists()


# --- a pointer that isn't text -----------------------------------------------


@pytest.mark.parametrize("site", ["case-mcp log_reasoning", "sift-mcp run_command"])
def test_an_undecodable_pointer_is_a_write_failure_naming_it(site, home):
    (home / ".vhir" / "active_case").write_bytes(b"/cases/\xff\xfe\n")
    if site.startswith("case-mcp"):
        reply = _call(cms.create_server(), "log_reasoning", text="why")
        assert reply["status"] == "not_recorded", reply
    else:
        reply = _call(_sift(), "run_command", **_py("print('ran')"))
        assert reply["success"] is True, reply
    warning = reply.get("warning", "")
    assert warning.startswith(FAILED) and "can't decode" in warning, reply
    assert warning.endswith(RAN), reply


# --- a case moved away between its check and the op folder --------------------


def test_a_case_moved_before_the_op_folder_is_not_recreated(
    home, tmp_path, monkeypatch
):
    case = _case(tmp_path)
    _point(home, case)
    real, moved = os.mkdir, []

    def mkdir(path, *args, **kwargs):
        if not moved and str(path).startswith(str(case) + "/"):
            os.rename(case, str(case) + "-moved")
            moved.append(str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", mkdir)
    accessor = getattr(pathlib, "_NormalAccessor", None)  # Python 3.10
    if accessor is not None:
        monkeypatch.setattr(accessor, "mkdir", staticmethod(mkdir), raising=False)
    reply = _call(_sift(), "run_command", **_py("print('ran')"))
    assert moved and not case.exists(), moved
    assert reply["success"] is True and "ran" in reply["data"]["stdout"], reply
    assert reply["data"]["exit_code"] == 0, reply
    assert reply.get("warning") == _gone(case) and reply.get("audit_id") is None, reply
