"""Every reply that wasn't recorded says why, in the same words everywhere.

A call whose audit entry wasn't written used to answer "Audit write failed —
action not recorded" whatever the cause: no case at all, a case moved away,
or a real write failure. The AI read a missing case as a failure and stopped.
Now each call's entry has one outcome (recorded, no case, case gone, write
failed) and every site answers it through the same table: no case under
`audit`, the other two under `warning`, after any warning already there.

Each site runs in-process on a scratch case under a scratch HOME, with the
writer's outcome fixed for the site's own entry, so every outcome reaches
every site whatever the case on disk.
"""

from __future__ import annotations

import asyncio
import inspect
import itertools
import json
import sys
from pathlib import Path

import case_mcp.server as cms
import forensic_mcp.case.manager as fmanager
import pytest
import report_mcp.server as rms
from sift_common import audit as audit_mod
from sift_common.audit import AuditWriter

NO_CASE = "not recorded: no case was active for this call"
GONE_PATH = "/cases/moved-away"
GONE = (
    f"not recorded: {GONE_PATH} is no longer a case (no CASE.yaml). "
    "The call itself ran; calling it again repeats it."
)
REASON = "[Errno 28] No space left on device"
FAILED = (
    f"Audit write failed — not recorded: {REASON}. "
    "The call itself ran; calling it again repeats it."
)
OUTCOMES = ("recorded", "no_case", "case_gone", "write_failed")
DETAIL = {"case_gone": GONE_PATH, "write_failed": REASON}
OWN = "sift-tester-20261027-001"
FINDING = {
    "title": "Mimikatz run on wkstn05",
    "observation": "Prefetch shows MIMIKATZ.EXE run at 14:32",
    "interpretation": "Credential dumping",
    "confidence": "MEDIUM",
    "confidence_justification": "One artifact",
    "type": "finding",
    "audit_ids": [OWN],
    "event_timestamp": "2026-10-01T14:32:00Z",
    "challenged": {"outcome": "not_challenged", "reason": "no skeptic in this test"},
}
SHELL = [
    {"command": f"grep -i mimikatz run{n}.log", "purpose": "find it",
     "output_excerpt": f"MIMIKATZ.EXE line {n}"}
    for n in range(3)
]  # fmt: skip


_N = itertools.count()


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    pointer = home / ".vhir" / "active_case"
    for module in (fmanager, cms, rms):
        monkeypatch.setattr(module, "_ACTIVE_CASE_FILE", pointer)
    case = tmp_path / "cases" / "case-a"
    (case / "audit").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.yaml").write_text("case_id: case-a\nname: case-a\nstatus: open\n")
    (case / "evidence.json").write_text('{"files": []}')
    (case / "audit" / "sift-mcp.jsonl").write_text(
        json.dumps({"audit_id": OWN, "tool": "run_command", "source": "mcp_server"})
        + "\n"
    )
    (case / "evidence" / "disk.bin").write_bytes(b"evidence")
    (home / ".vhir" / "gateway.yaml").write_text("gateway:\n  port: 4508\n")
    pointer.write_text(str(case))
    monkeypatch.setattr("webbrowser.open", lambda *a, **k: True)
    return case


def _fix(monkeypatch, kind: str, tools: set[str] | None = None) -> list[str]:
    """The writer's outcome is `kind` for these tools' entries (every tool's
    when none named), recorded for the rest. Returns the tools it answered."""
    asked: list[str] = []

    def record(self, tool, *args, **kwargs):
        asked.append(tool)
        if tools is not None and tool not in tools or kind == "recorded":
            return audit_mod.AuditOutcome(audit_id=f"{tool}-stub-001")
        return audit_mod.AuditOutcome(kind=kind, detail=DETAIL.get(kind, ""))

    monkeypatch.setattr(AuditWriter, "record", record, raising=False)
    return asked


def _call(server, tool: str, /, **args):
    out = server._tool_manager._tools[tool].fn(**args)
    return asyncio.run(out) if inspect.iscoroutine(out) else out


def _case_mcp(name, **args):
    return lambda case: _call(cms.create_server(), name, **args)


def _forensic(name, **args):
    from forensic_mcp.server import create_server

    return lambda case: _call(create_server(), name, **args)


def _report(name, **args):
    return lambda case: _call(rms.create_server(), name, **args)


def _sift(name, **args):
    from sift_mcp.server import create_server

    return lambda case: _call(create_server(), name, **args)


def _todo(name, **args):
    def run(case):
        from forensic_mcp.server import create_server

        server = create_server()
        todo = _call(server, "add_todo", description="check the prefetch")
        return _call(server, name, todo_id=todo["todo_id"], **args)

    return run


def _bundle(case):
    server = cms.create_server()
    (case / "bundle.json").write_text(json.dumps(_call(server, "export_bundle")))
    return _call(server, "import_bundle", bundle_path=str(case / "bundle.json"))


def _run_raising(exc):
    def run(case, monkeypatch):
        import sift_mcp.tools.generic as generic

        def boom(*a, **k):
            raise exc

        monkeypatch.setattr(generic, "run_command", boom)
        from sift_mcp.server import create_server

        return _call(create_server(), "run_command", command=["echo", "x"], purpose="t")

    return run


def _wrapped(module: str, cls: str, mcp: str, result: dict):
    def run(case):
        import importlib

        server = object.__new__(getattr(importlib.import_module(module), cls))
        server._audit = AuditWriter(mcp)
        return server._wrap_response("search", {"q": "x"}, dict(result))

    return run


def _register(case):
    disk = case / "evidence" / f"disk-{next(_N)}.bin"  # each call a new file
    disk.write_bytes(b"evidence")
    return _call(cms.create_server(), "evidence_register", path=str(disk))


def _sift_error():
    from sift_mcp.exceptions import SiftError

    return SiftError("blocked")


# (site, the tool its entry names, how to call it)
SITES = [
    ("case_init", "case_init", lambda case: _call(
        cms.create_server(), "case_init", name="new case", case_id=f"case-{next(_N)}",
        cases_dir=str(case.parent), share_wintools=False)),
    ("case_activate", "case_activate", _case_mcp("case_activate", case_id="case-a")),
    ("evidence_register", "evidence_register", _register),
    ("export_bundle", "export_bundle", _case_mcp("export_bundle")),
    ("import_bundle", "import_bundle", _bundle),
    ("record_action", "record_action", _case_mcp("record_action", description="noted")),
    ("log_reasoning", "log_reasoning", _case_mcp("log_reasoning", text="why")),
    ("log_external_action", "log_external_action", _case_mcp(
        "log_external_action", command="ls", output_summary="a b", purpose="look")),
    ("backup_case", "backup_case", lambda case: _call(
        cms.create_server(), "backup_case", destination=str(case.parent.parent / "bk"),
        purpose="before the change")),
    ("open_case_dashboard", "open_case_dashboard", _case_mcp("open_case_dashboard")),
    ("prepare_host_list", "prepare_host_list", _case_mcp("prepare_host_list", text="WKSTN05\n")),
    ("record_finding", "record_finding", _forensic("record_finding", finding=FINDING)),
    ("supporting_command", "supporting_command", _forensic(
        "record_finding", finding=FINDING, supporting_commands=SHELL[:1])),
    ("record_timeline_event", "record_timeline_event", _forensic(
        "record_timeline_event", event={"timestamp": "2026-10-01T14:32:00Z",
                                        "description": "MIMIKATZ.EXE ran", "source": "Prefetch"})),
    ("add_todo", "add_todo", _forensic("add_todo", description="check the prefetch")),
    ("update_todo", "update_todo", _todo("update_todo", note="looked")),
    ("complete_todo", "complete_todo", _todo("complete_todo")),
    ("get_investigation_framework", "get_investigation_framework", lambda case: _call(
        __import__("forensic_mcp.server").server.create_server("tools"),
        "get_investigation_framework")),
    ("generate_report", "generate_report", _report("generate_report", case_id="case-a")),
    ("set_case_metadata", "set_case_metadata", _report(
        "set_case_metadata", field="client", value="Stark Research Labs")),
    ("save_report", "save_report", _report("save_report", filename="r.md", content="# Report\n")),
    ("get_tool_help", "get_tool_help", _sift("get_tool_help", tool_name="PECmd")),
    ("suggest_tools", "suggest_tools", _sift("suggest_tools", artifact_type="prefetch")),
    ("run_command", "run_command", _sift(
        "run_command", command=[sys.executable, "-c", "print('ran')"], purpose="t")),
    ("run_command SiftError", "run_command", None),
    ("run_command OSError", "run_command", None),
    ("run_command other error", "run_command", None),
    ("forensic-rag", "search", _wrapped("rag_mcp.server", "RAGServer", "forensic-rag-mcp",
                                        {"results": []})),
    ("opencti", "search", _wrapped("opencti_mcp.server", "OpenCTIMCPServer", "opencti-mcp",
                                   {"results": []})),
    ("windows-triage", "search", _wrapped("windows_triage.server", "WindowsTriageServer",
                                          "windows-triage-mcp", {"verdict": "UNKNOWN"})),
]  # fmt: skip
RAISING = {
    "run_command SiftError": _sift_error,
    "run_command OSError": lambda: OSError("disk gone"),
    "run_command other error": lambda: KeyError("x"),
}


def _site(name, case, monkeypatch):
    run = dict((s, r) for s, _, r in SITES)[name]
    if name in RAISING:
        return _run_raising(RAISING[name]())(case, monkeypatch)
    return run(case)


def _own_fields(reply: dict) -> set[str]:
    return set(reply) - {"audit", "warning", "audit_id"}


@pytest.mark.parametrize("kind", OUTCOMES)
@pytest.mark.parametrize("site", [s for s, _, _ in SITES])
def test_each_site_answers_each_outcome_from_the_table(site, kind, case, monkeypatch):
    tool = next(t for s, t, _ in SITES if s == site)
    _fix(monkeypatch, "recorded")
    control = _site(site, case, monkeypatch)
    assert site in RAISING or "error" not in control, control
    asked = _fix(monkeypatch, kind, {tool})
    reply = _site(site, case, monkeypatch)
    warning = reply.get("warning") or ""
    if kind == "recorded":
        assert "audit" not in reply and "not recorded" not in warning, reply
    elif kind == "no_case":
        assert reply.get("audit") == NO_CASE and "not recorded" not in warning, reply
    else:
        text = GONE if kind == "case_gone" else FAILED
        assert "audit" not in reply and warning.endswith(text), reply
        assert warning.count("not recorded") == 1, reply
    assert tool in asked
    assert _own_fields(reply) == _own_fields(control)


def test_an_earlier_warning_is_kept_and_the_note_follows_it(case, monkeypatch):
    _fix(monkeypatch, "write_failed", {"search"})
    rag = _wrapped("rag_mcp.server", "RAGServer", "forensic-rag-mcp",
                   {"results": [], "warning": "index is stale"})(case)  # fmt: skip
    assert rag["warning"] == f"index is stale | {FAILED}"
    _fix(monkeypatch, "write_failed", {"record_finding"})
    finding = {**FINDING, "challenged": {"outcome": "stands"}}  # malformed: warned
    reply = _forensic("record_finding", finding=finding)(case)
    assert reply["status"] == "STAGED", reply
    earlier, _, note = reply["warning"].rpartition(" | ")
    assert earlier and "not recorded" not in earlier and note == FAILED, reply


def test_three_shell_entries_lost_with_their_case_give_one_note(case, monkeypatch):
    (case / "audit" / "forensic-mcp.jsonl").mkdir()  # lost on disk too
    _fix(monkeypatch, "case_gone")
    reply = _forensic("record_finding", finding=FINDING, supporting_commands=SHELL)(
        case
    )
    assert reply["status"] == "STAGED", reply
    assert reply["warning"].count(GONE) == 1, reply["warning"]
    assert reply["warning"].count("not recorded") == 1, reply


@pytest.mark.parametrize("kind", ["case_gone", "write_failed"])
def test_a_rejected_finding_carries_no_audit_note(kind, case, monkeypatch):
    # its entries fail on disk too, whatever the writer is asked
    (case / "audit" / "forensic-mcp.jsonl").mkdir()
    _fix(monkeypatch, kind)
    unquotable = [{"source": "Prefetch", "extraction": "PECmd -d .", "content": ""}]
    reply = _forensic(
        "record_finding",
        finding=FINDING,
        supporting_commands=SHELL,
        artifacts=unquotable,
    )(case)
    assert reply["status"] == "REJECTED", reply
    text = json.dumps(reply, ensure_ascii=False)
    for said in ("not recorded", "Audit write failed", "The call itself ran"):
        assert said not in text, reply


# --- the census: the texts live in one place ------------------------------

SRC = Path(__file__).resolve().parents[2] / "packages"
OLD = ("action not recorded", "reasoning not recorded", "for shell evidence")
NEW = (
    "Audit write failed",
    "not recorded: no case",
    "is no longer a case (no CASE.yaml)",
)


def _census() -> list[str]:
    hits = []
    for path in sorted(SRC.glob("*/src/**/*.py")):
        if path.name == "audit.py" and path.parent.name == "sift_common":
            continue  # the table's own module
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "logger." in line or "logging." in line:
                continue
            if any(t in line for t in OLD + NEW):
                hits.append(f"{path.relative_to(SRC)}:{n}: {line.strip()}")
    return hits


def test_no_site_writes_an_audit_outcome_text_of_its_own():
    assert _census() == []
