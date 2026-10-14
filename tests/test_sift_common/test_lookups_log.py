"""~/.vhir/logs/lookups.jsonl: one line per reference lookup that has no case
audit entry, with exactly ts, source, lookup, case and args (scalar
arguments only, each string cut to 120). Outside every case."""

from __future__ import annotations

import asyncio
import json
import logging
import stat
from datetime import datetime
from pathlib import Path

import pytest
from sift_common.oplog import log_lookup

KEYS = {"ts", "source", "lookup", "case", "args"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    return tmp_path


def _lines(home: Path) -> list[dict]:
    path = home / ".vhir" / "logs" / "lookups.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines()]


def test_a_line_has_exactly_the_five_keys_and_no_case_when_none_is_active(home):
    log_lookup("forensic-mcp", "get_playbook", {"name": "ransomware"})
    [line] = _lines(home)
    assert set(line) == KEYS
    datetime.strptime(line["ts"], "%Y-%m-%dT%H:%M:%SZ")  # as the skill hook writes
    assert line["source"] == "forensic-mcp"
    assert line["lookup"] == "get_playbook"
    assert line["case"] is None
    assert line["args"] == {"name": "ransomware"}


def test_the_active_case_is_named(home, monkeypatch):
    case = home / "cases" / "case-one"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: case-one\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    log_lookup("sift-mcp", "check_tools")
    assert _lines(home)[0]["case"] == "case-one"


def test_only_scalar_arguments_are_kept_and_strings_are_cut(home):
    args = {
        "s": "x" * 500,
        "n": 3,
        "b": True,
        "f": 1.5,
        "none": None,
        "list": ["a"],
        "dict": {"a": 1},
    }
    log_lookup("sift-mcp", "check_tools", args)
    assert _lines(home)[0]["args"] == {"s": "x" * 120, "n": 3, "b": True}


def test_lines_append_one_per_lookup_and_a_newline_stays_inside_its_line(home):
    log_lookup("forensic-mcp", "get_tool_guidance", {"tool_name": "a\nb"})
    log_lookup("forensic-mcp", "get_rules")
    path = home / ".vhir" / "logs" / "lookups.jsonl"
    assert len(path.read_text().splitlines()) == 2
    assert _lines(home)[0]["args"] == {"tool_name": "a\nb"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_failed_write_never_raises_and_warns_in_the_writer_s_oplog(home, caplog):
    (home / ".vhir").mkdir()
    (home / ".vhir" / "logs").write_text("a file where the folder goes")
    with caplog.at_level(logging.WARNING, logger="test_writer"):
        log_lookup("test-writer", "get_rules")
    assert [r.name for r in caplog.records] == ["test_writer"]
    assert "lookups log not written" in caplog.records[0].getMessage()


def _call(server, tool: str, args: dict):
    return asyncio.run(server.call_tool(tool, args))


FORENSIC_LOOKUPS = [
    ("get_rules", {}, {}),
    ("get_checkpoint_requirements", {"action_type": "attribution"}, None),
    ("validate_finding", {"finding_json": {"title": "t", "observation": "o"}}, {}),
    ("get_evidence_standards", {}, {}),
    ("get_confidence_definitions", {}, {}),
    ("get_anti_patterns", {}, {}),
    ("get_evidence_template", {}, {}),
    ("get_tool_guidance", {"tool_name": "fls"}, None),
    (
        "get_false_positive_context",
        {"tool_name": "hayabusa", "finding_type": "lateral"},
        None,
    ),
    ("get_corroboration_suggestions", {"finding_type": "lateral"}, None),
    ("list_playbooks", {}, {}),
    ("get_playbook", {"name": "ransomware"}, None),
    ("get_collection_checklist", {"artifact_type": "evtx"}, None),
    (
        "get_procedure",
        {"name": "finding-skeptic"},
        {"name": "finding-skeptic", "file": ""},
    ),
]


@pytest.mark.parametrize("tool,args,logged", FORENSIC_LOOKUPS)
def test_each_forensic_mcp_lookup_writes_one_line(home, tool, args, logged):
    from forensic_mcp.server import create_server

    _call(create_server(reference_mode="tools"), tool, args)
    [line] = _lines(home)
    assert (line["source"], line["lookup"]) == ("forensic-mcp", tool)
    assert line["args"] == (args if logged is None else logged)


@pytest.mark.parametrize(
    "tool,args,logged",
    [
        ("list_available_tools", {"category": "memory"}, {"category": "memory"}),
        ("check_tools", {"tool_names": ["fls"]}, {}),
    ],
)
def test_each_sift_mcp_lookup_writes_one_line(home, tool, args, logged):
    from sift_mcp.server import create_server

    _call(create_server(), tool, args)
    [line] = _lines(home)
    assert (line["source"], line["lookup"], line["args"]) == ("sift-mcp", tool, logged)


def test_an_audited_lookup_stays_audited_and_writes_no_line(home):
    from forensic_mcp.server import create_server

    _call(create_server(reference_mode="tools"), "get_investigation_framework", {})
    assert _lines(home) == []


def test_an_unwritable_log_leaves_the_tool_s_reply_unchanged(home):
    from forensic_mcp.server import create_server

    server = create_server(reference_mode="tools")
    args = {"tool_name": "fls"}
    written = _call(server, "get_tool_guidance", args)
    assert len(_lines(home)) == 1
    (home / ".vhir" / "logs" / "lookups.jsonl").unlink()
    (home / ".vhir" / "logs").rmdir()
    (home / ".vhir" / "logs").write_text("a file where the folder goes")
    assert _call(server, "get_tool_guidance", args) == written


@pytest.fixture
def case(home, monkeypatch):
    import forensic_mcp.case.manager as fm

    # its pointer path is fixed at import, so an earlier test's case could win
    monkeypatch.setattr(fm, "_ACTIVE_CASE_FILE", home / "no_active_case")
    case = home / "cases" / "case-one"
    for sub in ("audit", "reports", "evidence", "extractions"):
        (case / sub).mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        "case_id: case-one\nname: Case One\nstatus: open\nexaminer: tester\n"
    )
    for name, text in [
        ("findings.json", "[]"),
        ("timeline.json", "[]"),
        ("todos.json", "[]"),
        ("evidence.json", '{"files": []}'),
        ("actions.jsonl", ""),
    ]:
        (case / name).write_text(text)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    return case


def test_an_audited_lookup_keeps_its_audit_entry(home, case):
    from forensic_mcp.server import create_server

    _call(create_server(reference_mode="tools"), "get_investigation_framework", {})
    audit = (case / "audit" / "forensic-mcp.jsonl").read_text().splitlines()
    assert [json.loads(ln)["tool"] for ln in audit] == ["get_investigation_framework"]
    assert _lines(home) == []


def test_an_export_and_a_report_hold_nothing_from_the_lookups_log(
    home, case, monkeypatch
):
    import case_mcp.server as cs
    import report_mcp.server as rs

    monkeypatch.setattr(cs, "_ACTIVE_CASE_FILE", home / "no_active_case")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", home / "no_active_case")
    log_lookup("forensic-mcp", "get_playbook", {"name": "lookup-marker"})
    assert _lines(home)[0]["case"] == "case-one"

    def tool(server, name):
        return server._tool_manager._tools[name].fn

    exported = tool(cs.create_server(), "export_bundle")()
    report = tool(rs.create_server(), "generate_report")(profile="full")
    assert "error" not in exported and "error" not in report
    for text in (json.dumps(exported, default=str), json.dumps(report, default=str)):
        assert "lookup-marker" not in text
        assert "lookups.jsonl" not in text


def test_a_lookup_names_the_case_the_pointer_switched_to(home, case, monkeypatch):
    import forensic_mcp.case.manager as fm
    from forensic_mcp.server import create_server

    current = home / "cases" / "case-two"
    current.mkdir(parents=True)
    (current / "CASE.yaml").write_text("case_id: case-two\nstatus: open\n")
    pointer = home / ".vhir" / "active_case"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    pointer.write_text(str(current))
    monkeypatch.setattr(fm, "_ACTIVE_CASE_FILE", pointer)
    # VHIR_CASE_DIR still names case-one, as at the server's start
    _call(create_server(reference_mode="tools"), "get_rules", {})
    assert [line["case"] for line in _lines(home)] == ["case-two"]
