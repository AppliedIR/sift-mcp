"""case-mcp's and forensic-mcp's audit entries go to the case their tools act on.

Both servers find the case through the active-case pointer, while the audit
writer looked at VHIR_CASE_DIR first. With VHIR_CASE_DIR naming another case,
a tool changed one case and audited into the other, and a finding's
supporting commands were then looked up in the wrong trail. Each server now
gives the writer its own case resolver.

The real servers run in-process on scratch cases under a scratch HOME.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import case_mcp.server as case_server
import forensic_mcp.case.manager as fmanager
import pytest
from case_mcp.server import create_server as case_mcp
from forensic_mcp.server import create_server as forensic_mcp


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    pointer = home / ".vhir" / "active_case"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(case_server, "_ACTIVE_CASE_FILE", pointer)
    monkeypatch.setattr(fmanager, "_ACTIVE_CASE_FILE", pointer)
    return home


def _case(tmp_path: Path, name: str) -> Path:
    d = tmp_path / "cases" / name
    (d / "evidence").mkdir(parents=True)
    (d / "CASE.yaml").write_text(f"case_id: {name}\nname: {name}\nstatus: open\n")
    return d


def _point(home: Path, case: Path) -> None:
    (home / ".vhir" / "active_case").write_text(str(case))


def _tools(case: Path, mcp: str) -> list[str]:
    f = case / "audit" / f"{mcp}.jsonl"
    if not f.exists():
        return []
    return [
        json.loads(line)["tool"] for line in f.read_text().splitlines() if line.strip()
    ]


def _call(server, tool: str, args: dict) -> dict:
    r = asyncio.run(server.call_tool(tool, args))
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)


def test_work_in_the_active_case_is_audited_there_whatever_vhir_case_dir_says(
    tmp_path, home, monkeypatch
):
    a, b = _case(tmp_path, "case-a"), _case(tmp_path, "case-b")
    _point(home, b)
    monkeypatch.setenv("VHIR_CASE_DIR", str(a))
    (b / "evidence" / "disk.raw").write_bytes(b"\0" * 4096)
    _call(case_mcp(), "evidence_register", {"path": str(b / "evidence" / "disk.raw")})
    _call(forensic_mcp(), "add_todo", {"description": "check the disk"})
    assert json.loads((b / "evidence.json").read_text())["files"]
    assert (b / "todos.json").exists()
    assert _tools(b, "case-mcp") == ["evidence_register"]
    assert _tools(b, "forensic-mcp") == ["add_todo"]
    assert (_tools(a, "case-mcp"), _tools(a, "forensic-mcp")) == ([], [])


FINDING = {
    "title": "t",
    "observation": "o",
    "interpretation": "i",
    "confidence": "LOW",
    "confidence_justification": "j",
    "type": "finding",
    "audit_ids": [],
    "event_timestamp": "2026-01-01T00:00:00Z",
    "challenged": {"outcome": "not_challenged", "reason": "no skeptic in this test"},
}


def _activate_reason_and_record(tmp_path: Path, home: Path) -> dict:
    """From case A: activate B, log reasoning, record a finding with a supporting command."""
    _point(home, tmp_path / "cases" / "case-a")
    cs = case_mcp()
    _call(
        cs, "case_activate", {"case_id": "case-b", "cases_dir": str(tmp_path / "cases")}
    )
    _call(cs, "log_reasoning", {"text": "reasoning about case b"})
    command = {"command": "grep x y", "purpose": "p", "output_excerpt": "line"}
    return _call(
        forensic_mcp(),
        "record_finding",
        {"finding": FINDING, "supporting_commands": [command]},
    )


@pytest.mark.parametrize(
    "vhir_case_dir", [False, True], ids=["unset", "set to the old case"]
)
def test_activating_a_case_then_working_in_it_audits_there(
    tmp_path, home, monkeypatch, vhir_case_dir
):
    a, b = _case(tmp_path, "case-a"), _case(tmp_path, "case-b")
    if vhir_case_dir:
        monkeypatch.setenv("VHIR_CASE_DIR", str(a))
    r = _activate_reason_and_record(tmp_path, home)
    assert r.get("status") != "error", r
    assert _tools(b, "case-mcp") == ["case_activate", "log_reasoning"]
    assert _tools(b, "forensic-mcp") == ["supporting_command", "record_finding"]
    assert (_tools(a, "case-mcp"), _tools(a, "forensic-mcp")) == ([], [])
    (finding,) = json.loads((b / "findings.json").read_text())
    assert finding.get("provenance") == "MCP", finding.get("provenance")


def test_a_case_switched_with_the_cli_is_followed(tmp_path, home):
    b, c = _case(tmp_path, "case-b"), _case(tmp_path, "case-c")
    _point(home, b)
    (b / "evidence" / "disk.raw").write_bytes(b"\0" * 512)
    cs = case_mcp()
    _call(cs, "evidence_register", {"path": str(b / "evidence" / "disk.raw")})
    _point(home, c)  # `vhir case activate case-c`
    _call(cs, "log_reasoning", {"text": "about case c"})
    assert (_tools(b, "case-mcp"), _tools(c, "case-mcp")) == (
        ["evidence_register"],
        ["log_reasoning"],
    )
