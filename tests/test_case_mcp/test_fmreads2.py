"""fmreads2-065: case-mcp's case_status warns about approvals that don't
verify, and forensic-mcp's reads answer an error as an error.

- SPEC-001: case_status keeps its counts (by status, as documented) and adds
  `warning`, the same text get_findings and get_timeline give, naming every
  APPROVED finding and event that doesn't verify. At 66eb607 it said nothing.
- SPEC-002: get_findings and get_timeline answer `{"error": …, findings or
  events: [], "total": 0}`. At 66eb607 the error was a row in the list.

The real servers run in-process on scratch cases (test_timeline_reads' rig).
"""

from __future__ import annotations

import case_mcp.server as cms
import forensic_mcp.case.manager as fmm
import pytest
from vhir_cli import ledger
from vhir_cli.main import _case_status_data
from vhir_signing import sign_approved

from .test_approval_verification import SHOWN_06, _case_06
from .test_timeline_reads import (
    NOT_RECORDED,
    _event,
    _finding,
    _make_case,
    _tool,
    approved,  # noqa: F401 (fixture)
)

COUNTS = ("finding_count", "finding_draft", "finding_approved",
          "timeline_count", "timeline_draft", "timeline_approved")  # fmt: skip


def _status():
    return cms.create_server()._tool_manager._tools["case_status"].fn()


def _counts(out):
    return {k: out[k] for k in COUNTS}


# --- SPEC-001: case_status --------------------------------------------------------


@pytest.mark.usefixtures("approved")
def test_c1_case_status_names_findings_and_events_that_dont_verify(approved):  # noqa: F811
    out = _status()
    assert out["warning"] == (
        "Not approved as recorded: F-rig-002 ALTERED_AFTER_APPROVAL, "
        f"T-rig-002 ALTERED_AFTER_APPROVAL, T-rig-004 APPROVED_NO_LINE. {NOT_RECORDED}"
    )
    # the counts are by status, unchanged
    assert _counts(out) == _counts(_case_status_data(approved))
    assert (out["finding_approved"], out["timeline_approved"]) == (2, 3)


def test_c2_no_warning_when_every_approval_verifies(tmp_path, monkeypatch):
    d = _make_case(tmp_path, "INC-V", [_finding(1, "APPROVED"), _finding(2)],
                   [_event(1, "APPROVED")], monkeypatch)  # fmt: skip
    sign_approved(d)
    out = _status()
    assert "warning" not in out, out["warning"]
    assert (out["finding_approved"], out["timeline_approved"]) == (1, 1)


def test_c2b_an_approval_from_0_6_counts_with_no_warning(tmp_path, monkeypatch):
    """The 0.6 label isn't VALID, and isn't a fault: no warning, counted."""
    d, _ = _case_06(tmp_path, monkeypatch)
    out = _status()
    assert "warning" not in out
    assert out["finding_approved"] == 1
    got = _tool("get_findings")()  # the same reading as get_findings
    assert [f["approval_verification"] for f in got["findings"]] == [SHOWN_06]


@pytest.mark.parametrize("ledger_state", ["none", "unreadable"], ids=["C3", "C3b"])
def test_c3_no_approved_items_reply_as_at_the_base(tmp_path, monkeypatch, ledger_state):
    d = _make_case(tmp_path, "INC-D", [_finding(1)], [_event(1)], monkeypatch)
    if ledger_state == "unreadable":
        ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
        f = ledger.LEDGER_DIR / "INC-D.jsonl"
        f.write_text("{}\n")
        f.chmod(0)
    out = _status()
    assert "warning" not in out
    expected = _case_status_data(d)
    assert {k: out[k] for k in expected} == expected


def test_c3c_an_approved_item_with_no_ledger_line_is_named(tmp_path, monkeypatch):
    d = _make_case(tmp_path, "INC-N", [_finding(1, "APPROVED")], [], monkeypatch)
    out = _status()
    assert (
        out["warning"]
        == f"Not approved as recorded: F-rig-001 APPROVED_NO_LINE. {NOT_RECORDED}"
    )
    assert out["finding_approved"] == 1  # counted by status, as documented
    assert _counts(out) == _counts(_case_status_data(d))


def test_the_tool_list_says_the_counts_are_by_status():
    import asyncio

    tools = {t.name: t for t in asyncio.run(cms.create_server().list_tools())}
    text = " ".join(tools["case_status"].description.split())
    assert "The counts are by status; `warning` names any APPROVED finding" in text


# --- SPEC-002: an error is an error, not a row ------------------------------------


@pytest.mark.parametrize(
    "tool,key", [("get_findings", "findings"), ("get_timeline", "events")]
)
def test_c4_no_active_case_is_an_error_with_an_empty_list(
    tmp_path, monkeypatch, tool, key
):
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.setattr(fmm, "_ACTIVE_CASE_FILE", tmp_path / "no-active-case")
    out = _tool(tool)()
    assert out[key] == [] and out["total"] == 0, out
    assert out["error"].startswith("No active case"), out


@pytest.mark.parametrize("tool,key,name", [("get_findings", "findings", "findings.json"),
                                           ("get_timeline", "events", "timeline.json")])  # fmt: skip
def test_c5_a_corrupt_file_is_an_error_with_an_empty_list(
    tmp_path, monkeypatch, tool, key, name
):
    d = _make_case(tmp_path, "INC-C", [], [], monkeypatch)
    (d / name).write_text("{not json")
    out = _tool(tool)()
    assert out[key] == [] and out["total"] == 0, out
    assert "corrupt" in out["error"], out
