"""case-mcp's case_status warns about approvals that don't verify, and
forensic-mcp's reads answer an error as an error.

- case_status keeps its counts (by status, as documented) and adds `warning`,
  the same text get_findings and get_timeline give, naming every APPROVED
  finding and event that doesn't verify. Before, it said nothing.
- get_findings and get_timeline answer `{"error": …, findings or events: [],
  "total": 0}`. Before, the error was a row in the list.

The real servers run in-process on scratch cases (test_timeline_reads' rig).
"""

from __future__ import annotations

import json

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


# --- case_status ------------------------------------------------------------------


@pytest.mark.usefixtures("approved")
def test_case_status_names_findings_and_events_that_dont_verify(approved):  # noqa: F811
    out = _status()
    assert out["warning"] == (
        "Not approved as recorded: F-rig-002 ALTERED_AFTER_APPROVAL, "
        f"T-rig-002 ALTERED_AFTER_APPROVAL, T-rig-004 APPROVED_NO_LINE. {NOT_RECORDED}"
    )
    # the counts are by status, unchanged
    assert _counts(out) == _counts(_case_status_data(approved))
    assert (out["finding_approved"], out["timeline_approved"]) == (2, 3)


def test_no_warning_when_every_approval_verifies(tmp_path, monkeypatch):
    d = _make_case(tmp_path, "INC-V", [_finding(1, "APPROVED"), _finding(2)],
                   [_event(1, "APPROVED")], monkeypatch)  # fmt: skip
    sign_approved(d)
    out = _status()
    assert "warning" not in out, out["warning"]
    assert (out["finding_approved"], out["timeline_approved"]) == (1, 1)


def test_an_approval_from_0_6_counts_with_no_warning(tmp_path, monkeypatch):
    """The 0.6 label isn't VALID, and isn't a fault: no warning, counted."""
    d, _ = _case_06(tmp_path, monkeypatch)
    out = _status()
    assert "warning" not in out
    assert out["finding_approved"] == 1
    got = _tool("get_findings")()  # the same reading as get_findings
    assert [f["approval_verification"] for f in got["findings"]] == [SHOWN_06]


@pytest.mark.parametrize(
    "ledger_state", ["none", "unreadable"], ids=["no-ledger", "unreadable-ledger"]
)
def test_no_approved_items_reply_as_at_the_base(tmp_path, monkeypatch, ledger_state):
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


def test_an_approved_item_with_no_ledger_line_is_named(tmp_path, monkeypatch):
    d = _make_case(tmp_path, "INC-N", [_finding(1, "APPROVED")], [], monkeypatch)
    out = _status()
    assert (
        out["warning"]
        == f"Not approved as recorded: F-rig-001 APPROVED_NO_LINE. {NOT_RECORDED}"
    )
    assert out["finding_approved"] == 1  # counted by status, as documented
    assert _counts(out) == _counts(_case_status_data(d))


def _with_odd_id(tmp_path, monkeypatch, where, odd):
    """A case whose approvals verify, then an APPROVED item whose id is `odd`
    (a list or a dict) written into its findings or timeline file."""
    d = _make_case(tmp_path, "INC-O", [_finding(1, "APPROVED")], [_event(1, "APPROVED")],
                   monkeypatch)  # fmt: skip
    sign_approved(d)
    name, item = (
        ("findings.json", _finding(2))
        if where == "finding"
        else ("timeline.json", _event(2))
    )
    items = json.loads((d / name).read_text())
    items.append({**item, "id": odd, "status": "APPROVED"})
    (d / name).write_text(json.dumps(items))
    return d


ODD_IDS = {"list": ["F-rig-002"], "dict": {"id": "F-rig-002"}}


@pytest.mark.parametrize("where", ["finding", "event"])
@pytest.mark.parametrize("shape", list(ODD_IDS))
def test_an_approved_item_with_a_list_or_dict_id_is_named_not_a_raise(
    tmp_path, monkeypatch, shape, where
):
    _with_odd_id(tmp_path, monkeypatch, where, ODD_IDS[shape])
    out = _status()
    assert "error" not in out, out
    assert (
        out["warning"]
        == f"Not approved as recorded: {ODD_IDS[shape]} UNVERIFIED. {NOT_RECORDED}"
    )
    assert (out["finding_approved"], out["timeline_approved"]) == (
        (2, 1) if where == "finding" else (1, 2)
    )


@pytest.mark.parametrize("shape", list(ODD_IDS))
def test_get_findings_names_a_list_or_dict_id_and_lists_every_finding(
    tmp_path, monkeypatch, shape
):
    _with_odd_id(tmp_path, monkeypatch, "finding", ODD_IDS[shape])
    out = _tool("get_findings")()
    assert "error" not in out, out
    assert [f["approval_verification"] for f in out["findings"]] == [
        "VALID",
        "UNVERIFIED",
    ]
    assert f"{ODD_IDS[shape]} UNVERIFIED" in out["warning"]


def test_the_tool_list_says_the_counts_are_by_status():
    import asyncio

    tools = {t.name: t for t in asyncio.run(cms.create_server().list_tools())}
    text = " ".join(tools["case_status"].description.split())
    assert "The counts are by status; `warning` names any APPROVED finding" in text


# --- an error is an error, not a row ---------------------------------------------


@pytest.mark.parametrize(
    "tool,key", [("get_findings", "findings"), ("get_timeline", "events")]
)
def test_no_active_case_is_an_error_with_an_empty_list(
    tmp_path, monkeypatch, tool, key
):
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.setattr(fmm, "_ACTIVE_CASE_FILE", tmp_path / "no-active-case")
    out = _tool(tool)()
    assert out[key] == [] and out["total"] == 0, out
    assert out["error"].startswith("No active case"), out


@pytest.mark.parametrize("tool,key,name", [("get_findings", "findings", "findings.json"),
                                           ("get_timeline", "events", "timeline.json")])  # fmt: skip
def test_a_corrupt_file_is_an_error_with_an_empty_list(
    tmp_path, monkeypatch, tool, key, name
):
    d = _make_case(tmp_path, "INC-C", [], [], monkeypatch)
    (d / name).write_text("{not json")
    out = _tool(tool)()
    assert out[key] == [] and out["total"] == 0, out
    assert "corrupt" in out["error"], out
