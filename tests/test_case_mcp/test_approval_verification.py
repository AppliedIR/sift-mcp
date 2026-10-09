"""An APPROVED finding is shown as approved by forensic-mcp's get_findings
and case-mcp's export_bundle only when it verifies: each carries
`approval_verification`, vhir's own verdict (the check report-mcp and the
portal use). A finding altered by hand after approval is marked, and named
in a warning, so an AI building on it can't take it as approved."""

from __future__ import annotations

import json

import case_mcp.server as cms
import forensic_mcp.case.manager as fmm
import pytest
from sift_common.approvals import mark_approvals
from vhir_signing import sign_approved


def _finding(fid, status="APPROVED"):
    return {"id": fid, "title": f"title {fid}", "observation": "seen in 4688",
            "interpretation": "lateral movement", "confidence": "HIGH", "status": status}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "cases" / "INC-582"
    d.mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: INC-582\n")
    (d / "timeline.json").write_text("[]")
    pointer = tmp_path / "active_case"
    pointer.write_text(str(d))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setattr(fmm, "_ACTIVE_CASE_FILE", pointer)
    monkeypatch.setattr(cms, "_ACTIVE_CASE_FILE", pointer)
    (d / "findings.json").write_text(json.dumps([
        _finding("F-tester-001"), _finding("F-tester-002"),
        _finding("F-tester-003", "DRAFT")]))  # fmt: skip
    sign_approved(d)
    fs = json.loads((d / "findings.json").read_text())
    fs[1]["interpretation"] = "ALTERED BY HAND after approval"
    (d / "findings.json").chmod(0o644)
    (d / "findings.json").write_text(json.dumps(fs))
    return d


def _by_id(items):
    return {f["id"]: f for f in items}


def test_get_findings_marks_an_altered_approval_and_warns(case):
    from forensic_mcp.server import create_server

    out = create_server()._tool_manager._tools["get_findings"].fn()
    got = _by_id(out["findings"])
    assert got["F-tester-001"]["approval_verification"] == "VALID"
    assert got["F-tester-002"]["approval_verification"] == "ALTERED_AFTER_APPROVAL"
    assert "approval_verification" not in got["F-tester-003"]  # a draft isn't judged
    assert "F-tester-002 ALTERED_AFTER_APPROVAL" in out["warning"]
    assert "F-tester-001" not in out["warning"]


def test_export_bundle_marks_an_altered_approval_and_warns(case):
    out = cms.create_server()._tool_manager._tools["export_bundle"].fn()
    got = _by_id(out["findings"])
    assert got["F-tester-001"]["approval_verification"] == "VALID"
    assert got["F-tester-002"]["approval_verification"] == "ALTERED_AFTER_APPROVAL"
    assert "F-tester-002 ALTERED_AFTER_APPROVAL" in out["warning"]


def test_a_clean_case_gets_no_warning(case):
    from forensic_mcp.server import create_server

    out = create_server()._tool_manager._tools["get_findings"].fn(limit=1)
    assert [f["approval_verification"] for f in out["findings"]] == ["VALID"]
    assert "warning" not in out


def test_when_the_check_cant_run_an_approval_is_never_shown_as_verified(
    case, monkeypatch
):
    import vhir_cli.ledger_verify as lv

    def broken(case_dir):
        raise OSError("ledger unreadable")

    monkeypatch.setattr(lv, "approved_view", broken)
    items = [_finding("F-tester-001")]
    warning = mark_approvals(case, items)
    assert items[0]["approval_verification"] == "UNVERIFIED"
    assert "couldn't verify: ledger unreadable" in warning


def test_the_marker_is_only_in_the_response_never_written_back(case):
    """`approval_verification` is a read-time annotation: both tools mark
    their response copies, and the case files stay byte-identical."""
    from forensic_mcp.server import create_server

    before = {n: (case / n).read_bytes() for n in ("findings.json", "timeline.json")}
    got = create_server()._tool_manager._tools["get_findings"].fn()
    out = cms.create_server()._tool_manager._tools["export_bundle"].fn()
    assert any("approval_verification" in f for f in got["findings"])
    assert any("approval_verification" in f for f in out["findings"])
    assert {n: (case / n).read_bytes() for n in before} == before
    stored = json.loads((case / "findings.json").read_text())
    assert not any("approval_verification" in f for f in stored)


def test_content_that_isnt_the_record_verified_is_never_valid(case):
    """The tool's read and the check's read can see different files (a
    writer flipping findings.json between them, or a case switch): VALID
    holds only for the record the check verified, by its content hash, and
    an id the check never judged is UNVERIFIED."""
    stored = _by_id(json.loads((case / "findings.json").read_text()))
    flipped = dict(stored["F-tester-001"], interpretation="ALTERED, then put back")
    unseen = _finding("F-tester-009")
    items = [stored["F-tester-001"], flipped, unseen]
    warning = mark_approvals(case, items)
    assert [i["approval_verification"] for i in items] == [
        "VALID", "UNVERIFIED", "UNVERIFIED"]  # fmt: skip
    assert "F-tester-001 UNVERIFIED" in warning
    assert "F-tester-009 UNVERIFIED" in warning


def test_an_approval_from_0_6_keeps_the_checks_own_wording(tmp_path, monkeypatch):
    from vhir_cli import verification
    from vhir_cli.ledger_verify import signed_text

    d = tmp_path / "INC-06"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: INC-06\n")
    (d / "timeline.json").write_text("[]")
    old = dict(_finding("F-tester-001"), approved_by="tester",
               approved_at="2026-01-02T03:04:05+00:00")  # fmt: skip
    (d / "findings.json").write_text(json.dumps([old]))
    monkeypatch.setattr(verification, "VERIFICATION_DIR", tmp_path / "verification")
    verification.VERIFICATION_DIR.mkdir()
    (verification.VERIFICATION_DIR / "INC-06.jsonl").write_text(json.dumps({
        "finding_id": old["id"], "type": "finding", "hmac": "00", "hmac_version": 2,
        "content_snapshot": signed_text(old, "finding", 0), "approved_by": "tester",
        "approved_at": old["approved_at"], "case_id": "INC-06"}) + "\n")  # fmt: skip
    items = [dict(old)]
    assert mark_approvals(d, items) == ""
    assert items[0]["approval_verification"] == "approved under 0.6 (before signing)"


def test_altered_approval_stamps_on_verified_content_are_never_valid(case):
    """Who approved, and when, are part of the approval: the content hash
    doesn't cover them, so they're compared with the verified record."""
    stored = _by_id(json.loads((case / "findings.json").read_text()))["F-tester-001"]
    by = dict(stored, approved_by="someone-else")
    at = dict(stored, approved_at="2020-01-01T00:00:00+00:00")
    items = [dict(stored), by, at]
    warning = mark_approvals(case, items)
    assert [i["approval_verification"] for i in items] == [
        "VALID", "UNVERIFIED", "UNVERIFIED"]  # fmt: skip
    assert warning.count("F-tester-001 UNVERIFIED") == 2
