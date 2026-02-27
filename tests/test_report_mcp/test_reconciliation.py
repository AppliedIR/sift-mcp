"""Tests for verification ledger reconciliation in report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _patch_verification_dir(tmp_path, monkeypatch):
    """Redirect VERIFICATION_DIR to tmp_path for all tests."""
    monkeypatch.setattr("report_mcp.server.VERIFICATION_DIR", tmp_path / "verification")
    (tmp_path / "verification").mkdir()


@pytest.fixture()
def verification_dir(tmp_path):
    return tmp_path / "verification"


def _write_ledger(vdir: Path, case_id: str, entries: list[dict]) -> None:
    """Write entries to a ledger file."""
    path = vdir / f"{case_id}.jsonl"
    with open(path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def test_all_verified(verification_dir):
    """Matching items and ledger entries produce VERIFIED status."""
    from report_mcp.server import _reconcile_verification

    case_id = "INC-2026-TEST"
    _write_ledger(
        verification_dir,
        case_id,
        [
            {"finding_id": "F-001", "description_snapshot": "Obs one\nInterp one"},
            {"finding_id": "F-002", "description_snapshot": "Obs two\nInterp two"},
        ],
    )

    findings = [
        {
            "id": "F-001",
            "observation": "Obs one",
            "interpretation": "Interp one",
            "status": "APPROVED",
        },
        {
            "id": "F-002",
            "observation": "Obs two",
            "interpretation": "Interp two",
            "status": "APPROVED",
        },
    ]
    results = _reconcile_verification(case_id, findings, [])

    by_id = {r["id"]: r for r in results}
    assert by_id["F-001"]["status"] == "VERIFIED"
    assert by_id["F-002"]["status"] == "VERIFIED"
    assert "_summary" not in by_id


def test_approved_no_verification(verification_dir):
    """Item approved but no ledger entry."""
    from report_mcp.server import _reconcile_verification

    case_id = "INC-2026-TEST"
    _write_ledger(
        verification_dir,
        case_id,
        [
            {"finding_id": "F-001", "description_snapshot": "Obs one\nInterp one"},
        ],
    )

    findings = [
        {
            "id": "F-001",
            "observation": "Obs one",
            "interpretation": "Interp one",
            "status": "APPROVED",
        },
        {
            "id": "F-002",
            "observation": "Obs two",
            "interpretation": "Interp two",
            "status": "APPROVED",
        },
    ]
    results = _reconcile_verification(case_id, findings, [])

    by_id = {r["id"]: r for r in results}
    assert by_id["F-001"]["status"] == "VERIFIED"
    assert by_id["F-002"]["status"] == "APPROVED_NO_VERIFICATION"
    assert by_id["_summary"]["status"] == "COUNT_MISMATCH"


def test_verification_no_finding(verification_dir):
    """Ledger entry but item missing from approved list."""
    from report_mcp.server import _reconcile_verification

    case_id = "INC-2026-TEST"
    _write_ledger(
        verification_dir,
        case_id,
        [
            {"finding_id": "F-001", "description_snapshot": "Obs one\nInterp one"},
            {"finding_id": "F-002", "description_snapshot": "Ghost finding"},
        ],
    )

    findings = [
        {
            "id": "F-001",
            "observation": "Obs one",
            "interpretation": "Interp one",
            "status": "APPROVED",
        },
    ]
    results = _reconcile_verification(case_id, findings, [])

    by_id = {r["id"]: r for r in results}
    assert by_id["F-001"]["status"] == "VERIFIED"
    assert by_id["F-002"]["status"] == "VERIFICATION_NO_FINDING"
    assert by_id["_summary"]["status"] == "COUNT_MISMATCH"


def test_description_mismatch(verification_dir):
    """Description changed after approval — flagged as mismatch."""
    from report_mcp.server import _reconcile_verification

    case_id = "INC-2026-TEST"
    _write_ledger(
        verification_dir,
        case_id,
        [
            {
                "finding_id": "F-001",
                "description_snapshot": "Original obs\nOriginal interp",
            },
        ],
    )

    findings = [
        {
            "id": "F-001",
            "observation": "Tampered obs",
            "interpretation": "Tampered interp",
            "status": "APPROVED",
        },
    ]
    results = _reconcile_verification(case_id, findings, [])

    by_id = {r["id"]: r for r in results}
    assert by_id["F-001"]["status"] == "DESCRIPTION_MISMATCH"


def test_count_mismatch(verification_dir):
    """Different counts between approved items and ledger entries."""
    from report_mcp.server import _reconcile_verification

    case_id = "INC-2026-TEST"
    _write_ledger(
        verification_dir,
        case_id,
        [
            {"finding_id": "F-001", "description_snapshot": "Obs\nInterp"},
            {"finding_id": "F-002", "description_snapshot": "Two"},
            {"finding_id": "F-003", "description_snapshot": "Three"},
        ],
    )

    findings = [
        {
            "id": "F-001",
            "observation": "Obs",
            "interpretation": "Interp",
            "status": "APPROVED",
        },
    ]
    results = _reconcile_verification(case_id, findings, [])

    summary = next(r for r in results if r.get("id") == "_summary")
    assert summary["status"] == "COUNT_MISMATCH"
    assert "approved=1" in summary["detail"]
    assert "ledger=3" in summary["detail"]


def test_no_ledger_file(verification_dir):
    """No ledger file produces NO_VERIFICATION_LEDGER alert."""
    from report_mcp.server import _reconcile_verification

    results = _reconcile_verification("NONEXISTENT", [], [])
    assert len(results) == 1
    assert results[0]["alert"] == "NO_VERIFICATION_LEDGER"


def test_timeline_included(verification_dir):
    """Both findings and timeline events are reconciled."""
    from report_mcp.server import _reconcile_verification

    case_id = "INC-2026-TEST"
    _write_ledger(
        verification_dir,
        case_id,
        [
            {"finding_id": "F-001", "description_snapshot": "Obs\nInterp"},
            {"finding_id": "T-001", "description_snapshot": "Event"},
        ],
    )

    findings = [
        {
            "id": "F-001",
            "observation": "Obs",
            "interpretation": "Interp",
            "status": "APPROVED",
        }
    ]
    timeline = [{"id": "T-001", "description": "Event", "status": "APPROVED"}]
    results = _reconcile_verification(case_id, findings, timeline)

    by_id = {r["id"]: r for r in results}
    assert by_id["F-001"]["status"] == "VERIFIED"
    assert by_id["T-001"]["status"] == "VERIFIED"
