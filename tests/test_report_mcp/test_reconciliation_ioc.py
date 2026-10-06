"""IOC ledger entries are left out of the approved-vs-ledger count.

Ledger entries are keyed by finding_id.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from report_mcp.server import _HASH_EXCLUDE_KEYS


@pytest.fixture(autouse=True)
def _vdir(tmp_path, monkeypatch):
    monkeypatch.setattr("report_mcp.server.VERIFICATION_DIR", tmp_path / "v")
    (tmp_path / "v").mkdir()
    return tmp_path / "v"


def _snap(item: dict) -> str:
    h = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
    return json.dumps(h, sort_keys=True, default=str)


def _write(vdir: Path, entries: list[dict]) -> None:
    (vdir / "INC-IOC-1.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries)
    )


F1 = {"id": "F-001", "observation": "o", "interpretation": "i", "status": "APPROVED"}
IOC = {"id": "IOC-tester-001", "value": "203.0.113.7", "status": "APPROVED"}


def _by_id(vdir, entries, findings):
    from report_mcp.server import _reconcile_verification

    _write(vdir, entries)
    return {r["id"]: r for r in _reconcile_verification("INC-IOC-1", findings, [])}


def test_cli_signed_ioc_does_not_make_a_count_mismatch(_vdir):
    by_id = _by_id(
        _vdir,
        [
            {"finding_id": "F-001", "type": "finding", "content_snapshot": _snap(F1)},
            {"finding_id": IOC["id"], "type": "ioc", "content_snapshot": _snap(IOC)},
        ],
        [F1],
    )
    assert "_summary" not in by_id, by_id
    assert by_id[IOC["id"]]["status"] == "EXTRACTED_FROM_FINDING"


def test_portal_signed_ioc_does_not_make_a_count_mismatch(_vdir):
    # The portal writes type "finding" for every non-timeline item.
    by_id = _by_id(
        _vdir,
        [
            {"finding_id": "F-001", "type": "finding", "content_snapshot": _snap(F1)},
            {
                "finding_id": IOC["id"],
                "type": "finding",
                "content_snapshot": _snap(IOC),
            },
        ],
        [F1],
    )
    assert "_summary" not in by_id, by_id


def test_a_missing_finding_still_makes_a_count_mismatch(_vdir):
    by_id = _by_id(
        _vdir,
        [
            {"finding_id": "F-001", "type": "finding", "content_snapshot": _snap(F1)},
            {"finding_id": "F-002", "type": "finding", "content_snapshot": "ghost"},
            {"finding_id": IOC["id"], "type": "ioc", "content_snapshot": _snap(IOC)},
        ],
        [F1],
    )
    assert by_id["F-002"]["status"] == "VERIFICATION_NO_FINDING"
    detail = by_id["_summary"]["detail"]
    assert by_id["_summary"]["status"] == "COUNT_MISMATCH"
    assert "approved=1, ledger=2 (+1 auto-extracted IOCs excluded)" in detail, detail
