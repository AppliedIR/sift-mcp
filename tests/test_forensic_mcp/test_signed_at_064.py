"""Findings signed by 0.6.4 still verify, and are served as stored.

New findings no longer store the provenance tier (provenance,
provenance_detail), but older ones keep them, and their signed views and
content hash cover what they stored. signed_at_064.json holds four findings
written by 0.6.4's record_finding and approved by its vhir: a plain one, one
with a challenge, one with the older writer's provenance_warnings, and one
imported from a bundle. Its signed_views are the sha256 of each signed view,
taken with 0.6.4's case_io.
"""

import hashlib
import json
from pathlib import Path

import forensic_mcp.case.manager as fm
import pytest

case_io = pytest.importorskip("vhir_cli.case_io")

from test_forensic_mcp.test_case_manager import active_case, manager  # noqa: E402, F401

FIXTURE = json.loads((Path(__file__).parent / "signed_at_064.json").read_text())
FINDINGS = FIXTURE["findings"]
IDS = [f["id"] for f in FINDINGS]


def _by_id(fid: str) -> dict:
    return next(f for f in FINDINGS if f["id"] == fid)


def test_the_fixture_has_each_shape():
    old_writer = _by_id("F-tester-003")
    imported = _by_id("F-other-001")
    assert {"provenance", "provenance_detail"} <= set(_by_id("F-tester-001"))
    assert old_writer["provenance_warnings"] and "provenance" in old_writer
    assert imported["imported_from"] and imported["provenance_warnings"]


@pytest.mark.parametrize("fid", IDS)
@pytest.mark.parametrize("view", [0, 1, 2])
def test_each_signed_view_is_unchanged(fid, view):
    text = case_io.signed_text(_by_id(fid), "finding", view)
    assert (
        hashlib.sha256(text.encode()).hexdigest()
        == FIXTURE["signed_views"][fid][str(view)]
    )


@pytest.mark.parametrize("fid", IDS)
def test_forensic_mcp_hashes_it_as_signed(fid):
    f = _by_id(fid)
    assert fm._compute_content_hash(f) == f["content_hash"]
    assert {"provenance", "provenance_warnings"} <= fm._HASH_EXCLUDE_KEYS


def test_vhir_verifies_every_approval(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(FINDINGS))
    (tmp_path / "approvals.jsonl").write_text(
        "".join(json.dumps(a) + "\n" for a in FIXTURE["approvals"])
    )
    verdicts = {
        r["id"]: r["verification"] for r in case_io.verify_approval_integrity(tmp_path)
    }
    assert verdicts == dict.fromkeys(IDS, "confirmed")


def test_forensic_mcp_serves_them_as_stored(manager, active_case):  # noqa: F811
    path = Path(active_case["path"]) / "findings.json"
    path.write_text(json.dumps(FINDINGS))
    assert manager.get_findings() == FINDINGS
