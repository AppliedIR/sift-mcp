"""forensic-mcp hashes a staged finding with the same exclusion set as the
CLI, the portal and report-mcp.

forensic-mcp left the provenance_detail, provenance_chain, provenance_grade
and provenance_gaps keys out of its content hash; vhir, the portal and
report-mcp hash them. So every staged finding's stored hash disagreed with
the one vhir recomputes: `vhir approve` printed "modified since staging" on
unedited findings, and a rejected finding read TAMPERED.
"""

import json
from pathlib import Path

import forensic_mcp.case.manager as fm
from case_dashboard import routes as portal
from report_mcp import server as report

from test_forensic_mcp.test_case_manager import active_case, manager  # noqa: F401


def test_the_exclusion_sets_are_the_same_in_every_copy():
    assert (
        fm._HASH_EXCLUDE_KEYS == portal._HASH_EXCLUDE_KEYS == report._HASH_EXCLUDE_KEYS
    )


FINDING = {
    "title": "Suspicious process",
    "audit_ids": ["wt-tester-20260219-001"],
    "observation": "svchost.exe spawned from cmd.exe",
    "interpretation": "Unusual parent-child relationship",
    "confidence": "MEDIUM",
    "confidence_justification": "Single evidence source",
    "type": "finding",
}


def _staged(manager, active_case):  # noqa: F811
    result = manager.record_finding(dict(FINDING))
    findings = json.loads((Path(active_case["path"]) / "findings.json").read_text())
    return next(f for f in findings if f["id"] == result["finding_id"])


def test_a_staged_finding_hashes_the_same_for_the_portal(manager, active_case):  # noqa: F811
    f = _staged(manager, active_case)
    assert f["content_hash"] == portal._compute_content_hash(f)


def test_anchor_an_edited_observation_still_changes_the_hash(manager, active_case):  # noqa: F811
    f = _staged(manager, active_case)
    f["observation"] = "edited after staging"
    assert f["content_hash"] != portal._compute_content_hash(f)
