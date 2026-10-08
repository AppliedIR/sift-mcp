"""forensic-mcp hashes a staged finding with vhir's exclusion set.

forensic-mcp left the provenance_detail, provenance_chain, provenance_grade
and provenance_gaps keys out of its content hash; vhir hashes them. So every
staged finding's stored hash disagreed with the one vhir recomputes: `vhir
approve` printed "modified since staging" on unedited findings. forensic-mcp
keeps its own copy of the set (it doesn't depend on vhir-cli); the portal and
report-mcp now use vhir's.
"""

import json
from pathlib import Path

import forensic_mcp.case.manager as fm
import pytest

case_io = pytest.importorskip("vhir_cli.case_io")

from test_forensic_mcp.test_case_manager import active_case, manager  # noqa: E402, F401


def test_forensic_mcp_s_exclusion_set_is_vhir_s():
    assert fm._HASH_EXCLUDE_KEYS == case_io.HASH_EXCLUDE_KEYS


def test_no_other_package_keeps_a_copy():
    import case_dashboard.routes as portal
    import report_mcp.server as report

    assert not hasattr(portal, "_HASH_EXCLUDE_KEYS")
    assert not hasattr(report, "_HASH_EXCLUDE_KEYS")


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


def test_a_staged_finding_hashes_the_same_for_vhir(manager, active_case):  # noqa: F811
    f = _staged(manager, active_case)
    assert f["content_hash"] == case_io.compute_content_hash(f)


def test_anchor_an_edited_observation_still_changes_the_hash(manager, active_case):  # noqa: F811
    f = _staged(manager, active_case)
    f["observation"] = "edited after staging"
    assert f["content_hash"] != case_io.compute_content_hash(f)
