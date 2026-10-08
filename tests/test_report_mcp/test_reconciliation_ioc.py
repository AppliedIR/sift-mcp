"""A signed IOC cascade makes no false report failure.

report-mcp's own reconciliation once counted IOC ledger entries against the
approved findings and reported a COUNT_MISMATCH for every signed IOC. The
verdict now comes from vhir's verify_case, which judges each item by its own
line: an IOC approved with its finding verifies, and the finding is shown.
"""

from __future__ import annotations

import json

import pytest
import yaml
from vhir_signing import sign_approved


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-IOC-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-IOC-1"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


def test_a_signed_ioc_beside_its_finding_verifies(case):
    finding = {"id": "F-001", "observation": "o", "interpretation": "i",
               "status": "APPROVED", "iocs": ["203.0.113.7"]}  # fmt: skip
    ioc = {"id": "IOC-tester-001", "value": "203.0.113.7", "status": "APPROVED",
           "source_findings": ["F-001"], "confidence": "HIGH"}  # fmt: skip
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "iocs.json").write_text(json.dumps([ioc]))
    sign_approved(case)
    from report_mcp.server import _generate

    out = _generate("full", case)
    assert out["verification"]["not_verified"] == []
    assert out["verification"]["case_failures"] == []
    assert [f["id"] for f in out["report_data"]["findings"]] == ["F-001"]


def test_an_ioc_s_derived_fields_are_labelled(case):
    (case / "findings.json").write_text("[]")
    from report_mcp.server import _generate

    out = _generate("ioc", case)
    assert "derived, not signed" in out["verification"]["derived_ioc_note"]
