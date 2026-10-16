"""The report's MITRE ATT&CK mapping never shows an empty technique name.
forensic-mcp records a finding's techniques as IDs alone (mitre_ids), which
carry no name: the entry then has no "name" at all, and a finding that gives
the technique as {"id", "name"} lends its name, in either order."""

from __future__ import annotations

import json

import pytest
import yaml
from report_mcp import server as rs
from report_mcp.server import _build_mitre_mapping
from vhir_signing import sign_approved

NAME = "SMB/Windows Admin Shares"


def _f(n, **techniques):
    return {"id": f"F-tester-{n:03d}", "status": "APPROVED", "title": f"t{n}",
            "observation": "Seen on the host.", "interpretation": "", **techniques}  # fmt: skip


# name -> (findings, the mapping)
SHAPES = {
    "ids-the-dry-run-records": (
        [_f(1, mitre_ids=["T1021.002", "T1135"]),
         _f(2, mitre_ids=["T1021.001", "T1021.002", "T1021.006"])],
        {"T1021.002": {"findings": ["F-tester-001", "F-tester-002"]},
         "T1135": {"findings": ["F-tester-001"]},
         "T1021.001": {"findings": ["F-tester-002"]},
         "T1021.006": {"findings": ["F-tester-002"]}},
    ),
    "a-named-technique-keeps-its-name": (
        [_f(1, mitre_techniques=[{"id": "T1021.002", "name": NAME}])],
        {"T1021.002": {"name": NAME, "findings": ["F-tester-001"]}},
    ),
    "an-id-then-its-name": (
        [_f(1, mitre_ids=["T1021.002"]),
         _f(2, mitre_techniques=[{"id": "T1021.002", "name": NAME}])],
        {"T1021.002": {"name": NAME, "findings": ["F-tester-001", "F-tester-002"]}},
    ),
    "a-name-then-its-id": (
        [_f(1, mitre_techniques=[{"id": "T1021.002", "name": NAME}]),
         _f(2, mitre_ids=["T1021.002"])],
        {"T1021.002": {"name": NAME, "findings": ["F-tester-001", "F-tester-002"]}},
    ),
    "an-id-then-its-name-in-one-finding": (
        [_f(1, mitre_ids=["T1021.002", {"id": "T1021.002", "name": NAME}])],
        {"T1021.002": {"name": NAME, "findings": ["F-tester-001"]}},
    ),
    "a-name-then-its-id-in-one-finding": (
        [_f(1, mitre_ids=[{"id": "T1021.002", "name": NAME}, "T1021.002"])],
        {"T1021.002": {"name": NAME, "findings": ["F-tester-001"]}},
    ),
    "an-empty-name-is-left-out": (
        [_f(1, mitre_techniques=[{"id": "T1135", "name": ""}, {"technique_id": "T1570"}])],
        {"T1135": {"findings": ["F-tester-001"]}, "T1570": {"findings": ["F-tester-001"]}},
    ),
    "an-empty-name-then-a-name": (
        [_f(1, mitre_techniques=[{"id": "T1135", "name": ""}]),
         _f(2, mitre_techniques=[{"id": "T1135", "name": "Network Share Discovery"}])],
        {"T1135": {"name": "Network Share Discovery",
                   "findings": ["F-tester-001", "F-tester-002"]}},
    ),
    "no-techniques": ([_f(1)], {}),
}  # fmt: skip


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_mapping_never_shows_an_empty_name(shape):
    findings, want = SHAPES[shape]
    got = _build_mitre_mapping(findings)
    assert got == want
    assert all(e.get("name", "x") for e in got.values())


def test_the_first_name_given_is_kept():
    findings = [
        _f(1, mitre_ids=["T1135"]),
        _f(2, mitre_techniques=[{"id": "T1135", "name": "Network Share Discovery"}]),
        _f(3, mitre_techniques=[{"id": "T1135", "name": "Other"}]),
    ]
    assert _build_mitre_mapping(findings)["T1135"]["name"] == "Network Share Discovery"


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-MITRE"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-MITRE"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


@pytest.mark.parametrize("profile", ["full", "ioc"])
@pytest.mark.parametrize("shape", list(SHAPES))
def test_generate_report_never_shows_an_empty_name(case, shape, profile):
    findings, want = SHAPES[shape]
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text("[]")
    sign_approved(case)
    out = rs._generate(profile, case)
    assert out["verification"]["not_verified"] == []
    assert out["report_data"]["mitre_mapping"] == want
