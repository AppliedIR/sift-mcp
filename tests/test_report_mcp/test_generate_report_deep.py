"""A findings.json, timeline.json, iocs.json or todos.json holding a list
nested 500 deep parses, but
its one entry isn't a record. generate_report, in every profile, on a DRAFT
case and on a signed one, raises nothing and returns `unreadable` naming the
file: "holds a list with an entry that isn't a record". vhir-cli's tests
state the same for `vhir report`."""

from __future__ import annotations

import json
import traceback

import pytest
import yaml
from report_mcp.profiles import PROFILES
from vhir_signing import sign_approved

CASE = "INC-2026-DEEP"
WHY = "holds a list with an entry that isn't a record"
DEEP = "[" * 500 + "]" * 500


def _items(status):
    return {
        "findings.json": [{"id": "F-tester-001", "status": status, "title": "Beacon",
                           "confidence": "LOW", "observation": "o", "interpretation": "i",
                           "iocs": []}],
        "timeline.json": [{"id": "T-tester-001", "status": status, "description": "d",
                           "timestamp": "2026-10-08T09:00:00+00:00"}],
        "iocs.json": [{"id": "IOC-tester-001", "status": status, "value": "c2.example.net",
                       "type": "domain-name", "manually_reviewed": True,
                       "source_findings": ["F-tester-001"]}],
    }  # fmt: skip


@pytest.fixture
def rs(tmp_path, monkeypatch):
    import report_mcp.server as rs

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


def _case(tmp_path, monkeypatch, fixture, name):
    case = tmp_path / CASE
    case.mkdir()
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": CASE, "name": "Deep"}))
    for file, items in _items("APPROVED" if fixture == "signed" else "DRAFT").items():
        (case / file).write_text(json.dumps(items))
    (case / "todos.json").write_text("[]")
    if fixture == "signed":
        sign_approved(case)
    (case / name).write_text(DEEP)
    assert json.loads(DEEP), "the 500-deep list parses"
    return case


@pytest.mark.parametrize("profile", sorted(PROFILES))
@pytest.mark.parametrize("fixture", ["draft", "signed"])
@pytest.mark.parametrize(
    "name", ["findings.json", "timeline.json", "iocs.json", "todos.json"]
)
def test_generate_report_names_the_deep_file(
    rs, tmp_path, monkeypatch, name, fixture, profile
):
    case = _case(tmp_path, monkeypatch, fixture, name)
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}[
        "generate_report"
    ]
    try:
        got = tool.fn(profile=profile)
    except Exception as e:  # noqa: BLE001  (the row's property: nothing raises)
        pytest.fail(f"generate_report raised {type(e).__name__}: {e} at "
                    f"{traceback.extract_tb(e.__traceback__)[-1]}")  # fmt: skip
    got = got if isinstance(got, dict) else json.loads(got)
    unreadable = got.get("unreadable")
    assert unreadable, f"no `unreadable` in the reply (keys {sorted(got)})"
    # report-mcp names files by full path (O4-N3)
    assert {"file": str(case / name), "why": WHY} in unreadable, unreadable
