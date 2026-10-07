"""case-mcp's case_init and case_activate give a case its identity.

A new case gets `case_uuid` with `naming_version: 2` and its host logs; an
older case gets one at activation (`naming_version: 1`); a case whose
CASE.yaml lost its UUID while its logs record one is refused, with the UUID
to restore; and a copy of another case is refused at activation.
"""

from __future__ import annotations

import json
import shutil

import case_mcp.server as case_server
import pytest
import yaml
from case_mcp.server import create_server


@pytest.fixture
def home(tmp_path, monkeypatch):
    for var in ("VHIR_CASE_DIR", "VHIR_CASES_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    (tmp_path / ".vhir").mkdir()
    monkeypatch.setattr(
        case_server, "_ACTIVE_CASE_FILE", tmp_path / ".vhir" / "active_case"
    )
    return tmp_path


def _tool(tool, **kw):
    return create_server()._tool_manager._tools[tool].fn(**kw)


def _meta(case_dir):
    return yaml.safe_load((case_dir / "CASE.yaml").read_text())


def _init(home, case_id="C-1"):
    result = _tool(
        "case_init",
        name="n",
        case_id=case_id,
        share_wintools=False,
        cases_dir=str(home / "cases"),
    )
    assert "error" not in result, result
    return home / "cases" / case_id


def test_case_init_gives_the_case_its_identity(home):
    case_dir = _init(home)
    meta = _meta(case_dir)
    assert len(meta["case_uuid"].replace("-", "")) == 32
    assert meta["naming_version"] == 2
    header = json.loads((case_dir / "host-observations.jsonl").read_text())
    assert header["c12"] == meta["case_uuid"].replace("-", "")[:12]


def test_case_activate_gives_an_older_case_its_identity(home):
    case_dir = home / "cases" / "OLD-1"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: OLD-1\nstatus: open\nname: o\n")
    result = _tool("case_activate", case_id="OLD-1", cases_dir=str(home / "cases"))
    assert "error" not in result, result
    meta = _meta(case_dir)
    assert meta["naming_version"] == 1 and meta["name"] == "o"
    assert len(meta["case_uuid"].replace("-", "")) == 32


def test_case_activate_refuses_a_lost_identity(home):
    case_dir = _init(home)
    meta = _meta(case_dir)
    lost = meta.pop("case_uuid")
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(meta))
    result = _tool("case_activate", case_id="C-1", cases_dir=str(home / "cases"))
    assert lost in result.get("error", ""), result
    assert "case_uuid" not in _meta(case_dir)


def test_case_activate_refuses_a_copy(home):
    case_dir = _init(home)
    shutil.copytree(case_dir, home / "other" / "C-1")
    result = _tool("case_activate", case_id="C-1", cases_dir=str(home / "other"))
    assert "new-identity" in result.get("error", ""), result
    assert str(case_dir.resolve()) in result["error"]
