"""backup_case stops with every path it can't back up, and its skip option
finishes the backup with those paths listed in the manifest and the result."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from case_mcp.server import create_server

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission bits don't bind root",
)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    cd = tmp_path / "cases" / "SKIP-MCP"
    for sub in ("work", "evidence", "audit"):
        (cd / sub).mkdir(parents=True)
    (cd / "CASE.yaml").write_text(yaml.dump({"case_id": "SKIP-MCP", "status": "open"}))
    (cd / "findings.json").write_text("[]")
    (cd / "work" / "notes.txt").write_text("notes\n")
    (cd / "work" / "gone.txt").symlink_to("missing.txt")
    (cd / "work" / "loop").symlink_to("..")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("VHIR_CASE_DIR", str(cd))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    return cd


def _call(**kw) -> dict:
    fn = create_server()._tool_manager._tools["backup_case"].fn
    return fn(**kw)


def test_backup_case_stops_and_lists_every_path(case_dir, tmp_path):
    result = _call(destination=str(tmp_path / "out"))
    assert "skip_unreadable" in result["error"].splitlines()[0]
    assert "work/gone.txt" in result["error"] and "work/loop" in result["error"]


def test_backup_case_skip_option_finishes_and_lists_the_paths(case_dir, tmp_path):
    result = _call(destination=str(tmp_path / "out"), skip_unreadable=True)
    assert "error" not in result
    want = {"work/gone.txt", "work/loop"}
    assert {s["path"] for s in result["skipped"]} == want
    manifest = json.loads(
        (Path(result["backup_path"]) / "backup-manifest.json").read_text()
    )
    assert {s["path"] for s in manifest["skipped"]} == want


def test_backup_case_still_works_with_a_vhir_cli_without_the_skip_option(
    case_dir, tmp_path, monkeypatch
):
    from vhir_cli.commands import backup as B

    real = B.create_backup_data

    def older(case_dir, destination, examiner, *, purpose="", **kw):
        assert "skip_unreadable" not in kw
        return real(case_dir, destination, examiner, purpose=purpose, **kw)

    monkeypatch.setattr(B, "create_backup_data", older)
    (case_dir / "work" / "gone.txt").unlink()
    (case_dir / "work" / "loop").unlink()
    assert "error" not in _call(destination=str(tmp_path / "out"))


def test_the_skip_option_against_a_vhir_cli_without_it_fails_naming_it(
    case_dir, tmp_path, monkeypatch
):
    from vhir_cli.commands import backup as B

    def older(case_dir, destination, examiner, *, purpose=""):
        raise AssertionError("not reached")

    monkeypatch.setattr(B, "create_backup_data", older)
    with pytest.raises(TypeError, match="skip_unreadable"):
        _call(destination=str(tmp_path / "out"), skip_unreadable=True)
