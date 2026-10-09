"""Every path check reads a relative argument where the run will: in its
working folder, not in the gateway's own."""

import os
from pathlib import Path

import pytest
from sift_mcp import security


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "cases" / "case-a"
    (d / "audit").mkdir(parents=True)
    (d / "evidence").mkdir()
    (d / "extractions" / "op-1").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: case-a\n")
    (d / "audit" / "sift-mcp.jsonl").write_text("")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setattr(security, "resolve_case_dir", lambda: str(d))
    monkeypatch.chdir(tmp_path)  # the gateway's own folder, outside the case
    return d


def test_rm_reads_a_relative_target_in_the_runs_folder(case):
    op = str(case / "extractions" / "op-1")
    with pytest.raises(ValueError, match="Blocked"):
        security.validate_rm_targets(["../../audit/sift-mcp.jsonl"], base=op)


def test_the_case_data_guard_reads_it_there_too(case):
    op = str(case / "extractions" / "op-1")
    security.validate_case_data_targets(["cp", "/etc/hostname", "x.txt"], base=op)
    with pytest.raises(ValueError, match="Blocked"):
        security.validate_case_data_targets(
            ["cp", "/etc/hostname", "../../evidence.json"], base=op
        )


def test_an_output_path_is_checked_where_the_run_writes(case):
    op = str(case / "extractions" / "op-1")
    assert security.validate_output_path("../mine.csv", base=op) == str(
        (case / "extractions" / "mine.csv").resolve()
    )
    with pytest.raises(ValueError):
        security.validate_output_path("../../../../outside.csv", base=op)


def test_without_a_case_an_output_may_go_in_the_runs_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "resolve_case_dir", lambda: "")
    run_dir = tmp_path / "home-x" / "run"
    run_dir.mkdir(parents=True)
    monkeypatch.chdir("/")
    assert security.validate_output_path("out.csv", base=str(run_dir)) == str(
        run_dir / "out.csv"
    )


def test_an_input_is_checked_where_the_run_reads(tmp_path, monkeypatch):
    home = Path(os.path.expanduser("~"))
    run_dir = home / "nonexistent-run-folder"
    rel = os.path.relpath(home / ".ssh" / "id_rsa", run_dir)
    with pytest.raises(ValueError, match="protected"):
        security.validate_input_path(rel, base=str(run_dir))
    with pytest.raises(ValueError, match="protected"):
        security.validate_input_path(f"--key={rel}", base=str(run_dir))
