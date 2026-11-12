"""report-mcp reads a case's record files with vhir-cli's one reader,
`vhir_cli.case_io`, and keeps no copy of it: generate_report reads findings,
timeline, iocs and todos through it in every profile, and save_report reads
findings.json and iocs.json through it, as `vhir report` does. The IOCs a saved
report defangs are picked by vhir-cli's own `_report_iocs`."""

from __future__ import annotations

import pytest
import yaml
from report_mcp import server as rs
from report_mcp.profiles import PROFILES

RECORD_FILES = ("findings.json", "timeline.json", "iocs.json", "todos.json")


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-ONE-READER"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-ONE-READER"}))
    for name in RECORD_FILES:
        (d / name).write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


@pytest.fixture
def reads(monkeypatch):
    """The basenames vhir-cli's reader is asked for, in order."""
    from vhir_cli import case_io

    asked: list[str] = []
    real = case_io.read_record_file

    def spy(path):
        asked.append(path.name)
        return real(path)

    monkeypatch.setattr(case_io, "read_record_file", spy)
    return asked


def test_report_mcp_holds_vhirs_reader_and_no_copy():
    from vhir_cli import case_io
    from vhir_cli.commands import report

    assert rs._case_io is case_io
    assert rs._report_iocs is report._report_iocs
    for name in (
        "_ioc_records",
        "_fresh_records",
        "_RECORD_FILES",
        "_KINDS",
        "_Unsafe",
    ):
        assert not hasattr(rs, name), name


@pytest.mark.parametrize("profile", list(PROFILES))
def test_generate_report_reads_every_record_file_through_it(case, reads, profile):
    out = rs._generate(profile, case)
    assert reads == list(RECORD_FILES), reads
    assert "unreadable" not in out, out.get("unreadable")


def test_save_report_reads_findings_and_iocs_through_it(case, reads):
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}
    reads.clear()
    got = tool["save_report"].fn(filename="r.md", content="# R\n", profile="full")
    assert got.get("status") == "saved", got
    assert reads == ["findings.json", "iocs.json"], reads
