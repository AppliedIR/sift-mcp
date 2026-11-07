"""A finding citing an IPv4 address with a port, typed ipv4-addr: the IOCs
save_report defangs are vhir-cli's `_report_iocs` for the case, and they hold
the bare address, so the saved report shows it defanged."""

from __future__ import annotations

import json

import pytest
import yaml
from vhir_cli.commands import report as cli_report
from vhir_signing import sign_approved

FINDING = {"id": "F-tester-001", "title": "Beacon", "observation": "o",
           "interpretation": "i", "confidence": "HIGH", "status": "APPROVED",
           "iocs": [{"value": "10.1.2.3:8080", "type": "ipv4-addr"}]}  # fmt: skip
CONTENT = "# Report\n\nBeacon to 10.1.2.3:8080 seen.\n"


@pytest.fixture
def rs(tmp_path, monkeypatch):
    case = tmp_path / "INC-PORT-1"
    case.mkdir()
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-PORT-1", "name": "p"}))
    (case / "findings.json").write_text(json.dumps([FINDING]))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text("[]")
    sign_approved(case)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


def test_save_report_defangs_the_bare_address_vhir_picks(rs, monkeypatch):
    seen = []
    real = rs.defang_iocs

    def spy(text, iocs):
        seen.append(list(iocs))
        return real(text, iocs)

    monkeypatch.setattr(rs, "defang_iocs", spy)
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}
    got = tool["save_report"].fn(filename="r.md", content=CONTENT, profile="full")
    assert got.get("status") == "saved", got
    case = rs._resolve_case_dir()
    want = cli_report._report_iocs(case, rs.approved_view(case))
    assert seen and all(s == want for s in seen), (seen, want)
    assert "10.1.2.3" in want, want
    saved = (case / "reports" / "r.md").read_text()
    assert "10[.]1[.]2[.]3:8080" in saved and "10.1.2.3" not in saved, saved
