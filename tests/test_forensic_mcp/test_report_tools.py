"""Tests for report generation tools."""

import json
import os
from pathlib import Path

import pytest

from forensic_mcp.case.manager import CaseManager


@pytest.fixture
def manager(tmp_path, monkeypatch):
    """CaseManager with temp cases directory."""
    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    return CaseManager()


@pytest.fixture
def case_with_data(manager):
    """Case with approved + draft findings, timeline, and evidence."""
    result = manager.init_case("Test Incident", "Testing reports")
    case_dir = Path(result["path"])

    # Record findings
    manager.record_finding({
        "title": "Suspicious process",
        "evidence_ids": ["ev-001", "ev-004"],
        "observation": "svchost from cmd",
        "interpretation": "Process masquerading",
        "confidence": "HIGH",
        "confidence_justification": "Multiple evidence sources",
        "type": "finding",
        "iocs": [{"type": "hash", "value": "abc123"}, {"type": "ip", "value": "10.0.0.1"}],
        "mitre_techniques": [{"id": "T1036", "name": "Masquerading"}],
    })
    manager.record_finding({
        "title": "Lateral movement",
        "evidence_ids": ["ev-002"],
        "observation": "RDP session from workstation",
        "interpretation": "Attacker pivoted",
        "confidence": "MEDIUM",
        "confidence_justification": "Single source",
        "type": "finding",
        "iocs": [{"type": "ip", "value": "10.0.0.2"}],
        "mitre_techniques": [{"id": "T1021", "name": "Remote Services"}],
    })
    manager.record_finding({
        "title": "Draft finding",
        "evidence_ids": ["ev-003"],
        "observation": "Unconfirmed",
        "interpretation": "Needs review",
        "confidence": "LOW",
        "confidence_justification": "Speculative",
        "type": "finding",
    })

    # Approve first two findings (flat case root)
    findings = json.loads((case_dir / "findings.json").read_text())
    findings[0]["status"] = "APPROVED"
    findings[0]["approved_by"] = "analyst1"
    findings[0]["approved_at"] = "2026-02-20T12:00:00Z"
    findings[1]["status"] = "APPROVED"
    findings[1]["approved_by"] = "analyst1"
    findings[1]["approved_at"] = "2026-02-20T12:30:00Z"
    with open(case_dir / "findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    # Timeline events
    manager.record_timeline_event({
        "timestamp": "2026-02-19T10:00:00Z",
        "description": "Initial access detected",
        "evidence_ids": ["ev-001"],
        "source": "Firewall logs",
    })
    manager.record_timeline_event({
        "timestamp": "2026-02-19T14:00:00Z",
        "description": "Lateral movement",
        "evidence_ids": ["ev-002"],
        "source": "Event logs",
    })
    # Approve timeline events
    timeline = json.loads((case_dir / "timeline.json").read_text())
    for t in timeline:
        t["status"] = "APPROVED"
        t["approved_by"] = "analyst1"
    with open(case_dir / "timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)

    # Actions
    manager.record_action("Checked process list", tool="ps")

    return result


class TestFullReport:
    def test_excludes_draft_includes_approved(self, manager, case_with_data):
        result = manager.generate_full_report()
        assert result["report_type"] == "full"
        findings = result["report_data"]["findings"]
        assert len(findings) == 2
        assert all(f["status"] == "APPROVED" for f in findings)

    def test_has_zeltser_guidance(self, manager, case_with_data):
        result = manager.generate_full_report()
        assert "zeltser_tools_needed" in result
        assert "ir_get_template" in result["zeltser_tools_needed"]
        assert len(result["next_steps"]) > 0

    def test_has_timeline_and_iocs(self, manager, case_with_data):
        result = manager.generate_full_report()
        assert len(result["report_data"]["timeline"]) == 2
        assert "hash" in result["report_data"]["iocs"]
        assert "abc123" in result["report_data"]["iocs"]["hash"]

    def test_stub_has_content(self, manager, case_with_data):
        result = manager.generate_full_report()
        stub = result["report_stub"]
        assert "Incident Response Report" in stub
        assert "Suspicious process" in stub
        assert "[PLACEHOLDER" in stub


class TestExecutiveSummary:
    def test_has_counts_and_range(self, manager, case_with_data):
        result = manager.generate_executive_summary()
        data = result["report_data"]
        assert data["findings_count"] == 2
        assert "earliest" in data["timeline_range"]
        assert "latest" in data["timeline_range"]

    def test_stub_references_findings(self, manager, case_with_data):
        result = manager.generate_executive_summary()
        stub = result["report_stub"]
        assert "Suspicious process" in stub
        assert "Lateral movement" in stub


class TestTimelineReport:
    def test_all_approved_events(self, manager, case_with_data):
        result = manager.generate_timeline_report()
        assert result["report_data"]["event_count"] == 2

    def test_date_filter(self, manager, case_with_data):
        result = manager.generate_timeline_report(
            start_date="2026-02-19T12:00:00Z",
        )
        # Only the 14:00 event should match
        assert result["report_data"]["event_count"] == 1
        assert "Lateral movement" in result["report_data"]["events"][0]["description"]

    def test_empty_when_no_approved(self, manager):
        manager.init_case("Empty Case")
        result = manager.generate_timeline_report()
        assert result["report_data"]["event_count"] == 0


class TestIOCReport:
    def test_aggregates_iocs(self, manager, case_with_data):
        result = manager.generate_ioc_report()
        data = result["report_data"]
        assert data["total_iocs"] == 3  # abc123, 10.0.0.1, 10.0.0.2
        assert "hash" in data["iocs_by_type"]
        assert "ip" in data["iocs_by_type"]

    def test_no_zeltser_push(self, manager, case_with_data):
        result = manager.generate_ioc_report()
        assert "zeltser_tools_needed" not in result

    def test_has_mitre_mapping(self, manager, case_with_data):
        result = manager.generate_ioc_report()
        mitre = result["report_data"]["mitre_mapping"]
        assert len(mitre) == 2
        technique_ids = {m["id"] for m in mitre}
        assert "T1036" in technique_ids
        assert "T1021" in technique_ids


class TestFindingsReport:
    def test_defaults_to_all_approved(self, manager, case_with_data):
        result = manager.generate_findings_report()
        assert result["report_data"]["findings_count"] == 2

    def test_filter_by_id(self, manager, case_with_data):
        # Get actual finding ID from the case data
        case_dir = Path(case_with_data["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        first_id = findings[0]["id"]

        result = manager.generate_findings_report(finding_ids=[first_id])
        assert result["report_data"]["findings_count"] == 1
        assert result["report_data"]["findings"][0]["title"] == "Suspicious process"

    def test_empty_when_all_draft(self, manager):
        manager.init_case("Draft Only")
        manager.record_finding({
            "title": "Draft",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "LOW",
            "confidence_justification": "guess",
            "type": "finding",
        })
        result = manager.generate_findings_report()
        assert result["report_data"]["findings_count"] == 0


class TestStatusBrief:
    def test_correct_counts(self, manager, case_with_data):
        result = manager.generate_status_brief()
        counts = result["report_data"]["counts"]
        assert counts["findings_total"] == 3
        assert counts["findings_approved"] == 2
        assert counts["findings_draft"] == 1
        assert counts["timeline_events"] == 2

    def test_has_key_findings(self, manager, case_with_data):
        result = manager.generate_status_brief()
        key_findings = result["report_data"]["key_findings"]
        assert len(key_findings) == 2


class TestSaveReport:
    def test_saves_to_reports_dir(self, manager, case_with_data):
        result = manager.save_report("test-report.md", "# Report\n\nContent", "full")
        assert result["status"] == "saved"
        assert result["filename"] == "test-report.md"
        path = Path(result["path"])
        assert path.exists()
        assert path.read_text() == "# Report\n\nContent"

    def test_blocks_path_traversal(self, manager, case_with_data):
        with pytest.raises(ValueError):
            manager.save_report("../../../etc/passwd", "bad")

    def test_sanitizes_filename(self, manager, case_with_data):
        result = manager.save_report("my report (final).md", "content", "full")
        assert " " not in result["filename"]
        assert "(" not in result["filename"]
        path = Path(result["path"])
        assert path.exists()

    def test_atomic_write(self, manager, case_with_data):
        """save_report uses atomic write -- file is always complete."""
        content = "x" * 10000
        result = manager.save_report("big-report.md", content)
        assert result["characters"] == 10000
        assert Path(result["path"]).read_text() == content
