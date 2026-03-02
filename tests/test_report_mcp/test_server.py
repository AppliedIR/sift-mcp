"""Tests for report-mcp server tools."""

from __future__ import annotations

import json

import pytest
import yaml


@pytest.fixture()
def case_dir(tmp_path, monkeypatch):
    """Create a case directory with test data."""
    case = tmp_path / "TEST-REPORT-001"
    case.mkdir()
    (case / "audit").mkdir()
    (case / "reports").mkdir()

    monkeypatch.setenv("AIIR_CASE_DIR", str(case))
    monkeypatch.setenv("AIIR_EXAMINER", "tester")

    # CASE.yaml
    meta = {
        "case_id": "TEST-REPORT-001",
        "name": "Report Test Case",
        "status": "open",
        "examiner": "tester",
        "created": "2026-02-25T10:00:00+00:00",
        "description": "Case for testing report generation",
        "incident_type": "ransomware",
        "severity": "high",
    }
    with open(case / "CASE.yaml", "w") as f:
        yaml.dump(meta, f, default_flow_style=False)

    # findings.json — mix of APPROVED, DRAFT, REJECTED
    findings = [
        {
            "id": "F-tester-001",
            "title": "Lateral movement detected",
            "description": "PsExec used to move laterally to 10.0.1.5",
            "status": "APPROVED",
            "confidence": "HIGH",
            "confidence_justification": "Multiple artifacts confirm",
            "provenance": "MCP",
            "content_hash": "abc123",
            "evidence_ids": ["fm-tester-20260225-001"],
            "staged": "2026-02-25T11:00:00+00:00",
            "approved_at": "2026-02-25T12:00:00+00:00",
            "approved_by": "tester",
            "created_by": "tester",
            "modified_at": "2026-02-25T12:00:00+00:00",
            "verification": "confirmed",
            "iocs": {"IPv4": ["10.0.1.5"], "File": ["C:\\Windows\\Temp\\psexec.exe"]},
            "mitre_techniques": [
                {"id": "T1570", "name": "Lateral Tool Transfer"},
                {"id": "T1059.001", "name": "PowerShell"},
            ],
            "examiner_notes": "Confirmed by examiner",
            "examiner_modifications": "",
        },
        {
            "id": "F-tester-002",
            "title": "Ransomware payload execution",
            "description": "Ransomware binary abc123def456 executed at 14:32 UTC. Hash: aabbccddee1122334455667788990011aabbccddee1122334455667788990011",
            "status": "APPROVED",
            "confidence": "HIGH",
            "provenance": "MCP",
            "content_hash": "def456",
            "evidence_ids": ["fm-tester-20260225-002"],
            "staged": "2026-02-25T13:00:00+00:00",
            "approved_at": "2026-02-25T14:00:00+00:00",
            "approved_by": "tester",
            "created_by": "tester",
            "iocs": {
                "SHA256": [
                    "aabbccddee1122334455667788990011aabbccddee1122334455667788990011"
                ]
            },
            "mitre_techniques": [{"id": "T1486", "name": "Data Encrypted for Impact"}],
        },
        {
            "id": "F-tester-003",
            "title": "Initial access vector",
            "description": "Phishing email with malicious attachment",
            "status": "APPROVED",
            "confidence": "MEDIUM",
            "provenance": "HOOK",
            "iocs": {"Domain": ["evil.example.com"]},
            "mitre_techniques": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"}
            ],
        },
        {
            "id": "F-tester-004",
            "title": "Draft finding",
            "description": "Unconfirmed activity",
            "status": "DRAFT",
            "confidence": "LOW",
        },
        {
            "id": "F-tester-005",
            "title": "Rejected finding",
            "description": "False positive",
            "status": "REJECTED",
            "confidence": "LOW",
            "rejected_at": "2026-02-25T15:00:00+00:00",
            "rejected_by": "tester",
            "rejection_reason": "False positive",
        },
    ]
    with open(case / "findings.json", "w") as f:
        json.dump(findings, f)

    # timeline.json
    timeline = [
        {
            "id": "T-tester-001",
            "timestamp": "2026-02-25T08:00:00+00:00",
            "description": "Phishing email received",
            "status": "APPROVED",
        },
        {
            "id": "T-tester-002",
            "timestamp": "2026-02-25T10:30:00+00:00",
            "description": "Attachment opened",
            "status": "APPROVED",
        },
        {
            "id": "T-tester-003",
            "timestamp": "2026-02-25T14:32:00+00:00",
            "description": "Ransomware executed",
            "status": "APPROVED",
        },
        {
            "id": "T-tester-004",
            "timestamp": "2026-02-25T16:00:00+00:00",
            "description": "Draft event",
            "status": "DRAFT",
        },
    ]
    with open(case / "timeline.json", "w") as f:
        json.dump(timeline, f)

    # todos.json
    todos = [
        {"id": "TODO-tester-001", "description": "Check other hosts", "status": "open"},
        {"id": "TODO-tester-002", "description": "Image server", "status": "done"},
        {"id": "TODO-tester-003", "description": "Review logs", "status": "open"},
    ]
    with open(case / "todos.json", "w") as f:
        json.dump(todos, f)

    # evidence.json (registry format: {"files": [...]})
    evidence = {
        "files": [
            {
                "path": "/evidence/disk.E01",
                "sha256": "aaa",
                "description": "Disk image",
            },
            {
                "path": "/evidence/memory.raw",
                "sha256": "bbb",
                "description": "Memory dump",
            },
        ]
    }
    with open(case / "evidence.json", "w") as f:
        json.dump(evidence, f)

    return case


def _call_tool(server, name, **kwargs):
    """Call a tool on the server and return the parsed response."""
    tools = {t.name: t for t in server._tool_manager.list_tools()}
    tool = tools[name]
    result = tool.fn(**kwargs)
    if isinstance(result, (dict, list)):
        return result
    return json.loads(result)


class TestGenerateReport:
    """Tests for generate_report tool."""

    def test_full_profile(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        assert result["profile"] == "full"
        assert "generated_at" in result
        rd = result["report_data"]
        assert "metadata" in rd
        assert "findings" in rd
        assert "timeline" in rd
        assert "iocs" in rd
        assert "mitre_mapping" in rd
        assert "evidence" in rd
        assert "todos" in rd
        assert "summary" in rd
        # 3 approved findings only
        assert len(rd["findings"]) == 3
        # 3 approved timeline events
        assert len(rd["timeline"]) == 3

    def test_executive_profile(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="executive")

        rd = result["report_data"]
        assert "metadata" in rd
        assert "findings" in rd
        # Top 5 (we only have 3 approved, so all 3)
        assert len(rd["findings"]) == 3
        # Timeline is count only
        assert "timeline" not in rd
        assert "timeline_count" in rd
        assert rd["timeline_count"] == 3

    def test_status_profile(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="status")

        rd = result["report_data"]
        assert "summary" in rd
        assert "todos" in rd
        # Findings are count only
        assert "findings" not in rd
        assert rd.get("findings_count") == 3

    def test_timeline_profile_date_filter(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "generate_report",
            profile="timeline",
            start_date="2026-02-25T10:00:00",
            end_date="2026-02-25T15:00:00",
        )

        rd = result["report_data"]
        timeline = rd["timeline"]
        # Should include T-002 (10:30) and T-003 (14:32), not T-001 (08:00)
        assert len(timeline) == 2
        assert timeline[0]["id"] == "T-tester-002"
        assert timeline[1]["id"] == "T-tester-003"

    def test_findings_profile_filter_ids(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "generate_report",
            profile="findings",
            finding_ids=["F-tester-001"],
        )

        rd = result["report_data"]
        assert len(rd["findings"]) == 1
        assert rd["findings"][0]["id"] == "F-tester-001"

    def test_approved_only(self, case_dir):
        """DRAFT and REJECTED findings excluded from all profiles."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        rd = result["report_data"]
        for f in rd["findings"]:
            assert f.get("status") == "APPROVED"
        for t in rd["timeline"]:
            assert t.get("status") == "APPROVED"

    def test_strips_internal_fields(self, case_dir):
        """Internal fields removed from findings in output."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        stripped = {
            "provenance",
            "content_hash",
            "evidence_ids",
            "staged",
            "modified_at",
            "approved_by",
            "approved_at",
            "rejected_by",
            "rejected_at",
            "rejection_reason",
            "verification",
            "created_by",
        }
        for f in result["report_data"]["findings"]:
            for field in stripped:
                assert field not in f, f"Field '{field}' should be stripped"
            # But id, title, description should remain
            assert "id" in f
            assert "title" in f
            assert "description" in f

    def test_ioc_aggregation(self, case_dir):
        """IOCs deduplicated and cross-referenced to source findings."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        iocs = result["report_data"]["iocs"]
        assert "IPv4" in iocs
        assert any(e["value"] == "10.0.1.5" for e in iocs["IPv4"])
        # Cross-reference check
        ip_entry = next(e for e in iocs["IPv4"] if e["value"] == "10.0.1.5")
        assert "F-tester-001" in ip_entry["source_findings"]

    def test_mitre_mapping(self, case_dir):
        """MITRE techniques grouped by ID with finding cross-references."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        mitre = result["report_data"]["mitre_mapping"]
        assert "T1570" in mitre
        assert mitre["T1570"]["name"] == "Lateral Tool Transfer"
        assert "F-tester-001" in mitre["T1570"]["findings"]
        assert "T1486" in mitre
        assert "F-tester-002" in mitre["T1486"]["findings"]

    def test_zeltser_guidance_full(self, case_dir):
        """Full profile has Zeltser guidance with all 4 tools."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        zg = result["zeltser_guidance"]
        assert set(zg["tools"]) == {
            "ir_get_template",
            "ir_get_guidelines",
            "ir_load_context",
            "ir_review_report",
        }
        assert "workflow" in zg
        # incident_type from CASE.yaml
        assert zg["parameters"]["ir_load_context"]["incident_type"] == "ransomware"

    def test_zeltser_guidance_ioc_empty(self, case_dir):
        """IOC profile has no Zeltser guidance."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="ioc")

        assert "zeltser_guidance" not in result

    def test_zeltser_metadata_params(self, case_dir):
        """Zeltser guidance parameters derived from case metadata."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        params = result["zeltser_guidance"]["parameters"]
        assert params["ir_load_context"]["incident_type"] == "ransomware"
        assert params["ir_get_guidelines"]["topic"] == "full_report"

    def test_invalid_profile(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="nonexistent")

        assert "error" in result
        assert "nonexistent" in result["error"]

    def test_sections_in_output(self, case_dir):
        """Sections template included in output."""
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "generate_report", profile="full")

        assert "sections" in result
        assert len(result["sections"]) > 0
        names = [s["name"] for s in result["sections"]]
        assert "Executive Summary" in names
        assert "Findings" in names


class TestSetCaseMetadata:
    """Tests for set_case_metadata tool."""

    def test_valid_enum(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "set_case_metadata", field="incident_type", value="bec")

        assert result["status"] == "set"
        assert result["field"] == "incident_type"
        assert result["value"] == "bec"

        # Verify persisted
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert meta["incident_type"] == "bec"

    def test_invalid_enum(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "set_case_metadata", field="incident_type", value="foo")

        assert "error" in result
        assert "foo" in result["error"]

    def test_valid_datetime(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "set_case_metadata",
            field="detected_at",
            value="2026-02-25T08:00:00+00:00",
        )

        assert result["status"] == "set"
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert meta["detected_at"] == "2026-02-25T08:00:00+00:00"

    def test_protected_field_rejected(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "set_case_metadata", field="case_id", value="hacked")

        assert "error" in result
        assert "protected" in result["error"].lower()

    def test_unknown_field_accepted(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s, "set_case_metadata", field="custom_field", value="custom_value"
        )

        assert result["status"] == "set"
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert meta["custom_field"] == "custom_value"

    def test_list_field(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "set_case_metadata",
            field="affected_systems",
            value=["srv1", "srv2"],
        )

        assert result["status"] == "set"
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert meta["affected_systems"] == ["srv1", "srv2"]

    def test_list_field_rejects_string(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s, "set_case_metadata", field="affected_systems", value="not-a-list"
        )

        assert "error" in result
        assert "list" in result["error"].lower()


class TestGetCaseMetadata:
    """Tests for get_case_metadata tool."""

    def test_get_all(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "get_case_metadata")

        assert result["case_id"] == "TEST-REPORT-001"
        assert result["name"] == "Report Test Case"
        assert result["incident_type"] == "ransomware"

    def test_get_single_field(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "get_case_metadata", field="incident_type")

        assert result["field"] == "incident_type"
        assert result["value"] == "ransomware"

    def test_get_missing_field(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "get_case_metadata", field="nonexistent")

        assert result["field"] == "nonexistent"
        assert result["value"] is None


class TestSaveReport:
    """Tests for save_report tool."""

    def test_basic_save(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "save_report",
            filename="full-report-2026-02-25.md",
            content="# Full Report\n\nContent here.",
            profile="full",
        )

        assert result["status"] == "saved"
        assert result["filename"] == "full-report-2026-02-25.md"
        assert result["profile"] == "full"
        assert result["characters"] == len("# Full Report\n\nContent here.")

        saved = (case_dir / "reports" / "full-report-2026-02-25.md").read_text()
        assert saved == "# Full Report\n\nContent here."

    def test_path_traversal_blocked(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "save_report",
            filename="../etc/passwd",
            content="evil",
        )

        assert "error" in result
        assert "path traversal" in result["error"].lower()

    def test_filename_sanitization(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "save_report",
            filename="report (draft) v2.md",
            content="content",
        )

        assert result["status"] == "saved"
        assert result["filename"] == "report__draft__v2.md"

    def test_creates_reports_dir(self, case_dir):
        """Reports dir created if missing."""
        import shutil

        shutil.rmtree(case_dir / "reports")

        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(
            s,
            "save_report",
            filename="test.md",
            content="content",
        )

        assert result["status"] == "saved"
        assert (case_dir / "reports" / "test.md").exists()


class TestListReports:
    """Tests for list_reports tool."""

    def test_empty(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "list_reports")

        assert result["reports"] == []

    def test_with_files(self, case_dir):
        (case_dir / "reports" / "report1.md").write_text("Report 1")
        (case_dir / "reports" / "report2.md").write_text("Report 2 content")

        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "list_reports")

        assert len(result["reports"]) == 2
        filenames = {r["filename"] for r in result["reports"]}
        assert "report1.md" in filenames
        assert "report2.md" in filenames
        for r in result["reports"]:
            assert "size_bytes" in r
            assert "created_at" in r


class TestListProfiles:
    """Tests for list_profiles tool."""

    def test_returns_all_profiles(self, case_dir):
        from report_mcp.server import create_server

        s = create_server()
        result = _call_tool(s, "list_profiles")

        names = {p["name"] for p in result["profiles"]}
        assert names == {"full", "executive", "timeline", "ioc", "findings", "status"}

        for p in result["profiles"]:
            assert "description" in p
            assert "zeltser_tools" in p
