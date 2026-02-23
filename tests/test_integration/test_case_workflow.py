"""Integration tests for forensic-mcp case management workflow.

These tests use tmp_path (no SIFT tools needed) and validate the full
case lifecycle: init → record → query → verify JSON on disk.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.integration


class TestFullInvestigationLifecycle:
    def test_lifecycle(self, case_manager, tmp_path, monkeypatch):
        """init → record_finding → record_timeline_event → add_todo →
        complete_todo → get_case_status → verify JSON files on disk."""
        # Init
        result = case_manager.init_case("Test Incident", description="Integration test case")
        case_id = result["case_id"]
        assert case_id.startswith("INC-")
        assert result["status"] == "open"
        assert result["examiner"] == "integration"

        case_dir = tmp_path / case_id

        # Record finding
        finding = {
            "title": "Suspicious process execution",
            "observation": "powershell.exe spawned with encoded command",
            "interpretation": "Possible malicious script execution",
            "confidence": "MEDIUM",
            "type": "finding",
            "evidence_ids": ["sift-integration-20260223-001"],
            "confidence_justification": "Single source corroborated by timeline",
        }
        f_result = case_manager.record_finding(finding)
        assert f_result["status"] == "STAGED"
        finding_id = f_result["finding_id"]
        assert finding_id.startswith("F-integration-")

        # Record timeline event
        event = {
            "timestamp": "2026-02-20T14:10:45Z",
            "description": "powershell.exe process start",
            "source": "sift-mcp",
            "event_type": "process",
        }
        t_result = case_manager.record_timeline_event(event)
        assert t_result["status"] == "STAGED"
        event_id = t_result["event_id"]
        assert event_id.startswith("T-integration-")

        # Add TODO
        todo_result = case_manager.add_todo(
            description="Analyze encoded PowerShell command",
            priority="high",
            related_findings=[finding_id],
        )
        assert todo_result["status"] == "created"
        todo_id = todo_result["todo_id"]
        assert todo_id.startswith("TODO-integration-")

        # Complete TODO
        complete = case_manager.complete_todo(todo_id)
        assert complete["status"] == "updated"

        # Get case status
        status = case_manager.get_case_status(case_id)
        assert status["case_id"] == case_id
        assert status["name"] == "Test Incident"
        assert status["status"] == "open"
        assert status["findings"]["total"] == 1
        assert status["findings"]["draft"] == 1
        assert status["timeline_events"] == 1
        assert status["todos"]["total"] == 1
        assert status["todos"]["completed"] == 1
        assert status["todos"]["open"] == 0

        # Verify JSON files on disk
        findings_data = json.loads((case_dir / "findings.json").read_text())
        assert len(findings_data) == 1
        assert findings_data[0]["id"] == finding_id
        assert findings_data[0]["status"] == "DRAFT"
        assert findings_data[0]["title"] == "Suspicious process execution"

        timeline_data = json.loads((case_dir / "timeline.json").read_text())
        assert len(timeline_data) == 1
        assert timeline_data[0]["id"] == event_id
        assert timeline_data[0]["timestamp"] == "2026-02-20T14:10:45Z"

        todos_data = json.loads((case_dir / "todos.json").read_text())
        assert len(todos_data) == 1
        assert todos_data[0]["todo_id"] == todo_id
        assert todos_data[0]["status"] == "completed"


class TestFindingValidationRules:
    def test_missing_required_fields(self, case_manager, tmp_path):
        case_manager.init_case("Validation Test")
        result = case_manager.record_finding({})
        assert result["status"] == "VALIDATION_FAILED"
        assert any("title" in e for e in result["errors"])

    def test_invalid_confidence(self, case_manager, tmp_path):
        case_manager.init_case("Validation Test 2")
        result = case_manager.record_finding({
            "title": "Test",
            "observation": "Observed X",
            "interpretation": "Means Y",
            "confidence": "INVALID_LEVEL",
            "type": "finding",
            "evidence_ids": ["sift-integration-20260223-001"],
            "confidence_justification": "Just a test",
        })
        assert result["status"] == "VALIDATION_FAILED"
        assert any("confidence" in e.lower() for e in result["errors"])

    def test_attribution_needs_three_evidence_ids(self, case_manager, tmp_path):
        case_manager.init_case("Validation Test 3")
        result = case_manager.record_finding({
            "title": "Attribution test",
            "observation": "Actor X used tool Y",
            "interpretation": "Attribution to group Z",
            "confidence": "HIGH",
            "type": "attribution",
            "evidence_ids": ["id-1", "id-2"],  # Need 3 for attribution
            "confidence_justification": "Two sources confirmed",
        })
        assert result["status"] == "VALIDATION_FAILED"
        assert any("attribution" in e.lower() or "3 evidence" in e.lower() for e in result["errors"])


class TestAuditTrailRoundTrip:
    def test_audit_writes_and_reads(self, tmp_path, monkeypatch):
        """Audit JSONL written correctly with evidence IDs and examiner."""
        monkeypatch.setenv("AIIR_EXAMINER", "integration")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "audit").mkdir(exist_ok=True)

        from sift_common.audit import AuditWriter

        audit = AuditWriter(mcp_name="forensic-mcp")
        eid1 = audit.log(
            tool="record_finding",
            params={"title": "Test finding"},
            result_summary={"status": "STAGED"},
        )
        eid2 = audit.log(
            tool="record_timeline_event",
            params={"timestamp": "2026-02-20T14:10:45Z"},
            result_summary={"status": "STAGED"},
        )

        assert eid1.startswith("forensic-integration-")
        assert eid2.startswith("forensic-integration-")
        assert eid1 != eid2

        # Read back
        entries = audit.get_entries()
        assert len(entries) == 2
        assert entries[0]["evidence_id"] == eid1
        assert entries[0]["examiner"] == "integration"
        assert entries[0]["tool"] == "record_finding"
        assert entries[1]["evidence_id"] == eid2
        assert entries[1]["tool"] == "record_timeline_event"

        # Verify JSONL file on disk
        jsonl_file = tmp_path / "audit" / "forensic-mcp.jsonl"
        assert jsonl_file.exists()
        lines = [json.loads(line) for line in jsonl_file.read_text().splitlines() if line.strip()]
        assert len(lines) == 2


class TestEvidenceRegistrationIntegrity:
    def test_register_and_verify(self, case_manager, tmp_path):
        case_manager.init_case("Evidence Test")
        case_dir = case_manager.active_case_dir

        # Create a test file in the evidence directory
        evidence_file = case_dir / "evidence" / "sample.bin"
        evidence_file.write_bytes(b"known content for hash verification")

        # Register
        reg_result = case_manager.register_evidence(
            str(evidence_file), description="Test binary"
        )
        assert reg_result["status"] == "registered"
        assert len(reg_result["sha256"]) == 64

        # Verify integrity
        integrity = case_manager.verify_evidence_integrity()
        assert integrity["total"] == 1
        assert integrity["ok"] == 1
        assert integrity["files"][0]["status"] == "OK"

        # Check evidence access log
        access_log = case_manager.get_evidence_access_log()
        assert len(access_log) >= 1
        register_entries = [e for e in access_log if e["action"] == "register"]
        assert len(register_entries) == 1
        assert register_entries[0]["examiner"] == "integration"

    def test_evidence_becomes_readonly(self, case_manager, tmp_path):
        """Registered evidence is set to read-only (chmod 444)."""
        import stat

        case_manager.init_case("ReadOnly Test")
        case_dir = case_manager.active_case_dir
        evidence_file = case_dir / "evidence" / "readonly_test.bin"
        evidence_file.write_bytes(b"test data")

        case_manager.register_evidence(str(evidence_file))

        mode = evidence_file.stat().st_mode
        assert mode & stat.S_IRUSR  # Owner can read
        assert not (mode & stat.S_IWUSR)  # Owner cannot write
