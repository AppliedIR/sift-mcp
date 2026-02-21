"""Tests for CaseManager: lifecycle, findings, timeline, evidence, audit."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from forensic_mcp.case.manager import CaseManager


@pytest.fixture
def manager(tmp_path, monkeypatch):
    """CaseManager with temp cases directory."""
    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    mgr = CaseManager()
    return mgr


@pytest.fixture
def active_case(manager):
    """Manager with an initialized case."""
    result = manager.init_case("Test Incident", "Testing the case manager")
    return result


# --- Case Lifecycle ---

class TestCaseLifecycle:
    def test_init_case_creates_directory(self, manager):
        result = manager.init_case("My Incident")
        assert result["status"] == "open"
        assert result["case_id"].startswith("INC-")
        assert result["mode"] == "solo"

        case_dir = Path(result["path"])
        assert case_dir.exists()
        assert (case_dir / "CASE.yaml").exists()
        assert not (case_dir / "ACTIONS.md").exists()
        assert not (case_dir / "FINDINGS.md").exists()
        assert not (case_dir / "TIMELINE.md").exists()
        assert (case_dir / "evidence").is_dir()
        assert (case_dir / "extracted").is_dir()
        assert (case_dir / "reports").is_dir()
        assert (case_dir / "examiners" / "tester").is_dir()
        assert (case_dir / "examiners" / "tester" / "evidence.json").exists()

    def test_init_case_sets_active(self, manager):
        result = manager.init_case("Test")
        assert manager._active_case_id == result["case_id"]
        assert os.environ.get("AIIR_ACTIVE_CASE") == result["case_id"]

    def test_close_case(self, manager, active_case):
        result = manager.close_case(active_case["case_id"], summary="All done")
        assert result["status"] == "closed"

    def test_close_case_already_closed(self, manager, active_case):
        manager.close_case(active_case["case_id"])
        result = manager.close_case(active_case["case_id"])
        assert result["status"] == "already_closed"

    def test_close_case_warns_on_drafts(self, manager, active_case):
        # Stage a finding first
        manager.record_finding({
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        })
        result = manager.close_case(active_case["case_id"])
        assert result["status"] == "closed"
        assert "warning" in result
        assert "1 unapproved" in result["warning"]

    def test_get_case_status(self, manager, active_case):
        result = manager.get_case_status()
        assert result["case_id"] == active_case["case_id"]
        assert result["status"] == "open"
        assert result["findings"]["total"] == 0
        assert result["timeline_events"] == 0

    def test_list_cases(self, manager):
        manager.init_case("Case One")
        # Reset active to allow creating another
        manager._active_case_id = None
        result = manager.list_cases()
        assert len(result) >= 1
        assert result[0]["name"] == "Case One"

    def test_set_active_case(self, manager, active_case):
        case_id = active_case["case_id"]
        manager._active_case_id = None
        result = manager.set_active_case(case_id)
        assert result["active_case"] == case_id
        assert manager._active_case_id == case_id

    def test_set_active_case_not_found(self, manager):
        with pytest.raises(ValueError, match="Case not found"):
            manager.set_active_case("INC-NONEXISTENT")

    def test_require_active_case_raises(self, manager):
        with pytest.raises(ValueError, match="No active case"):
            manager._require_active_case()


# --- Investigation Records ---

class TestRecords:
    def test_record_action_writes_jsonl(self, manager, active_case):
        result = manager.record_action("Checked process list", tool="ps", command="ps aux")
        assert result["status"] == "recorded"
        actions_file = Path(active_case["path"]) / "examiners" / "tester" / "actions.jsonl"
        assert actions_file.exists()
        entry = json.loads(actions_file.read_text().strip())
        assert entry["description"] == "Checked process list"
        assert entry["tool"] == "ps"
        assert entry["command"] == "ps aux"

    def test_record_finding_valid(self, manager, active_case):
        finding = {
            "title": "Suspicious process",
            "evidence_ids": ["wt-2026-0219-001"],
            "observation": "svchost.exe spawned from cmd.exe",
            "interpretation": "Unusual parent-child relationship",
            "confidence": "MEDIUM",
            "confidence_justification": "Single evidence source",
            "type": "finding",
        }
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        assert result["finding_id"] == "F-001"

    def test_record_finding_assigns_sequential_ids(self, manager, active_case):
        finding = {
            "title": "Finding",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        r1 = manager.record_finding(finding)
        r2 = manager.record_finding({**finding, "title": "Second"})
        assert r1["finding_id"] == "F-001"
        assert r2["finding_id"] == "F-002"

    def test_record_finding_invalid(self, manager, active_case):
        result = manager.record_finding({"title": "Missing fields"})
        assert result["status"] == "VALIDATION_FAILED"
        assert len(result["errors"]) > 0

    def test_record_finding_no_md(self, manager, active_case):
        manager.record_finding({
            "title": "Test Finding",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        })
        assert not (Path(active_case["path"]) / "FINDINGS.md").exists()
        # Data is in JSON
        findings = json.loads((Path(active_case["path"]) / "examiners" / "tester" / "findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["title"] == "Test Finding"

    def test_record_timeline_event(self, manager, active_case):
        result = manager.record_timeline_event({
            "timestamp": "2026-02-19T10:30:00Z",
            "description": "First lateral movement detected",
        })
        assert result["status"] == "STAGED"
        assert result["event_id"] == "T-001"

    def test_record_timeline_event_no_md(self, manager, active_case):
        manager.record_timeline_event({
            "timestamp": "2026-02-19T10:30:00Z",
            "description": "First lateral movement detected",
        })
        assert not (Path(active_case["path"]) / "TIMELINE.md").exists()
        timeline = json.loads((Path(active_case["path"]) / "examiners" / "tester" / "timeline.json").read_text())
        assert len(timeline) == 1
        assert timeline[0]["description"] == "First lateral movement detected"

    def test_record_timeline_event_stores_evidence(self, manager, active_case):
        manager.record_timeline_event({
            "timestamp": "2026-02-19T11:00:00Z",
            "description": "Credential dumping observed",
            "evidence_ids": ["wt-20260219-001", "rag-20260219-002"],
            "source": "Memory analysis",
        })
        timeline = json.loads((Path(active_case["path"]) / "examiners" / "tester" / "timeline.json").read_text())
        assert "wt-20260219-001" in timeline[0]["evidence_ids"]
        assert timeline[0]["source"] == "Memory analysis"

    def test_record_timeline_event_missing_fields(self, manager, active_case):
        result = manager.record_timeline_event({})
        assert result["status"] == "VALIDATION_FAILED"

    def test_get_findings_filter(self, manager, active_case):
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        manager.record_finding(finding)
        all_findings = manager.get_findings()
        drafts = manager.get_findings(status="DRAFT")
        approved = manager.get_findings(status="APPROVED")
        assert len(all_findings) == 1
        assert len(drafts) == 1
        assert len(approved) == 0


# --- Evidence Management ---

class TestEvidence:
    def _evidence_dir(self, manager):
        """Helper to get case evidence directory."""
        return manager.active_case_dir / "evidence"

    def test_register_evidence(self, manager, active_case):
        evidence_file = self._evidence_dir(manager) / "test_evidence.bin"
        evidence_file.write_bytes(b"malware sample content here")

        result = manager.register_evidence(str(evidence_file), "Test malware sample")
        assert result["status"] == "registered"
        assert len(result["sha256"]) == 64
        # File should be read-only
        assert not os.access(evidence_file, os.W_OK)

    def test_register_evidence_outside_case_blocked(self, manager, active_case, tmp_path):
        """Path traversal: evidence outside case directory should be rejected."""
        outside_file = tmp_path / "outside.bin"
        outside_file.write_bytes(b"sneaky")
        with pytest.raises(ValueError, match="within case directory"):
            manager.register_evidence(str(outside_file))

    def test_verify_evidence_integrity_ok(self, manager, active_case):
        evidence_file = self._evidence_dir(manager) / "evidence.bin"
        evidence_file.write_bytes(b"evidence content")
        manager.register_evidence(str(evidence_file))

        result = manager.verify_evidence_integrity()
        assert result["total"] == 1
        assert result["ok"] == 1
        assert result["files"][0]["status"] == "OK"

    def test_verify_evidence_integrity_modified(self, manager, active_case):
        evidence_file = self._evidence_dir(manager) / "evidence.bin"
        evidence_file.write_bytes(b"original content")
        manager.register_evidence(str(evidence_file))

        # Modify the file (need to make writable first)
        evidence_file.chmod(0o644)
        evidence_file.write_bytes(b"tampered content")
        evidence_file.chmod(0o444)

        result = manager.verify_evidence_integrity()
        assert result["files"][0]["status"] == "MODIFIED"

    def test_verify_evidence_integrity_missing(self, manager, active_case):
        evidence_file = self._evidence_dir(manager) / "evidence.bin"
        evidence_file.write_bytes(b"content")
        manager.register_evidence(str(evidence_file))

        # Remove the file
        evidence_file.chmod(0o644)
        evidence_file.unlink()

        result = manager.verify_evidence_integrity()
        assert result["files"][0]["status"] == "MISSING"

    def test_list_evidence(self, manager, active_case):
        ev_dir = self._evidence_dir(manager)
        f1 = ev_dir / "ev1.bin"
        f1.write_bytes(b"one")
        f2 = ev_dir / "ev2.bin"
        f2.write_bytes(b"two")

        manager.register_evidence(str(f1), "First")
        manager.register_evidence(str(f2), "Second")

        evidence = manager.list_evidence()
        assert len(evidence) == 2

    def test_evidence_access_log(self, manager, active_case):
        evidence_file = self._evidence_dir(manager) / "ev.bin"
        evidence_file.write_bytes(b"data")
        manager.register_evidence(str(evidence_file))

        log = manager.get_evidence_access_log()
        assert len(log) >= 1
        assert log[0]["action"] == "register"


# --- TODOs ---

class TestTodos:
    def test_add_todo(self, manager, active_case):
        result = manager.add_todo("Run volatility on server-04")
        assert result["status"] == "created"
        assert result["todo_id"] == "TODO-001"

    def test_add_todo_with_details(self, manager, active_case):
        result = manager.add_todo(
            "Check lateral movement",
            assignee="jane",
            priority="high",
            related_findings=["F-001"],
        )
        assert result["todo_id"] == "TODO-001"
        todos = manager.list_todos(status="all")
        assert len(todos) == 1
        assert todos[0]["assignee"] == "jane"
        assert todos[0]["priority"] == "high"
        assert todos[0]["related_findings"] == ["F-001"]

    def test_list_todos_filters(self, manager, active_case):
        manager.add_todo("Todo A", assignee="steve")
        manager.add_todo("Todo B", assignee="jane")
        manager.complete_todo("TODO-001")

        open_todos = manager.list_todos(status="open")
        assert len(open_todos) == 1
        assert open_todos[0]["todo_id"] == "tester/TODO-002"

        all_todos = manager.list_todos(status="all")
        assert len(all_todos) == 2

        jane_todos = manager.list_todos(status="all", assignee="jane")
        assert len(jane_todos) == 1

    def test_complete_todo(self, manager, active_case):
        manager.add_todo("Do something")
        result = manager.complete_todo("TODO-001")
        assert result["status"] == "updated"

        todos = manager.list_todos(status="completed")
        assert len(todos) == 1
        assert todos[0]["completed_at"] is not None

    def test_update_todo_note(self, manager, active_case):
        manager.add_todo("Investigate further")
        result = manager.update_todo("TODO-001", note="Waiting on third party")
        assert result["status"] == "updated"

        todos = manager.list_todos(status="all")
        assert len(todos[0]["notes"]) == 1
        assert todos[0]["notes"][0]["note"] == "Waiting on third party"
        assert todos[0]["notes"][0]["by"] == "tester"

    def test_update_todo_not_found(self, manager, active_case):
        result = manager.update_todo("TODO-999")
        assert result["status"] == "not_found"

    def test_case_status_includes_todos(self, manager, active_case):
        manager.add_todo("A")
        manager.add_todo("B")
        manager.complete_todo("TODO-001")

        status = manager.get_case_status()
        assert status["todos"]["total"] == 2
        assert status["todos"]["open"] == 1
        assert status["todos"]["completed"] == 1

    def test_close_case_warns_open_todos(self, manager, active_case):
        manager.add_todo("Unfinished")
        case_id = active_case["case_id"]
        result = manager.close_case(case_id)
        assert "open TODO" in result.get("warning", "")
        assert result["open_todo_ids"] == ["tester/TODO-001"]


# --- Multi-Examiner ---

class TestMultiExaminer:
    def test_finding_tracks_created_by(self, manager, active_case):
        """created_by is set from resolve_examiner() (AIIR_EXAMINER)."""
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        manager.record_finding(finding)
        findings = manager.get_findings()
        assert findings[0]["created_by"] == "tester"

    def test_finding_examiner_identity(self, manager, active_case, monkeypatch):
        """Changing AIIR_EXAMINER changes created_by identity."""
        monkeypatch.setenv("AIIR_EXAMINER", "steve")
        # Create examiner dir for steve so records can be saved
        exam_dir = Path(active_case["path"]) / "examiners" / "steve"
        exam_dir.mkdir(parents=True, exist_ok=True)
        (exam_dir / "audit").mkdir(exist_ok=True)
        for f in ("findings.json", "timeline.json", "todos.json"):
            (exam_dir / f).write_text("[]")
        (exam_dir / "evidence.json").write_text('{"files": []}')

        finding = {
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        manager.record_finding(finding)
        findings = manager.get_findings()
        steve_findings = [f for f in findings if f.get("created_by") == "steve"]
        assert len(steve_findings) == 1

    def test_timeline_tracks_created_by(self, manager, active_case):
        """Timeline events use examiner identity."""
        manager.record_timeline_event({
            "timestamp": "2026-02-20T10:00:00Z",
            "description": "Event",
        })
        timeline = manager.get_timeline()
        assert timeline[0]["created_by"] == "tester"

    def test_two_examiners_same_case(self, manager, active_case, monkeypatch):
        """Two examiners record to their own dirs; merged reads show both."""
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        # Tester records a finding
        manager.record_finding(finding)

        # Switch to alice
        monkeypatch.setenv("AIIR_EXAMINER", "alice")
        exam_dir = Path(active_case["path"]) / "examiners" / "alice"
        exam_dir.mkdir(parents=True, exist_ok=True)
        (exam_dir / "audit").mkdir(exist_ok=True)
        for f in ("findings.json", "timeline.json", "todos.json"):
            (exam_dir / f).write_text("[]")
        (exam_dir / "evidence.json").write_text('{"files": []}')

        manager.record_finding({**finding, "title": "Second"})

        # Merged read should have both
        findings = manager.get_findings()
        examiners = {f["created_by"] for f in findings}
        assert "tester" in examiners
        assert "alice" in examiners


# --- Audit ---

class TestAudit:
    def test_audit_log_empty(self, manager, active_case):
        log = manager.get_audit_log()
        assert log == []

    def test_audit_summary_empty(self, manager, active_case):
        summary = manager.get_audit_summary()
        assert summary["total_entries"] == 0


# --- Atomic Writes ---

class TestAtomicWrites:
    def test_sequential_writes_produce_valid_json(self, manager, active_case):
        """Rapid sequential writes should always produce valid JSON."""
        finding_template = {
            "title": "Finding",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        for i in range(20):
            manager.record_finding({**finding_template, "title": f"Finding {i}"})

        # After rapid writes, JSON should still be valid
        case_dir = Path(active_case["path"])
        findings_data = json.loads((case_dir / "examiners" / "tester" / "findings.json").read_text())
        assert len(findings_data) == 20
        assert all(f["title"].startswith("Finding") for f in findings_data)

    def test_atomic_write_no_partial_on_save(self, manager, active_case):
        """Verify file is never truncated/empty after write."""
        case_dir = Path(active_case["path"])
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        manager.record_finding(finding)
        # File should be non-empty and valid JSON
        content = (case_dir / "examiners" / "tester" / "findings.json").read_text()
        assert len(content) > 2
        parsed = json.loads(content)
        assert len(parsed) == 1


# --- New Examiners Directory Structure ---

class TestExaminersDirectory:
    def test_init_case_collaborative_mode(self, manager):
        """Collaborative mode sets mode=collaborative in CASE.yaml and returns collaboration_setup."""
        result = manager.init_case("Collab Case", collaborative=True)
        assert result["mode"] == "collaborative"
        assert "collaboration_setup" in result
        assert result["collaboration_setup"]["mode"] == "collaborative"

        case_dir = Path(result["path"])
        import yaml
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert meta["mode"] == "collaborative"

    def test_set_active_case_auto_joins(self, manager, active_case, monkeypatch):
        """set_active_case auto-creates examiner dir and updates team list."""
        case_id = active_case["case_id"]
        case_dir = Path(active_case["path"])

        # Switch to a new examiner
        monkeypatch.setenv("AIIR_EXAMINER", "bob")
        manager._active_case_id = None
        result = manager.set_active_case(case_id)

        assert result["joined"] is True
        assert result["examiner"] == "bob"
        assert (case_dir / "examiners" / "bob").is_dir()
        assert (case_dir / "examiners" / "bob" / "findings.json").exists()
        assert (case_dir / "examiners" / "bob" / "audit").is_dir()

        # Team list should be updated
        import yaml
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert "bob" in meta["team"]

    def test_import_rejects_non_list_findings(self, manager, active_case):
        """import_contributions rejects bundle with non-list findings."""
        bundle = {
            "schema_version": 1,
            "case_id": active_case["case_id"],
            "examiner": "alice",
            "findings": "not a list",
        }
        result = manager.import_contributions(bundle)
        assert result["status"] == "error"
        assert "must be a list" in result["message"]

    def test_import_rejects_invalid_audit_entry(self, manager, active_case):
        """import_contributions rejects audit entries missing required fields."""
        bundle = {
            "schema_version": 1,
            "case_id": active_case["case_id"],
            "examiner": "alice",
            "findings": [],
            "timeline": [],
            "audit": {"test-mcp": [{"no_ts": True}]},
        }
        result = manager.import_contributions(bundle)
        assert result["status"] == "error"
        assert "missing required" in result["message"]

    def test_import_writes_to_examiners_dir(self, manager, active_case):
        """import_contributions writes to examiners/{examiner}/ not .team/."""
        case_dir = Path(active_case["path"])
        bundle = {
            "schema_version": 1,
            "case_id": active_case["case_id"],
            "examiner": "alice",
            "findings": [{"id": "F-001", "title": "Alice finding", "examiner": "alice"}],
            "timeline": [],
            "todos": [],
            "actions_jsonl": "",
            "approvals": [],
            "audit": {},
            "evidence_manifest": [],
        }
        result = manager.import_contributions(bundle)
        assert result["status"] == "imported"
        assert result["examiner"] == "alice"

        # Verify written to examiners/alice/, NOT .team/alice/
        assert (case_dir / "examiners" / "alice" / "findings.json").exists()
        assert not (case_dir / ".team").exists()
        findings = json.loads((case_dir / "examiners" / "alice" / "findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["title"] == "Alice finding"


# --- Corrupt JSONL Resilience ---

class TestGroundingScore:
    def test_score_grounding_no_audit(self, manager, active_case):
        """No audit files → WEAK."""
        finding = {"type": "malware"}
        result = manager._score_grounding(finding)
        assert result["level"] == "WEAK"
        assert len(result["sources_consulted"]) == 0
        assert len(result["sources_missing"]) == 3

    def test_score_grounding_one_source(self, manager, active_case):
        """One MCP audit file exists → PARTIAL."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "examiners" / "tester" / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "forensic-rag-mcp.jsonl").write_text(
            '{"ts": "2026-01-01T00:00:00Z", "tool": "search"}\n'
        )
        finding = {"type": "persistence"}
        result = manager._score_grounding(finding)
        assert result["level"] == "PARTIAL"
        assert "forensic-rag-mcp" in result["sources_consulted"]
        assert "forensic-rag-mcp" not in result["sources_missing"]

    def test_score_grounding_two_sources(self, manager, active_case):
        """Two MCP audit files → STRONG (empty dict)."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "examiners" / "tester" / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "forensic-rag-mcp.jsonl").write_text(
            '{"ts": "2026-01-01T00:00:00Z", "tool": "search"}\n'
        )
        (audit_dir / "opencti-mcp.jsonl").write_text(
            '{"ts": "2026-01-01T00:00:00Z", "tool": "lookup_ioc"}\n'
        )
        finding = {"type": "malware"}
        result = manager._score_grounding(finding)
        assert result == {}

    def test_score_grounding_suggestions(self, manager, active_case):
        """WEAK with finding type → includes FK suggestions."""
        finding = {"type": "persistence"}
        result = manager._score_grounding(finding)
        assert result["level"] == "WEAK"
        # corroboration.yaml has persistence entries referencing windows-triage and forensic-rag
        if result.get("suggestions"):
            assert any("windows-triage" in s.lower() or "forensic-rag" in s.lower() for s in result["suggestions"])

    def test_score_grounding_empty_file_ignored(self, manager, active_case):
        """Empty audit file is not counted as consulted."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "examiners" / "tester" / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "forensic-rag-mcp.jsonl").write_text("")
        finding = {"type": "malware"}
        result = manager._score_grounding(finding)
        assert result["level"] == "WEAK"
        assert len(result["sources_consulted"]) == 0


class TestCorruptJsonl:
    def test_corrupt_actions_skipped(self, manager, active_case):
        """Corrupt JSONL lines in actions.jsonl are skipped, not crash."""
        case_dir = Path(active_case["path"])
        actions_file = case_dir / "examiners" / "tester" / "actions.jsonl"
        actions_file.write_text(
            '{"ts": "2026-01-01T00:00:00Z", "description": "Good"}\n'
            "NOT VALID JSON\n"
            '{"ts": "2026-01-02T00:00:00Z", "description": "Also good"}\n'
        )
        actions = manager.get_actions()
        assert len(actions) == 2

    def test_corrupt_audit_skipped(self, manager, active_case):
        """Corrupt JSONL lines in audit files are skipped."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "examiners" / "tester" / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_file = audit_dir / "test-mcp.jsonl"
        audit_file.write_text(
            '{"ts": "2026-01-01T00:00:00Z", "mcp": "test-mcp", "tool": "t1"}\n'
            "CORRUPT LINE\n"
            '{"ts": "2026-01-02T00:00:00Z", "mcp": "test-mcp", "tool": "t2"}\n'
        )
        entries = manager.get_audit_log()
        assert len(entries) == 2

    def test_corrupt_evidence_access_log_skipped(self, manager, active_case):
        """Corrupt lines in evidence_access.jsonl are skipped."""
        case_dir = Path(active_case["path"])
        log_file = case_dir / "examiners" / "tester" / "evidence_access.jsonl"
        log_file.write_text(
            '{"ts": "2026-01-01T00:00:00Z", "action": "register", "path": "/a"}\n'
            "BAD\n"
        )
        entries = manager.get_evidence_access_log()
        assert len(entries) == 1


# --- Ingest Remote Audit Validation ---

class TestIngestRemoteAudit:
    def test_rejects_traversal_mcp_name(self, manager, active_case):
        """mcp_name with path traversal characters is rejected."""
        result = manager.ingest_remote_audit("/tmp/fake.jsonl", "../evil")
        assert result["status"] == "error"
        assert "Invalid mcp_name" in result["message"]

    def test_rejects_source_outside_case(self, manager, active_case, tmp_path):
        """Source path outside case directory is rejected."""
        outside = tmp_path / "outside.jsonl"
        outside.write_text('{"ts": "2026-01-01T00:00:00Z", "tool": "t"}\n')
        result = manager.ingest_remote_audit(str(outside), "test-mcp")
        assert result["status"] == "error"
        assert "within case directory" in result["message"]

    def test_valid_ingest(self, manager, active_case):
        """Valid source within case directory is ingested."""
        case_dir = Path(active_case["path"])
        source = case_dir / "examiners" / "tester" / "audit" / "remote.jsonl"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('{"ts": "2026-01-01T00:00:00Z", "tool": "check_file", "mcp": "test"}\n')
        result = manager.ingest_remote_audit(str(source), "test-mcp")
        assert result["status"] == "ok"
        assert result["ingested"] == 1


# --- Timeline Filtering ---

class TestTimelineFiltering:
    """get_timeline() with filter parameters."""

    def _seed_events(self, manager):
        """Create 4 timeline events with varying fields."""
        events = [
            {"timestamp": "2026-01-10T08:00:00Z", "description": "Login observed", "source": "evtx"},
            {"timestamp": "2026-01-11T10:30:00Z", "description": "Malware executed", "source": "prefetch"},
            {"timestamp": "2026-01-12T14:00:00Z", "description": "Lateral movement", "source": "evtx"},
            {"timestamp": "2026-01-13T16:00:00Z", "description": "Data exfil", "source": "netflow"},
        ]
        for e in events:
            manager.record_timeline_event(e)

    def test_filter_status(self, manager, active_case):
        self._seed_events(manager)
        # All events are DRAFT
        drafts = manager.get_timeline(status="DRAFT")
        assert len(drafts) == 4
        approved = manager.get_timeline(status="APPROVED")
        assert len(approved) == 0

    def test_filter_date_range(self, manager, active_case):
        self._seed_events(manager)
        events = manager.get_timeline(start_date="2026-01-11", end_date="2026-01-12T23:59:59Z")
        assert len(events) == 2
        descriptions = {e["description"] for e in events}
        assert "Malware executed" in descriptions
        assert "Lateral movement" in descriptions

    def test_filter_source(self, manager, active_case):
        self._seed_events(manager)
        evtx_events = manager.get_timeline(source="evtx")
        assert len(evtx_events) == 2

    def test_filter_examiner(self, manager, active_case):
        self._seed_events(manager)
        # All events created by "tester"
        events = manager.get_timeline(examiner="tester")
        assert len(events) == 4
        events = manager.get_timeline(examiner="other")
        assert len(events) == 0

    def test_filter_event_type(self, manager, active_case):
        manager.record_timeline_event({
            "timestamp": "2026-01-10T08:00:00Z",
            "description": "Process launch",
            "event_type": "execution",
        })
        manager.record_timeline_event({
            "timestamp": "2026-01-10T09:00:00Z",
            "description": "File write",
            "event_type": "file",
        })
        events = manager.get_timeline(event_type="execution")
        assert len(events) == 1
        assert events[0]["description"] == "Process launch"

    def test_no_filters_returns_all(self, manager, active_case):
        self._seed_events(manager)
        assert len(manager.get_timeline()) == 4


# --- Timeline Optional Fields ---

class TestTimelineOptionalFields:
    """Optional fields pass through via **event spread."""

    def test_related_findings(self, manager, active_case):
        result = manager.record_timeline_event({
            "timestamp": "2026-01-10T08:00:00Z",
            "description": "Suspicious login",
            "related_findings": ["F-001", "F-003"],
        })
        assert result["status"] == "STAGED"
        events = manager.get_timeline()
        assert events[0]["related_findings"] == ["F-001", "F-003"]

    def test_event_type(self, manager, active_case):
        manager.record_timeline_event({
            "timestamp": "2026-01-10T08:00:00Z",
            "description": "Process launch",
            "event_type": "execution",
        })
        events = manager.get_timeline()
        assert events[0]["event_type"] == "execution"

    def test_artifact_ref(self, manager, active_case):
        manager.record_timeline_event({
            "timestamp": "2026-01-10T08:00:00Z",
            "description": "Prefetch entry",
            "artifact_ref": "prefetch:EVIL.EXE-ABCD1234",
        })
        events = manager.get_timeline()
        assert events[0]["artifact_ref"] == "prefetch:EVIL.EXE-ABCD1234"


# --- Phase B: Defense-in-Depth (dict spread override) ---

class TestProtectedFieldOverride:
    """Verify that user-supplied protected fields are stripped and overwritten."""

    def test_status_override_blocked(self, manager, active_case):
        """User-supplied status='APPROVED' must be overwritten to DRAFT."""
        finding = {
            "title": "Injected status",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
            "status": "APPROVED",
            "id": "INJECTED",
            "examiner": "evil",
        }
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        assert result["finding_id"] == "F-001"

        # Read the raw persisted data and verify protected fields were overwritten
        findings = manager.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f["status"] == "DRAFT"
        assert f["id"].endswith("F-001")
        assert f["examiner"] == "tester"
        assert f["created_by"] == "tester"
        # User-supplied values must not leak through
        assert f["examiner"] != "evil"
        assert f["status"] != "APPROVED"

    def test_timeline_event_override_blocked(self, manager, active_case):
        """User-supplied protected fields on timeline events are also stripped."""
        event = {
            "timestamp": "2026-02-20T10:00:00Z",
            "description": "Injected event",
            "status": "APPROVED",
            "id": "INJECTED",
            "examiner": "evil",
        }
        result = manager.record_timeline_event(event)
        assert result["status"] == "STAGED"

        events = manager.get_timeline()
        assert len(events) == 1
        e = events[0]
        assert e["status"] == "DRAFT"
        assert e["id"].endswith("T-001")
        assert e["examiner"] == "tester"
        assert e["status"] != "APPROVED"
        assert e["examiner"] != "evil"


# --- Phase B: examiner_override propagation ---

class TestExaminerOverride:
    """Verify that examiner_override propagates identity into record metadata.

    Note: examiner_override affects metadata fields (examiner, created_by) but
    the data is stored in the current examiner's directory (self.examiner).
    The override is used by the gateway to tag records with the API caller's
    identity without changing which directory files are written to.
    """

    def test_finding_examiner_override(self, manager, active_case):
        """record_finding with examiner_override='alice' sets examiner and created_by to alice."""
        finding = {
            "title": "Alice finding",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        result = manager.record_finding(finding, examiner_override="alice")
        assert result["status"] == "STAGED"

        # Data is stored in current examiner's dir (tester), but metadata says alice
        case_dir = Path(active_case["path"])
        tester_findings = json.loads(
            (case_dir / "examiners" / "tester" / "findings.json").read_text()
        )
        assert len(tester_findings) == 1
        assert tester_findings[0]["examiner"] == "alice"
        assert tester_findings[0]["created_by"] == "alice"

    def test_timeline_examiner_override(self, manager, active_case):
        """record_timeline_event with examiner_override='alice' sets examiner and created_by."""
        event = {
            "timestamp": "2026-02-20T10:00:00Z",
            "description": "Alice event",
        }
        result = manager.record_timeline_event(event, examiner_override="alice")
        assert result["status"] == "STAGED"

        case_dir = Path(active_case["path"])
        tester_timeline = json.loads(
            (case_dir / "examiners" / "tester" / "timeline.json").read_text()
        )
        assert len(tester_timeline) == 1
        assert tester_timeline[0]["examiner"] == "alice"
        assert tester_timeline[0]["created_by"] == "alice"

    def test_action_examiner_override(self, manager, active_case):
        """record_action with examiner_override='alice' writes action with alice identity."""
        result = manager.record_action("Alice checked something", examiner_override="alice")
        assert result["status"] == "recorded"

        # record_action writes to examiner_dir(case_dir, override) — alice's dir
        case_dir = Path(active_case["path"])
        alice_dir = case_dir / "examiners" / "alice"
        actions_file = alice_dir / "actions.jsonl"
        assert actions_file.exists()
        entry = json.loads(actions_file.read_text().strip())
        assert entry["examiner"] == "alice"

