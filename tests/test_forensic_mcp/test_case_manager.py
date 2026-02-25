"""Tests for CaseManager: lifecycle, findings, timeline, todos."""

import json
import os
from pathlib import Path

import pytest
import yaml as _yaml
from forensic_mcp.case.manager import CaseManager


def _seed_audit_entries(audit_dir: Path) -> None:
    """Write audit entries for evidence IDs used across tests.

    This ensures record_finding() passes the provenance hard gate.
    """
    entries = [
        {"evidence_id": "ev-tester-20260225-001", "tool": "test", "ts": "2026-01-01T00:00:00Z"},
        {"evidence_id": "ev-tester-20260225-002", "tool": "test", "ts": "2026-01-01T00:00:00Z"},
        {"evidence_id": "ev-tester-20260225-003", "tool": "test", "ts": "2026-01-01T00:00:00Z"},
        {"evidence_id": "wt-tester-20260219-001", "tool": "test", "ts": "2026-02-19T00:00:00Z"},
        {"evidence_id": "wt-tester-20260219-001", "tool": "test", "ts": "2026-02-19T00:00:00Z"},
        {"evidence_id": "rag-tester-20260219-002", "tool": "test", "ts": "2026-02-19T00:00:00Z"},
    ]
    with open(audit_dir / "test-fixtures.jsonl", "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


@pytest.fixture
def manager(tmp_path, monkeypatch):
    """CaseManager with temp cases directory."""
    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
    monkeypatch.delenv("AIIR_ACTIVE_CASE", raising=False)
    # Isolate from real ~/.aiir/active_case
    monkeypatch.setenv("HOME", str(tmp_path))
    mgr = CaseManager()
    return mgr


@pytest.fixture
def active_case(manager, tmp_path, monkeypatch):
    """Manager with a manually created case directory."""
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc)
    case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
    case_dir = tmp_path / case_id
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    (case_dir / "extractions").mkdir()
    (case_dir / "reports").mkdir()
    audit_dir = case_dir / "audit"
    audit_dir.mkdir()
    _seed_audit_entries(audit_dir)
    case_meta = {
        "case_id": case_id,
        "name": "Test Incident",
        "description": "Testing the case manager",
        "status": "open",
        "examiner": "tester",
        "created": ts.isoformat(),
    }
    (case_dir / "CASE.yaml").write_text(_yaml.dump(case_meta, default_flow_style=False))
    (case_dir / "findings.json").write_text("[]")
    (case_dir / "timeline.json").write_text("[]")
    (case_dir / "todos.json").write_text("[]")
    (case_dir / "evidence.json").write_text('{"files": []}')
    manager._active_case_id = case_id
    manager._active_case_path = case_dir
    monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("AIIR_ACTIVE_CASE", case_id)
    return {
        "case_id": case_id,
        "path": str(case_dir),
        "status": "open",
        "examiner": "tester",
    }


# --- Case Lifecycle ---


class TestCaseLifecycle:
    def test_get_case_status(self, manager, active_case):
        result = manager.get_case_status()
        assert result["case_id"] == active_case["case_id"]
        assert result["status"] == "open"
        assert result["findings"]["total"] == 0
        assert result["timeline_events"] == 0

    def test_list_cases(self, manager, tmp_path):
        case_id = "INC-2026-0101000000"
        case_dir = tmp_path / case_id
        case_dir.mkdir()
        meta = {
            "case_id": case_id,
            "name": "Case One",
            "status": "open",
            "created": "2026-01-01T00:00:00",
            "examiner": "tester",
        }
        (case_dir / "CASE.yaml").write_text(_yaml.dump(meta, default_flow_style=False))
        result = manager.list_cases()
        assert len(result) >= 1
        assert result[0]["name"] == "Case One"

    def test_require_active_case_raises(self, manager):
        with pytest.raises(ValueError, match="No active case"):
            manager._require_active_case()

    def test_init_reads_active_case_from_env(self, tmp_path, monkeypatch):
        """AIIR_ACTIVE_CASE env var activates an existing case on __init__."""
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        # Create a case directory manually
        case_id = "INC-2026-0223120000"
        case_dir = tmp_path / case_id
        case_dir.mkdir()
        monkeypatch.setenv("AIIR_ACTIVE_CASE", case_id)
        mgr = CaseManager()
        assert mgr._active_case_id == case_id
        assert os.environ.get("AIIR_CASE_DIR") == str(case_dir)

    def test_init_ignores_missing_case_dir(self, tmp_path, monkeypatch):
        """AIIR_ACTIVE_CASE pointing to non-existent dir is ignored."""
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_ACTIVE_CASE", "INC-NONEXISTENT")
        mgr = CaseManager()
        assert mgr._active_case_id is None

    def test_init_ignores_invalid_case_id(self, tmp_path, monkeypatch):
        """AIIR_ACTIVE_CASE with path traversal is rejected."""
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_ACTIVE_CASE", "../etc/passwd")
        mgr = CaseManager()
        assert mgr._active_case_id is None


# --- Investigation Records ---


class TestRecords:
    def test_record_action_writes_jsonl(self, manager, active_case):
        result = manager.record_action(
            "Checked process list", tool="ps", command="ps aux"
        )
        assert result["status"] == "recorded"
        actions_file = Path(active_case["path"]) / "actions.jsonl"
        assert actions_file.exists()
        entry = json.loads(actions_file.read_text().strip())
        assert entry["description"] == "Checked process list"
        assert entry["tool"] == "ps"
        assert entry["command"] == "ps aux"

    def test_record_finding_valid(self, manager, active_case):
        finding = {
            "title": "Suspicious process",
            "evidence_ids": ["wt-tester-20260219-001"],
            "observation": "svchost.exe spawned from cmd.exe",
            "interpretation": "Unusual parent-child relationship",
            "confidence": "MEDIUM",
            "confidence_justification": "Single evidence source",
            "type": "finding",
        }
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        assert result["finding_id"] == "F-tester-001"

    def test_record_finding_assigns_sequential_ids(self, manager, active_case):
        finding = {
            "title": "Finding",
            "evidence_ids": ["ev-tester-20260225-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        r1 = manager.record_finding(finding)
        r2 = manager.record_finding({**finding, "title": "Second"})
        assert r1["finding_id"] == "F-tester-001"
        assert r2["finding_id"] == "F-tester-002"

    def test_record_finding_invalid(self, manager, active_case):
        result = manager.record_finding({"title": "Missing fields"})
        assert result["status"] == "VALIDATION_FAILED"
        assert len(result["errors"]) > 0

    def test_record_finding_no_md(self, manager, active_case):
        manager.record_finding(
            {
                "title": "Test Finding",
                "evidence_ids": ["ev-tester-20260225-001"],
                "observation": "obs",
                "interpretation": "interp",
                "confidence": "MEDIUM",
                "confidence_justification": "justified",
                "type": "finding",
            }
        )
        assert not (Path(active_case["path"]) / "FINDINGS.md").exists()
        # Data is in JSON at case root
        findings = json.loads((Path(active_case["path"]) / "findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["title"] == "Test Finding"

    def test_record_timeline_event(self, manager, active_case):
        result = manager.record_timeline_event(
            {
                "timestamp": "2026-02-19T10:30:00Z",
                "description": "First lateral movement detected",
            }
        )
        assert result["status"] == "STAGED"
        assert result["event_id"] == "T-tester-001"

    def test_record_timeline_event_no_md(self, manager, active_case):
        manager.record_timeline_event(
            {
                "timestamp": "2026-02-19T10:30:00Z",
                "description": "First lateral movement detected",
            }
        )
        assert not (Path(active_case["path"]) / "TIMELINE.md").exists()
        timeline = json.loads((Path(active_case["path"]) / "timeline.json").read_text())
        assert len(timeline) == 1
        assert timeline[0]["description"] == "First lateral movement detected"

    def test_record_timeline_event_stores_evidence(self, manager, active_case):
        manager.record_timeline_event(
            {
                "timestamp": "2026-02-19T11:00:00Z",
                "description": "Credential dumping observed",
                "evidence_ids": ["wt-tester-20260219-001", "rag-tester-20260219-002"],
                "source": "Memory analysis",
            }
        )
        timeline = json.loads((Path(active_case["path"]) / "timeline.json").read_text())
        assert "wt-tester-20260219-001" in timeline[0]["evidence_ids"]
        assert timeline[0]["source"] == "Memory analysis"

    def test_record_timeline_event_missing_fields(self, manager, active_case):
        result = manager.record_timeline_event({})
        assert result["status"] == "VALIDATION_FAILED"

    def test_get_findings_filter(self, manager, active_case):
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-tester-20260225-001"],
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


# --- TODOs ---


class TestTodos:
    def test_add_todo(self, manager, active_case):
        result = manager.add_todo("Run volatility on server-04")
        assert result["status"] == "created"
        assert result["todo_id"] == "TODO-tester-001"

    def test_add_todo_with_details(self, manager, active_case):
        result = manager.add_todo(
            "Check lateral movement",
            assignee="jane",
            priority="high",
            related_findings=["F-tester-001"],
        )
        assert result["todo_id"] == "TODO-tester-001"
        todos = manager.list_todos(status="all")
        assert len(todos) == 1
        assert todos[0]["assignee"] == "jane"
        assert todos[0]["priority"] == "high"
        assert todos[0]["related_findings"] == ["F-tester-001"]

    def test_list_todos_filters(self, manager, active_case):
        manager.add_todo("Todo A", assignee="steve")
        manager.add_todo("Todo B", assignee="jane")
        manager.complete_todo("TODO-tester-001")

        open_todos = manager.list_todos(status="open")
        assert len(open_todos) == 1
        assert open_todos[0]["todo_id"] == "TODO-tester-002"

        all_todos = manager.list_todos(status="all")
        assert len(all_todos) == 2

        jane_todos = manager.list_todos(status="all", assignee="jane")
        assert len(jane_todos) == 1

    def test_complete_todo(self, manager, active_case):
        manager.add_todo("Do something")
        result = manager.complete_todo("TODO-tester-001")
        assert result["status"] == "updated"

        todos = manager.list_todos(status="completed")
        assert len(todos) == 1
        assert todos[0]["completed_at"] is not None

    def test_update_todo_note(self, manager, active_case):
        manager.add_todo("Investigate further")
        result = manager.update_todo("TODO-tester-001", note="Waiting on third party")
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
        manager.complete_todo("TODO-tester-001")

        status = manager.get_case_status()
        assert status["todos"]["total"] == 2
        assert status["todos"]["open"] == 1
        assert status["todos"]["completed"] == 1


# --- Multi-Examiner ---


class TestMultiExaminer:
    def test_finding_tracks_created_by(self, manager, active_case):
        """created_by is set from resolve_examiner() (AIIR_EXAMINER)."""
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-tester-20260225-001"],
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

        finding = {
            "title": "Test",
            "evidence_ids": ["ev-tester-20260225-001"],
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
        manager.record_timeline_event(
            {
                "timestamp": "2026-02-20T10:00:00Z",
                "description": "Event",
            }
        )
        timeline = manager.get_timeline()
        assert timeline[0]["created_by"] == "tester"

    def test_two_examiners_same_case(self, manager, active_case, monkeypatch):
        """Two examiners record to same flat files; reads show both."""
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-tester-20260225-001"],
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
        manager.record_finding({**finding, "title": "Second"})

        # Both should be in the same findings.json
        findings = manager.get_findings()
        examiners = {f["created_by"] for f in findings}
        assert "tester" in examiners
        assert "alice" in examiners


# --- Atomic Writes ---


class TestAtomicWrites:
    def test_sequential_writes_produce_valid_json(self, manager, active_case):
        """Rapid sequential writes should always produce valid JSON."""
        finding_template = {
            "title": "Finding",
            "evidence_ids": ["ev-tester-20260225-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        for i in range(20):
            manager.record_finding({**finding_template, "title": f"Finding {i}"})

        # After rapid writes, JSON should still be valid (flat case root)
        case_dir = Path(active_case["path"])
        findings_data = json.loads((case_dir / "findings.json").read_text())
        assert len(findings_data) == 20
        assert all(f["title"].startswith("Finding") for f in findings_data)

    def test_atomic_write_no_partial_on_save(self, manager, active_case):
        """Verify file is never truncated/empty after write."""
        case_dir = Path(active_case["path"])
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-tester-20260225-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        manager.record_finding(finding)
        # File should be non-empty and valid JSON
        content = (case_dir / "findings.json").read_text()
        assert len(content) > 2
        parsed = json.loads(content)
        assert len(parsed) == 1


# --- Grounding Score ---


class TestGroundingScore:
    def test_score_grounding_no_audit(self, manager, active_case):
        """No audit files -> WEAK."""
        finding = {"type": "malware"}
        result = manager._score_grounding(finding)
        assert result["level"] == "WEAK"
        assert len(result["sources_consulted"]) == 0
        assert len(result["sources_missing"]) == 3

    def test_score_grounding_one_source(self, manager, active_case):
        """One MCP audit file exists -> PARTIAL."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
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
        """Two MCP audit files -> STRONG (empty dict)."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
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
        """WEAK with finding type -> includes FK suggestions."""
        finding = {"type": "persistence"}
        result = manager._score_grounding(finding)
        assert result["level"] == "WEAK"
        # corroboration.yaml has persistence entries referencing windows-triage and forensic-rag
        if result.get("suggestions"):
            assert any(
                "windows-triage" in s.lower() or "forensic-rag" in s.lower()
                for s in result["suggestions"]
            )

    def test_score_grounding_empty_file_ignored(self, manager, active_case):
        """Empty audit file is not counted as consulted."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "forensic-rag-mcp.jsonl").write_text("")
        finding = {"type": "malware"}
        result = manager._score_grounding(finding)
        assert result["level"] == "WEAK"
        assert len(result["sources_consulted"]) == 0


# --- Corrupt JSONL Resilience ---


class TestCorruptJsonl:
    def test_corrupt_actions_skipped(self, manager, active_case):
        """Corrupt JSONL lines in actions.jsonl are skipped, not crash."""
        case_dir = Path(active_case["path"])
        actions_file = case_dir / "actions.jsonl"
        actions_file.write_text(
            '{"ts": "2026-01-01T00:00:00Z", "description": "Good"}\n'
            "NOT VALID JSON\n"
            '{"ts": "2026-01-02T00:00:00Z", "description": "Also good"}\n'
        )
        actions = manager.get_actions()
        assert len(actions) == 2


# --- Timeline Filtering ---


class TestTimelineFiltering:
    """get_timeline() with filter parameters."""

    def _seed_events(self, manager):
        """Create 4 timeline events with varying fields."""
        events = [
            {
                "timestamp": "2026-01-10T08:00:00Z",
                "description": "Login observed",
                "source": "evtx",
            },
            {
                "timestamp": "2026-01-11T10:30:00Z",
                "description": "Malware executed",
                "source": "prefetch",
            },
            {
                "timestamp": "2026-01-12T14:00:00Z",
                "description": "Lateral movement",
                "source": "evtx",
            },
            {
                "timestamp": "2026-01-13T16:00:00Z",
                "description": "Data exfil",
                "source": "netflow",
            },
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
        events = manager.get_timeline(
            start_date="2026-01-11", end_date="2026-01-12T23:59:59Z"
        )
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
        manager.record_timeline_event(
            {
                "timestamp": "2026-01-10T08:00:00Z",
                "description": "Process launch",
                "event_type": "execution",
            }
        )
        manager.record_timeline_event(
            {
                "timestamp": "2026-01-10T09:00:00Z",
                "description": "File write",
                "event_type": "file",
            }
        )
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
        result = manager.record_timeline_event(
            {
                "timestamp": "2026-01-10T08:00:00Z",
                "description": "Suspicious login",
                "related_findings": ["F-tester-001", "F-tester-003"],
            }
        )
        assert result["status"] == "STAGED"
        events = manager.get_timeline()
        assert events[0]["related_findings"] == ["F-tester-001", "F-tester-003"]

    def test_event_type(self, manager, active_case):
        manager.record_timeline_event(
            {
                "timestamp": "2026-01-10T08:00:00Z",
                "description": "Process launch",
                "event_type": "execution",
            }
        )
        events = manager.get_timeline()
        assert events[0]["event_type"] == "execution"

    def test_artifact_ref(self, manager, active_case):
        manager.record_timeline_event(
            {
                "timestamp": "2026-01-10T08:00:00Z",
                "description": "Prefetch entry",
                "artifact_ref": "prefetch:EVIL.EXE-ABCD1234",
            }
        )
        events = manager.get_timeline()
        assert events[0]["artifact_ref"] == "prefetch:EVIL.EXE-ABCD1234"


# --- Phase B: Defense-in-Depth (dict spread override) ---


class TestProtectedFieldOverride:
    """Verify that user-supplied protected fields are stripped and overwritten."""

    def test_status_override_blocked(self, manager, active_case):
        """User-supplied status='APPROVED' must be overwritten to DRAFT."""
        finding = {
            "title": "Injected status",
            "evidence_ids": ["ev-tester-20260225-001"],
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
        assert result["finding_id"] == "F-tester-001"

        # Read the raw persisted data and verify protected fields were overwritten
        findings = manager.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f["status"] == "DRAFT"
        assert f["id"] == "F-tester-001"
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
        assert e["id"] == "T-tester-001"
        assert e["examiner"] == "tester"
        assert e["status"] != "APPROVED"
        assert e["examiner"] != "evil"


# --- Phase B: examiner_override propagation ---


class TestExaminerOverride:
    """Verify that examiner_override propagates identity into record metadata.

    Note: examiner_override affects metadata fields (examiner, created_by).
    With flat directory structure, data is stored in the same case root files.
    The override is used by the gateway to tag records with the API caller's
    identity.
    """

    def test_finding_examiner_override(self, manager, active_case):
        """record_finding with examiner_override='alice' sets examiner and created_by to alice."""
        finding = {
            "title": "Alice finding",
            "evidence_ids": ["ev-tester-20260225-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        result = manager.record_finding(finding, examiner_override="alice")
        assert result["status"] == "STAGED"

        # Data is stored in case root findings.json, but metadata says alice
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["examiner"] == "alice"
        assert findings[0]["created_by"] == "alice"

    def test_timeline_examiner_override(self, manager, active_case):
        """record_timeline_event with examiner_override='alice' sets examiner and created_by."""
        event = {
            "timestamp": "2026-02-20T10:00:00Z",
            "description": "Alice event",
        }
        result = manager.record_timeline_event(event, examiner_override="alice")
        assert result["status"] == "STAGED"

        case_dir = Path(active_case["path"])
        timeline = json.loads((case_dir / "timeline.json").read_text())
        assert len(timeline) == 1
        assert timeline[0]["examiner"] == "alice"
        assert timeline[0]["created_by"] == "alice"

    def test_action_examiner_override(self, manager, active_case):
        """record_action with examiner_override='alice' writes action with alice identity."""
        result = manager.record_action(
            "Alice checked something", examiner_override="alice"
        )
        assert result["status"] == "recorded"

        case_dir = Path(active_case["path"])
        actions_file = case_dir / "actions.jsonl"
        assert actions_file.exists()
        entry = json.loads(actions_file.read_text().strip())
        assert entry["examiner"] == "alice"
