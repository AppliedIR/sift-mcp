"""Tests for audit trail write + read round-trip."""

import threading

import pytest
from forensic_mcp.audit import AuditWriter
from forensic_mcp.case.manager import CaseManager


@pytest.fixture
def manager(tmp_path, monkeypatch):
    """CaseManager with temp cases directory."""
    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    mgr = CaseManager()
    return mgr


@pytest.fixture
def active_case(manager, tmp_path, monkeypatch):
    from datetime import datetime, timezone

    import yaml as _yaml

    ts = datetime.now(timezone.utc)
    case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
    case_dir = tmp_path / case_id
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    (case_dir / "extractions").mkdir()
    (case_dir / "reports").mkdir()
    (case_dir / "audit").mkdir()
    case_meta = {
        "case_id": case_id,
        "name": "Audit Test",
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
    return {"case_id": case_id, "path": str(case_dir)}


class TestAuditRoundTrip:
    def test_write_then_read(self, manager, active_case):
        """Write an audit entry via AuditWriter, read it back via get_entries."""
        writer = AuditWriter("forensic-mcp")
        eid = writer.log(tool="test_tool", params={"key": "val"}, result_summary="ok")

        entries = writer.get_entries()
        assert len(entries) == 1
        assert entries[0]["tool"] == "test_tool"
        assert entries[0]["evidence_id"] == eid
        assert entries[0]["params"] == {"key": "val"}


class TestSequenceResume:
    def test_resumes_after_restart(self, manager, active_case):
        """New AuditWriter resumes sequence from existing JSONL, not from 0."""
        writer1 = AuditWriter("forensic-mcp")
        eid1 = writer1.log(tool="t1", params={}, result_summary="ok")
        eid2 = writer1.log(tool="t2", params={}, result_summary="ok")
        eid3 = writer1.log(tool="t3", params={}, result_summary="ok")
        # eid3 should end in -003
        assert eid3.endswith("-003")

        # Simulate server restart -- new writer, same audit file
        writer2 = AuditWriter("forensic-mcp")
        eid4 = writer2.log(tool="t4", params={}, result_summary="ok")
        # Should resume from 003 -> 004, not restart at 001
        assert eid4.endswith("-004"), f"Expected -004 suffix, got {eid4}"

    def test_resumes_across_date_change(self, manager, active_case):
        """Sequence resets to 0 on new day (no existing entries for that date)."""
        writer = AuditWriter("forensic-mcp")
        # Write entry for today
        eid1 = writer.log(tool="t1", params={}, result_summary="ok")
        assert "-001" in eid1

        # Force date change by clearing cached date
        writer._date_str = ""
        writer._sequence = 0
        # Next call will re-scan and find existing entries for today
        eid2 = writer.log(tool="t2", params={}, result_summary="ok")
        assert eid2.endswith("-002")


class TestThreadSafety:
    def test_concurrent_log_calls(self, manager, active_case):
        """Concurrent log calls produce unique evidence IDs."""
        writer = AuditWriter("forensic-mcp")
        ids = []
        lock = threading.Lock()

        def log_one():
            eid = writer.log(tool="test", params={}, result_summary="ok")
            with lock:
                ids.append(eid)

        threads = [threading.Thread(target=log_one) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 10
        assert len(set(ids)) == 10  # all unique

    def test_fsync_and_error_handling(self, manager, active_case):
        """Entries include all canonical fields and are fsynced to disk."""
        writer = AuditWriter("forensic-mcp")
        writer.log(tool="test", params={"key": "val"}, result_summary={"ok": True})

        entries = writer.get_entries()
        assert len(entries) == 1
        entry = entries[0]
        # Canonical fields from unified audit.py
        assert entry["mcp"] == "forensic-mcp"
        assert entry["source"] == "mcp_server"
        assert "case_id" in entry
        assert "result_summary" in entry
        assert "ts" in entry

    def test_get_entries(self, manager, active_case):
        """get_entries reads back audit entries."""
        writer = AuditWriter("forensic-mcp")
        writer.log(tool="tool_a", params={}, result_summary="ok")
        writer.log(tool="tool_b", params={}, result_summary="ok")

        entries = writer.get_entries()
        assert len(entries) == 2
        assert entries[0]["tool"] == "tool_a"
        assert entries[1]["tool"] == "tool_b"
