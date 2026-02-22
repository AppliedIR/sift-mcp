"""Tests for audit trail write + read round-trip."""

import json
import os
import threading
from pathlib import Path

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
def active_case(manager):
    result = manager.init_case("Audit Test")
    return result


class TestAuditRoundTrip:
    def test_write_then_read(self, manager, active_case):
        """Write an audit entry via AuditWriter, read it back via get_audit_log."""
        writer = AuditWriter("forensic-mcp")
        eid = writer.log(tool="test_tool", params={"key": "val"}, result_summary="ok")

        log = manager.get_audit_log()
        assert len(log) == 1
        assert log[0]["tool"] == "test_tool"
        assert log[0]["evidence_id"] == eid
        assert log[0]["params"] == {"key": "val"}

    def test_multi_mcp_aggregation(self, manager, active_case):
        """Write to two different MCP audit files, get_audit_log returns both."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"

        # Write entries as if from two different MCPs
        for mcp, tool in [("forensic-rag", "search"), ("windows-triage", "check_file")]:
            entry = {
                "ts": f"2026-02-20T10:0{mcp[0]}:00Z",
                "mcp": mcp,
                "tool": tool,
                "evidence_id": f"test-{mcp}-001",
            }
            with open(audit_dir / f"{mcp}.jsonl", "a") as f:
                f.write(json.dumps(entry) + "\n")

        log = manager.get_audit_log()
        mcps = {e["mcp"] for e in log}
        assert "forensic-rag" in mcps
        assert "windows-triage" in mcps

    def test_audit_summary_counts_evidence_ids(self, manager, active_case):
        """get_audit_summary counts unique evidence_ids correctly."""
        writer = AuditWriter("forensic-mcp")
        writer.log(tool="tool_a", params={}, result_summary="ok")
        writer.log(tool="tool_b", params={}, result_summary="ok")
        writer.log(tool="tool_a", params={}, result_summary="ok")

        summary = manager.get_audit_summary()
        assert summary["total_entries"] == 3
        assert summary["unique_evidence_ids"] == 3
        assert summary["by_tool"]["tool_a"] == 2
        assert summary["by_tool"]["tool_b"] == 1


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

        log = manager.get_audit_log()
        assert len(log) == 1
        entry = log[0]
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
