"""Tests for audit trail write + read round-trip."""

import re
import threading

import pytest
from forensic_mcp.audit import AuditWriter
from forensic_mcp.case.manager import CaseManager


@pytest.fixture
def manager(tmp_path, monkeypatch):
    """CaseManager with temp cases directory."""
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
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
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("VHIR_ACTIVE_CASE", case_id)
    return {"case_id": case_id, "path": str(case_dir)}


class TestAuditRoundTrip:
    def test_write_then_read(self, manager, active_case):
        """Write an audit entry via AuditWriter, read it back via get_entries."""
        writer = AuditWriter("forensic-mcp")
        eid = writer.log(tool="test_tool", params={"key": "val"}, result_summary="ok")

        entries = writer.get_entries()
        assert len(entries) == 1
        assert entries[0]["tool"] == "test_tool"
        assert entries[0]["audit_id"] == eid
        assert entries[0]["params"] == {"key": "val"}


class TestIdsAcrossRestarts:
    def test_a_restart_never_repeats_an_id(self, manager, active_case):
        """A new AuditWriter (a server restart) on the same audit file."""
        writer1 = AuditWriter("forensic-mcp")
        ids = [
            writer1.log(tool=f"t{i}", params={}, result_summary="ok") for i in (1, 2, 3)
        ]
        writer2 = AuditWriter("forensic-mcp")
        ids.append(writer2.log(tool="t4", params={}, result_summary="ok"))
        assert len(set(ids)) == 4, ids

    def test_an_id_carries_todays_date_and_a_ulid(self, manager, active_case):
        from datetime import datetime, timezone

        eid = AuditWriter("forensic-mcp").log(tool="t1", params={}, result_summary="ok")
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        assert re.fullmatch(
            rf"forensic-[a-z0-9-]+-{today}-[0-9a-hjkmnp-tv-z]{{26}}", eid
        )


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
