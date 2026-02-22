"""Tests for sift_mcp.response — envelope builder with FK enrichment."""

import pytest
from sift_mcp.response import build_response, reset_call_counter, DISCIPLINE_REMINDERS


@pytest.fixture(autouse=True)
def reset_counter():
    reset_call_counter()
    yield
    reset_call_counter()


class TestBuildResponse:
    def test_basic_response(self):
        resp = build_response(
            tool_name="test_tool",
            success=True,
            data={"output": "test"},
            evidence_id="sift-20260220-001",
        )
        assert resp["success"] is True
        assert resp["tool"] == "test_tool"
        assert resp["evidence_id"] == "sift-20260220-001"
        assert "discipline_reminder" in resp

    def test_error_response(self):
        resp = build_response(
            tool_name="test_tool",
            success=False,
            data=None,
            evidence_id="sift-20260220-002",
            error="Tool not found",
        )
        assert resp["success"] is False
        assert resp["error"] == "Tool not found"

    def test_metadata_included(self):
        resp = build_response(
            tool_name="test_tool",
            success=True,
            data={},
            evidence_id="sift-20260220-003",
            elapsed_seconds=2.345,
            exit_code=0,
            command=["echo", "hello"],
        )
        assert resp["metadata"]["elapsed_seconds"] == 2.35
        assert resp["metadata"]["exit_code"] == 0
        assert resp["metadata"]["command"] == ["echo", "hello"]


class TestKnowledgeEnrichment:
    def test_amcacheparser_enrichment(self):
        """AmcacheParser should get caveats from FK tool + artifact data."""
        resp = build_response(
            tool_name="run_amcacheparser",
            success=True,
            data={"rows": []},
            evidence_id="sift-20260220-010",
            fk_tool_name="AmcacheParser",
        )
        assert "caveats" in resp
        assert len(resp["caveats"]) >= 1
        assert "advisories" in resp
        # Should include does_not_prove advisories from amcache artifact
        advisories_text = " ".join(resp["advisories"])
        assert "executed" in advisories_text.lower()

    def test_corroboration_included(self):
        resp = build_response(
            tool_name="run_amcacheparser",
            success=True,
            data={},
            evidence_id="sift-20260220-011",
            fk_tool_name="AmcacheParser",
        )
        assert "corroboration" in resp
        assert "for_execution" in resp["corroboration"]

    def test_field_notes_included(self):
        resp = build_response(
            tool_name="run_amcacheparser",
            success=True,
            data={},
            evidence_id="sift-20260220-012",
            fk_tool_name="AmcacheParser",
        )
        assert "field_notes" in resp
        assert "FileKeyLastWriteTimestamp" in resp["field_notes"]

    def test_cross_mcp_checks_included(self):
        """Response envelope should include cross_mcp_checks when artifact has them."""
        resp = build_response(
            tool_name="run_amcacheparser",
            success=True,
            data={},
            evidence_id="sift-20260220-030",
            fk_tool_name="AmcacheParser",
        )
        # AmcacheParser parses amcache artifact, which should have cross_mcp_checks
        assert "cross_mcp_checks" in resp
        checks = resp["cross_mcp_checks"]
        assert len(checks) >= 1
        # Each check has mcp, tool, when
        for check in checks:
            assert "mcp" in check
            assert "tool" in check
            assert "when" in check

    def test_unknown_tool_no_enrichment(self):
        resp = build_response(
            tool_name="unknown_tool",
            success=True,
            data={},
            evidence_id="sift-20260220-020",
        )
        # Should still work, just without enrichment
        assert resp["success"] is True
        assert "caveats" not in resp


class TestDisciplineReminders:
    def test_reminders_rotate(self):
        reminders = []
        for i in range(10):
            resp = build_response(
                tool_name="test",
                success=True,
                data={},
                evidence_id=f"sift-20260220-{100+i:03d}",
            )
            reminders.append(resp["discipline_reminder"])

        # Should cycle through all 10
        assert len(set(reminders)) == 10

    def test_reminder_wraps_around(self):
        # Make 11 calls — should wrap
        for i in range(11):
            resp = build_response(
                tool_name="test",
                success=True,
                data={},
                evidence_id=f"sift-20260220-{200+i:03d}",
            )
        # 11th call (counter=11) → index 1 (11 % 10)
        assert resp["discipline_reminder"] == DISCIPLINE_REMINDERS[1]


class TestAudit:
    def test_audit_writes_to_case_dir(self, tmp_path, monkeypatch):
        from sift_mcp.audit import AuditWriter
        import json

        case_dir = tmp_path / "test-case"
        case_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")

        writer = AuditWriter("sift-mcp")
        eid = writer.log(tool="test_tool", params={"x": 1}, result_summary={"ok": True})

        assert eid.startswith("sift-")
        log_file = case_dir / "audit" / "sift-mcp.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["tool"] == "test_tool"
        assert entry["evidence_id"] == eid

    def test_audit_no_case_dir(self, monkeypatch):
        from sift_mcp.audit import AuditWriter

        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        writer = AuditWriter("sift-mcp")
        eid = writer.log(tool="test", params={}, result_summary={})
        assert eid.startswith("sift-")  # Still returns an ID

    def test_canonical_fields(self, tmp_path, monkeypatch):
        from sift_mcp.audit import AuditWriter
        import json

        case_dir = tmp_path / "test-case"
        case_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")

        writer = AuditWriter("sift-mcp")
        writer.log(tool="run_command", params={"cmd": "ls"}, result_summary={"ok": True})

        log_file = case_dir / "audit" / "sift-mcp.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["mcp"] == "sift-mcp"
        assert entry["source"] == "mcp_server"
        assert "case_id" in entry
        assert "result_summary" in entry
        assert "params" in entry

    def test_thread_safe_sequence(self, tmp_path, monkeypatch):
        from sift_mcp.audit import AuditWriter
        import threading

        case_dir = tmp_path / "test-case"
        case_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")

        writer = AuditWriter("sift-mcp")
        ids = []
        lock = threading.Lock()

        def log_one():
            eid = writer.log(tool="test", params={}, result_summary={})
            with lock:
                ids.append(eid)

        threads = [threading.Thread(target=log_one) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 10
        assert len(set(ids)) == 10
