"""Tests for audit trail and structured response wrappers."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from windows_triage.audit import AuditWriter, resolve_examiner
from windows_triage.tool_metadata import TOOL_METADATA, DEFAULT_METADATA


class TestAuditWriter:
    """AuditWriter class tests."""

    def test_evidence_id_format(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("windows-triage-mcp")
        eid = writer.log(tool="check_file", params={"path": "test.exe"}, result_summary={})
        parts = eid.split("-")
        assert parts[0] == "windowstriage"
        assert parts[1] == "tester"
        assert len(parts[2]) == 8
        assert parts[2].isdigit()
        assert len(parts[-1]) == 3

    def test_monotonic_sequence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("windows-triage-mcp")
        ids = [writer.log(tool="check_file", params={}, result_summary={}) for _ in range(5)]
        seqs = [int(eid.split("-")[-1]) for eid in ids]
        assert seqs == [1, 2, 3, 4, 5]

    def test_reset_counter(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("windows-triage-mcp")
        writer.log(tool="check_file", params={}, result_summary={})
        writer.log(tool="check_file", params={}, result_summary={})
        writer.reset_counter()
        eid = writer.log(tool="check_file", params={}, result_summary={})
        assert eid.endswith("-001")

    def test_writes_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("windows-triage-mcp")
        writer.log(tool="check_file", params={"path": "C:\\test.exe"}, result_summary={"verdict": "EXPECTED"})

        audit_file = tmp_path / "audit" / "windows-triage-mcp.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["tool"] == "check_file"
        assert entry["mcp"] == "windows-triage-mcp"
        assert entry["params"] == {"path": "C:\\test.exe"}
        assert entry["result_summary"] == {"verdict": "EXPECTED"}
        assert "examiner" in entry
        assert "case_id" in entry
        assert "source" in entry

    def test_appends_multiple(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("windows-triage-mcp")
        for _ in range(3):
            writer.log(tool="check_file", params={}, result_summary={})

        audit_file = tmp_path / "audit" / "windows-triage-mcp.jsonl"
        lines = [json.loads(l) for l in audit_file.read_text().strip().split("\n")]
        assert len(lines) == 3

    def test_no_write_without_case_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        writer = AuditWriter("windows-triage-mcp")
        eid = writer.log(tool="check_file", params={}, result_summary={})
        assert eid
        assert not (tmp_path / "examiners").exists()

    def test_thread_safe_sequence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("windows-triage-mcp")
        ids = []
        lock = threading.Lock()

        def log_one():
            eid = writer.log(tool="check_file", params={}, result_summary={})
            with lock:
                ids.append(eid)

        threads = [threading.Thread(target=log_one) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 10
        assert len(set(ids)) == 10

    def test_resumes_after_restart(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer1 = AuditWriter("windows-triage-mcp")
        writer1.log(tool="check_file", params={}, result_summary={})
        writer1.log(tool="check_file", params={}, result_summary={})

        writer2 = AuditWriter("windows-triage-mcp")
        eid = writer2.log(tool="check_file", params={}, result_summary={})
        assert eid.endswith("-003")

    def test_get_entries(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("windows-triage-mcp")
        writer.log(tool="check_file", params={}, result_summary={})
        writer.log(tool="check_hash", params={}, result_summary={})

        entries = writer.get_entries()
        assert len(entries) == 2
        assert entries[0]["tool"] == "check_file"
        assert entries[1]["tool"] == "check_hash"


class TestToolMetadata:
    """Tool metadata lookup."""

    def test_known_tools(self):
        expected_tools = {
            "check_file", "check_process_tree", "check_service",
            "check_scheduled_task", "check_autorun", "check_registry",
            "check_hash", "analyze_filename", "check_lolbin",
            "check_hijackable_dll", "check_pipe", "get_db_stats", "get_health",
        }
        assert set(TOOL_METADATA.keys()) == expected_tools

    def test_all_have_caveats_and_constraint(self):
        for tool, meta in TOOL_METADATA.items():
            assert isinstance(meta["caveats"], list), f"{tool} missing caveats list"
            assert len(meta["caveats"]) > 0, f"{tool} has empty caveats"
            assert "interpretation_constraint" in meta, f"{tool} missing constraint"

    def test_default_metadata(self):
        assert "caveats" in DEFAULT_METADATA
        assert "interpretation_constraint" in DEFAULT_METADATA


class TestWrapResponse:
    """Response wrapping via server method."""

    def _make_server_instance(self):
        from windows_triage.server import WindowsTriageServer
        with patch.object(WindowsTriageServer, '__init__', lambda self, **kw: None):
            server = WindowsTriageServer.__new__(WindowsTriageServer)
            server._audit = AuditWriter("windows-triage-mcp")
            return server

    def test_wraps_successful_result(self):
        server = self._make_server_instance()
        result = {"verdict": "EXPECTED", "path": "C:\\Windows\\System32\\cmd.exe"}
        wrapped = server._wrap_response("check_file", {"path": "C:\\Windows\\System32\\cmd.exe"}, result)
        assert "evidence_id" in wrapped
        assert "examiner" in wrapped
        assert "caveats" in wrapped
        assert "interpretation_constraint" in wrapped
        assert wrapped["verdict"] == "EXPECTED"

    def test_error_result_gets_evidence_id_but_no_caveats(self):
        server = self._make_server_instance()
        result = {"error": "Unknown tool: bad"}
        wrapped = server._wrap_response("bad", {}, result)
        assert "evidence_id" in wrapped
        assert "examiner" in wrapped
        assert "caveats" not in wrapped

    def test_unknown_tool_gets_defaults(self):
        server = self._make_server_instance()
        result = {"status": "ok"}
        wrapped = server._wrap_response("future_tool", {}, result)
        assert "examiner" in wrapped
        assert wrapped["caveats"] == DEFAULT_METADATA["caveats"]

    def test_writes_audit_when_case_dir_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        server = self._make_server_instance()
        server._wrap_response("check_file", {"path": "test.exe"}, {"verdict": "UNKNOWN"})

        audit_file = tmp_path / "audit" / "windows-triage-mcp.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["tool"] == "check_file"
        assert entry["mcp"] == "windows-triage-mcp"
        assert entry["params"] == {"path": "test.exe"}

    def test_no_audit_when_case_dir_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        server = self._make_server_instance()
        server._wrap_response("check_file", {"path": "test.exe"}, {"verdict": "UNKNOWN"})
        assert not (tmp_path / "examiners").exists()
