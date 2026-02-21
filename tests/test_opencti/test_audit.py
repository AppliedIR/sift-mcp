"""Tests for audit trail and structured response wrappers."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from opencti_mcp.audit import AuditWriter, resolve_examiner
from opencti_mcp.tool_metadata import TOOL_METADATA, DEFAULT_METADATA


class TestAuditWriter:
    """AuditWriter class tests."""

    def test_evidence_id_format(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("opencti-mcp")
        eid = writer.log(tool="lookup_ioc", params={"ioc": "8.8.8.8"}, result_summary={})
        parts = eid.split("-")
        assert parts[0] == "opencti"
        assert parts[1] == "tester"
        assert len(parts[2]) == 8
        assert parts[2].isdigit()
        assert len(parts[-1]) == 3

    def test_monotonic_sequence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("opencti-mcp")
        ids = [writer.log(tool="lookup_ioc", params={}, result_summary={}) for _ in range(5)]
        seqs = [int(eid.split("-")[-1]) for eid in ids]
        assert seqs == [1, 2, 3, 4, 5]

    def test_reset_counter(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("opencti-mcp")
        writer.log(tool="lookup_ioc", params={}, result_summary={})
        writer.log(tool="lookup_ioc", params={}, result_summary={})
        writer.reset_counter()
        eid = writer.log(tool="lookup_ioc", params={}, result_summary={})
        assert eid.endswith("-001")

    def test_writes_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("opencti-mcp")
        writer.log(tool="lookup_ioc", params={"ioc": "8.8.8.8"}, result_summary={"found": True})

        audit_file = tmp_path / "examiners" / "tester" / "audit" / "opencti-mcp.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["tool"] == "lookup_ioc"
        assert entry["mcp"] == "opencti-mcp"
        assert entry["params"] == {"ioc": "8.8.8.8"}
        assert entry["result_summary"] == {"found": True}
        assert "examiner" in entry
        assert "case_id" in entry
        assert "source" in entry

    def test_appends_multiple(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("opencti-mcp")
        for _ in range(3):
            writer.log(tool="lookup_ioc", params={}, result_summary={})

        audit_file = tmp_path / "examiners" / "tester" / "audit" / "opencti-mcp.jsonl"
        lines = [json.loads(l) for l in audit_file.read_text().strip().split("\n")]
        assert len(lines) == 3

    def test_no_write_without_case_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        writer = AuditWriter("opencti-mcp")
        eid = writer.log(tool="lookup_ioc", params={}, result_summary={})
        assert eid
        assert not (tmp_path / "examiners").exists()

    def test_thread_safe_sequence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("opencti-mcp")
        ids = []
        lock = threading.Lock()

        def log_one():
            eid = writer.log(tool="lookup_ioc", params={}, result_summary={})
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
        writer1 = AuditWriter("opencti-mcp")
        writer1.log(tool="lookup_ioc", params={}, result_summary={})
        writer1.log(tool="lookup_ioc", params={}, result_summary={})

        writer2 = AuditWriter("opencti-mcp")
        eid = writer2.log(tool="lookup_ioc", params={}, result_summary={})
        assert eid.endswith("-003")

    def test_get_entries(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        writer = AuditWriter("opencti-mcp")
        writer.log(tool="lookup_ioc", params={}, result_summary={})
        writer.log(tool="search_threat_actor", params={}, result_summary={})

        entries = writer.get_entries()
        assert len(entries) == 2
        assert entries[0]["tool"] == "lookup_ioc"
        assert entries[1]["tool"] == "search_threat_actor"


class TestToolMetadata:
    """Tool metadata lookup."""

    EXPECTED_TOOLS = {
        "search_threat_intel", "lookup_ioc", "search_threat_actor",
        "search_malware", "search_attack_pattern", "search_vulnerability",
        "get_recent_indicators", "search_reports", "search_campaign",
        "search_tool", "search_infrastructure", "search_incident",
        "search_observable", "search_sighting", "search_organization",
        "search_sector", "search_location", "search_course_of_action",
        "search_grouping", "search_note", "lookup_hash",
        "get_entity", "get_relationships",
        "create_indicator", "create_note", "create_sighting", "trigger_enrichment",
        "get_health", "list_connectors", "get_network_status",
        "force_reconnect", "get_cache_stats",
    }

    def test_known_tools(self):
        assert set(TOOL_METADATA.keys()) == self.EXPECTED_TOOLS

    def test_tool_count(self):
        assert len(TOOL_METADATA) == 32

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
        from opencti_mcp.server import OpenCTIMCPServer
        with patch.object(OpenCTIMCPServer, '__init__', lambda self: None):
            server = OpenCTIMCPServer.__new__(OpenCTIMCPServer)
            server._audit = AuditWriter("opencti-mcp")
            return server

    def test_wraps_successful_result(self):
        server = self._make_server_instance()
        result = {"results": [], "total": 0}
        wrapped = server._wrap_response("search_threat_actor", {"query": "APT29"}, result)
        assert "evidence_id" in wrapped
        assert wrapped["evidence_id"].startswith("opencti-")
        assert "examiner" in wrapped
        assert "caveats" in wrapped
        assert "interpretation_constraint" in wrapped
        assert wrapped["results"] == []

    def test_error_result_gets_evidence_id_but_no_caveats(self):
        server = self._make_server_instance()
        result = {"error": "validation_error", "message": "bad input"}
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
        server._wrap_response("lookup_ioc", {"ioc": "8.8.8.8"}, {"found": True})

        audit_file = tmp_path / "examiners" / "tester" / "audit" / "opencti-mcp.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["tool"] == "lookup_ioc"
        assert entry["mcp"] == "opencti-mcp"
        assert entry["params"] == {"ioc": "8.8.8.8"}

    def test_no_audit_when_case_dir_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        server = self._make_server_instance()
        server._wrap_response("lookup_ioc", {"ioc": "8.8.8.8"}, {"found": True})
        assert not (tmp_path / "examiners").exists()
