"""Tests for audit trail and structured response wrappers."""

from __future__ import annotations

import json
import threading
from unittest.mock import patch

from rag_mcp.audit import AuditWriter
from rag_mcp.tool_metadata import DEFAULT_METADATA, TOOL_METADATA


class TestAuditWriter:
    """AuditWriter class tests."""

    def test_evidence_id_format(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("forensic-rag-mcp")
        eid = writer.log(
            tool="search", params={"q": "test"}, result_summary={"ok": True}
        )
        parts = eid.split("-")
        assert parts[0] == "forensicrag"
        assert parts[1] == "tester"
        assert len(parts[2]) == 8
        assert parts[2].isdigit()
        assert len(parts[-1]) == 3

    def test_monotonic_sequence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer = AuditWriter("forensic-rag-mcp")
        ids = [
            writer.log(tool="search", params={}, result_summary={}) for _ in range(5)
        ]
        seqs = [int(eid.split("-")[-1]) for eid in ids]
        assert seqs == [1, 2, 3, 4, 5]

    def test_reset_counter(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))
        writer = AuditWriter("forensic-rag-mcp")
        writer.log(tool="search", params={}, result_summary={})
        writer.log(tool="search", params={}, result_summary={})
        writer.reset_counter()
        eid = writer.log(tool="search", params={}, result_summary={})
        assert eid.endswith("-001")

    def test_writes_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer = AuditWriter("forensic-rag-mcp")
        writer.log(
            tool="search", params={"query": "mimikatz"}, result_summary={"count": 5}
        )

        audit_file = tmp_path / "audit" / "forensic-rag-mcp.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["tool"] == "search"
        assert entry["mcp"] == "forensic-rag-mcp"
        assert entry["params"] == {"query": "mimikatz"}
        assert entry["result_summary"] == {"count": 5}
        assert "examiner" in entry
        assert "case_id" in entry
        assert "source" in entry

    def test_appends_multiple(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer = AuditWriter("forensic-rag-mcp")
        for _ in range(3):
            writer.log(tool="search", params={}, result_summary={})

        audit_file = tmp_path / "audit" / "forensic-rag-mcp.jsonl"
        lines = [json.loads(l) for l in audit_file.read_text().strip().split("\n")]
        assert len(lines) == 3

    def test_no_write_without_case_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))
        writer = AuditWriter("forensic-rag-mcp")
        eid = writer.log(tool="search", params={}, result_summary={})
        assert eid  # still returns evidence ID
        assert not (tmp_path / "examiners").exists()

    def test_thread_safe_sequence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer = AuditWriter("forensic-rag-mcp")
        ids = []
        lock = threading.Lock()

        def log_one():
            eid = writer.log(tool="search", params={}, result_summary={})
            with lock:
                ids.append(eid)

        threads = [threading.Thread(target=log_one) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 10
        assert len(set(ids)) == 10  # all unique

    def test_resumes_after_restart(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer1 = AuditWriter("forensic-rag-mcp")
        writer1.log(tool="search", params={}, result_summary={})
        writer1.log(tool="search", params={}, result_summary={})

        writer2 = AuditWriter("forensic-rag-mcp")
        eid = writer2.log(tool="search", params={}, result_summary={})
        assert eid.endswith("-003")

    def test_get_entries(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer = AuditWriter("forensic-rag-mcp")
        writer.log(tool="search", params={"q": "a"}, result_summary={})
        writer.log(tool="list_sources", params={}, result_summary={})

        entries = writer.get_entries()
        assert len(entries) == 2
        assert entries[0]["tool"] == "search"
        assert entries[1]["tool"] == "list_sources"

    def test_elapsed_ms(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        writer = AuditWriter("forensic-rag-mcp")
        writer.log(tool="search", params={}, result_summary={}, elapsed_ms=42.567)

        entries = writer.get_entries()
        assert entries[0]["elapsed_ms"] == 42.6


class TestToolMetadata:
    """Tool metadata lookup."""

    def test_known_tool(self):
        meta = TOOL_METADATA["search"]
        assert isinstance(meta["caveats"], list)
        assert len(meta["caveats"]) > 0
        assert "interpretation_constraint" in meta

    def test_all_tools_have_metadata(self):
        expected_tools = {"search", "list_sources", "get_stats"}
        assert set(TOOL_METADATA.keys()) == expected_tools

    def test_default_metadata(self):
        assert "caveats" in DEFAULT_METADATA
        assert "interpretation_constraint" in DEFAULT_METADATA


class TestWrapResponse:
    """Response wrapping integration (via server method)."""

    def _make_server_instance(self):
        """Create a minimal server instance for testing _wrap_response."""
        from rag_mcp.server import RAGServer

        with patch.object(RAGServer, "__init__", lambda self: None):
            server = RAGServer.__new__(RAGServer)
            server._audit = AuditWriter("forensic-rag-mcp")
            return server

    def test_wraps_successful_result(self):
        server = self._make_server_instance()
        result = {"status": "ok", "query": "test", "results": []}
        wrapped = server._wrap_response("search", {"query": "test"}, result)
        assert "evidence_id" in wrapped
        assert "examiner" in wrapped
        assert "caveats" in wrapped
        assert "interpretation_constraint" in wrapped
        assert wrapped["status"] == "ok"
        assert wrapped["query"] == "test"

    def test_error_result_gets_evidence_id_but_no_caveats(self):
        server = self._make_server_instance()
        result = {"error": "Unknown tool: bad"}
        wrapped = server._wrap_response("bad", {}, result)
        assert "evidence_id" in wrapped
        assert "examiner" in wrapped
        assert "caveats" not in wrapped
        assert wrapped["error"] == "Unknown tool: bad"

    def test_unknown_tool_gets_defaults(self):
        server = self._make_server_instance()
        result = {"status": "ok"}
        wrapped = server._wrap_response("unknown_tool", {}, result)
        assert "examiner" in wrapped
        assert wrapped["caveats"] == DEFAULT_METADATA["caveats"]

    def test_writes_audit_when_case_dir_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "CASE.yaml").touch(exist_ok=True)
        server = self._make_server_instance()
        result = {"status": "ok"}
        server._wrap_response("search", {"query": "test"}, result)

        audit_file = tmp_path / "audit" / "forensic-rag-mcp.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["tool"] == "search"
        assert entry["mcp"] == "forensic-rag-mcp"
        assert entry["params"] == {"query": "test"}

    def test_no_audit_when_case_dir_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        server = self._make_server_instance()
        result = {"status": "ok"}
        server._wrap_response("search", {"query": "test"}, result)
        assert not (tmp_path / "examiners").exists()
