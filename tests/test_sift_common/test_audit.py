"""Unit tests for sift_common.audit — AuditWriter, resolve_examiner, _sanitize_slug."""

import json

import pytest
from sift_common.audit import AuditWriter, _sanitize_slug, resolve_examiner


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
    monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)
    monkeypatch.delenv("AIIR_EXAMINER", raising=False)
    monkeypatch.delenv("AIIR_ANALYST", raising=False)
    monkeypatch.delenv("AIIR_ACTIVE_CASE", raising=False)


# ---------------------------------------------------------------------------
# _sanitize_slug
# ---------------------------------------------------------------------------


class TestSanitizeSlug:
    def test_lowercase(self):
        assert _sanitize_slug("Alice") == "alice"

    def test_replaces_spaces(self):
        assert _sanitize_slug("John Doe") == "john-doe"

    def test_replaces_special_chars(self):
        assert _sanitize_slug("user@domain.com") == "user-domain-com"

    def test_strips_leading_hyphens(self):
        assert _sanitize_slug("---admin") == "admin"

    def test_truncates_to_40(self):
        result = _sanitize_slug("a" * 50)
        assert len(result) <= 40

    def test_empty_returns_unknown(self):
        assert _sanitize_slug("") == "unknown"

    def test_all_special_returns_unknown(self):
        assert _sanitize_slug("@@@") == "unknown"

    def test_valid_slug_unchanged(self):
        assert _sanitize_slug("alice-smith") == "alice-smith"


# ---------------------------------------------------------------------------
# resolve_examiner
# ---------------------------------------------------------------------------


class TestResolveExaminer:
    def test_aiir_examiner_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "alice")
        assert resolve_examiner() == "alice"

    def test_aiir_analyst_fallback(self, monkeypatch):
        monkeypatch.setenv("AIIR_ANALYST", "bob")
        assert resolve_examiner() == "bob"

    def test_examiner_takes_priority(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "alice")
        monkeypatch.setenv("AIIR_ANALYST", "bob")
        assert resolve_examiner() == "alice"

    def test_os_user_fallback(self):
        # With no env vars set, falls back to OS username
        result = resolve_examiner()
        assert len(result) > 0

    def test_sanitizes_result(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "Alice Smith")
        assert resolve_examiner() == "alice-smith"


# ---------------------------------------------------------------------------
# AuditWriter
# ---------------------------------------------------------------------------


class TestAuditWriter:
    def test_creates_audit_file(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        writer.log(tool="test_tool", params={"key": "value"}, result_summary="ok")
        log_file = audit_dir / "test-mcp.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["mcp"] == "test-mcp"
        assert entry["tool"] == "test_tool"
        assert entry["examiner"] == "tester"

    def test_returns_evidence_id(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        eid = writer.log(tool="t", params={}, result_summary="ok")
        assert eid.startswith("test-tester-")
        assert eid.endswith("-001")

    def test_sequential_evidence_ids(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        ids = [writer.log(tool="t", params={}, result_summary="ok") for _ in range(3)]
        assert ids[0].endswith("-001")
        assert ids[1].endswith("-002")
        assert ids[2].endswith("-003")

    def test_explicit_evidence_id(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        eid = writer.log(
            tool="t",
            params={},
            result_summary="ok",
            evidence_id="custom-id-001",
        )
        assert eid == "custom-id-001"

    def test_no_case_dir_skips_write(self, monkeypatch):
        """Without AIIR_CASE_DIR, audit entry not written but no error."""
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp")
        eid = writer.log(tool="t", params={}, result_summary="ok")
        assert eid.startswith("test-tester-")

    def test_elapsed_ms_recorded(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        writer.log(tool="t", params={}, result_summary="ok", elapsed_ms=42.5)
        entry = json.loads((audit_dir / "test-mcp.jsonl").read_text().strip())
        assert entry["elapsed_ms"] == 42.5

    def test_resume_sequence_after_restart(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")

        # Write 3 entries with first writer
        w1 = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        for _ in range(3):
            w1.log(tool="t", params={}, result_summary="ok")

        # Create new writer (simulates restart)
        w2 = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        eid = w2.log(tool="t", params={}, result_summary="ok")
        assert eid.endswith("-004")

    def test_get_entries(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        writer.log(tool="tool_a", params={}, result_summary="ok")
        writer.log(tool="tool_b", params={}, result_summary="ok")
        entries = writer.get_entries()
        assert len(entries) == 2
        assert entries[0]["tool"] == "tool_a"
        assert entries[1]["tool"] == "tool_b"

    def test_get_entries_empty(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        assert writer.get_entries() == []

    def test_get_entries_no_case_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))
        writer = AuditWriter("test-mcp")
        assert writer.get_entries() == []

    def test_reset_counter(self, tmp_path, monkeypatch):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        writer.log(tool="t", params={}, result_summary="ok")
        writer.reset_counter()
        # After reset, sequence should resume from file
        eid = writer.log(tool="t", params={}, result_summary="ok")
        assert eid.endswith("-002")

    def test_examiner_property(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "alice")
        writer = AuditWriter("test-mcp")
        assert writer.examiner == "alice"

    def test_corrupt_jsonl_skipped(self, tmp_path, monkeypatch):
        """Corrupt lines in audit JSONL are skipped on read."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        log_file = audit_dir / "test-mcp.jsonl"
        log_file.write_text(
            "not json\n"
            + json.dumps(
                {
                    "ts": "2026-01-01",
                    "tool": "t",
                    "mcp": "test-mcp",
                    "evidence_id": "test-001",
                    "examiner": "tester",
                }
            )
            + "\n"
        )
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        entries = writer.get_entries()
        assert len(entries) == 1

    def test_summarize_dict_passthrough(self, tmp_path, monkeypatch):
        """Dict results pass through to audit entry."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        writer.log(tool="t", params={}, result_summary={"key": "val"})
        entry = json.loads((audit_dir / "test-mcp.jsonl").read_text().strip())
        assert entry["result_summary"] == {"key": "val"}

    def test_summarize_list(self, tmp_path, monkeypatch):
        """List results are summarized as count."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        writer.log(tool="t", params={}, result_summary=[1, 2, 3])
        entry = json.loads((audit_dir / "test-mcp.jsonl").read_text().strip())
        assert entry["result_summary"] == {"count": 3, "type": "list"}

    def test_audit_dir_from_env(self, tmp_path, monkeypatch):
        """AIIR_AUDIT_DIR env var takes priority over AIIR_CASE_DIR."""
        audit_dir = tmp_path / "custom-audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_AUDIT_DIR", str(audit_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp")
        writer.log(tool="t", params={}, result_summary="ok")
        assert (audit_dir / "test-mcp.jsonl").exists()

    def test_audit_dir_from_case_dir(self, tmp_path, monkeypatch):
        """AIIR_CASE_DIR/audit/ used when no explicit dir."""
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").touch()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("test-mcp")
        writer.log(tool="t", params={}, result_summary="ok")
        assert (case_dir / "audit" / "test-mcp.jsonl").exists()

    def test_audit_dir_fallthrough_to_active_case(self, tmp_path, monkeypatch):
        """AIIR_CASE_DIR without CASE.yaml falls through to active_case."""
        # Parent dir (no CASE.yaml) — simulates the BUG-027 scenario
        parent_dir = tmp_path / "cases"
        parent_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(parent_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        # Real case dir with CASE.yaml
        real_case = tmp_path / "cases" / "INC-001"
        real_case.mkdir()
        (real_case / "CASE.yaml").touch()
        # Write active_case pointer
        aiir_dir = tmp_path / ".aiir"
        aiir_dir.mkdir()
        (aiir_dir / "active_case").write_text(str(real_case))
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))
        writer = AuditWriter("test-mcp")
        writer.log(tool="t", params={}, result_summary="ok")
        # Audit should land in the real case dir, not the parent
        assert (real_case / "audit" / "test-mcp.jsonl").exists()
        assert not (parent_dir / "audit").exists()

    def test_mcp_name_prefix_generation(self, tmp_path, monkeypatch):
        """Evidence ID prefix strips -mcp and hyphens."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        writer = AuditWriter("case-mcp", audit_dir=str(audit_dir))
        eid = writer.log(tool="t", params={}, result_summary="ok")
        assert eid.startswith("case-tester-")

        writer2 = AuditWriter("forensic-mcp", audit_dir=str(audit_dir))
        eid2 = writer2.log(tool="t", params={}, result_summary="ok")
        assert eid2.startswith("forensic-tester-")

    def test_get_entries_since_filter(self, tmp_path, monkeypatch):
        """since parameter filters entries by timestamp."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        log_file = audit_dir / "test-mcp.jsonl"
        log_file.write_text(
            json.dumps({"ts": "2026-01-01T00:00:00", "tool": "old"})
            + "\n"
            + json.dumps({"ts": "2026-02-01T00:00:00", "tool": "new"})
            + "\n"
        )
        writer = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        entries = writer.get_entries(since="2026-01-15T00:00:00")
        assert len(entries) == 1
        assert entries[0]["tool"] == "new"
