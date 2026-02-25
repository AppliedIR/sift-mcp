"""Tests for provenance classification and enforcement in forensic-mcp."""

import json
import os
from pathlib import Path

import pytest
import yaml as _yaml
from forensic_mcp.audit import AuditWriter
from forensic_mcp.case.manager import CaseManager, _compute_content_hash


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    return CaseManager()


@pytest.fixture
def active_case(manager, tmp_path, monkeypatch):
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc)
    case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
    case_dir = tmp_path / case_id
    case_dir.mkdir()
    for d in ("evidence", "extractions", "reports", "audit"):
        (case_dir / d).mkdir()
    case_meta = {
        "case_id": case_id,
        "name": "Test",
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


@pytest.fixture
def audit(monkeypatch):
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    return AuditWriter(mcp_name="forensic-mcp")


def _valid_finding(**overrides):
    base = {
        "title": "Test finding",
        "evidence_ids": ["ev-001"],
        "observation": "Observed something",
        "interpretation": "Interpreted something",
        "confidence": "MEDIUM",
        "confidence_justification": "Single source",
        "type": "finding",
    }
    base.update(overrides)
    return base


# --- _classify_provenance ---


class TestClassifyProvenance:
    def test_mcp_evidence_ids(self, manager, active_case):
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"evidence_id": "sift-tester-20260225-001", "tool": "run_command"})
            + "\n"
        )
        result = manager._classify_provenance(
            ["sift-tester-20260225-001"], case_dir
        )
        assert result["summary"] == "MCP"
        assert "sift-tester-20260225-001" in result["mcp"]
        assert len(result["none"]) == 0

    def test_hook_evidence_ids(self, manager, active_case):
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "claude-code.jsonl").write_text(
            json.dumps({"evidence_id": "hook-tester-20260225-001", "source": "claude-code-hook"})
            + "\n"
        )
        result = manager._classify_provenance(
            ["hook-tester-20260225-001"], case_dir
        )
        assert result["summary"] == "HOOK"
        assert "hook-tester-20260225-001" in result["hook"]

    def test_shell_evidence_ids(self, manager, active_case):
        case_dir = Path(active_case["path"])
        result = manager._classify_provenance(["shell-tester-20260225-001"], case_dir)
        assert result["summary"] == "SHELL"
        assert "shell-tester-20260225-001" in result["shell"]

    def test_mixed_evidence_ids(self, manager, active_case):
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"evidence_id": "sift-001", "tool": "run_command"}) + "\n"
        )
        result = manager._classify_provenance(
            ["sift-001", "shell-tester-20260225-001"], case_dir
        )
        assert result["summary"] == "MIXED"
        assert "sift-001" in result["mcp"]
        assert "shell-tester-20260225-001" in result["shell"]

    def test_all_none(self, manager, active_case):
        case_dir = Path(active_case["path"])
        result = manager._classify_provenance(["unknown-001", "unknown-002"], case_dir)
        assert result["summary"] == "NONE"
        assert len(result["none"]) == 2

    def test_mcp_priority_over_hook(self, manager, active_case):
        """Same ID in both MCP and hook files -> MCP wins."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "claude-code.jsonl").write_text(
            json.dumps({"evidence_id": "dual-001"}) + "\n"
        )
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"evidence_id": "dual-001", "tool": "run_command"}) + "\n"
        )
        result = manager._classify_provenance(["dual-001"], case_dir)
        assert result["summary"] == "MCP"
        assert "dual-001" in result["mcp"]

    def test_mixed_with_none(self, manager, active_case):
        """MCP + NONE = MIXED (not NONE)."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"evidence_id": "sift-001"}) + "\n"
        )
        result = manager._classify_provenance(
            ["sift-001", "unknown-001"], case_dir
        )
        assert result["summary"] == "MIXED"


# --- record_finding with provenance ---


class TestRecordFindingProvenance:
    def test_supporting_commands_creates_shell_entries(self, manager, active_case, audit):
        cmds = [
            {
                "command": "vol.py -f mem.raw pslist",
                "output_excerpt": "PID  Name\n1234 evil.exe",
                "purpose": "List processes from memory dump",
            }
        ]
        result = manager.record_finding(
            _valid_finding(), supporting_commands=cmds, audit=audit
        )
        assert result["status"] == "STAGED"
        # Shell evidence ID should be in the finding
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        eids = findings[0]["evidence_ids"]
        shell_eids = [e for e in eids if e.startswith("shell-")]
        assert len(shell_eids) == 1

    def test_supporting_commands_validation(self, manager, active_case, audit):
        """Max 5, required fields, truncation."""
        cmds = [
            {
                "command": f"cmd{i}",
                "output_excerpt": "x" * 3000,
                "purpose": f"purpose{i}",
            }
            for i in range(7)
        ]
        result = manager.record_finding(
            _valid_finding(), supporting_commands=cmds, audit=audit
        )
        assert result["status"] == "STAGED"
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        # Only 5 should be kept
        assert len(findings[0]["supporting_commands"]) == 5
        # Output should be truncated
        for cmd in findings[0]["supporting_commands"]:
            assert len(cmd["output_excerpt"]) <= 2000

    def test_hard_gate_none_rejected(self, manager, active_case):
        """All NONE + no supporting_commands -> REJECTED."""
        finding = _valid_finding(evidence_ids=["unknown-001"])
        result = manager.record_finding(finding)
        assert result["status"] == "REJECTED"
        assert "no provenance" in result["error"]

    def test_shell_only_stages_ok(self, manager, active_case, audit):
        """With supporting_commands but no MCP IDs -> STAGED."""
        finding = _valid_finding(evidence_ids=["unknown-001"])
        cmds = [
            {
                "command": "strings /evidence/file.exe",
                "output_excerpt": "suspicious string",
                "purpose": "Extract strings",
            }
        ]
        result = manager.record_finding(
            finding, supporting_commands=cmds, audit=audit
        )
        assert result["status"] == "STAGED"

    def test_stores_content_hash(self, manager, active_case, audit):
        cmds = [
            {"command": "ls", "output_excerpt": "files", "purpose": "List files"}
        ]
        manager.record_finding(
            _valid_finding(), supporting_commands=cmds, audit=audit
        )
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert "content_hash" in findings[0]
        assert len(findings[0]["content_hash"]) == 64

    def test_stores_provenance(self, manager, active_case, audit):
        cmds = [
            {"command": "ls", "output_excerpt": "files", "purpose": "List files"}
        ]
        manager.record_finding(
            _valid_finding(), supporting_commands=cmds, audit=audit
        )
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert "provenance" in findings[0]
        assert findings[0]["provenance"] in ("MCP", "HOOK", "SHELL", "MIXED", "NONE")

    def test_stores_supporting_commands(self, manager, active_case, audit):
        cmds = [
            {"command": "ps aux", "output_excerpt": "pid list", "purpose": "Check procs"}
        ]
        manager.record_finding(
            _valid_finding(), supporting_commands=cmds, audit=audit
        )
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert "supporting_commands" in findings[0]
        assert findings[0]["supporting_commands"][0]["command"] == "ps aux"

    def test_mcp_evidence_stages_without_commands(self, manager, active_case):
        """Evidence IDs that exist in MCP audit -> stages fine without supporting_commands."""
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"evidence_id": "sift-tester-20260225-001", "tool": "run_command"})
            + "\n"
        )
        finding = _valid_finding(evidence_ids=["sift-tester-20260225-001"])
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"

    def test_protected_fields_provenance_content_hash(self, manager, active_case, audit):
        """User can't inject fake provenance or content_hash."""
        finding = _valid_finding(
            evidence_ids=["sift-tester-20260225-001"],
        )
        finding["provenance"] = "FAKE"
        finding["content_hash"] = "fake_hash"
        case_dir = Path(active_case["path"])
        audit_dir = case_dir / "audit"
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"evidence_id": "sift-tester-20260225-001"}) + "\n"
        )
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["provenance"] != "FAKE"
        assert findings[0]["content_hash"] != "fake_hash"

    def test_supporting_commands_missing_fields_skipped(self, manager, active_case, audit):
        """Commands missing required fields are skipped."""
        cmds = [
            {"command": "ls"},  # Missing purpose
            {"purpose": "something"},  # Missing command
            {"command": "valid", "purpose": "ok", "output_excerpt": "out"},  # Valid
        ]
        result = manager.record_finding(
            _valid_finding(), supporting_commands=cmds, audit=audit
        )
        assert result["status"] == "STAGED"
        case_dir = Path(active_case["path"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert len(findings[0]["supporting_commands"]) == 1


# --- compute_content_hash ---


class TestComputeContentHash:
    def test_deterministic(self):
        item = {"id": "F-001", "title": "Test"}
        assert _compute_content_hash(item) == _compute_content_hash(item)

    def test_excludes_volatile(self):
        base = {"id": "F-001", "title": "Test"}
        with_volatile = {
            **base,
            "status": "APPROVED",
            "provenance": "MCP",
            "content_hash": "old",
            "modified_at": "2026-01-01",
        }
        assert _compute_content_hash(base) == _compute_content_hash(with_volatile)

    def test_includes_supporting_commands(self):
        base = {"id": "F-001", "title": "Test"}
        with_cmds = {
            **base,
            "supporting_commands": [{"command": "ls", "purpose": "list"}],
        }
        assert _compute_content_hash(base) != _compute_content_hash(with_cmds)
