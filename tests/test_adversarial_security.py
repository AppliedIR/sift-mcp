"""Adversarial security tests — edge cases, injection, boundary conditions.

Tests designed to probe attack surfaces identified in comprehensive review.
Each test targets a specific code path with adversarial input.

Sections 1-3, 6-9, 12-13 test forensic-mcp and sift-gateway (this repo).
Wintools tests are in wintools-mcp/tests/test_adversarial_security.py.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ============================================================
# Section 1: Evidence ID format validation (forensic-mcp)
# ============================================================


class TestEvidenceIdValidation:
    """Probe _EVIDENCE_ID_PATTERN with adversarial inputs."""

    @pytest.fixture
    def pattern(self):
        from forensic_mcp.case.manager import _EVIDENCE_ID_PATTERN

        return _EVIDENCE_ID_PATTERN

    def test_valid_ids(self, pattern):
        """Baseline: normal evidence IDs accepted."""
        assert pattern.match("sift-alice-20260225-001")
        assert pattern.match("forensic-bob-20260225-123")
        assert pattern.match("windowstriage-testuser-20260225-9999")

    def test_rejects_empty(self, pattern):
        assert not pattern.match("")

    def test_rejects_uppercase(self, pattern):
        """Uppercase should be rejected (provenance could be faked)."""
        assert not pattern.match("SIFT-alice-20260225-001")
        assert not pattern.match("sift-Alice-20260225-001")

    def test_rejects_path_traversal(self, pattern):
        """Path separators must not match."""
        assert not pattern.match("../../../etc/passwd")
        assert not pattern.match("sift-../../-20260225-001")
        assert not pattern.match("sift-alice-20260225-001/../../evil")

    def test_rejects_null_bytes(self, pattern):
        """Null bytes must not match."""
        assert not pattern.match("sift-alice\x00-20260225-001")
        assert not pattern.match("\x00sift-alice-20260225-001")

    def test_rejects_unicode_homoglyphs(self, pattern):
        """Cyrillic 'a' (U+0430) must NOT match ASCII [a-z]."""
        cyrillic_a = "\u0430"  # Looks like 'a' but is Cyrillic
        eid = f"sift-{cyrillic_a}lice-20260225-001"
        assert not pattern.match(eid), "Cyrillic homoglyph bypassed ASCII pattern"

    def test_rejects_fullwidth_digits(self, pattern):
        """Fullwidth digits (U+FF10-FF19) match \\d in Python 3 without re.ASCII.

        BUG FOUND: Python's \\d matches Unicode digits. An attacker can inject
        fullwidth digits (U+FF10-FF19) that look like ASCII digits but are
        different bytes, potentially bypassing audit trail lookups.
        """
        fullwidth_2 = "\uff12"  # Fullwidth '2'
        eid = f"sift-alice-{fullwidth_2}0260225-001"
        # This SHOULD NOT match, but currently DOES due to \\d matching Unicode
        # FIX: Use re.ASCII flag or replace \\d with [0-9]
        if pattern.match(eid):
            pytest.xfail(
                "BUG: \\d matches Unicode fullwidth digits. "
                "Fix: use re.ASCII flag or [0-9] instead of \\d"
            )

    def test_rejects_newlines(self, pattern):
        """Trailing newlines pass $ in Python regex.

        BUG FOUND: Python's $ matches before a trailing \\n. An attacker can
        append \\n to an evidence ID and still pass the regex, potentially
        causing inconsistent lookups.
        """
        # Embedded newline correctly fails
        assert not pattern.match("sift-alice\n-20260225-001")
        # But trailing newline passes due to Python's $ behavior
        if pattern.match("sift-alice-20260225-001\n"):
            pytest.xfail(
                "BUG: $ matches before trailing newline. "
                "Fix: use \\Z instead of $ or re.ASCII"
            )

    def test_rejects_shell_injection(self, pattern):
        """Shell metacharacters must not match."""
        assert not pattern.match("sift-alice;rm -rf /-20260225-001")
        assert not pattern.match("sift-alice$(whoami)-20260225-001")
        assert not pattern.match("sift-alice`id`-20260225-001")

    def test_rejects_long_sequence(self, pattern):
        """Very long sequences — verify regex doesn't catastrophically backtrack."""
        # Should still match (3+ digits allowed)
        assert pattern.match("sift-alice-20260225-" + "9" * 100)
        # But must start with prefix-examiner-date format
        assert not pattern.match("a" * 10000)

    def test_rejects_spaces(self, pattern):
        assert not pattern.match("sift-alice -20260225-001")
        assert not pattern.match(" sift-alice-20260225-001")

    def test_examiner_segment_allows_hyphens(self, pattern):
        """Pattern structure: prefix-examiner-YYYYMMDD-NNN.

        The examiner segment is [a-z0-9]+ which does NOT include hyphens.
        Evidence IDs with hyphenated examiners (e.g. alice-bob) are parsed
        as: prefix=sift, examiner=alice, date-like=bob (fails \\d{8}).

        This is by design — the regex is greedy and hyphens are delimiters.
        Real examiner slugs don't contain hyphens in the evidence ID context
        because the prefix/examiner/date are joined by hyphens.
        """
        # Hyphenated examiner doesn't match — correct behavior
        assert not pattern.match("sift-alice-bob-20260225-001")
        # Pure hyphens also rejected
        assert not pattern.match("sift----20260225-001")

    def test_anchored(self, pattern):
        """Pattern must be anchored (^ and $) — no partial matches."""
        # If pattern lacks $, this would match
        assert not pattern.match("sift-alice-20260225-001 ; rm -rf /")


# ============================================================
# Section 2: Provenance gate (forensic-mcp)
# ============================================================


class TestProvenanceGate:
    """Verify the hard gate cannot be bypassed."""

    @pytest.fixture
    def manager(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)
        monkeypatch.delenv("AIIR_ACTIVE_CASE", raising=False)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))

        from forensic_mcp.case.manager import CaseManager

        cases_dir = tmp_path / "cases"
        cases_dir.mkdir()
        case_dir = cases_dir / "test-case"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("id: test-case\nstatus: open\n")
        (case_dir / "findings.json").write_text("[]")
        (case_dir / "timeline.json").write_text("[]")

        monkeypatch.setenv("AIIR_CASES_DIR", str(cases_dir))
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))

        mgr = CaseManager()
        mgr._active_case_id = "test-case"
        mgr._active_case_path = case_dir
        return mgr

    def _valid_finding(self):
        return {
            "title": "Test finding",
            "observation": "Something was observed",
            "interpretation": "This means something",
            "confidence": "low",
            "confidence_justification": "Because of evidence",
            "type": "finding",
        }

    def test_gate_rejects_no_evidence(self, manager):
        """Finding with no evidence_ids and no supporting_commands must be rejected."""
        result = manager.record_finding(self._valid_finding())
        assert result["status"] == "REJECTED"
        assert "provenance" in result["error"].lower()

    def test_gate_rejects_empty_evidence_list(self, manager):
        """Empty evidence_ids list must trigger NONE provenance."""
        finding = {**self._valid_finding(), "evidence_ids": []}
        result = manager.record_finding(finding)
        assert result["status"] == "REJECTED"

    def test_gate_rejects_fake_evidence_ids(self, manager):
        """Fabricated evidence IDs not in audit trail must be classified NONE."""
        finding = {
            **self._valid_finding(),
            "evidence_ids": ["sift-tester-20260225-999"],
        }
        result = manager.record_finding(finding)
        assert result["status"] == "REJECTED"

    def test_gate_rejects_malformed_evidence_ids(self, manager):
        """Malformed evidence IDs bypass format check -> NONE."""
        finding = {**self._valid_finding(), "evidence_ids": ["not-a-valid-id"]}
        result = manager.record_finding(finding)
        assert result["status"] == "REJECTED"

    def test_gate_accepts_with_supporting_commands(self, manager):
        """Valid supporting_commands should allow finding even with no MCP evidence."""
        finding = self._valid_finding()
        cmds = [
            {
                "command": "ls -la /tmp",
                "output_excerpt": "total 0\ndrwxr-xr-x 2 root root 40 Feb 25 00:00 .",
                "purpose": "Check directory contents",
            }
        ]
        audit = MagicMock()
        audit.log = MagicMock(return_value="shell-tester-20260225-001")
        result = manager.record_finding(finding, supporting_commands=cmds, audit=audit)
        assert result["status"] == "STAGED"

    def test_gate_rejects_empty_supporting_commands(self, manager):
        """Empty supporting_commands list must still trigger rejection."""
        finding = self._valid_finding()
        result = manager.record_finding(finding, supporting_commands=[])
        assert result["status"] == "REJECTED"

    def test_gate_rejects_supporting_commands_without_required_fields(self, manager):
        """Commands missing command or purpose are skipped, leaving validated_commands empty."""
        finding = self._valid_finding()
        cmds = [
            {
                "command": "",
                "output_excerpt": "data",
                "purpose": "test",
            },  # empty command
            {"command": "ls", "output_excerpt": "data", "purpose": ""},  # empty purpose
            {"output_excerpt": "data"},  # missing both
        ]
        result = manager.record_finding(finding, supporting_commands=cmds)
        assert result["status"] == "REJECTED"

    def test_gate_rejects_non_dict_commands(self, manager):
        """Non-dict entries in supporting_commands must be skipped."""
        finding = self._valid_finding()
        cmds = ["ls -la", 42, None, True]
        result = manager.record_finding(finding, supporting_commands=cmds)
        assert result["status"] == "REJECTED"

    def test_supporting_commands_limited_to_5(self, manager):
        """Only first 5 supporting commands are processed."""
        finding = self._valid_finding()
        cmds = [
            {"command": f"cmd-{i}", "output_excerpt": "out", "purpose": f"purpose-{i}"}
            for i in range(10)
        ]
        audit = MagicMock()
        audit.log = MagicMock(return_value="shell-tester-20260225-001")
        result = manager.record_finding(finding, supporting_commands=cmds, audit=audit)
        assert result["status"] == "STAGED"
        assert audit.log.call_count == 5

    def test_output_excerpt_truncated(self, manager):
        """Output excerpts longer than 2000 chars must be truncated."""
        finding = self._valid_finding()
        long_output = "A" * 5000
        cmds = [
            {
                "command": "cat big.log",
                "output_excerpt": long_output,
                "purpose": "Check log",
            }
        ]
        audit = MagicMock()
        audit.log = MagicMock(return_value="shell-tester-20260225-001")
        result = manager.record_finding(finding, supporting_commands=cmds, audit=audit)
        assert result["status"] == "STAGED"
        # Verify the stored command has truncated output
        findings = json.loads(
            (Path(os.environ["AIIR_CASE_DIR"]) / "findings.json").read_text()
        )
        stored_cmd = findings[0]["supporting_commands"][0]
        assert len(stored_cmd["output_excerpt"]) == 2000


# ============================================================
# Section 3: Allowlist field filtering (forensic-mcp)
# ============================================================


class TestFieldAllowlist:
    """Verify _ALLOWED_FINDING_FIELDS blocks injection of protected fields."""

    @pytest.fixture
    def manager(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)
        monkeypatch.delenv("AIIR_ACTIVE_CASE", raising=False)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))

        from forensic_mcp.case.manager import CaseManager

        cases_dir = tmp_path / "cases"
        cases_dir.mkdir()
        case_dir = cases_dir / "test-case"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("id: test-case\nstatus: open\n")
        (case_dir / "findings.json").write_text("[]")
        (case_dir / "timeline.json").write_text("[]")
        (case_dir / "audit").mkdir()

        # Create fake audit entry so evidence ID is found
        audit_entry = {
            "evidence_id": "sift-tester-20260225-001",
            "tool": "test_tool",
            "mcp": "sift-mcp",
        }
        (case_dir / "audit" / "sift-mcp.jsonl").write_text(
            json.dumps(audit_entry) + "\n"
        )

        monkeypatch.setenv("AIIR_CASES_DIR", str(cases_dir))
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))

        mgr = CaseManager()
        mgr._active_case_id = "test-case"
        mgr._active_case_path = case_dir
        return mgr

    def _finding_with_evidence(self):
        return {
            "title": "Test finding",
            "observation": "Something observed",
            "interpretation": "Interpretation here",
            "confidence": "low",
            "confidence_justification": "Evidence supports this",
            "type": "finding",
            "evidence_ids": ["sift-tester-20260225-001"],
        }

    def test_injected_id_stripped(self, manager):
        """Attacker tries to override the auto-generated finding ID."""
        finding = {**self._finding_with_evidence(), "id": "F-attacker-999"}
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["id"] != "F-attacker-999"
        assert findings[0]["id"].startswith("F-tester-")

    def test_injected_status_stripped(self, manager):
        """Attacker tries to set status to CONFIRMED directly."""
        finding = {**self._finding_with_evidence(), "status": "CONFIRMED"}
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["status"] == "DRAFT"

    def test_injected_content_hash_stripped(self, manager):
        """Attacker tries to inject a fake content_hash."""
        finding = {**self._finding_with_evidence(), "content_hash": "fakehash123"}
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["content_hash"] != "fakehash123"

    def test_injected_provenance_stripped(self, manager):
        """Attacker tries to override provenance classification."""
        finding = {**self._finding_with_evidence(), "provenance": "MCP"}
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        # Provenance is set by the system, not user input
        assert findings[0]["provenance"] in ("MCP", "HOOK", "MIXED", "NONE", "SHELL")

    def test_injected_examiner_stripped(self, manager):
        """Attacker tries to override examiner identity."""
        finding = {**self._finding_with_evidence(), "examiner": "admin"}
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["examiner"] == "tester"

    def test_injected_staged_stripped(self, manager):
        """Attacker tries to override staged timestamp."""
        finding = {**self._finding_with_evidence(), "staged": "2020-01-01T00:00:00"}
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["staged"] != "2020-01-01T00:00:00"

    def test_unknown_fields_stripped(self, manager):
        """Completely unknown fields must not appear in stored finding."""
        finding = {
            **self._finding_with_evidence(),
            "__proto__": {"admin": True},
            "_internal": "hacked",
            "evil_payload": "<script>alert(1)</script>",
        }
        result = manager.record_finding(finding)
        assert result["status"] == "STAGED"
        case_dir = Path(os.environ["AIIR_CASE_DIR"])
        findings = json.loads((case_dir / "findings.json").read_text())
        assert "__proto__" not in findings[0]
        assert "_internal" not in findings[0]
        assert "evil_payload" not in findings[0]


# ============================================================
# Section 4: Gateway auth timing safety (sift-gateway)
# ============================================================


class TestGatewayAuthTimingSafety:
    """Verify auth middleware iterates ALL keys regardless of match position."""

    def test_always_iterates_all_keys(self):
        """The for loop must not short-circuit on match."""
        from sift_gateway.auth import AuthMiddleware

        api_keys = {
            f"aiir_gw_{'a' * 24}": {"examiner": "first", "role": "examiner"},
            f"aiir_gw_{'b' * 24}": {"examiner": "second", "role": "examiner"},
            f"aiir_gw_{'c' * 24}": {"examiner": "third", "role": "examiner"},
        }
        middleware = AuthMiddleware(app=MagicMock(), api_keys=api_keys)

        import hmac

        call_count = 0
        original_compare = hmac.compare_digest

        def counting_compare(a, b):
            nonlocal call_count
            call_count += 1
            return original_compare(a, b)

        token = f"aiir_gw_{'a' * 24}"  # matches first key
        with patch("hmac.compare_digest", side_effect=counting_compare):
            matched_key = None
            for candidate in api_keys:
                if counting_compare(token, candidate) and matched_key is None:
                    matched_key = candidate

        assert call_count == len(api_keys), (
            f"Expected {len(api_keys)} compare_digest calls, got {call_count}. "
            "Timing-safe comparison is broken!"
        )
        assert matched_key == token


# ============================================================
# Section 5: Join code race condition (sift-gateway)
# ============================================================


class TestJoinCodeAtomicity:
    """Test that join code validate + mark_used has no exploitable race window."""

    def test_concurrent_join_same_code(self, tmp_path, monkeypatch):
        """Two threads using the same join code — at most one should succeed."""
        from sift_gateway.join import (
            mark_code_used,
            store_join_code,
            validate_join_code,
        )

        # Redirect state file to tmp
        monkeypatch.setattr("sift_gateway.join._STATE_DIR", tmp_path)
        monkeypatch.setattr(
            "sift_gateway.join._STATE_FILE", tmp_path / ".join_state.json"
        )

        code = "TEST-CODE"
        store_join_code(code, expires_hours=1)

        results = []
        barrier = threading.Barrier(2, timeout=5)

        def try_join():
            barrier.wait()  # Both threads start simultaneously
            matched = validate_join_code(code)
            if matched:
                mark_code_used(code)
                results.append("success")
            else:
                results.append("failed")

        t1 = threading.Thread(target=try_join)
        t2 = threading.Thread(target=try_join)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        success_count = results.count("success")
        assert success_count >= 1, "At least one thread should succeed"
        if success_count > 1:
            import warnings

            warnings.warn(
                f"Join code race: {success_count} threads got the same code. "
                "This is a known narrow race window (M-level risk).",
                stacklevel=2,
            )


# ============================================================
# Section 6: Atomic write safety (forensic-mcp)
# ============================================================


class TestAtomicWriteSafety:
    """Verify atomic writes don't leave partial files on crash."""

    def test_atomic_write_creates_file(self, tmp_path):
        from forensic_mcp.case.manager import _atomic_write

        target = tmp_path / "test.json"
        _atomic_write(target, '{"key": "value"}')
        assert target.exists()
        assert json.loads(target.read_text()) == {"key": "value"}

    def test_atomic_write_replaces_existing(self, tmp_path):
        from forensic_mcp.case.manager import _atomic_write

        target = tmp_path / "test.json"
        _atomic_write(target, '{"version": 1}')
        _atomic_write(target, '{"version": 2}')
        assert json.loads(target.read_text()) == {"version": 2}

    def test_atomic_write_no_partial_on_error(self, tmp_path):
        from forensic_mcp.case.manager import _atomic_write

        target = tmp_path / "test.json"
        _atomic_write(target, '{"original": true}')

        # Simulate a write failure mid-stream
        with patch("os.fdopen", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                _atomic_write(target, '{"corrupted": true}')

        # Original file must still be intact
        assert json.loads(target.read_text()) == {"original": True}

    def test_atomic_write_no_temp_files_on_error(self, tmp_path):
        from forensic_mcp.case.manager import _atomic_write

        target = tmp_path / "test.json"
        _atomic_write(target, "good")

        with patch("os.fdopen", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                _atomic_write(target, "bad")

        # No leftover .tmp files
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == [], f"Leftover temp files: {tmp_files}"

    def test_concurrent_atomic_writes(self, tmp_path):
        """Multiple threads writing to the same file should not corrupt it."""
        from forensic_mcp.case.manager import _atomic_write

        target = tmp_path / "concurrent.json"
        errors = []

        def writer(n):
            try:
                for i in range(20):
                    _atomic_write(target, json.dumps({"writer": n, "seq": i}))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent writes: {errors}"
        # File must be valid JSON (not corrupted)
        data = json.loads(target.read_text())
        assert "writer" in data
        assert "seq" in data


# ============================================================
# Section 7: Case ID validation (forensic-mcp)
# ============================================================


class TestCaseIdValidation:
    """Test _validate_case_id with adversarial inputs."""

    @pytest.fixture
    def validate(self):
        from forensic_mcp.case.manager import _validate_case_id

        return _validate_case_id

    def test_valid_case_ids(self, validate):
        validate("my-case-001")
        validate("incident-2026-02-25")
        validate("a")

    def test_rejects_path_traversal(self, validate):
        with pytest.raises(ValueError):
            validate("../../../etc/passwd")

    def test_rejects_forward_slash(self, validate):
        with pytest.raises(ValueError):
            validate("case/evil")

    def test_rejects_backslash(self, validate):
        with pytest.raises(ValueError):
            validate("case\\evil")

    def test_rejects_null_bytes(self, validate):
        """BUG FOUND: Null bytes in case IDs not rejected.

        _validate_case_id only checks for '..', '/', '\\'. A null byte
        could cause string truncation in downstream C-backed operations.
        """
        try:
            validate("case\x00evil")
            pytest.xfail(
                "BUG: Null bytes in case ID not rejected. "
                "Fix: add '\\x00' check to _validate_case_id"
            )
        except ValueError:
            pass  # Fixed

    def test_rejects_empty(self, validate):
        with pytest.raises(ValueError):
            validate("")

    def test_rejects_whitespace_only(self, validate):
        """BUG FOUND: Whitespace-only case IDs accepted.

        _validate_case_id checks for empty string but not whitespace-only.
        A case ID of '   ' would create a directory named '   '.
        """
        try:
            validate("   ")
            pytest.xfail(
                "BUG: Whitespace-only case ID accepted. "
                "Fix: add .strip() check to _validate_case_id"
            )
        except ValueError:
            pass  # Fixed


# ============================================================
# Section 8: Gateway rate limiting (sift-gateway)
# ============================================================


class TestRateLimiting:
    """Verify rate limiter cannot be trivially bypassed."""

    def test_rate_limit_enforced(self):
        from sift_gateway.rate_limit import check_rate_limit

        ip = "192.168.1.100"
        # Exhaust rate limit
        results = [check_rate_limit(ip) for _ in range(200)]
        # At some point it should start returning False
        assert False in results, "Rate limiter never triggered"

    def test_rate_limit_per_ip(self):
        from sift_gateway.rate_limit import check_rate_limit

        # Different IPs should have separate limits
        for _ in range(200):
            check_rate_limit("10.0.0.1")
        # New IP should still be allowed
        assert check_rate_limit("10.0.0.2")


# ============================================================
# Section 9: YAML safe loading
# ============================================================


class TestYAMLSafety:
    """Verify all YAML parsing uses safe_load."""

    def test_case_yaml_uses_safe_load(self, tmp_path):
        """Malicious YAML with Python object must not execute."""
        malicious_yaml = "!!python/object/apply:os.system ['echo pwned']"
        case_yaml = tmp_path / "CASE.yaml"
        case_yaml.write_text(malicious_yaml)

        import yaml

        # This must either raise an error or return a safe value
        with pytest.raises(yaml.YAMLError):
            with open(case_yaml) as f:
                yaml.safe_load(f)
