"""Tests for the forensic-audit.sh Claude Code hook script."""

import json
import os
import subprocess
from pathlib import Path

HOOK_SCRIPT = (
    Path(__file__).parent.parent.parent / "claude-code" / "hooks" / "forensic-audit.sh"
)


def _make_active_case(tmp_path):
    """Create active case directory and pointer file."""
    case_dir = tmp_path / "cases" / "INC-TEST"
    case_dir.mkdir(parents=True)
    aiir_dir = tmp_path / ".aiir"
    aiir_dir.mkdir(parents=True, exist_ok=True)
    (aiir_dir / "active_case").write_text(str(case_dir))
    return case_dir


def _run_hook(stdin_data: str, env: dict) -> subprocess.CompletedProcess:
    """Run the hook script with given stdin and env."""
    return subprocess.run(
        ["sh", str(HOOK_SCRIPT)],
        input=stdin_data,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def _make_env(tmp_path, examiner="tester"):
    """Build env dict overriding HOME and AIIR_EXAMINER."""
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["AIIR_EXAMINER"] = examiner
    # Remove env vars that would override active_case file resolution
    env.pop("AIIR_CASE_DIR", None)
    env.pop("AIIR_AUDIT_DIR", None)
    return env


def _hook_input(
    command="ls -la",
    tool_response="file1\nfile2",
    tool_use_id="tu_123",
    session_id="sess_456",
    cwd="/tmp",
):
    return json.dumps(
        {
            "tool_input": {"command": command, "cwd": cwd},
            "tool_response": tool_response,
            "tool_use_id": tool_use_id,
            "session_id": session_id,
        }
    )


class TestWithActiveCase:
    def test_appends_valid_jsonl(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        audit_file = case_dir / "audit" / "claude-code.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["source"] == "claude-code-hook"
        assert entry["command"] == "ls -la"
        assert entry["evidence_id"].startswith("hook-tester-")
        assert entry["tool_use_id"] == "tu_123"
        assert entry["session_id"] == "sess_456"

    def test_creates_audit_dir(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        # Don't pre-create audit dir
        assert not (case_dir / "audit").exists()
        env = _make_env(tmp_path)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        assert (case_dir / "audit" / "claude-code.jsonl").exists()

    def test_evidence_id_sequencing(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        # Run twice
        _run_hook(_hook_input(command="first"), env)
        _run_hook(_hook_input(command="second"), env)
        audit_file = case_dir / "audit" / "claude-code.jsonl"
        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 2
        e1 = json.loads(lines[0])
        e2 = json.loads(lines[1])
        # Second should have higher sequence
        assert e1["evidence_id"].endswith("-001")
        assert e2["evidence_id"].endswith("-002")

    def test_output_truncation(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        long_output = "x" * 5000
        result = _run_hook(_hook_input(tool_response=long_output), env)
        assert result.returncode == 0
        audit_file = case_dir / "audit" / "claude-code.jsonl"
        entry = json.loads(audit_file.read_text().strip())
        assert len(entry["output_excerpt"]) <= 2000


class TestAiirCaseDirEnvVar:
    def test_env_var_takes_priority(self, tmp_path):
        """AIIR_CASE_DIR should be used instead of ~/.aiir/active_case."""
        # Set up active_case pointing to one dir
        file_case = _make_active_case(tmp_path)
        # Set up AIIR_CASE_DIR pointing to another dir
        env_case = tmp_path / "env-case"
        env_case.mkdir(parents=True)
        env = _make_env(tmp_path)
        env["AIIR_CASE_DIR"] = str(env_case)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        # Audit should be in AIIR_CASE_DIR, not active_case dir
        assert (env_case / "audit" / "claude-code.jsonl").exists()
        assert not (file_case / "audit").exists()

    def test_env_var_without_active_case_file(self, tmp_path):
        """AIIR_CASE_DIR works even without ~/.aiir/active_case."""
        env_case = tmp_path / "env-case"
        env_case.mkdir(parents=True)
        env = _make_env(tmp_path)
        env["AIIR_CASE_DIR"] = str(env_case)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        assert (env_case / "audit" / "claude-code.jsonl").exists()

    def test_audit_dir_override(self, tmp_path):
        """AIIR_AUDIT_DIR overrides the default case_dir/audit path."""
        env_case = tmp_path / "env-case"
        env_case.mkdir(parents=True)
        custom_audit = tmp_path / "custom-audit"
        custom_audit.mkdir(parents=True)
        env = _make_env(tmp_path)
        env["AIIR_CASE_DIR"] = str(env_case)
        env["AIIR_AUDIT_DIR"] = str(custom_audit)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        assert (custom_audit / "claude-code.jsonl").exists()
        assert not (env_case / "audit").exists()


class TestWithoutActiveCase:
    def test_exits_zero_no_audit(self, tmp_path):
        env = _make_env(tmp_path)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        # No audit file should be created
        assert not (tmp_path / "cases").exists()


class TestNeverExitsTwo:
    def test_empty_stdin(self, tmp_path):
        _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        result = _run_hook("", env)
        assert result.returncode != 2

    def test_bad_json(self, tmp_path):
        _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        result = _run_hook("NOT JSON", env)
        assert result.returncode != 2
