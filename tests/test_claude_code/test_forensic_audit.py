"""Tests for the forensic-audit.sh Claude Code hook script."""

import json
import os
import re
import subprocess
from pathlib import Path

# hook-<examiner>-<YYYYMMDD>-<26-char lowercase ULID>
ULID_ID = re.compile(r"^hook-tester-[0-9]{8}-[0-9a-hjkmnp-tv-z]{26}\Z")

HOOK_SCRIPT = (
    Path(__file__).parent.parent.parent
    / "claude-code"
    / "shared"
    / "hooks"
    / "forensic-audit.sh"
)


def _make_active_case(tmp_path):
    """Create active case directory and pointer file."""
    case_dir = tmp_path / "cases" / "INC-TEST"
    case_dir.mkdir(parents=True)
    vhir_dir = tmp_path / ".vhir"
    vhir_dir.mkdir(parents=True, exist_ok=True)
    (vhir_dir / "active_case").write_text(str(case_dir))
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
    """Build env dict overriding HOME and VHIR_EXAMINER."""
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["VHIR_EXAMINER"] = examiner
    # Remove env vars that would override active_case file resolution
    env.pop("VHIR_CASE_DIR", None)
    env.pop("VHIR_AUDIT_DIR", None)
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
            "tool_input": {"command": command},
            "tool_response": tool_response,
            "cwd": cwd,  # top level only, as Claude Code sends it
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
        assert entry["audit_id"].startswith("hook-tester-")
        assert entry["tool_use_id"] == "tu_123"
        assert entry["session_id"] == "sess_456"

    def test_records_the_sessions_cwd(self, tmp_path):
        """Claude Code sends cwd at the payload's top level, not in tool_input."""
        case_dir = _make_active_case(tmp_path)
        result = _run_hook(
            _hook_input(cwd="/home/examiner/cases/INC-1"), _make_env(tmp_path)
        )
        assert result.returncode == 0
        entry = json.loads(
            (case_dir / "audit" / "claude-code.jsonl").read_text().strip()
        )
        assert entry["cwd"] == "/home/examiner/cases/INC-1"

    def test_creates_audit_dir(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        # Don't pre-create audit dir
        assert not (case_dir / "audit").exists()
        env = _make_env(tmp_path)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        assert (case_dir / "audit" / "claude-code.jsonl").exists()

    def test_each_call_gets_its_own_audit_id(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        _run_hook(_hook_input(command="first"), env)
        _run_hook(_hook_input(command="second"), env)
        audit_file = case_dir / "audit" / "claude-code.jsonl"
        ids = [json.loads(x)["audit_id"] for x in audit_file.read_text().splitlines()]
        assert len(ids) == 2 and ids[0] != ids[1], ids
        assert all(ULID_ID.match(i) for i in ids), ids

    def test_parallel_calls_never_share_an_audit_id(self, tmp_path):
        """The 7z and vol3 commands sent together, as the AI does: each call
        gets its own id, so a citation of one can't resolve to another."""
        case_dir = _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        cmds = [
            "7z x evidence/mem.7z -oextract",
            "vol -f extract/mem2.raw windows.pslist",
        ]
        procs = [
            subprocess.Popen(
                ["sh", str(HOOK_SCRIPT)],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                env=env,
            )
            for _ in range(12)
        ]
        for i, p in enumerate(procs):
            p.stdin.write(_hook_input(command=cmds[i % 2], tool_use_id=f"tu{i}"))
            p.stdin.close()
        for p in procs:
            p.wait(timeout=60)
        audit_file = case_dir / "audit" / "claude-code.jsonl"
        ids = [json.loads(x)["audit_id"] for x in audit_file.read_text().splitlines()]
        assert len(ids) == 12 and len(set(ids)) == 12, sorted(ids)
        assert all(ULID_ID.match(i) for i in ids), ids

    def test_output_truncation(self, tmp_path):
        case_dir = _make_active_case(tmp_path)
        env = _make_env(tmp_path)
        long_output = "x" * 5000
        result = _run_hook(_hook_input(tool_response=long_output), env)
        assert result.returncode == 0
        audit_file = case_dir / "audit" / "claude-code.jsonl"
        entry = json.loads(audit_file.read_text().strip())
        assert len(entry["output_excerpt"]) <= 2000


class TestVhirCaseDirEnvVar:
    def test_env_var_takes_priority(self, tmp_path):
        """VHIR_CASE_DIR should be used instead of ~/.vhir/active_case."""
        # Set up active_case pointing to one dir
        file_case = _make_active_case(tmp_path)
        # Set up VHIR_CASE_DIR pointing to another dir
        env_case = tmp_path / "env-case"
        env_case.mkdir(parents=True)
        env = _make_env(tmp_path)
        env["VHIR_CASE_DIR"] = str(env_case)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        # Audit should be in VHIR_CASE_DIR, not active_case dir
        assert (env_case / "audit" / "claude-code.jsonl").exists()
        assert not (file_case / "audit").exists()

    def test_env_var_without_active_case_file(self, tmp_path):
        """VHIR_CASE_DIR works even without ~/.vhir/active_case."""
        env_case = tmp_path / "env-case"
        env_case.mkdir(parents=True)
        env = _make_env(tmp_path)
        env["VHIR_CASE_DIR"] = str(env_case)
        result = _run_hook(_hook_input(), env)
        assert result.returncode == 0
        assert (env_case / "audit" / "claude-code.jsonl").exists()

    def test_audit_dir_override(self, tmp_path):
        """VHIR_AUDIT_DIR overrides the default case_dir/audit path."""
        env_case = tmp_path / "env-case"
        env_case.mkdir(parents=True)
        custom_audit = tmp_path / "custom-audit"
        custom_audit.mkdir(parents=True)
        env = _make_env(tmp_path)
        env["VHIR_CASE_DIR"] = str(env_case)
        env["VHIR_AUDIT_DIR"] = str(custom_audit)
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
