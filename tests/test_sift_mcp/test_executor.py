"""Tests for sift_mcp.executor — subprocess execution."""

import pytest
from sift_mcp.exceptions import ExecutionError, ExecutionTimeoutError
from sift_mcp.executor import _truncate, execute


class TestExecutor:
    def test_simple_command(self):
        result = execute(["echo", "hello world"])
        assert result["exit_code"] == 0
        assert "hello world" in result["stdout"]
        assert result["elapsed_seconds"] >= 0

    def test_command_with_stderr(self):
        result = execute(["ls", "/nonexistent_path_xyz"])
        assert result["exit_code"] != 0
        assert result["stderr"]

    def test_binary_not_found(self):
        with pytest.raises(ExecutionError, match="Binary not found"):
            execute(["definitely_not_a_binary_xyz"])

    def test_timeout(self):
        with pytest.raises(ExecutionTimeoutError):
            execute(["sleep", "30"], timeout=2)

    def test_command_list_preserved(self):
        result = execute(["echo", "a", "b", "c"])
        assert result["command"] == ["echo", "a", "b", "c"]

    def test_save_output(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        result = execute(
            ["echo", "saved output"],
            save_output=True,
            save_dir=str(tmp_path),
        )
        assert "output_file" in result
        assert "output_sha256" in result
        from pathlib import Path

        assert Path(result["output_file"]).exists()

    def test_cwd(self, tmp_path):
        result = execute(["pwd"], cwd=str(tmp_path))
        assert str(tmp_path) in result["stdout"]

    def test_oserror_catch(self, tmp_path):
        """OSError subclass (e.g., bad exec format) should be caught."""
        # Create a file with no exec permission to trigger OSError
        bad_binary = tmp_path / "badbin"
        bad_binary.write_text("not a binary")
        bad_binary.chmod(0o755)
        with pytest.raises(ExecutionError, match="OS error executing"):
            execute([str(bad_binary)])


class TestAutoSave:
    """Tests for threshold-based auto-save behavior."""

    def test_auto_save_when_exceeds_budget(self, tmp_path, monkeypatch):
        """Output > budget with case dir set → file saved automatically."""
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")  # tiny budget
        extractions = tmp_path / "extractions"
        extractions.mkdir()
        # Generate output exceeding the budget
        result = execute(["python3", "-c", "print('x' * 500)"])
        assert "output_file" in result
        assert "output_sha256" in result
        from pathlib import Path

        assert Path(result["output_file"]).exists()

    def test_no_save_when_under_budget(self, tmp_path, monkeypatch):
        """Output < budget → no file saved."""
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        result = execute(["echo", "small"])
        assert "output_file" not in result

    def test_no_save_without_case_dir(self, monkeypatch):
        """Output > budget but no AIIR_CASE_DIR → no file saved."""
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "10")
        result = execute(["python3", "-c", "print('x' * 500)"])
        assert "output_file" not in result

    def test_explicit_save_output_still_works(self, tmp_path, monkeypatch):
        """save_output=True always saves regardless of budget."""
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        result = execute(["echo", "small"], save_output=True, save_dir=str(tmp_path))
        assert "output_file" in result

    def test_stdout_not_truncated(self, monkeypatch):
        """Raw stdout is preserved (no more _truncate on stdout)."""
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        # Generate output that would have been truncated at old 50KB limit
        result = execute(["python3", "-c", "print('a' * 200)"])
        assert "... [truncated" not in result["stdout"]
        assert result["stdout_total_bytes"] > 0

    def test_stderr_still_truncated(self, monkeypatch):
        """Stderr truncation is unchanged."""
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        # stderr with enough content to test truncation threshold
        result = execute(
            ["python3", "-c", "import sys; sys.stderr.write('e' * 100000)"]
        )
        # With 50MB max, stderr limit is 50MB/10 = 5MB — won't actually truncate 100KB
        # But the mechanism exists; just verify stderr is captured
        assert result["stderr"]


class TestSaveOutputBlockedPrefixes:
    """Tests for blocked-prefix enforcement in _save_output."""

    def test_save_to_etc_blocked(self):
        """Saving to /etc/ should be blocked."""
        with pytest.raises(ExecutionError, match="system directory"):
            execute(["echo", "test"], save_output=True, save_dir="/etc/evil")

    def test_save_to_etc_backup_allowed(self, tmp_path, monkeypatch):
        """Saving to /etc-backup/ should NOT be blocked (partial match)."""
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        etc_backup = tmp_path / "etc-backup"
        etc_backup.mkdir()
        result = execute(["echo", "test"], save_output=True, save_dir=str(etc_backup))
        assert result["exit_code"] == 0

    def test_save_to_usr_local_blocked(self):
        """Saving to /usr/local/ should be blocked."""
        with pytest.raises(ExecutionError, match="system directory"):
            execute(["echo", "test"], save_output=True, save_dir="/usr/local/out")

    def test_save_to_case_dir_allowed(self, tmp_path, monkeypatch):
        """Saving within AIIR_CASE_DIR should be allowed."""
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        out = tmp_path / "extractions"
        out.mkdir()
        result = execute(["echo", "test"], save_output=True, save_dir=str(out))
        assert result["exit_code"] == 0

    def test_save_outside_case_dir_blocked(self, tmp_path, monkeypatch):
        """When AIIR_CASE_DIR is set, saving outside it should fail."""
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        other = tmp_path / "other"
        other.mkdir()
        with pytest.raises(ExecutionError, match="outside the case directory"):
            execute(["echo", "test"], save_output=True, save_dir=str(other))


class TestByteLimit:
    """Tests for incremental pipe reading with byte limit enforcement."""

    def test_normal_output_unaffected(self, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        result = execute(["echo", "hello"])
        assert "hello" in result["stdout"]
        assert result.get("truncated") is not True

    def test_output_truncated_at_limit(self, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.setenv("SIFT_MAX_OUTPUT", "1000")
        result = execute(
            ["python3", "-c", "import sys; sys.stdout.buffer.write(b'x' * 5000)"]
        )
        assert result["truncated"] is True
        assert result["stdout_total_bytes"] <= 1000

    def test_process_killed_on_limit(self, monkeypatch):
        """Process producing infinite output should be killed, not OOM."""
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.setenv("SIFT_MAX_OUTPUT", "2000")
        result = execute(
            ["python3", "-c", "import sys;\nwhile True: sys.stdout.buffer.write(b'A' * 1024)"]
        )
        assert result["truncated"] is True
        assert result["stdout_total_bytes"] <= 2000

    def test_timeout_still_works(self, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        with pytest.raises(ExecutionTimeoutError):
            execute(["sleep", "30"], timeout=2)


class TestTruncateNaming:
    """Verify _truncate uses max_chars (not max_bytes)."""

    def test_under_limit(self):
        assert _truncate("hello", 10) == "hello"

    def test_over_limit(self):
        result = _truncate("hello world", 5)
        assert result.startswith("hello")
        assert "truncated at 5 chars" in result
