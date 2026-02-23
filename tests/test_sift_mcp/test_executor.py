"""Tests for sift_mcp.executor — subprocess execution."""

import pytest
from sift_mcp.executor import execute
from sift_mcp.exceptions import ExecutionError, ExecutionTimeoutError


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
            execute(["sleep", "10"], timeout=1)

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
