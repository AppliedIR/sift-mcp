"""Tests for sift_mcp.executor — subprocess execution."""

import pytest
from sift_mcp.executor import execute
from sift_mcp.exceptions import ExecutionError, TimeoutError


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
        with pytest.raises(TimeoutError):
            execute(["sleep", "10"], timeout=1)

    def test_command_list_preserved(self):
        result = execute(["echo", "a", "b", "c"])
        assert result["command"] == ["echo", "a", "b", "c"]

    def test_save_output(self, tmp_path):
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
