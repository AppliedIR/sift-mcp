"""Tests for sift_mcp.tools.generic — denylist-protected execution."""

import os

import pytest
from unittest.mock import patch

from sift_mcp.tools.generic import run_command
from sift_mcp.exceptions import DeniedBinaryError, ExecutionError
from sift_mcp.catalog import clear_catalog_cache


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestGenericRunCommand:
    def test_rejects_denied_binary(self):
        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["mkfs", "/dev/sda1"])

    def test_rejects_dd(self):
        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["dd", "if=/dev/zero", "of=/dev/sda"])

    def test_rejects_shutdown(self):
        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["shutdown", "-h", "now"])

    def test_rejects_empty_command(self):
        with pytest.raises(ValueError, match="Empty command"):
            run_command([])

    def test_strips_path_prefix_denied(self):
        """Binary with full path should still be checked against denylist."""
        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["/usr/sbin/mkfs", "/dev/sda1"])

    def test_allows_uncataloged_binary(self):
        """Uncataloged binaries can execute if found on system."""
        mock_result = {
            "exit_code": 0,
            "stdout": "hello",
            "stderr": "",
            "elapsed_seconds": 0.1,
            "command": ["echo", "hello"],
        }
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/echo"), \
             patch("sift_mcp.tools.generic.execute", return_value=mock_result):
            result = run_command(["echo", "hello"])
            assert result["exit_code"] == 0

    def test_binary_not_found_raises_execution_error(self):
        """Binary not on system raises ExecutionError, not catalog error."""
        with patch("sift_mcp.tools.generic.find_binary", return_value=None):
            with pytest.raises(ExecutionError, match="not found"):
                run_command(["nonexistent_tool", "--flag"])

    def test_denied_binary_error_message(self):
        """Verify the error message for denied binaries."""
        with pytest.raises(DeniedBinaryError) as exc_info:
            run_command(["fdisk", "/dev/sda"])
        assert "cannot be overridden" in str(exc_info.value)

    def test_rm_blocks_root(self):
        """rm -rf / is blocked."""
        with pytest.raises(ValueError, match="filesystem root"):
            run_command(["rm", "-rf", "/"])

    def test_rm_blocks_evidence_directory(self, tmp_path, monkeypatch):
        """rm targeting case evidence dir is blocked."""
        case_dir = tmp_path / "INC-2026-001"
        case_dir.mkdir()
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        with pytest.raises(ValueError, match="case evidence"):
            run_command(["rm", "-rf", str(evidence_dir)])

    def test_rm_blocks_cases_dir(self):
        """rm targeting /cases is blocked."""
        with pytest.raises(ValueError, match="protected evidence directory"):
            run_command(["rm", "-rf", "/cases"])

    def test_rm_allows_temp_cleanup(self):
        """rm on non-protected dir succeeds (if binary found)."""
        mock_result = {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0.1,
            "command": ["rm", "/tmp/parsed_output.csv"],
            "stdout_total_bytes": 0,
        }
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/rm"), \
             patch("sift_mcp.tools.generic.execute", return_value=mock_result):
            result = run_command(["rm", "/tmp/parsed_output.csv"])
            assert result["exit_code"] == 0


class TestOutputParsing:
    """Tests for byte-budgeted output parsing in run_command."""

    def _mock_exec(self, stdout, stdout_bytes=None):
        """Build a mock execute result."""
        if stdout_bytes is None:
            stdout_bytes = len(stdout.encode("utf-8"))
        return {
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
            "elapsed_seconds": 0.1,
            "command": ["sometool", "--flag"],
            "stdout_total_bytes": stdout_bytes,
        }

    def test_small_output_returns_raw(self):
        """Output under budget → no parsing, raw stdout in result."""
        result = self._mock_exec("small output")
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"), \
             patch("sift_mcp.tools.generic.execute", return_value=result):
            out = run_command(["sometool", "--flag"])
        assert out["stdout"] == "small output"
        assert "_parsed" not in out

    def test_large_output_parsed_text(self, monkeypatch):
        """Text output over budget → _parsed with lines."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")
        big_output = "\n".join(f"line {i}" for i in range(500))
        result = self._mock_exec(big_output)
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"), \
             patch("sift_mcp.tools.generic.execute", return_value=result):
            out = run_command(["sometool", "--flag"])
        assert "_parsed" in out
        assert out["_output_format"] == "parsed_text"
        assert out["_parsed"]["total_lines"] == 500
        assert out["_parsed"]["preview_lines"] < 500
        assert out["stdout"] is None

    def test_large_output_parsed_csv(self, monkeypatch):
        """CSV tool output over budget → _parsed with rows + columns."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "200")
        csv_output = "Name,Value\n" + "\n".join(f"item{i},{i}" for i in range(500))
        result = self._mock_exec(csv_output)

        from sift_mcp.catalog import ToolDefinition
        mock_td = ToolDefinition(
            name="csvtool", binary="csvtool", category="test",
            output_format="csv",
        )
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/csvtool"), \
             patch("sift_mcp.tools.generic.execute", return_value=result), \
             patch("sift_mcp.tools.generic.get_tool_def", return_value=mock_td):
            out = run_command(["csvtool", "--flag"])
        assert out["_output_format"] == "parsed_csv"
        assert out["_parsed"]["total_rows"] >= 490  # ~500 data rows
        assert out["_parsed"]["preview_rows"] < out["_parsed"]["total_rows"]
        assert out["_parsed"]["columns"] == ["Name", "Value"]

    def test_large_output_parsed_json(self, monkeypatch):
        """JSON tool output over budget → _parsed with entries."""
        import json as json_mod
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "200")
        json_output = json_mod.dumps([{"id": i} for i in range(500)])
        result = self._mock_exec(json_output)

        from sift_mcp.catalog import ToolDefinition
        mock_td = ToolDefinition(
            name="jsontool", binary="jsontool", category="test",
            output_format="json",
        )
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/jsontool"), \
             patch("sift_mcp.tools.generic.execute", return_value=result), \
             patch("sift_mcp.tools.generic.get_tool_def", return_value=mock_td):
            out = run_command(["jsontool", "--flag"])
        assert out["_output_format"] == "parsed_json"
        assert out["_parsed"]["total_entries"] == 500
        assert out["_parsed"]["preview_entries"] < 500

    def test_uncataloged_tool_defaults_to_text(self, monkeypatch):
        """Non-catalog tool → text parser used."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")
        big_output = "\n".join(f"line {i}" for i in range(500))
        result = self._mock_exec(big_output)
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"), \
             patch("sift_mcp.tools.generic.execute", return_value=result), \
             patch("sift_mcp.tools.generic.get_tool_def", return_value=None):
            out = run_command(["sometool", "--flag"])
        assert out["_output_format"] == "parsed_text"

    def test_stdout_nulled_when_parsed(self, monkeypatch):
        """Raw stdout set to None when _parsed present."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")
        big_output = "\n".join(f"line {i}" for i in range(500))
        result = self._mock_exec(big_output)
        with patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"), \
             patch("sift_mcp.tools.generic.execute", return_value=result):
            out = run_command(["sometool", "--flag"])
        assert out["stdout"] is None
        assert out["_parsed"] is not None
