"""Tests for sift_mcp.tools.generic — denylist-protected execution."""

from unittest.mock import patch

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.exceptions import DeniedBinaryError, ExecutionError
from sift_mcp.tools.generic import run_command


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestGenericRunCommand:
    def test_rejects_denied_binary(self):
        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["mkfs", "/dev/sda1"])

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
        with (
            patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/echo"),
            patch("sift_mcp.tools.generic.execute", return_value=mock_result),
        ):
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
            run_command(["mkfs.ext4", "/dev/sda"])
        assert "cannot be overridden" in str(exc_info.value)

    def test_rm_blocks_root(self):
        """rm -rf / is blocked."""
        with pytest.raises(ValueError):
            run_command(["rm", "-rf", "/"])

    def test_rm_blocks_evidence_directory(self, tmp_path, monkeypatch):
        """rm targeting case evidence dir is blocked."""
        case_dir = tmp_path / "INC-2026-001"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: test\n")
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir()
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        with pytest.raises(ValueError):
            run_command(["rm", "-rf", str(evidence_dir)])

    def test_rm_blocks_cases_dir(self):
        """rm targeting /cases is blocked."""
        with pytest.raises(ValueError):
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
        with (
            patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/rm"),
            patch("sift_mcp.tools.generic.execute", return_value=mock_result),
        ):
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
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
        ):
            out = run_command(["sometool", "--flag"])
        assert out["stdout"] == "small output"
        assert "_parsed" not in out

    def test_large_output_parsed_text(self, monkeypatch):
        """Text output over budget → _parsed with lines."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")
        big_output = "\n".join(f"line {i}" for i in range(500))
        result = self._mock_exec(big_output)
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
        ):
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
            name="csvtool",
            binary="csvtool",
            category="test",
            output_format="csv",
        )
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/csvtool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
            patch("sift_mcp.tools.generic.get_tool_def", return_value=mock_td),
        ):
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
            name="jsontool",
            binary="jsontool",
            category="test",
            output_format="json",
        )
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/jsontool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
            patch("sift_mcp.tools.generic.get_tool_def", return_value=mock_td),
        ):
            out = run_command(["jsontool", "--flag"])
        assert out["_output_format"] == "parsed_json"
        assert out["_parsed"]["total_entries"] == 500
        assert out["_parsed"]["preview_entries"] < 500

    def test_uncataloged_tool_defaults_to_text(self, monkeypatch):
        """Non-catalog tool → text parser used."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")
        big_output = "\n".join(f"line {i}" for i in range(500))
        result = self._mock_exec(big_output)
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
            patch("sift_mcp.tools.generic.get_tool_def", return_value=None),
        ):
            out = run_command(["sometool", "--flag"])
        assert out["_output_format"] == "parsed_text"

    def test_stdout_nulled_when_parsed(self, monkeypatch):
        """Raw stdout set to None when _parsed present."""
        monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "100")
        big_output = "\n".join(f"line {i}" for i in range(500))
        result = self._mock_exec(big_output)
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/sometool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
        ):
            out = run_command(["sometool", "--flag"])
        assert out["stdout"] is None
        assert out["_parsed"] is not None


class TestPreviewLinesCapsJson:
    """preview_lines caps the entries of a JSON/JSONL reply above the byte
    budget, as it caps CSV rows and text lines."""

    _ROWS = [
        {
            "PID": 1000 + i,
            "PPID": 4,
            "ImageFileName": f"svchost{i}.exe",
            "CreateTime": "2018-09-06T17:00:00+00:00",
            "ExitTime": None,
            "__children": [],
        }
        for i in range(400)
    ]

    def _run(self, stdout, preview_lines=0, budget=None, monkeypatch=None):
        from sift_mcp.catalog import ToolDefinition

        if budget is None:
            monkeypatch.delenv("SIFT_RESPONSE_BUDGET", raising=False)
        else:
            monkeypatch.setenv("SIFT_RESPONSE_BUDGET", str(budget))
        result = {
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
            "stdout_total_bytes": len(stdout.encode("utf-8")),
        }
        td = ToolDefinition(
            name="jsontool", binary="jsontool", category="test", output_format="json"
        )
        with (
            patch(
                "sift_mcp.tools.generic.find_binary", return_value="/usr/bin/jsontool"
            ),
            patch("sift_mcp.tools.generic.execute", return_value=result),
            patch("sift_mcp.tools.generic.get_tool_def", return_value=td),
        ):
            return run_command(["jsontool"], preview_lines=preview_lines)

    @pytest.mark.parametrize("n", [1, 5, 20])
    def test_json_array_capped_at_n(self, n, monkeypatch):
        import json as json_mod

        out = self._run(
            json_mod.dumps(self._ROWS, indent=2), n, monkeypatch=monkeypatch
        )
        assert out["_output_format"] == "parsed_json"
        assert out["_parsed"]["data"] == self._ROWS[:n]
        assert out["_parsed"]["preview_entries"] == n
        assert out["_parsed"]["total_entries"] == 400
        assert out["_parsed"]["truncated"] is True

    @pytest.mark.parametrize("n", [1, 5, 20])
    def test_jsonl_capped_at_n(self, n, monkeypatch):
        import json as json_mod

        text = "\n".join(json_mod.dumps(r) for r in self._ROWS)
        out = self._run(text, n, monkeypatch=monkeypatch)
        assert out["_output_format"] == "parsed_json"
        assert out["_parsed"]["data"] == self._ROWS[:n]
        assert out["_parsed"]["total_entries"] == 400

    def test_budget_still_binds_below_n(self, monkeypatch):
        """N larger than the budget holds: the budget stops first."""
        import json as json_mod

        wide = [dict(r, CommandLine="x" * 600) for r in self._ROWS]
        out = self._run(json_mod.dumps(wide), 100, monkeypatch=monkeypatch)
        # budget = max(10240, 100 * 200) = 20000 bytes: about 27 rows of ~740 B
        assert out["_parsed"]["data"] == wide[: len(out["_parsed"]["data"])]
        assert 1 <= len(out["_parsed"]["data"]) < 100
        assert out["_parsed"]["preview_bytes"] <= 20000

    def test_preview_lines_zero_keeps_budget_fill(self, monkeypatch):
        """Twin: no preview_lines gives the base budget fill, not a cap."""
        import json as json_mod

        from sift_common.parsers.json_parser import parse_json

        text = json_mod.dumps(self._ROWS, indent=2)
        out = self._run(text, 0, monkeypatch=monkeypatch)
        assert out["_parsed"] == parse_json(text, byte_budget=10_240)
        assert len(out["_parsed"]["data"]) > 20

    @pytest.mark.parametrize("n", [0, 5])
    def test_under_budget_returned_whole(self, n, monkeypatch):
        """Twin: output under the budget is returned whole, preview_lines or not."""
        import json as json_mod

        text = json_mod.dumps(self._ROWS[:30])
        out = self._run(text, n, budget=len(text) + 1, monkeypatch=monkeypatch)
        assert out["stdout"] == text
        assert "_parsed" not in out
        assert out["_output_format"] == "json"

    def test_seed_shapes_kept_verbatim_and_counted(self, monkeypatch):
        """Seed shapes as entries: the first N come back as they were, N at most."""
        import json as json_mod

        shapes = [
            {"value": "10.0.0.1", "type": "ip"},
            {"value": "x"},
            ["a", "b"],
            "plain",
            42,
            None,
            "",
            "tab\there",
            "cr\rhere",
            "esc\x1b[31mred",
            "nul\x00here",
            "c1\x85\x9bhere",
            "non-ascii é 日本",
            "<script>alert(1)</script>&amp;",
            {"host": ["dc01", "dev01"]},
            "L" * (70 * 1024),
        ] * 3
        text = json_mod.dumps(shapes)
        for n in (5, 16):
            out = self._run(text, n, monkeypatch=monkeypatch)
            data = out["_parsed"]["data"]
            assert len(data) <= n
            assert data == shapes[: len(data)]
        out = self._run(text, 16, budget=200_000, monkeypatch=monkeypatch)
        assert out["_parsed"]["data"] == shapes[:16]
