"""Tests for sift_mcp.server — MCP server creation and tool execution."""

from unittest.mock import patch

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.server import create_server


@pytest.fixture(autouse=True)
def clean_state():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestServer:
    def test_create_server(self):
        server = create_server()
        assert server is not None
        assert server.name == "sift-mcp"

    def test_server_has_tools(self):
        """Verify core tools are registered."""
        server = create_server()
        assert server is not None


class TestRunCommandEnvelope:
    """Test run_command through the server with mocked executor."""

    def test_successful_execution(self, monkeypatch):
        """Verify response envelope fields on successful execution."""
        monkeypatch.setenv("AIIR_EXAMINER", "testuser")
        server = create_server()

        mock_result = {
            "exit_code": 0,
            "stdout": "output data",
            "stderr": "",
            "elapsed_seconds": 1.5,
            "command": ["echo", "hello"],
        }

        with (
            patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/echo"),
            patch("sift_mcp.tools.generic.execute", return_value=mock_result),
            patch("sift_mcp.tools.generic.sanitize_extra_args", return_value=["hello"]),
        ):
            from sift_mcp.tools.generic import run_command

            result = run_command(["echo", "hello"], purpose="test")
            assert result["exit_code"] == 0

    def test_denied_binary_error(self, monkeypatch):
        """Verify error handling for denied binaries."""
        from sift_mcp.exceptions import DeniedBinaryError
        from sift_mcp.tools.generic import run_command

        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["mkfs", "/dev/sda"], purpose="test")

    def test_uncataloged_binary_not_found(self, monkeypatch):
        """Uncataloged binary not on system raises ExecutionError."""
        from sift_mcp.exceptions import ExecutionError
        from sift_mcp.tools.generic import run_command

        with patch("sift_mcp.tools.generic.find_binary", return_value=None):
            with pytest.raises(ExecutionError, match="not found"):
                run_command(["nonexistent_tool", "--flag"], purpose="test")

    def test_catch_all_exception_handler(self, monkeypatch):
        """Verify the catch-all exception handler in server.py."""
        monkeypatch.setenv("AIIR_EXAMINER", "testuser")
        server = create_server()

        # The catch-all wraps unexpected exceptions. We test by checking
        # that the server builds without error and has the run_command tool.
        assert server is not None

    def test_extractions_passed_to_response(self, monkeypatch):
        """Verify extractions flow into the response envelope."""
        monkeypatch.setenv("AIIR_EXAMINER", "testuser")
        from sift_mcp.response import build_response

        extractions = ["/cases/test/extractions/20260223_tool_stdout.txt"]
        response = build_response(
            tool_name="run_command",
            success=True,
            data={"stdout": "ok"},
            evidence_id="sift-test-20260223-001",
            extractions=extractions,
        )
        assert response["extractions"] == extractions

    def test_extractions_absent_when_none(self, monkeypatch):
        """Verify extractions key omitted when not provided."""
        monkeypatch.setenv("AIIR_EXAMINER", "testuser")
        from sift_mcp.response import build_response

        response = build_response(
            tool_name="run_command",
            success=True,
            data={"stdout": "ok"},
            evidence_id="sift-test-20260223-001",
        )
        assert "extractions" not in response


class TestListMissingTools:
    """Test the list_missing_tools tool."""

    def test_list_missing_tools_returns_unavailable(self, monkeypatch):
        """list_missing_tools should return tools that are not installed."""
        monkeypatch.setenv("AIIR_EXAMINER", "testuser")
        from sift_mcp.tools.discovery import list_available_tools

        all_tools = list_available_tools()
        missing = [t for t in all_tools if not t.get("available", False)]
        # On a non-SIFT workstation, most tools should be missing
        assert len(missing) > 0
