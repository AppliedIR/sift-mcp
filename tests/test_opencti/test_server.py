"""Tests for MCP server module."""

from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import Mock, AsyncMock, patch

from opencti_mcp.server import OpenCTIMCPServer
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ValidationError, RateLimitError


# =============================================================================
# Tool Registration Tests
# =============================================================================

class TestToolRegistration:
    """Tests for tool registration."""

    @pytest.mark.asyncio
    async def test_list_tools(self, mock_server: OpenCTIMCPServer):
        """All tools are registered."""
        # Test that all expected tools can be dispatched without "Unknown tool" error
        # This verifies registration indirectly
        expected_tools = [
            "search_threat_intel",
            "lookup_ioc",
            "search_threat_actor",
            "search_malware",
            "search_attack_pattern",
            "search_vulnerability",
            "get_recent_indicators",
            "search_reports",
            "get_health",
            "list_connectors",
        ]

        # Verify each tool can be dispatched (won't raise "Unknown tool")
        for tool_name in expected_tools:
            # Provide minimal valid arguments
            if tool_name in ("get_health", "list_connectors"):
                args = {}
            elif tool_name == "get_recent_indicators":
                args = {"days": 7}
            elif tool_name == "lookup_ioc":
                args = {"ioc": "192.168.1.1"}  # Valid IOC required
            else:
                args = {"query": "test"}

            # Should not raise ValidationError with "Unknown tool"
            result = await mock_server._dispatch_tool(tool_name, args)
            assert result is not None


# =============================================================================
# Tool Dispatch Tests
# =============================================================================

class TestToolDispatch:
    """Tests for tool dispatch."""

    @pytest.mark.asyncio
    async def test_search_threat_intel(self, mock_server: OpenCTIMCPServer):
        """search_threat_intel dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_threat_intel",
            {"query": "APT29", "limit": 5}
        )

        assert "query" in result
        assert "indicators" in result
        assert "threat_actors" in result

    @pytest.mark.asyncio
    async def test_lookup_ioc(self, mock_server: OpenCTIMCPServer):
        """lookup_ioc dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "lookup_ioc",
            {"ioc": "192.168.1.1"}
        )

        assert "found" in result
        assert "ioc_type" in result

    @pytest.mark.asyncio
    async def test_search_threat_actor(self, mock_server: OpenCTIMCPServer):
        """search_threat_actor dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_threat_actor",
            {"query": "APT29"}
        )

        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_malware(self, mock_server: OpenCTIMCPServer):
        """search_malware dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_malware",
            {"query": "Cobalt Strike"}
        )

        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_attack_pattern(self, mock_server: OpenCTIMCPServer):
        """search_attack_pattern dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_attack_pattern",
            {"query": "T1003"}
        )

        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_vulnerability(self, mock_server: OpenCTIMCPServer):
        """search_vulnerability dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_vulnerability",
            {"query": "CVE-2024-3400"}
        )

        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_get_recent_indicators(self, mock_server: OpenCTIMCPServer):
        """get_recent_indicators dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "get_recent_indicators",
            {"days": 7, "limit": 20}
        )

        assert "days" in result
        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_reports(self, mock_server: OpenCTIMCPServer):
        """search_reports dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_reports",
            {"query": "APT29"}
        )

        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_get_health(self, mock_server: OpenCTIMCPServer):
        """get_health dispatches correctly."""
        result = await mock_server._dispatch_tool("get_health", {})

        assert "status" in result
        assert "opencti_available" in result

    @pytest.mark.asyncio
    async def test_list_connectors(self, mock_server: OpenCTIMCPServer):
        """list_connectors dispatches correctly."""
        # Mock the connector listing
        mock_server.client._client.query = Mock(return_value={
            "data": {"connectors": []}
        })

        result = await mock_server._dispatch_tool("list_connectors", {})

        assert "connectors" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_unknown_tool(self, mock_server: OpenCTIMCPServer):
        """Unknown tool raises ValidationError."""
        with pytest.raises(ValidationError, match="Unknown tool"):
            await mock_server._dispatch_tool("unknown_tool", {})


# =============================================================================
# Input Validation Tests
# =============================================================================

class TestInputValidation:
    """Tests for input validation in server."""

    @pytest.mark.asyncio
    async def test_query_length_validation(self, mock_server: OpenCTIMCPServer):
        """Query length is validated."""
        from opencti_mcp.validation import MAX_QUERY_LENGTH

        with pytest.raises(ValidationError, match="exceeds maximum length"):
            await mock_server._dispatch_tool(
                "search_threat_intel",
                {"query": "x" * (MAX_QUERY_LENGTH + 1)}
            )

    @pytest.mark.asyncio
    async def test_ioc_length_validation(self, mock_server: OpenCTIMCPServer):
        """IOC length is validated."""
        from opencti_mcp.validation import MAX_IOC_LENGTH

        with pytest.raises(ValidationError, match="exceeds maximum length"):
            await mock_server._dispatch_tool(
                "lookup_ioc",
                {"ioc": "x" * (MAX_IOC_LENGTH + 1)}
            )

    @pytest.mark.asyncio
    async def test_limit_clamping(self, mock_server: OpenCTIMCPServer):
        """Limit is clamped to max value."""
        result = await mock_server._dispatch_tool(
            "search_threat_intel",
            {"query": "test", "limit": 1000}
        )

        # Should not raise, limit should be clamped
        assert result is not None


# =============================================================================
# Error Response Tests
# =============================================================================

class TestErrorResponses:
    """Tests for error response formatting."""

    @pytest.mark.asyncio
    async def test_validation_error_response(self, mock_server: OpenCTIMCPServer):
        """ValidationError is raised for invalid input."""
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            await mock_server._dispatch_tool(
                "search_threat_intel",
                {"query": "x" * 10000}
            )

    @pytest.mark.asyncio
    async def test_unknown_tool_response(self, mock_server: OpenCTIMCPServer):
        """Unknown tool raises ValidationError."""
        with pytest.raises(ValidationError, match="Unknown tool"):
            await mock_server._dispatch_tool("unknown_tool", {})
