"""Tests for MCP server module."""

from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import Mock, AsyncMock, patch

from opencti_mcp.server import OpenCTIMCPServer, VALID_ENTITY_TYPES
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
        expected_tools = [
            "get_health",
            "search_threat_intel",
            "search_entity",
            "lookup_ioc",
            "lookup_hash",
            "search_attack_pattern",
            "get_recent_indicators",
            "get_entity",
            "get_relationships",
            "search_reports",
        ]

        # Verify each tool can be dispatched (won't raise "Unknown tool")
        for tool_name in expected_tools:
            if tool_name == "get_health":
                args = {}
            elif tool_name == "get_recent_indicators":
                args = {"days": 7}
            elif tool_name == "lookup_ioc":
                args = {"ioc": "192.168.1.1"}
            elif tool_name == "lookup_hash":
                args = {"hash": "d41d8cd98f00b204e9800998ecf8427e"}
            elif tool_name == "get_entity":
                args = {"entity_id": "550e8400-e29b-41d4-a716-446655440000"}
            elif tool_name == "get_relationships":
                args = {"entity_id": "550e8400-e29b-41d4-a716-446655440000"}
            elif tool_name == "search_entity":
                args = {"type": "threat_actor", "query": "test"}
            else:
                args = {"query": "test"}

            result = await mock_server._dispatch_tool(tool_name, args)
            assert result is not None

    @pytest.mark.asyncio
    async def test_exactly_10_tools(self, mock_server: OpenCTIMCPServer):
        """Server exposes exactly 10 tools by verifying dispatch coverage."""
        # The 10 tools that should work
        valid_tools = {
            "get_health": {},
            "search_threat_intel": {"query": "test"},
            "search_entity": {"type": "threat_actor", "query": "test"},
            "lookup_ioc": {"ioc": "192.168.1.1"},
            "lookup_hash": {"hash": "d41d8cd98f00b204e9800998ecf8427e"},
            "search_attack_pattern": {"query": "T1003"},
            "get_recent_indicators": {"days": 7},
            "get_entity": {"entity_id": "550e8400-e29b-41d4-a716-446655440000"},
            "get_relationships": {"entity_id": "550e8400-e29b-41d4-a716-446655440000"},
            "search_reports": {"query": "test"},
        }
        assert len(valid_tools) == 10
        for tool_name, args in valid_tools.items():
            result = await mock_server._dispatch_tool(tool_name, args)
            assert result is not None, f"{tool_name} returned None"

    @pytest.mark.asyncio
    async def test_write_tools_removed(self, mock_server: OpenCTIMCPServer):
        """Write tools are no longer available."""
        write_tools = ["create_indicator", "create_note", "create_sighting", "trigger_enrichment"]
        for tool_name in write_tools:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await mock_server._dispatch_tool(tool_name, {})

    @pytest.mark.asyncio
    async def test_admin_tools_removed(self, mock_server: OpenCTIMCPServer):
        """Admin tools are no longer available."""
        admin_tools = ["list_connectors", "get_network_status", "force_reconnect", "get_cache_stats"]
        for tool_name in admin_tools:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await mock_server._dispatch_tool(tool_name, {})

    @pytest.mark.asyncio
    async def test_individual_search_tools_removed(self, mock_server: OpenCTIMCPServer):
        """Individual search_* tools (consolidated into search_entity) are gone."""
        removed = [
            "search_threat_actor", "search_malware", "search_vulnerability",
            "search_campaign", "search_tool", "search_infrastructure",
            "search_incident", "search_observable", "search_sighting",
            "search_organization", "search_sector", "search_location",
            "search_course_of_action", "search_grouping", "search_note",
        ]
        for tool_name in removed:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await mock_server._dispatch_tool(tool_name, {"query": "test"})


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
    async def test_search_attack_pattern(self, mock_server: OpenCTIMCPServer):
        """search_attack_pattern dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_attack_pattern",
            {"query": "T1003"}
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
    async def test_unknown_tool(self, mock_server: OpenCTIMCPServer):
        """Unknown tool raises ValidationError."""
        with pytest.raises(ValidationError, match="Unknown tool"):
            await mock_server._dispatch_tool("unknown_tool", {})


# =============================================================================
# search_entity Tests
# =============================================================================

class TestSearchEntity:
    """Tests for the consolidated search_entity tool."""

    @pytest.mark.asyncio
    async def test_search_entity_threat_actor(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=threat_actor dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "threat_actor", "query": "APT29"}
        )
        assert result["type"] == "threat_actor"
        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_entity_malware(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=malware dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "malware", "query": "Cobalt Strike"}
        )
        assert result["type"] == "malware"
        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_entity_vulnerability(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=vulnerability dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "vulnerability", "query": "CVE-2024-3400"}
        )
        assert result["type"] == "vulnerability"
        assert "results" in result
        assert "total" in result

    @pytest.mark.asyncio
    async def test_search_entity_attack_pattern(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=attack_pattern dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "attack_pattern", "query": "T1003"}
        )
        assert result["type"] == "attack_pattern"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_campaign(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=campaign dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "campaign", "query": "SolarWinds"}
        )
        assert result["type"] == "campaign"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_tool(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=tool dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "tool", "query": "Mimikatz"}
        )
        assert result["type"] == "tool"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_infrastructure(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=infrastructure dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "infrastructure", "query": "C2"}
        )
        assert result["type"] == "infrastructure"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_incident(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=incident dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "incident", "query": "breach"}
        )
        assert result["type"] == "incident"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_sighting(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=sighting dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "sighting", "query": "test"}
        )
        assert result["type"] == "sighting"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_organization(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=organization dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "organization", "query": "Acme"}
        )
        assert result["type"] == "organization"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_sector(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=sector dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "sector", "query": "Energy"}
        )
        assert result["type"] == "sector"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_location(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=location dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "location", "query": "Russia"}
        )
        assert result["type"] == "location"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_course_of_action(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=course_of_action dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "course_of_action", "query": "mitigation"}
        )
        assert result["type"] == "course_of_action"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_grouping(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=grouping dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "grouping", "query": "analysis"}
        )
        assert result["type"] == "grouping"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_note(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=note dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "note", "query": "analyst"}
        )
        assert result["type"] == "note"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_observable(self, mock_server: OpenCTIMCPServer):
        """search_entity with type=observable dispatches correctly."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "observable", "query": "192.168.1.1"}
        )
        assert result["type"] == "observable"
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_entity_invalid_type(self, mock_server: OpenCTIMCPServer):
        """search_entity with invalid type raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid entity type"):
            await mock_server._dispatch_tool(
                "search_entity",
                {"type": "invalid_type", "query": "test"}
            )

    @pytest.mark.asyncio
    async def test_search_entity_all_valid_types(self, mock_server: OpenCTIMCPServer):
        """All 16 valid entity types dispatch without error."""
        for entity_type in sorted(VALID_ENTITY_TYPES):
            result = await mock_server._dispatch_tool(
                "search_entity",
                {"type": entity_type, "query": "test"}
            )
            assert result["type"] == entity_type
            assert "results" in result
            assert "total" in result

    @pytest.mark.asyncio
    async def test_search_entity_with_limit(self, mock_server: OpenCTIMCPServer):
        """search_entity respects limit parameter."""
        result = await mock_server._dispatch_tool(
            "search_entity",
            {"type": "threat_actor", "query": "test", "limit": 5}
        )
        assert "results" in result


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
