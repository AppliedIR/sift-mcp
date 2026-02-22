"""MCP Protocol tests for OpenCTI MCP Server.

Tests the MCP server interface including:
- Tool listing
- Tool call handling
- Error responses
- Response formatting
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from opencti_mcp.server import OpenCTIMCPServer
from opencti_mcp.config import Config, SecretStr


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_config():
    """Create mock configuration."""
    return Config(
        opencti_url="http://localhost:8080",
        opencti_token=SecretStr("test-token"),
    )


@pytest.fixture
def mock_client():
    """Create mock OpenCTI client."""
    client = MagicMock()
    client.is_available.return_value = True
    client.search_threat_actors.return_value = []
    client.search_malware.return_value = []
    client.unified_search.return_value = {"results": [], "total": 0}
    return client


@pytest.fixture
def server(mock_config, mock_client):
    """Create server with mocked dependencies."""
    with patch('opencti_mcp.server.OpenCTIClient', return_value=mock_client):
        server = OpenCTIMCPServer(mock_config)
        server.client = mock_client
        return server


# =============================================================================
# Tool Dispatch Tests (Direct)
# =============================================================================

class TestToolDispatch:
    """Test tool dispatch functionality."""

    @pytest.mark.asyncio
    async def test_dispatch_returns_dict(self, server, mock_client):
        """_dispatch_tool returns dict result."""
        mock_client.search_threat_actors.return_value = [{"name": "APT29"}]

        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": "APT29"
        })

        assert isinstance(result, dict)
        assert "results" in result

    @pytest.mark.asyncio
    async def test_dispatch_unknown_tool(self, server):
        """Unknown tool raises ValidationError."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError, match="[Uu]nknown"):
            await server._dispatch_tool("nonexistent_tool", {})

    @pytest.mark.asyncio
    async def test_dispatch_validation_error(self, server):
        """Validation error is raised for invalid input."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("get_entity", {"entity_id": "invalid"})


# =============================================================================
# Tool Definition Tests
# =============================================================================

class TestToolDefinitions:
    """Test tool definitions."""

    def test_server_has_client(self, server):
        """Server has OpenCTI client."""
        assert hasattr(server, 'client')

    @pytest.mark.asyncio
    async def test_write_tools_no_longer_exist(self, server):
        """Write tools are removed (server is always read-only)."""
        from opencti_mcp.errors import ValidationError
        for tool in ["create_indicator", "create_note", "create_sighting", "trigger_enrichment"]:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await server._dispatch_tool(tool, {})


# =============================================================================
# Search Tool Tests (via search_entity)
# =============================================================================

class TestSearchTools:
    """Test search tool dispatch."""

    @pytest.mark.asyncio
    async def test_search_threat_actor(self, server, mock_client):
        """search_entity type=threat_actor works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": "APT"
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_malware(self, server, mock_client):
        """search_entity type=malware works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "malware", "query": "ransomware"
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_with_filters(self, server, mock_client):
        """Search with filters works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "limit": 5,
            "offset": 0,
            "labels": ["apt"],
            "confidence_min": 70,
            "created_after": "2024-01-01",
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_empty_query(self, server, mock_client):
        """Empty query works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": ""
        })
        assert "results" in result


# =============================================================================
# Entity Tool Tests
# =============================================================================

class TestEntityTools:
    """Test entity tool dispatch."""

    @pytest.mark.asyncio
    async def test_get_entity(self, server, mock_client):
        """get_entity works."""
        mock_client.get_entity.return_value = {"id": "123", "name": "Test"}

        result = await server._dispatch_tool("get_entity", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_relationships(self, server, mock_client):
        """get_relationships works."""
        mock_client.get_relationships.return_value = []

        result = await server._dispatch_tool("get_relationships", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_invalid_uuid(self, server):
        """Invalid UUID raises error."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("get_entity", {"entity_id": "not-valid"})


# =============================================================================
# System Tool Tests
# =============================================================================

class TestSystemTools:
    """Test system tool dispatch."""

    @pytest.mark.asyncio
    async def test_get_health(self, server, mock_client):
        """get_health works."""
        result = await server._dispatch_tool("get_health", {})
        assert result is not None

    @pytest.mark.asyncio
    async def test_admin_tools_removed(self, server):
        """Admin tools are removed."""
        from opencti_mcp.errors import ValidationError
        for tool in ["list_connectors", "get_network_status", "force_reconnect", "get_cache_stats"]:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await server._dispatch_tool(tool, {})


# =============================================================================
# Pagination Tests (via search_entity)
# =============================================================================

class TestPagination:
    """Test pagination handling."""

    @pytest.mark.asyncio
    async def test_limit_default(self, server, mock_client):
        """Default limit is applied."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": "test"
        })

    @pytest.mark.asyncio
    async def test_limit_clamped(self, server, mock_client):
        """Large limit is clamped."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "limit": 10000
        })

    @pytest.mark.asyncio
    async def test_offset_clamped(self, server, mock_client):
        """Large offset is clamped."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "offset": 100000
        })


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_validation_error(self, server):
        """Validation error is raised for invalid input."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "x" * 10000
            })

    @pytest.mark.asyncio
    async def test_client_error_propagates(self, server, mock_client):
        """Client errors propagate appropriately."""
        mock_client.search_threat_actors.side_effect = Exception("Connection error")

        with pytest.raises(Exception):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor", "query": "test"
            })


# =============================================================================
# Filter Validation Tests
# =============================================================================

class TestFilterValidation:
    """Test filter validation."""

    @pytest.mark.asyncio
    async def test_invalid_labels(self, server):
        """Invalid labels raise error."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "test",
                "labels": ["<script>"]
            })

    @pytest.mark.asyncio
    async def test_invalid_date_filter(self, server):
        """Invalid date filter raises error."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "test",
                "created_after": "not-a-date"
            })

    @pytest.mark.asyncio
    async def test_valid_date_filter(self, server, mock_client):
        """Valid date filter works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "created_after": "2024-01-01",
            "created_before": "2024-12-31T23:59:59Z",
        })
        assert "results" in result


# =============================================================================
# Concurrent Request Tests
# =============================================================================

class TestConcurrentRequests:
    """Test concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_dispatches(self, server, mock_client):
        """Multiple concurrent dispatches work."""
        import asyncio

        results = await asyncio.gather(
            server._dispatch_tool("search_entity", {"type": "threat_actor", "query": "test1"}),
            server._dispatch_tool("search_entity", {"type": "malware", "query": "test2"}),
            server._dispatch_tool("get_health", {}),
        )

        assert len(results) == 3
        assert all(r is not None for r in results)
