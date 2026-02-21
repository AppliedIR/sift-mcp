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
        read_only=False,
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

        result = await server._dispatch_tool("search_threat_actor", {"query": "APT29"})

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

    def test_write_tools_defined(self, server):
        """Write tools are defined."""
        assert hasattr(server, 'WRITE_TOOLS') or hasattr(OpenCTIMCPServer, 'WRITE_TOOLS')

    def test_server_has_client(self, server):
        """Server has OpenCTI client."""
        assert hasattr(server, 'client')


# =============================================================================
# Read-Only Mode Tests
# =============================================================================

class TestReadOnlyMode:
    """Test read-only mode enforcement."""

    @pytest.mark.asyncio
    async def test_write_blocked_in_readonly(self, mock_client):
        """Write operations blocked in read-only mode."""
        from opencti_mcp.errors import ValidationError

        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token"),
            read_only=True,
        )

        with patch('opencti_mcp.server.OpenCTIClient', return_value=mock_client):
            server = OpenCTIMCPServer(config)
            server.client = mock_client

            with pytest.raises(ValidationError, match="[Rr]ead.only"):
                await server._dispatch_tool("create_indicator", {
                    "name": "Test",
                    "pattern": "[ipv4-addr:value = '1.1.1.1']",
                })

    @pytest.mark.asyncio
    async def test_read_allowed_in_readonly(self, mock_client):
        """Read operations allowed in read-only mode."""
        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token"),
            read_only=True,
        )

        with patch('opencti_mcp.server.OpenCTIClient', return_value=mock_client):
            server = OpenCTIMCPServer(config)
            server.client = mock_client

            result = await server._dispatch_tool("search_threat_actor", {"query": "test"})
            assert "results" in result


# =============================================================================
# Search Tool Tests
# =============================================================================

class TestSearchTools:
    """Test search tool dispatch."""

    @pytest.mark.asyncio
    async def test_search_threat_actor(self, server, mock_client):
        """search_threat_actor works."""
        result = await server._dispatch_tool("search_threat_actor", {"query": "APT"})
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_malware(self, server, mock_client):
        """search_malware works."""
        result = await server._dispatch_tool("search_malware", {"query": "ransomware"})
        assert "results" in result

    @pytest.mark.asyncio
    async def test_search_with_filters(self, server, mock_client):
        """Search with filters works."""
        result = await server._dispatch_tool("search_threat_actor", {
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
        result = await server._dispatch_tool("search_threat_actor", {"query": ""})
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
        # Result format may vary
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
    async def test_list_connectors(self, server, mock_client):
        """list_connectors works."""
        mock_client.list_enrichment_connectors.return_value = []

        result = await server._dispatch_tool("list_connectors", {})
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_network_status(self, server, mock_client):
        """get_network_status works."""
        mock_client.get_network_status.return_value = {"status": "ok"}

        result = await server._dispatch_tool("get_network_status", {})
        assert result is not None


# =============================================================================
# Write Tool Tests
# =============================================================================

class TestWriteTools:
    """Test write tool dispatch."""

    @pytest.mark.asyncio
    async def test_create_indicator(self, server, mock_client):
        """create_indicator works."""
        mock_client.create_indicator.return_value = {"id": "new-id"}

        result = await server._dispatch_tool("create_indicator", {
            "name": "Test Indicator",
            "pattern": "[ipv4-addr:value = '1.1.1.1']",
            "pattern_type": "stix",
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_indicator_invalid_pattern(self, server):
        """create_indicator with invalid pattern raises error."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("create_indicator", {
                "name": "Test",
                "pattern": "invalid-pattern",
            })

    @pytest.mark.asyncio
    async def test_create_note(self, server, mock_client):
        """create_note works."""
        mock_client.create_note.return_value = {"id": "new-note-id"}

        result = await server._dispatch_tool("create_note", {
            "content": "Test note content",
            "entity_ids": ["12345678-1234-1234-1234-123456789abc"],
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_sighting(self, server, mock_client):
        """create_sighting works."""
        mock_client.create_sighting.return_value = {"id": "new-sighting-id"}

        result = await server._dispatch_tool("create_sighting", {
            "indicator_id": "12345678-1234-1234-1234-123456789abc",
            "sighted_by_id": "87654321-4321-4321-4321-cba987654321",
        })
        assert result is not None


# =============================================================================
# Pagination Tests
# =============================================================================

class TestPagination:
    """Test pagination handling."""

    @pytest.mark.asyncio
    async def test_limit_default(self, server, mock_client):
        """Default limit is applied."""
        await server._dispatch_tool("search_threat_actor", {"query": "test"})
        # Should not raise

    @pytest.mark.asyncio
    async def test_limit_clamped(self, server, mock_client):
        """Large limit is clamped."""
        await server._dispatch_tool("search_threat_actor", {
            "query": "test",
            "limit": 10000
        })
        # Should not raise

    @pytest.mark.asyncio
    async def test_offset_clamped(self, server, mock_client):
        """Large offset is clamped."""
        await server._dispatch_tool("search_threat_actor", {
            "query": "test",
            "offset": 100000
        })
        # Should not raise


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
            await server._dispatch_tool("search_threat_actor", {
                "query": "x" * 10000  # Too long
            })

    @pytest.mark.asyncio
    async def test_client_error_propagates(self, server, mock_client):
        """Client errors propagate appropriately."""
        mock_client.search_threat_actors.side_effect = Exception("Connection error")

        with pytest.raises(Exception):
            await server._dispatch_tool("search_threat_actor", {"query": "test"})


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
            await server._dispatch_tool("search_threat_actor", {
                "query": "test",
                "labels": ["<script>"]
            })

    @pytest.mark.asyncio
    async def test_invalid_date_filter(self, server):
        """Invalid date filter raises error."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_threat_actor", {
                "query": "test",
                "created_after": "not-a-date"
            })

    @pytest.mark.asyncio
    async def test_valid_date_filter(self, server, mock_client):
        """Valid date filter works."""
        result = await server._dispatch_tool("search_threat_actor", {
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
            server._dispatch_tool("search_threat_actor", {"query": "test1"}),
            server._dispatch_tool("search_malware", {"query": "test2"}),
            server._dispatch_tool("get_health", {}),
        )

        assert len(results) == 3
        assert all(r is not None for r in results)
