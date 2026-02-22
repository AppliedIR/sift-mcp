"""Edge case tests for specific MCP tools.

Tests unusual inputs and edge cases for each tool handler.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from opencti_mcp.server import OpenCTIMCPServer
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ValidationError


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_config():
    """Create test configuration."""
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
    client.search_campaigns.return_value = []
    client.search_vulnerabilities.return_value = []
    client.search_attack_patterns.return_value = []
    client.search_reports.return_value = []
    client.search_observables.return_value = []
    client.search_indicators.return_value = []
    client.search_sightings.return_value = []
    client.search_incidents.return_value = []
    client.search_tools.return_value = []
    client.search_courses_of_action.return_value = []
    client.search_infrastructure.return_value = []
    client.search_groupings.return_value = []
    client.search_notes.return_value = []
    client.search_organizations.return_value = []
    client.search_sectors.return_value = []
    client.search_locations.return_value = []
    client.unified_search.return_value = {"results": [], "total": 0}
    client.get_entity.return_value = {"id": "test", "name": "Test"}
    client.get_relationships.return_value = []
    client.lookup_observable.return_value = None
    client.lookup_hash.return_value = None
    client.get_recent_indicators.return_value = []
    return client


@pytest.fixture
def server(mock_config, mock_client):
    """Create server with mocked dependencies."""
    with patch('opencti_mcp.server.OpenCTIClient', return_value=mock_client):
        server = OpenCTIMCPServer(mock_config)
        server.client = mock_client
        return server


# =============================================================================
# Search Tool Edge Cases (via search_entity)
# =============================================================================

class TestSearchToolEdgeCases:
    """Edge cases for search tools."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("query", [
        "",  # Empty
        " ",  # Whitespace
        "   ",  # Multiple spaces
        "\t",  # Tab
        "\n",  # Newline
        "a",  # Single char
        "ab",  # Two chars
    ])
    async def test_minimal_queries(self, server, mock_client, query: str):
        """Handle minimal/empty queries."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": query
        })
        assert "results" in result

    @pytest.mark.asyncio
    @pytest.mark.parametrize("query", [
        "APT-29",  # Hyphen
        "APT_29",  # Underscore
        "APT.29",  # Period
        "APT/29",  # Slash
        "APT 29",  # Space
        "APT+29",  # Plus
        "APT@29",  # At
        "APT#29",  # Hash
    ])
    async def test_special_char_queries(self, server, mock_client, query: str):
        """Handle special characters in queries."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": query
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_query_with_quotes(self, server, mock_client):
        """Handle quoted queries."""
        queries = [
            '"exact match"',
            "'single quotes'",
            '"nested "quote""',
        ]
        for query in queries:
            try:
                result = await server._dispatch_tool("search_entity", {
                    "type": "threat_actor", "query": query
                })
                assert result is not None
            except ValidationError:
                pass  # Acceptable

    @pytest.mark.asyncio
    async def test_unicode_queries(self, server, mock_client):
        """Handle unicode in queries."""
        queries = [
            "熊猫",  # Chinese
            "медведь",  # Russian
            "דוב",  # Hebrew
            "🐻",  # Emoji
        ]
        for query in queries:
            result = await server._dispatch_tool("search_entity", {
                "type": "threat_actor", "query": query
            })
            assert "results" in result


# =============================================================================
# Pagination Edge Cases (via search_entity with full-filter type)
# =============================================================================

class TestPaginationEdgeCases:
    """Edge cases for pagination."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("limit", [0, 1, 100, 1000, 10000])
    async def test_limit_values(self, server, mock_client, limit: int):
        """Handle various limit values."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "limit": limit
        })
        assert "results" in result

    @pytest.mark.asyncio
    @pytest.mark.parametrize("offset", [0, 1, 100, 1000, 10000])
    async def test_offset_values(self, server, mock_client, offset: int):
        """Handle various offset values."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "offset": offset
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_negative_limit(self, server, mock_client):
        """Handle negative limit."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "limit": -1
        })
        # Should handle gracefully (clamp to 0 or default)
        assert "results" in result

    @pytest.mark.asyncio
    async def test_negative_offset(self, server, mock_client):
        """Handle negative offset."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "offset": -1
        })
        # Should handle gracefully
        assert "results" in result


# =============================================================================
# Filter Edge Cases (via search_entity with full-filter type)
# =============================================================================

class TestFilterEdgeCases:
    """Edge cases for filters."""

    @pytest.mark.asyncio
    async def test_empty_labels_list(self, server, mock_client):
        """Handle empty labels list."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "labels": []
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_single_label(self, server, mock_client):
        """Handle single label."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "labels": ["apt"]
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_many_labels(self, server, mock_client):
        """Handle many labels - may be limited."""
        try:
            result = await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "test",
                "labels": ["label" + str(i) for i in range(20)]
            })
            assert "results" in result
        except ValidationError:
            pass  # May reject if too many labels

    @pytest.mark.asyncio
    @pytest.mark.parametrize("confidence", [0, 1, 50, 99, 100])
    async def test_confidence_boundary_values(self, server, mock_client, confidence: int):
        """Handle boundary confidence values."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "confidence_min": confidence
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_date_at_boundaries(self, server, mock_client):
        """Handle date boundaries."""
        dates = [
            "1970-01-01",
            "1970-01-01T00:00:00Z",
            "2100-12-31",
            "2100-12-31T23:59:59Z",
        ]
        for date in dates:
            result = await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "test",
                "created_after": date
            })
            assert "results" in result


# =============================================================================
# Entity ID Edge Cases
# =============================================================================

class TestEntityIDEdgeCases:
    """Edge cases for entity ID handling."""

    @pytest.mark.asyncio
    async def test_nil_uuid(self, server, mock_client):
        """Handle nil UUID."""
        result = await server._dispatch_tool("get_entity", {
            "entity_id": "00000000-0000-0000-0000-000000000000"
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_max_uuid(self, server, mock_client):
        """Handle max UUID."""
        result = await server._dispatch_tool("get_entity", {
            "entity_id": "ffffffff-ffff-ffff-ffff-ffffffffffff"
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_uuid_case_variations(self, server, mock_client):
        """Handle UUID case variations."""
        uuids = [
            "12345678-1234-1234-1234-123456789abc",  # lowercase
            "12345678-1234-1234-1234-123456789ABC",  # uppercase
            "12345678-1234-1234-1234-123456789AbC",  # mixed
        ]
        for uuid in uuids:
            result = await server._dispatch_tool("get_entity", {"entity_id": uuid})
            assert result is not None


# =============================================================================
# IOC Lookup Edge Cases
# =============================================================================

class TestIOCLookupEdgeCases:
    """Edge cases for IOC lookup."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("ioc", [
        "192.168.1.1",  # IPv4
        "10.0.0.1",  # Private IPv4
        "0.0.0.0",  # Zero IPv4
        "255.255.255.255",  # Broadcast
        "127.0.0.1",  # Loopback
    ])
    async def test_ipv4_edge_cases(self, server, mock_client, ioc: str):
        """Handle IPv4 edge cases."""
        result = await server._dispatch_tool("lookup_ioc", {"ioc": ioc})
        assert result is not None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("ioc", [
        "::1",  # Loopback
        "::",  # Any
        "2001:db8::1",  # Documentation
        "fe80::1",  # Link-local
    ])
    async def test_ipv6_edge_cases(self, server, mock_client, ioc: str):
        """Handle IPv6 edge cases."""
        result = await server._dispatch_tool("lookup_ioc", {"ioc": ioc})
        assert result is not None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("hash_value", [
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
    ])
    async def test_hash_edge_cases(self, server, mock_client, hash_value: str):
        """Handle hash edge cases."""
        result = await server._dispatch_tool("lookup_hash", {"hash": hash_value})
        assert result is not None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("domain", [
        "a.com",  # Minimal
        "example.com",  # Normal
        "sub.example.com",  # Subdomain
        "a.b.c.d.example.com",  # Deep subdomain
        "example.co.uk",  # Multi-part TLD
    ])
    async def test_domain_edge_cases(self, server, mock_client, domain: str):
        """Handle domain edge cases."""
        result = await server._dispatch_tool("lookup_ioc", {"ioc": domain})
        assert result is not None


# =============================================================================
# Relationship Edge Cases
# =============================================================================

class TestRelationshipEdgeCases:
    """Edge cases for relationship queries."""

    @pytest.mark.asyncio
    async def test_relationship_types(self, server, mock_client):
        """Test various relationship type filters."""
        types = [
            "indicates",
            "uses",
            "targets",
            "attributed-to",
            "related-to",
        ]
        for rel_type in types:
            result = await server._dispatch_tool("get_relationships", {
                "entity_id": "12345678-1234-1234-1234-123456789abc",
                "relationship_type": rel_type,
            })
            assert result is not None

    @pytest.mark.asyncio
    async def test_relationship_directions(self, server, mock_client):
        """Test relationship direction filters."""
        directions = ["from", "to", "both"]
        for direction in directions:
            try:
                result = await server._dispatch_tool("get_relationships", {
                    "entity_id": "12345678-1234-1234-1234-123456789abc",
                    "direction": direction,
                })
                assert result is not None
            except ValidationError:
                pass  # Direction may not be supported


# =============================================================================
# Health Check Edge Cases
# =============================================================================

class TestHealthCheckEdgeCases:
    """Edge cases for health check."""

    @pytest.mark.asyncio
    async def test_health_when_available(self, server, mock_client):
        """Health check when OpenCTI is available."""
        mock_client.is_available.return_value = True

        result = await server._dispatch_tool("get_health", {})
        assert result is not None

    @pytest.mark.asyncio
    async def test_health_when_unavailable(self, server, mock_client):
        """Health check when OpenCTI is unavailable."""
        mock_client.is_available.return_value = False

        result = await server._dispatch_tool("get_health", {})
        # Should still return result (just showing unavailable)
        assert result is not None


# =============================================================================
# Unified Search Edge Cases
# =============================================================================

class TestUnifiedSearchEdgeCases:
    """Edge cases for unified search."""

    @pytest.mark.asyncio
    async def test_unified_search_all_types(self, server, mock_client):
        """Unified search across all types."""
        result = await server._dispatch_tool("search_threat_intel", {
            "query": "test"
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_unified_search_specific_types(self, server, mock_client):
        """Unified search with specific types."""
        types_to_test = [
            ["indicator"],
            ["threat_actor", "malware"],
            ["vulnerability", "attack_pattern", "tool"],
        ]
        for types in types_to_test:
            result = await server._dispatch_tool("search_threat_intel", {
                "query": "test",
                "types": types
            })
            assert result is not None


# =============================================================================
# Recent Indicators Edge Cases
# =============================================================================

class TestRecentIndicatorsEdgeCases:
    """Edge cases for recent indicators."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("days", [1, 7, 30, 90, 365])
    async def test_various_day_ranges(self, server, mock_client, days: int):
        """Test various day ranges."""
        result = await server._dispatch_tool("get_recent_indicators", {
            "days": days
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_zero_days(self, server, mock_client):
        """Test zero days (today only)."""
        result = await server._dispatch_tool("get_recent_indicators", {
            "days": 0
        })
        # Should handle gracefully
        assert result is not None

    @pytest.mark.asyncio
    async def test_negative_days(self, server, mock_client):
        """Test negative days."""
        # Should handle gracefully (clamp to 0 or error)
        try:
            result = await server._dispatch_tool("get_recent_indicators", {
                "days": -1
            })
            assert result is not None
        except ValidationError:
            pass  # Also acceptable
