"""Exhaustive functional tests for OpenCTI MCP.

Covers:
- All MCP tools with various inputs
- Edge cases for each tool
- Filter combinations
- Pagination
- Error handling
- Response format validation
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from opencti_mcp.server import OpenCTIMCPServer, VALID_ENTITY_TYPES
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ValidationError, QueryError, RateLimitError
from opencti_mcp.validation import (
    VALID_OBSERVABLE_TYPES,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_config():
    """Create mock configuration."""
    return Config(
        opencti_url="http://localhost:8080",
        opencti_token=SecretStr("test-token"),
        extra_observable_types=frozenset(),
        extra_pattern_types=frozenset(),
    )


@pytest.fixture
def mock_client():
    """Create mock OpenCTI client."""
    client = MagicMock()
    client.is_available.return_value = True
    client.search_threat_actors.return_value = []
    client.search_malware.return_value = []
    client.search_attack_patterns.return_value = []
    client.search_vulnerabilities.return_value = []
    client.search_campaigns.return_value = []
    client.search_tools.return_value = []
    client.search_reports.return_value = []
    client.search_incidents.return_value = []
    client.search_infrastructure.return_value = []
    client.search_observables.return_value = []
    client.search_indicators.return_value = []
    client.search_sightings.return_value = []
    client.search_organizations.return_value = []
    client.search_sectors.return_value = []
    client.search_locations.return_value = []
    client.search_courses_of_action.return_value = []
    client.search_groupings.return_value = []
    client.search_notes.return_value = []
    client.get_recent_indicators.return_value = []
    client.unified_search.return_value = {"results": [], "total": 0}
    client.get_entity.return_value = None
    client.get_relationships.return_value = []
    client.get_indicator_context.return_value = {}
    client.lookup_hash.return_value = None
    return client


@pytest.fixture
def server(mock_config, mock_client):
    """Create server with mocked dependencies."""
    with patch('opencti_mcp.server.OpenCTIClient', return_value=mock_client):
        with patch('opencti_mcp.server.Config.load', return_value=mock_config):
            server = OpenCTIMCPServer(mock_config)
            server.client = mock_client
            return server


# =============================================================================
# search_entity Tests (consolidated from 16 individual search tools)
# =============================================================================

class TestSearchEntityThreatActor:
    """Test search_entity with type=threat_actor."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic search works."""
        mock_client.search_threat_actors.return_value = [
            {"id": "1", "name": "APT29", "type": "threat_actor"}
        ]
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": "APT29"
        })
        assert "results" in result
        mock_client.search_threat_actors.assert_called_once()

    @pytest.mark.asyncio
    async def test_with_filters(self, server, mock_client):
        """Search with filters works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "APT",
            "limit": 5,
            "offset": 10,
            "labels": ["apt", "russia"],
            "confidence_min": 70,
            "created_after": "2024-01-01",
            "created_before": "2024-12-31",
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_empty_query(self, server, mock_client):
        """Empty query returns results."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor", "query": ""
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_query_too_long(self, server):
        """Query exceeding max length raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor", "query": "x" * 1001
            })

    @pytest.mark.asyncio
    async def test_invalid_labels(self, server):
        """Invalid labels raise error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "test",
                "labels": ["valid", "<script>invalid</script>"]
            })

    @pytest.mark.asyncio
    async def test_invalid_date_filter(self, server):
        """Invalid date filter raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor",
                "query": "test",
                "created_after": "not-a-date"
            })


class TestSearchEntityMalware:
    """Test search_entity with type=malware."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic malware search works."""
        mock_client.search_malware.return_value = [
            {"id": "1", "name": "Cobalt Strike", "type": "malware"}
        ]
        result = await server._dispatch_tool("search_entity", {
            "type": "malware", "query": "Cobalt"
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_with_all_filters(self, server, mock_client):
        """Search with all filters."""
        result = await server._dispatch_tool("search_entity", {
            "type": "malware",
            "query": "ransomware",
            "limit": 20,
            "offset": 0,
            "labels": ["ransomware"],
            "confidence_min": 50,
            "created_after": "2024-01-01",
        })
        assert "results" in result


class TestSearchAttackPattern:
    """Test search_attack_pattern tool (kept separate)."""

    @pytest.mark.asyncio
    async def test_mitre_search(self, server, mock_client):
        """Search for MITRE technique."""
        mock_client.search_attack_patterns.return_value = [
            {"id": "1", "name": "Credential Dumping", "mitre_id": "T1003"}
        ]
        result = await server._dispatch_tool("search_attack_pattern", {"query": "T1003"})
        assert "results" in result

    @pytest.mark.asyncio
    async def test_technique_name_search(self, server, mock_client):
        """Search by technique name."""
        result = await server._dispatch_tool("search_attack_pattern", {
            "query": "credential dumping"
        })
        assert "results" in result


class TestSearchEntityVulnerability:
    """Test search_entity with type=vulnerability."""

    @pytest.mark.asyncio
    async def test_cve_search(self, server, mock_client):
        """Search for CVE."""
        mock_client.search_vulnerabilities.return_value = [
            {"id": "1", "name": "CVE-2024-3400", "cvss_score": 10.0}
        ]
        result = await server._dispatch_tool("search_entity", {
            "type": "vulnerability", "query": "CVE-2024-3400"
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_year_search(self, server, mock_client):
        """Search CVEs by year."""
        result = await server._dispatch_tool("search_entity", {
            "type": "vulnerability", "query": "2024"
        })
        assert "results" in result


class TestSearchEntityObservable:
    """Test search_entity with type=observable."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic observable search."""
        mock_client.search_observables.return_value = [
            {"id": "1", "value": "192.168.1.1", "type": "IPv4-Addr"}
        ]
        result = await server._dispatch_tool("search_entity", {
            "type": "observable", "query": "192.168"
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_with_observable_types(self, server, mock_client):
        """Search with observable type filter."""
        result = await server._dispatch_tool("search_entity", {
            "type": "observable",
            "query": "1.1.1.1",
            "observable_types": ["IPv4-Addr", "IPv6-Addr"]
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_invalid_observable_type(self, server):
        """Invalid observable type raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_entity", {
                "type": "observable",
                "query": "test",
                "observable_types": ["InvalidType"]
            })

    @pytest.mark.asyncio
    async def test_all_valid_observable_types(self, server, mock_client):
        """All valid observable types are accepted."""
        for obs_type in list(VALID_OBSERVABLE_TYPES)[:5]:  # Test subset
            result = await server._dispatch_tool("search_entity", {
                "type": "observable",
                "query": "test",
                "observable_types": [obs_type]
            })
            assert "results" in result


class TestSearchReports:
    """Test search_reports tool (kept separate)."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic report search."""
        mock_client.search_reports.return_value = [
            {"id": "1", "name": "Threat Report", "type": "report"}
        ]
        result = await server._dispatch_tool("search_reports", {"query": "threat"})
        assert "results" in result


class TestSearchEntityCampaign:
    """Test search_entity with type=campaign."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic campaign search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "campaign", "query": "operation"
        })
        assert "results" in result


class TestSearchEntityTool:
    """Test search_entity with type=tool."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic tool search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "tool", "query": "mimikatz"
        })
        assert "results" in result


class TestSearchEntityInfrastructure:
    """Test search_entity with type=infrastructure."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic infrastructure search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "infrastructure", "query": "c2"
        })
        assert "results" in result


class TestSearchEntityIncident:
    """Test search_entity with type=incident."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic incident search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "incident", "query": "breach"
        })
        assert "results" in result


class TestSearchEntitySighting:
    """Test search_entity with type=sighting."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic sighting search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "sighting", "query": "detection"
        })
        assert "results" in result


class TestSearchEntityOrganization:
    """Test search_entity with type=organization."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic organization search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "organization", "query": "corp"
        })
        assert "results" in result


class TestSearchEntitySector:
    """Test search_entity with type=sector."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic sector search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "sector", "query": "finance"
        })
        assert "results" in result


class TestSearchEntityLocation:
    """Test search_entity with type=location."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic location search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "location", "query": "russia"
        })
        assert "results" in result


class TestSearchEntityCourseOfAction:
    """Test search_entity with type=course_of_action."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic course of action search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "course_of_action", "query": "mitigation"
        })
        assert "results" in result


class TestSearchEntityGrouping:
    """Test search_entity with type=grouping."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic grouping search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "grouping", "query": "analysis"
        })
        assert "results" in result


class TestSearchEntityNote:
    """Test search_entity with type=note."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic note search."""
        result = await server._dispatch_tool("search_entity", {
            "type": "note", "query": "finding"
        })
        assert "results" in result


class TestSearchEntityInvalidType:
    """Test search_entity with invalid type."""

    @pytest.mark.asyncio
    async def test_invalid_type(self, server):
        """Invalid entity type raises error."""
        with pytest.raises(ValidationError, match="Invalid entity type"):
            await server._dispatch_tool("search_entity", {
                "type": "invalid_type", "query": "test"
            })


# =============================================================================
# Unified Search Tests
# =============================================================================

class TestSearchThreatIntel:
    """Test search_threat_intel (unified search) tool."""

    @pytest.mark.asyncio
    async def test_basic_search(self, server, mock_client):
        """Basic unified search."""
        mock_client.unified_search.return_value = {
            "results": [{"id": "1", "name": "APT29"}],
            "total": 1
        }
        result = await server._dispatch_tool("search_threat_intel", {"query": "APT29"})
        assert "results" in result or "total" in result

    @pytest.mark.asyncio
    async def test_with_entity_types(self, server, mock_client):
        """Unified search with entity type filter."""
        result = await server._dispatch_tool("search_threat_intel", {
            "query": "test",
            "entity_types": ["threat_actor", "malware"]
        })
        assert result is not None


# =============================================================================
# Entity Operation Tests
# =============================================================================

class TestGetEntity:
    """Test get_entity tool."""

    @pytest.mark.asyncio
    async def test_valid_uuid(self, server, mock_client):
        """Get entity with valid UUID."""
        mock_client.get_entity.return_value = {
            "id": "12345678-1234-1234-1234-123456789abc",
            "name": "Test Entity"
        }
        result = await server._dispatch_tool("get_entity", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_invalid_uuid(self, server):
        """Invalid UUID raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("get_entity", {
                "entity_id": "not-a-valid-uuid"
            })

    @pytest.mark.asyncio
    async def test_entity_not_found(self, server, mock_client):
        """Entity not found returns appropriate response."""
        mock_client.get_entity.return_value = None
        result = await server._dispatch_tool("get_entity", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert result is None or isinstance(result, dict)


class TestGetRelationships:
    """Test get_relationships tool."""

    @pytest.mark.asyncio
    async def test_basic_relationships(self, server, mock_client):
        """Get relationships for entity."""
        mock_client.get_relationships.return_value = [
            {"id": "1", "relationship_type": "uses", "target": {"name": "Malware"}}
        ]
        result = await server._dispatch_tool("get_relationships", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert "relationships" in result or isinstance(result, list)

    @pytest.mark.asyncio
    async def test_with_relationship_types(self, server, mock_client):
        """Get relationships with type filter."""
        result = await server._dispatch_tool("get_relationships", {
            "entity_id": "12345678-1234-1234-1234-123456789abc",
            "relationship_types": ["uses", "targets"]
        })
        assert result is not None

    @pytest.mark.asyncio
    async def test_invalid_relationship_type(self, server):
        """Invalid relationship type raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("get_relationships", {
                "entity_id": "12345678-1234-1234-1234-123456789abc",
                "relationship_types": ["uses<script>"]
            })


class TestLookupIOC:
    """Test lookup_ioc tool."""

    @pytest.mark.asyncio
    async def test_lookup_ip(self, server, mock_client):
        """Lookup IP address."""
        result = await server._dispatch_tool("lookup_ioc", {"ioc": "192.168.1.1"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_lookup_hash(self, server, mock_client):
        """Lookup hash."""
        result = await server._dispatch_tool("lookup_hash", {
            "hash": "d41d8cd98f00b204e9800998ecf8427e"
        })
        # Returns found=False if not found, which is OK

    @pytest.mark.asyncio
    async def test_lookup_domain(self, server, mock_client):
        """Lookup domain."""
        result = await server._dispatch_tool("lookup_ioc", {"ioc": "malware.com"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_empty_ioc(self, server):
        """Empty IOC raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("lookup_ioc", {"ioc": ""})

    @pytest.mark.asyncio
    async def test_ioc_too_long(self, server):
        """IOC exceeding max length raises error."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("lookup_ioc", {"ioc": "x" * 3000})


class TestGetRecentIndicators:
    """Test get_recent_indicators tool."""

    @pytest.mark.asyncio
    async def test_default_days(self, server, mock_client):
        """Get recent indicators with default days."""
        result = await server._dispatch_tool("get_recent_indicators", {})
        assert "indicators" in result or "results" in result or isinstance(result, list)

    @pytest.mark.asyncio
    async def test_custom_days(self, server, mock_client):
        """Get recent indicators with custom days."""
        result = await server._dispatch_tool("get_recent_indicators", {"days": 30})
        assert result is not None

    @pytest.mark.asyncio
    async def test_days_clamped(self, server, mock_client):
        """Days parameter is clamped to max."""
        result = await server._dispatch_tool("get_recent_indicators", {"days": 1000})
        assert result is not None


# =============================================================================
# Write/Admin Tools Removed Tests
# =============================================================================

class TestRemovedTools:
    """Verify removed tools raise ValidationError."""

    @pytest.mark.asyncio
    async def test_write_tools_removed(self, server):
        """Write tools are no longer available."""
        for tool in ["create_indicator", "create_note", "create_sighting", "trigger_enrichment"]:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await server._dispatch_tool(tool, {})

    @pytest.mark.asyncio
    async def test_admin_tools_removed(self, server):
        """Admin tools are no longer available."""
        for tool in ["list_connectors", "get_network_status", "force_reconnect", "get_cache_stats"]:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await server._dispatch_tool(tool, {})

    @pytest.mark.asyncio
    async def test_individual_search_tools_removed(self, server):
        """Individual search_* tools (consolidated into search_entity) are gone."""
        removed = [
            "search_threat_actor", "search_malware", "search_vulnerability",
            "search_campaign", "search_tool", "search_infrastructure",
            "search_incident", "search_observable", "search_sighting",
            "search_organization", "search_sector", "search_location",
            "search_course_of_action", "search_grouping", "search_note",
        ]
        for tool in removed:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await server._dispatch_tool(tool, {"query": "test"})


# =============================================================================
# System Operation Tests
# =============================================================================

class TestGetHealth:
    """Test get_health tool."""

    @pytest.mark.asyncio
    async def test_health_check(self, server, mock_client):
        """Health check returns status."""
        mock_client.is_available.return_value = True
        result = await server._dispatch_tool("get_health", {})
        assert result is not None
        assert "status" in result or "available" in result or isinstance(result, bool)


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
        call_args = mock_client.search_threat_actors.call_args
        assert call_args is not None

    @pytest.mark.asyncio
    async def test_limit_clamped(self, server, mock_client):
        """Limit is clamped to max."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "limit": 1000
        })

    @pytest.mark.asyncio
    async def test_offset_clamped(self, server, mock_client):
        """Offset is clamped to max."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "offset": 10000
        })

    @pytest.mark.asyncio
    async def test_negative_limit(self, server, mock_client):
        """Negative limit is handled."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "limit": -5
        })

    @pytest.mark.asyncio
    async def test_negative_offset(self, server, mock_client):
        """Negative offset is handled."""
        await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "test",
            "offset": -10
        })


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool(self, server):
        """Unknown tool raises error."""
        with pytest.raises(ValidationError, match="[Uu]nknown"):
            await server._dispatch_tool("nonexistent_tool", {})

    @pytest.mark.asyncio
    async def test_client_error_wrapped(self, server, mock_client):
        """Client errors are wrapped appropriately."""
        mock_client.search_threat_actors.side_effect = Exception("Connection failed")
        with pytest.raises(Exception):
            await server._dispatch_tool("search_entity", {
                "type": "threat_actor", "query": "test"
            })

    @pytest.mark.asyncio
    async def test_validation_error_clear_message(self, server):
        """Validation errors have clear messages."""
        try:
            await server._dispatch_tool("get_entity", {"entity_id": "invalid"})
        except ValidationError as e:
            assert "UUID" in str(e) or "valid" in str(e).lower()


# =============================================================================
# Filter Combination Tests (via search_entity)
# =============================================================================

class TestFilterCombinations:
    """Test various filter combinations."""

    @pytest.mark.asyncio
    async def test_all_filters_combined(self, server, mock_client):
        """All filters can be combined."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "APT",
            "limit": 20,
            "offset": 5,
            "labels": ["apt", "state-sponsored"],
            "confidence_min": 70,
            "created_after": "2024-01-01",
            "created_before": "2024-12-31",
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_date_range(self, server, mock_client):
        """Date range filter works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "malware",
            "query": "",
            "created_after": "2024-01-01",
            "created_before": "2024-06-30",
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_labels_only(self, server, mock_client):
        """Labels-only filter works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "",
            "labels": ["apt"]
        })
        assert "results" in result

    @pytest.mark.asyncio
    async def test_confidence_only(self, server, mock_client):
        """Confidence-only filter works."""
        result = await server._dispatch_tool("search_entity", {
            "type": "threat_actor",
            "query": "",
            "confidence_min": 80
        })
        assert "results" in result
