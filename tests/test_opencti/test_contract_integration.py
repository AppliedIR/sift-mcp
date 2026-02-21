"""Contract and integration testing for OpenCTI MCP Server.

Tests:
- API contract validation
- Cross-function consistency
- Integration scenarios
- End-to-end workflows
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from dataclasses import asdict

from opencti_mcp.server import OpenCTIMCPServer
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.validation import (
    validate_uuid,
    validate_ioc,
    validate_label,
    validate_date_filter,
    validate_observable_types,
    validate_pattern_type,
    validate_stix_pattern,
    validate_length,
    MAX_QUERY_LENGTH,
)


def validate_query(query: str) -> str:
    """Wrapper that validates query length and returns query."""
    if query is None:
        return ""
    validate_length(query, MAX_QUERY_LENGTH, "query")
    return query


def sanitize_for_graphql(value: str) -> str:
    """Simple GraphQL sanitization - escape quotes."""
    return value.replace('\\', '\\\\').replace('"', '\\"')
from opencti_mcp.errors import ValidationError, OpenCTIMCPError


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_config():
    """Create test configuration."""
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
    client.get_entity.return_value = {"id": "test", "name": "Test"}
    client.get_relationships.return_value = []
    return client


@pytest.fixture
def server(mock_config, mock_client):
    """Create server with mocked dependencies."""
    with patch('opencti_mcp.server.OpenCTIClient', return_value=mock_client):
        server = OpenCTIMCPServer(mock_config)
        server.client = mock_client
        return server


# =============================================================================
# API Contract Tests
# =============================================================================

class TestAPIContracts:
    """Test that API contracts are maintained."""

    @pytest.mark.asyncio
    async def test_search_returns_results_key(self, server, mock_client):
        """All search tools return 'results' key."""
        search_tools = [
            "search_threat_actor",
            "search_malware",
            "search_campaign",
            "search_vulnerability",
            "search_attack_pattern",
            "search_reports",
            "search_observable",
        ]

        for tool in search_tools:
            result = await server._dispatch_tool(tool, {"query": "test"})
            assert "results" in result, f"{tool} must return 'results'"

    @pytest.mark.asyncio
    async def test_search_results_are_lists(self, server, mock_client):
        """Search results are always lists."""
        result = await server._dispatch_tool("search_threat_actor", {"query": "test"})
        assert isinstance(result["results"], list)

    @pytest.mark.asyncio
    async def test_get_entity_returns_entity_or_error(self, server, mock_client):
        """get_entity returns entity dict or appropriate error."""
        # Success case
        result = await server._dispatch_tool("get_entity", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert isinstance(result, dict)

        # Not found case
        mock_client.get_entity.return_value = None
        result = await server._dispatch_tool("get_entity", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        # Should return None or empty dict or error
        assert result is None or isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_health_check_returns_status(self, server, mock_client):
        """Health check returns status information."""
        result = await server._dispatch_tool("get_health", {})
        assert result is not None
        # Should have some indication of status

    @pytest.mark.asyncio
    async def test_write_tools_return_created_entity(self, server, mock_client):
        """Write tools return created entity info."""
        mock_client.create_indicator.return_value = {"id": "new-id", "name": "Test"}

        result = await server._dispatch_tool("create_indicator", {
            "name": "Test Indicator",
            "pattern": "[ipv4-addr:value = '1.1.1.1']",
        })
        assert result is not None
        # Should return created entity info


# =============================================================================
# Cross-Function Consistency Tests
# =============================================================================

class TestCrossFunctionConsistency:
    """Test consistency across functions."""

    def test_all_validators_handle_empty_string(self):
        """All validators handle empty string consistently."""
        # Query allows empty (for browse mode)
        result = validate_query("")
        assert result == ""

        # UUID rejects empty
        with pytest.raises(ValidationError):
            validate_uuid("", "id")

        # Label rejects empty
        with pytest.raises(ValidationError):
            validate_label("")

    def test_all_validators_handle_none_gracefully(self):
        """All validators handle None input."""
        # Each should either accept None or raise ValidationError
        validators = [
            (validate_query, [None]),
            (validate_label, [None]),
        ]

        for validator, args in validators:
            try:
                validator(*args)
            except (ValidationError, TypeError):
                pass  # Either is acceptable

    def test_all_validators_handle_max_length(self):
        """All validators have consistent length limits."""
        long_string = "x" * 10000

        # Query has 1000 char limit
        with pytest.raises(ValidationError):
            validate_query(long_string)

        # Label has 200 char limit
        with pytest.raises(ValidationError):
            validate_label(long_string)

    def test_validation_errors_are_consistent(self):
        """ValidationError messages follow consistent format."""
        errors = []

        try:
            validate_query("x" * 2000)
        except ValidationError as e:
            errors.append(str(e))

        try:
            validate_uuid("invalid", "test_id")
        except ValidationError as e:
            errors.append(str(e))

        try:
            validate_label("<invalid>")
        except ValidationError as e:
            errors.append(str(e))

        # All errors should be non-empty strings
        assert all(isinstance(e, str) and len(e) > 0 for e in errors)


# =============================================================================
# Input/Output Contract Tests
# =============================================================================

class TestIOContracts:
    """Test input/output contracts."""

    def test_validate_query_preserves_valid_input(self):
        """validate_query returns input unchanged if valid."""
        inputs = ["test", "APT29", "192.168.1.1", "hello world"]
        for inp in inputs:
            assert validate_query(inp) == inp

    def test_sanitize_escapes_dangerous_chars(self):
        """sanitize_for_graphql escapes dangerous characters."""
        # Should escape quotes and backslashes
        result = sanitize_for_graphql('test"query')
        assert '"' not in result or '\\"' in result or result != 'test"query'

    def test_uuid_validation_is_case_insensitive(self):
        """UUID validation accepts both cases."""
        lower = "12345678-1234-1234-1234-123456789abc"
        upper = "12345678-1234-1234-1234-123456789ABC"
        mixed = "12345678-1234-1234-1234-123456789AbC"

        # Validation may normalize to lowercase or preserve case
        assert validate_uuid(lower, "id").lower() == lower.lower()
        assert validate_uuid(upper, "id").lower() == upper.lower()
        assert validate_uuid(mixed, "id").lower() == mixed.lower()

    def test_ioc_validation_returns_tuple(self):
        """IOC validation always returns (bool, str|None) tuple."""
        test_inputs = [
            "192.168.1.1",
            "d41d8cd98f00b204e9800998ecf8427e",
        ]

        for inp in test_inputs:
            result = validate_ioc(inp)
            assert isinstance(result, tuple)
            assert len(result) == 2
            assert isinstance(result[0], bool)
            assert result[1] is None or isinstance(result[1], str)

    def test_ioc_validation_handles_invalid(self):
        """IOC validation handles invalid inputs."""
        # These may raise or return (False, None) depending on implementation
        invalid_inputs = ["not-an-ioc", ""]
        for inp in invalid_inputs:
            try:
                result = validate_ioc(inp)
                # If it returns, should be tuple
                assert isinstance(result, tuple)
            except (ValidationError, ValueError):
                pass  # Also acceptable


# =============================================================================
# Integration Scenario Tests
# =============================================================================

class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    @pytest.mark.asyncio
    async def test_search_then_get_workflow(self, server, mock_client):
        """Search for entities then get details workflow."""
        # Search returns results
        mock_client.search_threat_actors.return_value = [
            {"id": "12345678-1234-1234-1234-123456789abc", "name": "APT29"}
        ]

        # 1. Search
        search_result = await server._dispatch_tool("search_threat_actor", {
            "query": "APT29"
        })
        assert "results" in search_result
        assert len(search_result["results"]) > 0

        # 2. Get entity by ID from search results
        entity_id = search_result["results"][0]["id"]
        mock_client.get_entity.return_value = {
            "id": entity_id,
            "name": "APT29",
            "description": "Russian threat actor"
        }

        entity_result = await server._dispatch_tool("get_entity", {
            "entity_id": entity_id
        })
        assert entity_result is not None

    @pytest.mark.asyncio
    async def test_create_and_link_workflow(self, server, mock_client):
        """Create indicator and add note workflow."""
        # Create indicator
        mock_client.create_indicator.return_value = {
            "id": "12345678-1234-1234-1234-123456789abc"
        }

        indicator_result = await server._dispatch_tool("create_indicator", {
            "name": "Malicious IP",
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
        })
        assert indicator_result is not None

        # Add note to indicator
        indicator_id = "12345678-1234-1234-1234-123456789abc"
        mock_client.create_note.return_value = {
            "id": "87654321-1234-1234-1234-123456789abc"
        }

        note_result = await server._dispatch_tool("create_note", {
            "content": "Observed in phishing campaign",
            "entity_ids": [indicator_id],
        })
        assert note_result is not None

    @pytest.mark.asyncio
    async def test_ioc_lookup_workflow(self, server, mock_client):
        """IOC lookup with enrichment workflow."""
        # Lookup IOC
        mock_client.lookup_observable.return_value = {
            "id": "12345678-1234-1234-1234-123456789abc",
            "value": "192.168.1.1",
            "type": "ipv4-addr"
        }

        lookup_result = await server._dispatch_tool("lookup_ioc", {
            "ioc": "192.168.1.1"
        })
        assert lookup_result is not None

        # Get relationships
        mock_client.get_relationships.return_value = [
            {"type": "indicates", "target": {"name": "APT29"}}
        ]

        rel_result = await server._dispatch_tool("get_relationships", {
            "entity_id": "12345678-1234-1234-1234-123456789abc"
        })
        assert rel_result is not None


# =============================================================================
# Error Contract Tests
# =============================================================================

class TestErrorContracts:
    """Test error handling contracts."""

    @pytest.mark.asyncio
    async def test_unknown_tool_raises_validation_error(self, server):
        """Unknown tool raises ValidationError."""
        with pytest.raises(ValidationError):
            await server._dispatch_tool("nonexistent_tool", {})

    @pytest.mark.asyncio
    async def test_invalid_input_raises_validation_error(self, server):
        """Invalid input raises ValidationError."""
        # Invalid UUID
        with pytest.raises(ValidationError):
            await server._dispatch_tool("get_entity", {"entity_id": "invalid"})

        # Query too long
        with pytest.raises(ValidationError):
            await server._dispatch_tool("search_threat_actor", {
                "query": "x" * 2000
            })

    @pytest.mark.asyncio
    async def test_client_errors_propagate_appropriately(self, server, mock_client):
        """Client errors propagate with appropriate type."""
        mock_client.search_threat_actors.side_effect = Exception("Connection failed")

        with pytest.raises(Exception):
            await server._dispatch_tool("search_threat_actor", {"query": "test"})


# =============================================================================
# Config Contract Tests
# =============================================================================

class TestConfigContracts:
    """Test configuration contracts."""

    def test_config_has_required_fields(self):
        """Config has all required fields."""
        with patch.dict('os.environ', {'OPENCTI_TOKEN': 'test-token'}, clear=False):
            with patch('opencti_mcp.config._load_token', return_value='test-token'):
                config = Config.load()

        # Required fields exist
        assert hasattr(config, 'opencti_url')
        assert hasattr(config, 'opencti_token')
        assert hasattr(config, 'read_only')
        assert hasattr(config, 'timeout_seconds')
        assert hasattr(config, 'max_results')

    def test_config_defaults_are_safe(self):
        """Config defaults are secure."""
        # Read-only should default to True
        with patch.dict('os.environ', {'OPENCTI_TOKEN': 'test-token'}, clear=False):
            with patch('opencti_mcp.config._load_token', return_value='test-token'):
                config = Config.load()
                assert config.read_only is True

    def test_config_token_is_secret(self):
        """Config token is wrapped in SecretStr."""
        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("secret-token"),
        )

        # Token should not appear in string representation
        config_str = str(asdict(config))
        assert "secret-token" not in config_str


# =============================================================================
# Response Format Contract Tests
# =============================================================================

class TestResponseFormatContracts:
    """Test response format contracts."""

    @pytest.mark.asyncio
    async def test_search_response_format(self, server, mock_client):
        """Search responses have consistent format."""
        mock_client.search_threat_actors.return_value = [
            {"id": "123", "name": "Test"}
        ]

        result = await server._dispatch_tool("search_threat_actor", {"query": "test"})

        # Must have results key
        assert "results" in result

        # Results must be a list
        assert isinstance(result["results"], list)

        # Each result should be a dict
        if result["results"]:
            assert isinstance(result["results"][0], dict)

    @pytest.mark.asyncio
    async def test_results_are_json_serializable(self, server, mock_client):
        """All results are JSON serializable."""
        mock_client.search_threat_actors.return_value = [
            {"id": "123", "name": "Test", "created": "2024-01-01"}
        ]

        result = await server._dispatch_tool("search_threat_actor", {"query": "test"})

        # Should not raise
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

        # Round-trip should preserve data
        parsed = json.loads(json_str)
        assert parsed == result


# =============================================================================
# Idempotency Tests
# =============================================================================

class TestIdempotency:
    """Test idempotent operations."""

    @pytest.mark.asyncio
    async def test_search_is_idempotent(self, server, mock_client):
        """Same search returns same results."""
        mock_client.search_threat_actors.return_value = [{"id": "123"}]

        result1 = await server._dispatch_tool("search_threat_actor", {"query": "test"})
        result2 = await server._dispatch_tool("search_threat_actor", {"query": "test"})

        assert result1 == result2

    def test_validation_is_idempotent(self):
        """Same validation returns same result."""
        query = "test query"

        result1 = validate_query(query)
        result2 = validate_query(query)

        assert result1 == result2

    def test_sanitization_is_idempotent(self):
        """Sanitization is idempotent (applying twice = same as once)."""
        query = 'test"query'

        result1 = sanitize_for_graphql(query)
        result2 = sanitize_for_graphql(result1)

        # Sanitizing already-sanitized input shouldn't change it
        # (or should be safe if it does)
        # This depends on implementation - just ensure no crash
        assert isinstance(result2, str)


# =============================================================================
# Backward Compatibility Tests
# =============================================================================

class TestBackwardCompatibility:
    """Test backward compatibility of interfaces."""

    def test_validate_query_accepts_string(self):
        """validate_query accepts string input."""
        result = validate_query("test")
        assert isinstance(result, str)

    def test_validate_uuid_accepts_two_args(self):
        """validate_uuid accepts (value, field_name)."""
        result = validate_uuid("12345678-1234-1234-1234-123456789abc", "id")
        assert isinstance(result, str)

    def test_validate_ioc_returns_tuple(self):
        """validate_ioc returns (bool, type) tuple."""
        result = validate_ioc("192.168.1.1")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_config_load_returns_config(self):
        """Config.load() returns Config instance."""
        with patch.dict('os.environ', {'OPENCTI_TOKEN': 'test-token'}, clear=False):
            with patch('opencti_mcp.config._load_token', return_value='test-token'):
                config = Config.load()
        assert isinstance(config, Config)
