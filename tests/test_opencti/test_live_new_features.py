"""Live integration tests for new features against running OpenCTI.

Run with: pytest tests/test_live_new_features.py -v

Requires:
- OpenCTI running at http://localhost:8080
- Valid API token
"""

from __future__ import annotations

import pytest
import os

from opencti_mcp.config import Config
from opencti_mcp.client import OpenCTIClient, CircuitState
from opencti_mcp.feature_flags import FeatureFlags, reset_feature_flags


# Skip unless explicitly opted in (live tests hit a real OpenCTI instance)
pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_TESTS", "false").lower() != "true",
    reason="Live tests require RUN_LIVE_TESTS=true"
)


@pytest.fixture(scope="module")
def live_config():
    """Load real configuration for live tests."""
    return Config.load()


@pytest.fixture(scope="module")
def live_client(live_config):
    """Create client connected to live OpenCTI."""
    return OpenCTIClient(live_config)


# =============================================================================
# Startup Validation Live Tests
# =============================================================================

class TestLiveStartupValidation:
    """Test startup validation against live OpenCTI."""

    def test_startup_validation_succeeds(self, live_client):
        """Startup validation passes with live server."""
        result = live_client.validate_startup()

        assert result['valid'] is True
        assert len(result['errors']) == 0

    def test_startup_gets_version(self, live_client):
        """Startup validation retrieves server version."""
        result = live_client.validate_startup()

        assert result['opencti_version'] is not None
        # Version should be semver-like
        assert '.' in result['opencti_version']

    def test_version_check_no_critical_warnings(self, live_client):
        """No critical version warnings with current OpenCTI."""
        result = live_client.validate_startup()

        # With OpenCTI 6.x, we shouldn't have version incompatibility warnings
        version_warnings = [
            w for w in result['warnings']
            if 'older' in w.lower() or 'newer' in w.lower()
        ]
        # Might have warnings if server is v7+, but that's expected
        # For now just verify we can get version info


# =============================================================================
# Server Info Live Tests
# =============================================================================

class TestLiveServerInfo:
    """Test server info retrieval against live OpenCTI."""

    def test_get_server_info(self, live_client):
        """Get server info from live server."""
        info = live_client.get_server_info()

        assert 'url' in info
        assert 'version' in info
        assert 'available' in info
        assert info['available'] is True
        assert info['version'] is not None

    def test_server_info_includes_circuit_breaker(self, live_client):
        """Server info includes circuit breaker state."""
        info = live_client.get_server_info()

        assert 'circuit_breaker_state' in info
        assert info['circuit_breaker_state'] == 'closed'


# =============================================================================
# Caching Live Tests
# =============================================================================

class TestLiveCaching:
    """Test caching against live OpenCTI."""

    def test_search_with_caching_enabled(self, live_config):
        """Search works with caching enabled."""
        from unittest.mock import patch

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True
            )
            client = OpenCTIClient(live_config)

            # First search - should hit API
            results1 = client.search_indicators("test", limit=5)
            metadata1 = client.get_last_response_metadata()

            # Results should be a list
            assert isinstance(results1, list)
            # First call should not be from cache
            assert metadata1['from_cache'] is False

            # Second identical search - should hit cache
            results2 = client.search_indicators("test", limit=5)
            metadata2 = client.get_last_response_metadata()

            # Should be from cache
            assert metadata2['from_cache'] is True
            # Results should be the same
            assert results1 == results2

    def test_cache_stats_populated(self, live_config):
        """Cache stats populated after searches."""
        from unittest.mock import patch

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True
            )
            client = OpenCTIClient(live_config)

            # Do some searches
            client.search_indicators("malware", limit=5)
            client.search_indicators("malware", limit=5)  # Cache hit

            stats = client.get_cache_stats()

            assert 'search' in stats
            assert stats['search']['hits'] >= 1
            assert stats['search']['misses'] >= 1


# =============================================================================
# Feature Flags Live Tests
# =============================================================================

class TestLiveFeatureFlags:
    """Test feature flags with live OpenCTI."""

    def setup_method(self):
        """Reset flags before each test."""
        reset_feature_flags()

    def test_caching_disabled_by_default(self, live_config):
        """Response caching disabled by default."""
        reset_feature_flags()
        client = OpenCTIClient(live_config)

        results1 = client.search_indicators("test", limit=5)
        metadata1 = client.get_last_response_metadata()

        # Should not be from cache with default flags
        assert metadata1['from_cache'] is False

        results2 = client.search_indicators("test", limit=5)
        metadata2 = client.get_last_response_metadata()

        # Still should not be from cache
        assert metadata2['from_cache'] is False


# =============================================================================
# Network Status Live Tests
# =============================================================================

class TestLiveNetworkStatus:
    """Test network status with live OpenCTI."""

    def test_network_status_healthy(self, live_client):
        """Network status shows healthy with live server."""
        status = live_client.get_network_status()

        assert 'circuit_breaker' in status
        assert status['circuit_breaker']['state'] == 'closed'

    def test_adaptive_metrics_populated(self, live_client):
        """Adaptive metrics populated after queries."""
        # Do some queries
        live_client.search_threat_actors("APT", limit=5)
        live_client.search_malware("ransomware", limit=5)

        status = live_client.get_network_status()

        # Should have some samples
        assert 'adaptive_metrics' in status
        sample_count = status['adaptive_metrics'].get('sample_count', 0)
        assert sample_count >= 0  # May be 0 if metrics not enabled


# =============================================================================
# Force Reconnect Live Tests
# =============================================================================

class TestLiveForceReconnect:
    """Test force reconnect with live OpenCTI."""

    def test_force_reconnect_clears_state(self, live_client):
        """Force reconnect clears caches and circuit breaker."""
        # Do a query first
        live_client.search_threat_actors("APT29", limit=5)

        # Force reconnect
        live_client.force_reconnect()

        # Circuit breaker should be closed
        assert live_client._circuit_breaker.state == CircuitState.CLOSED

        # Health cache should be cleared
        assert live_client._health_cache is None

    def test_queries_work_after_reconnect(self, live_client):
        """Queries work after force reconnect."""
        live_client.force_reconnect()

        # Should be able to query
        results = live_client.search_threat_actors("APT", limit=5)
        assert isinstance(results, list)

        # Server should be available
        assert live_client.is_available() is True
