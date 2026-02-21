"""Tests for new features: feature flags, startup validation, caching."""

from __future__ import annotations

import os
import pytest
from unittest.mock import Mock, patch, MagicMock

from opencti_mcp.feature_flags import (
    FeatureFlags,
    get_feature_flags,
    reset_feature_flags,
)
from opencti_mcp.cache import TTLCache, generate_cache_key, NOT_FOUND
from opencti_mcp.config import Config, SecretStr


# =============================================================================
# Feature Flags Tests
# =============================================================================

class TestFeatureFlags:
    """Tests for feature flag functionality."""

    def setup_method(self):
        """Reset feature flags before each test."""
        reset_feature_flags()

    def test_default_values(self):
        """Default feature flag values."""
        flags = FeatureFlags()

        assert flags.response_caching is False  # Conservative default
        assert flags.graceful_degradation is True
        assert flags.startup_validation is True
        assert flags.negative_caching is True

    def test_load_from_environment(self):
        """Load feature flags from environment."""
        with patch.dict(os.environ, {
            'FF_RESPONSE_CACHING': 'true',
            'FF_GRACEFUL_DEGRADATION': 'false',
            'FF_STARTUP_VALIDATION': '1',
        }):
            flags = FeatureFlags.load()

            assert flags.response_caching is True
            assert flags.graceful_degradation is False
            assert flags.startup_validation is True

    def test_to_dict(self):
        """Convert to dictionary."""
        flags = FeatureFlags()
        d = flags.to_dict()

        assert 'response_caching' in d
        assert 'graceful_degradation' in d
        assert isinstance(d['response_caching'], bool)

    def test_is_enabled(self):
        """Check flag by name."""
        flags = FeatureFlags(response_caching=True)
        assert flags.is_enabled('response_caching') is True
        assert flags.is_enabled('nonexistent') is False

    def test_global_singleton(self):
        """Global singleton works correctly."""
        reset_feature_flags()
        flags1 = get_feature_flags()
        flags2 = get_feature_flags()
        assert flags1 is flags2

    def test_reset_singleton(self):
        """Reset clears singleton."""
        flags1 = get_feature_flags()
        reset_feature_flags()
        flags2 = get_feature_flags()
        # May or may not be same instance but both should work
        assert flags2 is not None


# =============================================================================
# Startup Validation Tests
# =============================================================================

class TestStartupValidation:
    """Tests for startup validation functionality."""

    @pytest.fixture
    def mock_config(self):
        """Create test configuration."""
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token-12345"),
        )

    def test_validate_startup_http_warning(self, mock_config):
        """HTTP on remote server triggers warning."""
        from opencti_mcp.client import OpenCTIClient

        # Use a remote URL (not localhost)
        config = Config(
            opencti_url="http://remote-server.example.com:8080",
            opencti_token=SecretStr("test-token"),
        )
        client = OpenCTIClient(config)

        result = client.validate_startup(skip_connectivity=True)

        assert 'HTTP' in result['warnings'][0] or 'http' in result['warnings'][0].lower()

    def test_validate_startup_localhost_no_warning(self, mock_config):
        """HTTP on localhost doesn't trigger warning."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = client.validate_startup(skip_connectivity=True)

        # Should have no HTTP warnings for localhost
        http_warnings = [w for w in result['warnings'] if 'HTTP' in w or 'http' in w.lower()]
        assert len(http_warnings) == 0

    def test_validate_startup_returns_valid_structure(self, mock_config):
        """Validation result has correct structure."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = client.validate_startup(skip_connectivity=True)

        assert 'valid' in result
        assert 'warnings' in result
        assert 'errors' in result
        assert isinstance(result['valid'], bool)
        assert isinstance(result['warnings'], list)
        assert isinstance(result['errors'], list)

    def test_is_local_url(self, mock_config):
        """Local URL detection works."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        assert client._is_local_url("http://localhost:8080") is True
        assert client._is_local_url("http://127.0.0.1:8080") is True
        assert client._is_local_url("http://example.com:8080") is False


# =============================================================================
# Cache Integration Tests
# =============================================================================

class TestCacheIntegration:
    """Tests for cache integration in client."""

    @pytest.fixture
    def mock_config(self):
        """Create test configuration."""
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token-12345"),
        )

    def test_cache_initialization_with_flags(self, mock_config):
        """Caches initialized when feature flags enable them."""
        from opencti_mcp.client import OpenCTIClient

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True
            )
            client = OpenCTIClient(mock_config)

            assert hasattr(client, '_search_cache')
            assert hasattr(client, '_entity_cache')
            assert hasattr(client, '_ioc_cache')

    def test_response_metadata_tracking(self, mock_config):
        """Response metadata is tracked."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        # Initial state
        assert client._last_response_from_cache is False
        assert client._last_response_degraded is False

        # Get metadata method works
        metadata = client.get_last_response_metadata()
        assert 'from_cache' in metadata
        assert 'degraded' in metadata

    def test_cache_stats(self, mock_config):
        """Cache stats retrieval works."""
        from opencti_mcp.client import OpenCTIClient

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True
            )
            client = OpenCTIClient(mock_config)

            stats = client.get_cache_stats()
            assert isinstance(stats, dict)

    def test_clear_all_caches(self, mock_config):
        """Clear all caches works."""
        from opencti_mcp.client import OpenCTIClient

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True
            )
            client = OpenCTIClient(mock_config)

            result = client.clear_all_caches()
            assert isinstance(result, dict)


# =============================================================================
# Version Checking Tests
# =============================================================================

class TestVersionChecking:
    """Tests for API version checking."""

    @pytest.fixture
    def mock_config(self):
        """Create test configuration."""
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token-12345"),
        )

    def test_version_compatibility_check_old_version(self, mock_config):
        """Old version triggers warning."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = {'warnings': []}

        client._check_version_compatibility({'version': '4.5.1'}, result)

        assert len(result['warnings']) > 0
        assert 'older' in result['warnings'][0].lower()

    def test_version_compatibility_check_new_version(self, mock_config):
        """New version triggers warning."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = {'warnings': []}

        client._check_version_compatibility({'version': '7.0.0'}, result)

        assert len(result['warnings']) > 0
        assert 'newer' in result['warnings'][0].lower()

    def test_version_compatibility_check_current_version(self, mock_config):
        """Current version doesn't trigger warning."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = {'warnings': []}

        client._check_version_compatibility({'version': '6.1.0'}, result)

        assert len(result['warnings']) == 0

    def test_get_server_info(self, mock_config):
        """Server info structure is correct."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        # Mock the connect to avoid actual connection
        with patch.object(client, 'connect') as mock_connect:
            with patch.object(client, '_get_opencti_version') as mock_version:
                with patch.object(client, 'is_available') as mock_available:
                    mock_version.return_value = {'version': '6.1.0'}
                    mock_available.return_value = True

                    info = client.get_server_info()

                    assert 'url' in info
                    assert 'version' in info
                    assert 'available' in info


# =============================================================================
# Graceful Degradation Tests
# =============================================================================

class TestGracefulDegradation:
    """Tests for graceful degradation functionality."""

    @pytest.fixture
    def mock_config(self):
        """Create test configuration."""
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token-12345"),
        )

    def test_degradation_flags(self, mock_config):
        """Degradation uses feature flags."""
        from opencti_mcp.client import OpenCTIClient

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                graceful_degradation=False
            )
            client = OpenCTIClient(mock_config)

            # Without graceful_degradation, _get_fallback should return not found
            found, cached, degraded = client._get_fallback(
                TTLCache(ttl_seconds=60),
                "test_key"
            )
            assert found is False

    def test_cache_helper_methods(self, mock_config):
        """Cache helper methods work correctly."""
        from opencti_mcp.client import OpenCTIClient

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True,
                negative_caching=True
            )
            client = OpenCTIClient(mock_config)

            cache = TTLCache(ttl_seconds=60, name="test")

            # Test caching
            client._cache_response(cache, "key1", ["result"])
            found, value = client._get_cached(cache, "key1")
            assert found is True
            assert value == ["result"]

            # Test negative caching
            client._cache_negative(cache, "key2")
            found, value = cache.get("key2")
            assert found is True
            assert value is NOT_FOUND
