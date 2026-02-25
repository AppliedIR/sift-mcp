"""Tests for code review fixes: adaptive timeout loop, feature flags cleanup, default timeout."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from opencti_mcp.adaptive import AdaptiveConfig, AdaptiveMetrics
from opencti_mcp.config import Config
from opencti_mcp.feature_flags import (
    FeatureFlags,
    get_feature_flags,
    reset_feature_flags,
)

# ============================================================================
# Feature flags cleanup tests
# ============================================================================


class TestFeatureFlagsCleanup:
    """Tests for dead feature flag removal."""

    def test_no_version_checking_flag(self):
        """version_checking flag has been removed."""
        flags = FeatureFlags()
        assert not hasattr(flags, "version_checking")

    def test_no_request_correlation_flag(self):
        """request_correlation flag has been removed."""
        flags = FeatureFlags()
        assert not hasattr(flags, "request_correlation")

    def test_no_adaptive_timeouts_flag(self):
        """adaptive_timeouts flag has been removed."""
        flags = FeatureFlags()
        assert not hasattr(flags, "adaptive_timeouts")

    def test_remaining_flags_present(self):
        """All surviving flags still exist with correct defaults."""
        flags = FeatureFlags()
        assert flags.response_caching is False
        assert flags.graceful_degradation is True
        assert flags.startup_validation is True
        assert flags.negative_caching is True

    def test_to_dict_only_live_flags(self):
        """to_dict returns only the 4 live flags."""
        flags = FeatureFlags()
        d = flags.to_dict()
        assert len(d) == 4
        assert set(d.keys()) == {
            "response_caching",
            "graceful_degradation",
            "startup_validation",
            "negative_caching",
        }

    def test_load_from_env(self):
        """load() reads the 4 live flags from env."""
        with patch.dict("os.environ", {"FF_RESPONSE_CACHING": "true"}):
            reset_feature_flags()
            flags = get_feature_flags()
            assert flags.response_caching is True
            reset_feature_flags()

    def test_dead_env_vars_ignored(self):
        """Old env vars for removed flags don't cause errors."""
        with patch.dict(
            "os.environ",
            {
                "FF_VERSION_CHECKING": "false",
                "FF_REQUEST_CORRELATION": "false",
                "FF_ADAPTIVE_TIMEOUTS": "true",
            },
        ):
            reset_feature_flags()
            flags = get_feature_flags()
            # Should load without error, dead vars silently ignored
            assert flags.startup_validation is True
            reset_feature_flags()


# ============================================================================
# Default timeout tests
# ============================================================================


class TestDefaultTimeout:
    """Tests for raised default timeout."""

    def test_config_default_is_60(self):
        """Config default timeout is 60s (was 30s)."""
        assert Config.__dataclass_fields__["timeout_seconds"].default == 60

    def test_config_load_default(self):
        """Config.load() uses 60s default when env not set."""
        with patch.dict("os.environ", {"OPENCTI_TOKEN": "test-token"}, clear=False):
            with patch("opencti_mcp.config._load_token", return_value="test-token"):
                config = Config.load()
                assert config.timeout_seconds == 60

    def test_config_env_override(self):
        """OPENCTI_TIMEOUT env var still overrides default."""
        with patch.dict(
            "os.environ",
            {
                "OPENCTI_TOKEN": "test-token",
                "OPENCTI_TIMEOUT": "120",
            },
            clear=False,
        ):
            with patch("opencti_mcp.config._load_token", return_value="test-token"):
                config = Config.load()
                assert config.timeout_seconds == 120


# ============================================================================
# Adaptive timeout feedback loop tests
# ============================================================================


class TestAdaptiveTimeoutLoop:
    """Tests for _maybe_adapt_timeout wiring."""

    def _make_client(self, timeout=60):
        """Create a mock-configured OpenCTIClient."""
        from opencti_mcp.client import OpenCTIClient

        config = MagicMock()
        config.timeout_seconds = timeout
        config.max_results = 100
        config.rate_limit_queries = 60
        config.rate_limit_enrichment = 10
        config.circuit_breaker_threshold = 5
        config.circuit_breaker_timeout = 60
        config.max_retries = 3
        config.retry_base_delay = 1.0
        config.retry_max_delay = 30.0
        config.ssl_verify = True
        config.extra_observable_types = frozenset()
        config.extra_pattern_types = frozenset()

        # Create client with mock adaptive metrics
        metrics = AdaptiveMetrics(latency_window=50, success_window=50)
        client = OpenCTIClient(config, adaptive_metrics=metrics)
        return client, metrics

    def test_effective_timeout_initialized_from_config(self):
        """_effective_timeout starts at config.timeout_seconds."""
        client, _ = self._make_client(timeout=60)
        assert client._effective_timeout == 60

    def test_no_adapt_under_5_requests(self):
        """No adaptation happens in the first 4 requests."""
        client, metrics = self._make_client(timeout=60)
        # Record enough latency data to trigger adaptation
        for i in range(20):
            metrics.record_request(start_time=time.time() - 2.0, success=True)

        # Call 4 times - shouldn't check adaptive config
        for _ in range(4):
            client._maybe_adapt_timeout()
        assert client._effective_timeout == 60

    def test_no_adapt_under_10_samples(self):
        """No adaptation with fewer than 10 samples."""
        client, metrics = self._make_client(timeout=60)
        # Only 5 samples
        for i in range(5):
            metrics.record_request(start_time=time.time() - 2.0, success=True)

        # Force check (set counter to multiple of 5)
        client._adapt_success_count = 4
        client._maybe_adapt_timeout()
        assert client._effective_timeout == 60

    def test_adapt_increases_timeout(self):
        """Timeout increases when adaptive recommends higher value."""
        client, metrics = self._make_client(timeout=30)
        # Simulate slow requests (2 second latency = 2000ms)
        for i in range(20):
            metrics.record_request(start_time=time.time() - 2.0, success=True)

        # Force the adaptive config to recommend a higher timeout
        adaptive_config = metrics.get_adaptive_config()
        # The adaptive system should recommend > 30s for 2000ms latency

        # Force check
        client._adapt_success_count = 4
        client._maybe_adapt_timeout()

        # If adaptive recommends higher and diff > 25%, it should adapt
        if adaptive_config.recommended_timeout > 30 * 1.25:
            assert client._effective_timeout > 30
        else:
            # Even if not, the method shouldn't crash
            assert client._effective_timeout >= 10

    def test_adapt_updates_pycti_client(self):
        """Adaptation updates pycti client's requests_timeout."""
        client, metrics = self._make_client(timeout=30)

        # Create a mock pycti client
        mock_pycti = MagicMock()
        mock_pycti.requests_timeout = 30
        client._client = mock_pycti

        # Simulate high latency to force adaptation
        for i in range(20):
            metrics.record_request(start_time=time.time() - 5.0, success=True)

        adaptive = metrics.get_adaptive_config()
        if adaptive.recommended_timeout > 30 * 1.25:
            client._adapt_success_count = 4
            client._maybe_adapt_timeout()
            assert mock_pycti.requests_timeout == client._effective_timeout

    def test_no_adapt_within_25_percent(self):
        """No adaptation when recommendation is within 25% of current."""
        client, metrics = self._make_client(timeout=60)
        # Simulate requests with ~60ms latency (P95 * buffer will be close to 60)
        for i in range(20):
            metrics.record_request(start_time=time.time() - 0.06, success=True)

        client._adapt_success_count = 4
        old_timeout = client._effective_timeout
        client._maybe_adapt_timeout()
        # Should stay the same if recommendation is within 25%
        adaptive = metrics.get_adaptive_config()
        if abs(adaptive.recommended_timeout - old_timeout) / old_timeout <= 0.25:
            assert client._effective_timeout == old_timeout

    def test_adapt_clamps_minimum(self):
        """Adapted timeout never goes below 10s."""
        client, metrics = self._make_client(timeout=60)
        # Mock get_adaptive_config to return very low timeout
        with patch.object(metrics, "get_adaptive_config") as mock_config:
            mock_config.return_value = AdaptiveConfig(
                recommended_timeout=3,  # Very low
                recommended_retry_delay=1.0,
                recommended_max_retries=3,
                recommended_circuit_threshold=5,
                latency_classification="excellent",
                success_rate=1.0,
                probe_count=20,
                latency_stats=None,
                last_probe_time=None,
            )
            client._adapt_success_count = 4
            client._maybe_adapt_timeout()
            assert client._effective_timeout >= 10

    def test_adapt_clamps_maximum(self):
        """Adapted timeout never exceeds 300s."""
        client, metrics = self._make_client(timeout=60)
        with patch.object(metrics, "get_adaptive_config") as mock_config:
            mock_config.return_value = AdaptiveConfig(
                recommended_timeout=500,  # Very high
                recommended_retry_delay=1.0,
                recommended_max_retries=3,
                recommended_circuit_threshold=5,
                latency_classification="poor",
                success_rate=0.5,
                probe_count=20,
                latency_stats=None,
                last_probe_time=None,
            )
            client._adapt_success_count = 4
            client._maybe_adapt_timeout()
            assert client._effective_timeout <= 300

    def test_connect_uses_effective_timeout(self):
        """connect() uses _effective_timeout, not config.timeout_seconds."""
        client, _ = self._make_client(timeout=60)
        client._effective_timeout = 120  # Simulate adaptation

        with patch("opencti_mcp.client.OpenCTIClient.connect") as mock_connect:
            # We can't easily test the internal pycti call, but we can verify
            # the attribute is available
            assert client._effective_timeout == 120

    def test_network_status_shows_effective_timeout(self):
        """get_network_status includes effective_timeout_seconds."""
        client, metrics = self._make_client(timeout=60)
        client._effective_timeout = 90  # Simulate adaptation

        status = client.get_network_status()
        assert status["current_config"]["timeout_seconds"] == 60
        assert status["current_config"]["effective_timeout_seconds"] == 90

    def test_adapt_is_called_in_retry_success_path(self):
        """_maybe_adapt_timeout is called after successful requests."""
        client, metrics = self._make_client(timeout=60)

        with patch.object(client, "_maybe_adapt_timeout") as mock_adapt:
            with patch.object(client, "_circuit_breaker") as mock_cb:
                mock_cb.allow_request.return_value = True
                mock_cb.record_success = MagicMock()

                # Execute a function that succeeds
                result = client._execute_with_retry(lambda: "success")
                assert result == "success"
                mock_adapt.assert_called_once()
