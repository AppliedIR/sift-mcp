"""Tests for new features: feature flags, startup validation, caching."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from opencti_mcp.cache import NOT_FOUND, TTLCache
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.feature_flags import (
    FeatureFlags,
    get_feature_flags,
    reset_feature_flags,
)

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
        with patch.dict(
            os.environ,
            {
                "FF_RESPONSE_CACHING": "true",
                "FF_GRACEFUL_DEGRADATION": "false",
                "FF_STARTUP_VALIDATION": "1",
            },
        ):
            flags = FeatureFlags.load()

            assert flags.response_caching is True
            assert flags.graceful_degradation is False
            assert flags.startup_validation is True

    def test_to_dict(self):
        """Convert to dictionary."""
        flags = FeatureFlags()
        d = flags.to_dict()

        assert "response_caching" in d
        assert "graceful_degradation" in d
        assert isinstance(d["response_caching"], bool)

    def test_is_enabled(self):
        """Check flag by name."""
        flags = FeatureFlags(response_caching=True)
        assert flags.is_enabled("response_caching") is True
        assert flags.is_enabled("nonexistent") is False

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

        assert (
            "HTTP" in result["warnings"][0] or "http" in result["warnings"][0].lower()
        )

    def test_validate_startup_localhost_no_warning(self, mock_config):
        """HTTP on localhost doesn't trigger warning."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = client.validate_startup(skip_connectivity=True)

        # Should have no HTTP warnings for localhost
        http_warnings = [
            w for w in result["warnings"] if "HTTP" in w or "http" in w.lower()
        ]
        assert len(http_warnings) == 0

    def test_validate_startup_returns_valid_structure(self, mock_config):
        """Validation result has correct structure."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        result = client.validate_startup(skip_connectivity=True)

        assert "valid" in result
        assert "warnings" in result
        assert "errors" in result
        assert isinstance(result["valid"], bool)
        assert isinstance(result["warnings"], list)
        assert isinstance(result["errors"], list)

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

        with patch("opencti_mcp.client.get_feature_flags") as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True, graceful_degradation=True
            )
            client = OpenCTIClient(mock_config)

            assert hasattr(client, "_search_cache")
            assert hasattr(client, "_entity_cache")
            assert hasattr(client, "_ioc_cache")

    def test_response_metadata_tracking(self, mock_config):
        """Response metadata is tracked."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        # Initial state
        assert client._last_response_from_cache is False
        assert client._last_response_degraded is False

        # Get metadata method works
        metadata = client.get_last_response_metadata()
        assert "from_cache" in metadata
        assert "degraded" in metadata

    def test_cache_stats(self, mock_config):
        """Cache stats retrieval works."""
        from opencti_mcp.client import OpenCTIClient

        with patch("opencti_mcp.client.get_feature_flags") as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True, graceful_degradation=True
            )
            client = OpenCTIClient(mock_config)

            stats = client.get_cache_stats()
            assert isinstance(stats, dict)

    def test_clear_all_caches(self, mock_config):
        """Clear all caches works."""
        from opencti_mcp.client import OpenCTIClient

        with patch("opencti_mcp.client.get_feature_flags") as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True, graceful_degradation=True
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

    def test_get_server_info(self, mock_config):
        """Server info structure is correct."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        # Mock the connect to avoid actual connection
        with patch.object(client, "connect") as mock_connect:
            with patch.object(client, "_get_opencti_version") as mock_version:
                with patch.object(client, "is_available") as mock_available:
                    mock_version.return_value = {"version": "6.1.0"}
                    mock_available.return_value = True

                    info = client.get_server_info()

                    assert "url" in info
                    assert "version" in info
                    assert "available" in info


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

        with patch("opencti_mcp.client.get_feature_flags") as mock_flags:
            mock_flags.return_value = FeatureFlags(graceful_degradation=False)
            client = OpenCTIClient(mock_config)

            # Without graceful_degradation, _get_fallback should return not found
            found, cached, degraded = client._get_fallback(
                TTLCache(ttl_seconds=60), "test_key"
            )
            assert found is False

    def test_cache_helper_methods(self, mock_config):
        """Cache helper methods work correctly."""
        from opencti_mcp.client import OpenCTIClient

        with patch("opencti_mcp.client.get_feature_flags") as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True, graceful_degradation=True, negative_caching=True
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


# =============================================================================
# Startup Degraded Mode Tests (Rev 2 — UAT/CR-verified fix)
# =============================================================================


class TestStartupDegradedMode:
    """Pins the bounded-probe + degraded-mode behavior added in Rev 2.

    Pre-fix: unreachable OpenCTI server caused pycti's __init__
    health_check to block for 300s (default requests_timeout).
    Post-fix: validate_startup uses a probe client with
    perform_health_check=False + bounded requests_timeout. On failure,
    sets _degraded=True and returns cleanly; tools fail-fast via
    _ensure_not_degraded.
    """

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://unreachable.example.com:8080",
            opencti_token=SecretStr("test-token-12345"),
        )

    def test_validate_startup_unreachable_returns_degraded(self, mock_config):
        """Connection error → degraded mode, returns cleanly (no raise)."""
        import requests
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        with patch.object(client, "_connect_probe") as mock_probe:
            mock_probe.side_effect = requests.exceptions.ConnectionError(
                "Connection refused"
            )
            result = client.validate_startup()

        assert result["valid"] is False
        assert client._degraded is True
        assert "DEGRADED" in result["errors"][0]
        assert "unreachable" in result["errors"][0]

    def test_validate_startup_timeout_returns_degraded(self, mock_config):
        """Timeout (server hung) → same degraded path."""
        import requests
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        with patch.object(client, "_connect_probe") as mock_probe:
            mock_probe.side_effect = requests.exceptions.Timeout("Read timed out")
            result = client.validate_startup()

        assert client._degraded is True
        assert result["valid"] is False

    def test_degraded_mode_tools_fail_fast(self, mock_config):
        """Real tool methods (NOT just the helper) raise when _degraded=True.

        Pre-fix this test only exercised the helper directly — the
        regression-guard against missing wiring was absent. Post-fix
        the guard lives at the top of connect(); all 20+ tool methods
        funnel through it, so calling any of them in degraded mode
        raises within milliseconds without contacting the server.

        Repeated for 3 representative tools per spec Test 3 + the
        helper assertion to pin the message shape operators see.
        """
        from opencti_mcp.client import OpenCTIClient
        from opencti_mcp.errors import DegradedError

        client = OpenCTIClient(mock_config)
        client._degraded = True
        client._degraded_reason = "server unreachable within 10s: ConnectionError"

        # Helper raises with actionable text — keep to pin message shape
        with pytest.raises(DegradedError) as exc_info:
            client._ensure_not_degraded("lookup_ioc")
        msg = str(exc_info.value)
        assert "lookup_ioc" in msg
        assert "DEGRADED" in msg
        assert "vhir service restart" in msg

        # Actual regression guard: invoke 3 real tool methods. Each
        # MUST hit the chokepoint in connect() and either raise
        # DegradedError or surface it via a structured "degraded"
        # response dict (some tools have graceful_degradation handlers
        # that catch and convert to a structured return). EITHER shape
        # meets spec acceptance criterion 3 ("return structured error
        # with actionable message in <100ms"). Pre-fix: tools blocked
        # 300s on the runtime client's requests_timeout.
        #
        # The load-bearing guarantee here is the wall-clock cap, NOT
        # the precise exception class. DegradedError is in fail-fast
        # branch of the retry loop, so the loop must short-circuit
        # (no 4× backoff = no 16s ordeal).
        import time

        for method_name, args in (
            ("get_indicator_context", ("1.2.3.4",)),
            ("get_recent_indicators", (7, 10)),
            ("get_entity", ("00000000-0000-0000-0000-000000000000",)),
        ):
            method = getattr(client, method_name)
            t0 = time.monotonic()
            try:
                result = method(*args)
                # Returned (not raised) — must be a structured response
                # carrying DEGRADED marker so the operator/MCP-tool
                # surface can fail-fast at the next layer.
                serialized = str(result)
                assert "DEGRADED" in serialized.upper() or "degraded" in serialized, (
                    f"{method_name} returned without DEGRADED marker: {result!r}"
                )
            except (DegradedError, Exception) as e:
                # DegradedError direct, or wrapped (e.g., QueryError
                # from the retry layer chains the original message
                # through `raise ... from e`). The chain must carry
                # "DEGRADED" through to the operator-facing text.
                chain_text = str(e) + "; cause=" + str(e.__cause__ or "")
                assert "DEGRADED" in chain_text or "Degraded" in chain_text, (
                    f"{method_name} raised {type(e).__name__} but chain "
                    f"text lacks DEGRADED marker: {chain_text!r}"
                )
            elapsed = time.monotonic() - t0
            # Spec acceptance criterion 3: <1s for tool calls in
            # degraded mode. Pre-fix-with-retries: 16s+ due to backoff.
            assert elapsed < 1.0, (
                f"{method_name} took {elapsed:.3f}s — should be <1s "
                f"(DegradedError must NOT be retried by transient loop)"
            )

    def test_validate_startup_uses_probe_not_runtime_client(self, mock_config):
        """Spec Test 4 — validate_startup must call _connect_probe(),
        NOT connect(). Pre-Rev-2 it called connect() which triggers
        pycti's __init__ health_check (300s hang on unreachable host).
        """
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        with patch.object(client, "_connect_probe") as mp:
            mp.return_value = object()  # mock probe client
            with patch.object(client, "_get_opencti_version", return_value=None):
                with patch.object(client, "connect") as mc:
                    try:
                        client.validate_startup()
                    except Exception:
                        pass  # post-probe path may raise; we only care
                        # that connect() was bypassed
                    mp.assert_called()
                    mc.assert_not_called()

    def test_probe_uses_perform_health_check_false(self, mock_config):
        """The probe must pass perform_health_check=False so pycti's
        __init__ doesn't fire its own HTTP call. Pre-fix, the default
        True caused 300s hang in the constructor.
        """
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        with patch("pycti.OpenCTIApiClient") as mock_api:
            mock_api.return_value = object()
            client._connect_probe()

        call_kwargs = mock_api.call_args.kwargs
        assert call_kwargs["perform_health_check"] is False
        # requests_timeout uses _STARTUP_PROBE_TIMEOUT (default 10)
        assert call_kwargs["requests_timeout"] >= 1
        assert call_kwargs["requests_timeout"] <= 300

    def test_server_reuses_validated_client_instance(self, mock_config):
        """BLOCKER regression — live test caught 2026-05-11.

        Pre-fix __main__.py built one OpenCTIClient for validation,
        OpenCTIMCPServer built another. `_degraded` set on the first
        never reached the tool-call path that used the second.
        AC3 (degraded mode tool call <1s) failed live with 8s+ retry
        loop because instance #2's `_degraded` was always False.

        Post-fix: `OpenCTIMCPServer(config, client=instance)` accepts
        the validated client and uses it. This test pins the wiring so
        a future refactor doesn't silently regress to two instances.
        """
        from opencti_mcp.client import OpenCTIClient
        from opencti_mcp.server import OpenCTIMCPServer

        validated = OpenCTIClient(mock_config)
        validated._degraded = True
        validated._degraded_reason = "test"

        # Construct server with the validated client — must reuse it,
        # NOT build a fresh one.
        server = OpenCTIMCPServer(mock_config, client=validated)
        assert server.client is validated, (
            "OpenCTIMCPServer must reuse the passed client instance, "
            "not construct a new one. Two-instance bug: degraded flag "
            "set on the validated client wouldn't reach tool calls."
        )

        # Default (no client passed) still works — backwards compat
        server_default = OpenCTIMCPServer(mock_config)
        assert isinstance(server_default.client, OpenCTIClient)
        assert server_default.client is not validated  # different instance

    def test_other_exceptions_in_validate_startup_still_raise_path(self, mock_config):
        """Non-network exceptions (auth failure, GraphQL mismatch) must
        NOT set degraded — those are real config errors and need to
        surface as before.
        """
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        with patch.object(client, "_connect_probe") as mock_probe:
            mock_probe.side_effect = RuntimeError("Unauthorized: bad token")
            result = client.validate_startup()

        # Falls through the "Other failures" branch — sets valid=False
        # but does NOT flip degraded
        assert client._degraded is False
        assert result["valid"] is False
        assert "Connectivity test failed: RuntimeError" in result["errors"]


class TestStartupProbeTimeoutEnv:
    """OPENCTI_STARTUP_TIMEOUT env var with 1-300 bounds check."""

    def test_default_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_STARTUP_TIMEOUT", raising=False)
        from opencti_mcp.client import _load_startup_probe_timeout

        assert _load_startup_probe_timeout() == 10

    def test_env_override_valid(self, monkeypatch):
        from opencti_mcp.client import _load_startup_probe_timeout

        monkeypatch.setenv("OPENCTI_STARTUP_TIMEOUT", "30")
        assert _load_startup_probe_timeout() == 30

        monkeypatch.setenv("OPENCTI_STARTUP_TIMEOUT", "1")
        assert _load_startup_probe_timeout() == 1

        monkeypatch.setenv("OPENCTI_STARTUP_TIMEOUT", "300")
        assert _load_startup_probe_timeout() == 300

    def test_env_override_non_integer_rejects(self, monkeypatch):
        from opencti_mcp.client import _load_startup_probe_timeout

        monkeypatch.setenv("OPENCTI_STARTUP_TIMEOUT", "foo")
        with pytest.raises(ValueError, match="must be an integer"):
            _load_startup_probe_timeout()

    def test_env_override_out_of_range_rejects(self, monkeypatch):
        from opencti_mcp.client import _load_startup_probe_timeout

        for bad in ("0", "-1", "301", "9999"):
            monkeypatch.setenv("OPENCTI_STARTUP_TIMEOUT", bad)
            with pytest.raises(ValueError, match="1-300 second range"):
                _load_startup_probe_timeout()
