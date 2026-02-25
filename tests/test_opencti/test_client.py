"""Tests for OpenCTI client module."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from opencti_mcp.client import CircuitBreaker, CircuitState, OpenCTIClient, RateLimiter
from opencti_mcp.config import Config
from opencti_mcp.errors import QueryError, RateLimitError

# =============================================================================
# Rate Limiter Tests
# =============================================================================


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_allows_within_limit(self):
        """Allow calls within limit."""
        limiter = RateLimiter(max_calls=5, window_seconds=60)

        for _ in range(5):
            assert limiter.check() is True
            limiter.record()

    def test_blocks_over_limit(self):
        """Block calls over limit."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        limiter.record()
        limiter.record()

        assert limiter.check() is False

    def test_wait_time(self):
        """Wait time is calculated correctly."""
        limiter = RateLimiter(max_calls=1, window_seconds=60)

        limiter.record()

        wait = limiter.wait_time()
        assert wait > 0
        assert wait <= 60

    def test_check_and_record_atomic(self):
        """check_and_record atomically checks and records."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        # First two should succeed
        assert limiter.check_and_record() is True
        assert limiter.check_and_record() is True

        # Third should fail
        assert limiter.check_and_record() is False

    def test_thread_safety(self):
        """RateLimiter is thread-safe under concurrent access."""
        import threading

        limiter = RateLimiter(max_calls=100, window_seconds=60)
        results = []

        def record_calls():
            for _ in range(20):
                result = limiter.check_and_record()
                results.append(result)

        threads = [threading.Thread(target=record_calls) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have exactly 100 True and 100 False
        assert results.count(True) == 100
        assert results.count(False) == 100


# =============================================================================
# Circuit Breaker Tests
# =============================================================================


class TestCircuitBreaker:
    """Tests for CircuitBreaker class."""

    def test_starts_closed(self):
        """Circuit starts in closed state."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold(self):
        """Circuit opens after failure threshold reached."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

        # Record failures up to threshold
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()

        # Should now be open
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_success_resets_failures(self):
        """Success resets failure count."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

        cb.record_failure()
        cb.record_failure()
        cb.record_success()

        # Should be closed with reset counter
        assert cb.state == CircuitState.CLOSED

        # Should need 3 more failures to open
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_timeout(self):
        """Circuit transitions to half-open after timeout."""
        import time

        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(1.1)

        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_reset_closes_circuit(self):
        """Reset forces circuit to closed."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED


# =============================================================================
# Client Connection Tests
# =============================================================================


class TestClientConnection:
    """Tests for client connection handling."""

    def test_connect_caches_client(self, mock_config: Config):
        """Client is cached after first connection."""
        client = OpenCTIClient(mock_config)
        mock_pycti = Mock()
        client._client = mock_pycti

        # Should return cached client without creating a new one
        result = client.connect()
        assert result is mock_pycti

    def test_is_available_true(self, mock_opencti_client: OpenCTIClient):
        """is_available returns True when connected."""
        assert mock_opencti_client.is_available() is True

    def test_is_available_false_on_error(self, mock_config: Config):
        """is_available returns False on connection error."""
        client = OpenCTIClient(mock_config)
        client._client = Mock()
        client._client.stix_cyber_observable.list.side_effect = Exception(
            "Connection failed"
        )

        assert client.is_available() is False

    def test_health_check_caching(self, mock_opencti_client: OpenCTIClient):
        """Health check result is cached."""
        # First call
        result1 = mock_opencti_client.is_available()
        assert result1 is True

        # Second call should use cache (not call API again)
        call_count_before = (
            mock_opencti_client._client.stix_cyber_observable.list.call_count
        )
        result2 = mock_opencti_client.is_available()
        call_count_after = (
            mock_opencti_client._client.stix_cyber_observable.list.call_count
        )

        assert result2 is True
        assert call_count_after == call_count_before  # No new API call

    def test_clear_health_cache(self, mock_opencti_client: OpenCTIClient):
        """Health cache can be cleared."""
        # Prime the cache
        mock_opencti_client.is_available()

        # Clear it
        mock_opencti_client.clear_health_cache()

        # Next call should hit API
        call_count_before = (
            mock_opencti_client._client.stix_cyber_observable.list.call_count
        )
        mock_opencti_client.is_available()
        call_count_after = (
            mock_opencti_client._client.stix_cyber_observable.list.call_count
        )

        assert call_count_after == call_count_before + 1


# =============================================================================
# Search Method Tests
# =============================================================================


class TestSearchMethods:
    """Tests for search methods."""

    def test_search_indicators(self, mock_opencti_client: OpenCTIClient):
        """Search indicators returns formatted results."""
        results = mock_opencti_client.search_indicators("test")

        assert len(results) == 1
        assert results[0]["type"] == "indicator"
        assert results[0]["name"] == "Test IOC"

    def test_search_threat_actors(self, mock_opencti_client: OpenCTIClient):
        """Search threat actors returns formatted results."""
        results = mock_opencti_client.search_threat_actors("APT")

        assert len(results) == 1
        assert results[0]["type"] == "threat_actor"
        assert results[0]["name"] == "APT29"

    def test_search_malware(self, mock_opencti_client: OpenCTIClient):
        """Search malware returns formatted results."""
        results = mock_opencti_client.search_malware("cobalt")

        assert len(results) == 1
        assert results[0]["type"] == "malware"
        assert results[0]["name"] == "Cobalt Strike"

    def test_search_attack_patterns(self, mock_opencti_client: OpenCTIClient):
        """Search attack patterns returns formatted results."""
        results = mock_opencti_client.search_attack_patterns("T1003")

        assert len(results) == 1
        assert results[0]["type"] == "attack_pattern"
        assert results[0]["mitre_id"] == "T1003"

    def test_search_vulnerabilities(self, mock_opencti_client: OpenCTIClient):
        """Search vulnerabilities returns formatted results."""
        results = mock_opencti_client.search_vulnerabilities("CVE-2024")

        assert len(results) == 1
        assert results[0]["type"] == "vulnerability"
        assert results[0]["name"] == "CVE-2024-3400"

    def test_search_reports(self, mock_opencti_client: OpenCTIClient):
        """Search reports returns formatted results."""
        results = mock_opencti_client.search_reports("APT29")

        assert len(results) == 1
        assert results[0]["type"] == "report"

    def test_unified_search(self, mock_opencti_client: OpenCTIClient):
        """Unified search queries all entity types."""
        results = mock_opencti_client.unified_search("test")

        assert "query" in results
        assert "indicators" in results
        assert "threat_actors" in results
        assert "malware" in results
        assert "attack_patterns" in results
        assert "vulnerabilities" in results
        assert "reports" in results


# =============================================================================
# Context Method Tests
# =============================================================================


class TestContextMethods:
    """Tests for context/lookup methods."""

    def test_get_indicator_context_found(self, mock_opencti_client: OpenCTIClient):
        """Get indicator context returns full context."""
        result = mock_opencti_client.get_indicator_context("192.168.1.1")

        assert result["found"] is True
        assert result["ioc"] == "192.168.1.1"
        assert result["source"] == "opencti"

    def test_get_indicator_context_not_found(self, mock_opencti_client: OpenCTIClient):
        """Get indicator context handles not found."""
        mock_opencti_client._client.indicator.list.return_value = []

        result = mock_opencti_client.get_indicator_context("unknown-ioc")

        assert result["found"] is False

    def test_get_recent_indicators(self, mock_opencti_client: OpenCTIClient):
        """Get recent indicators returns results."""
        results = mock_opencti_client.get_recent_indicators(days=7)

        assert len(results) == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_query_error_on_exception(self, mock_opencti_client: OpenCTIClient):
        """QueryError raised on API exception."""
        mock_opencti_client._client.indicator.list.side_effect = Exception("API error")

        with pytest.raises(QueryError):
            mock_opencti_client.search_indicators("test")

    def test_rate_limit_error(self, mock_opencti_client: OpenCTIClient):
        """RateLimitError when limit exceeded."""
        # Exhaust rate limit by recording calls
        mock_opencti_client._query_limiter.max_calls = 1
        mock_opencti_client._query_limiter.calls.clear()
        mock_opencti_client._query_limiter.record()  # Use up the single allowed call

        with pytest.raises(RateLimitError):
            mock_opencti_client.search_indicators("test")


# =============================================================================
# Validation Tests
# =============================================================================


class TestInputValidation:
    """Tests for input validation in client."""

    def test_validates_query_length(self, mock_opencti_client: OpenCTIClient):
        """Query length is validated."""
        from opencti_mcp.errors import ValidationError
        from opencti_mcp.validation import MAX_QUERY_LENGTH

        with pytest.raises(ValidationError):
            mock_opencti_client.search_indicators("x" * (MAX_QUERY_LENGTH + 1))

    def test_validates_limit(self, mock_opencti_client: OpenCTIClient):
        """Limit is clamped to max."""
        # Should not raise, but clamp the limit
        results = mock_opencti_client.search_indicators("test", limit=1000)
        # Verify the search was still called (limit was clamped, not rejected)
        assert mock_opencti_client._client.indicator.list.called
