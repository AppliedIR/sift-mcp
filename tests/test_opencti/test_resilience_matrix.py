"""Resilience Matrix Tests: Timeout Handling, Retry/Backoff, and Circuit Breaker.

Tests cover T1-T17 (Timeout), R1-R20 (Retry/Backoff), CB1-CB12 (Circuit Breaker).
Each test is tagged with its matrix ID for traceability.
"""

from __future__ import annotations

import os
import sys
import time
import threading
from time import monotonic
from unittest.mock import Mock, MagicMock, patch, PropertyMock, call

import pytest

from opencti_mcp.client import (
    OpenCTIClient,
    CircuitBreaker,
    CircuitState,
    TRANSIENT_ERRORS,
    TRANSIENT_HTTP_CODES,
)
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import (
    ConfigurationError,
    ValidationError,
    QueryError,
)
# Import the opencti_mcp ConnectionError under a distinct name
from opencti_mcp.errors import ConnectionError as OCTIConnectionError
from opencti_mcp.adaptive import AdaptiveMetrics, AdaptiveConfig


# =============================================================================
# Helpers
# =============================================================================

def make_config(**overrides) -> Config:
    """Create a Config with sensible test defaults, applying overrides."""
    defaults = dict(
        opencti_url="http://localhost:8080",
        opencti_token=SecretStr("test-token-12345"),
        timeout_seconds=60,
        max_results=100,
        max_retries=3,
        retry_base_delay=1.0,
        retry_max_delay=30.0,
        circuit_breaker_threshold=5,
        circuit_breaker_timeout=60,
    )
    defaults.update(overrides)
    return Config(**defaults)


def make_client(config: Config = None, adaptive_metrics: AdaptiveMetrics = None) -> OpenCTIClient:
    """Create an OpenCTIClient with optional config/metrics overrides."""
    if config is None:
        config = make_config()
    client = OpenCTIClient(config, adaptive_metrics=adaptive_metrics)
    # Set a mock pycti client to avoid real connections
    client._client = MagicMock()
    return client


# ---------------------------------------------------------------------------
# Exception helpers
#
# The retry logic in _is_transient_error checks type(error).__name__ against
# the TRANSIENT_ERRORS frozenset. We need exceptions whose class __name__
# matches entries like "ConnectionError", "TimeoutError", "SSLError", etc.
#
# Python builtins (ConnectionError, TimeoutError, OSError) already have the
# right names.  For requests-library types we create stand-in classes.
# ---------------------------------------------------------------------------

# Use the *real* Python builtin ConnectionError (not opencti_mcp.errors.ConnectionError)
_BuiltinConnectionError = type(
    "ConnectionError", (Exception,), {}
)  # __name__ == "ConnectionError"

# Re-use the real Python TimeoutError — its __name__ is already "TimeoutError"
_BuiltinTimeoutError = TimeoutError

# Re-use the real Python OSError
_BuiltinOSError = OSError

# Stand-ins for requests-library exceptions (names must match TRANSIENT_ERRORS)
SSLError = type("SSLError", (Exception,), {})
ProxyError = type("ProxyError", (Exception,), {})


class FakeHTTPError(Exception):
    """Simulates an HTTP error with a status code on the response object.

    The class name is FakeHTTPError (NOT in TRANSIENT_ERRORS), so transient
    classification depends solely on the .response.status_code attribute.
    """

    def __init__(self, status_code: int):
        self.response = Mock(status_code=status_code)
        super().__init__(f"HTTP {status_code}")


# =============================================================================
# TIMEOUT HANDLING (T1 - T17)
# =============================================================================

class TestTimeoutHandling:
    """Tests T1 through T17: timeout defaults, validation, adaptive behaviour."""

    # -- T1 --
    def test_t1_default_timeout_is_60(self):
        """T1: Default timeout_seconds is 60."""
        cfg = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("tok"),
        )
        assert cfg.timeout_seconds == 60

    # -- T2 --
    def test_t2_env_var_overrides_default(self, monkeypatch):
        """T2: OPENCTI_TIMEOUT env var overrides the default."""
        monkeypatch.setenv("OPENCTI_TIMEOUT", "120")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        cfg = Config.load()
        assert cfg.timeout_seconds == 120

    # -- T3a --
    def test_t3a_timeout_validation_rejects_below_1(self):
        """T3: Timeout < 1 is rejected."""
        with pytest.raises(ConfigurationError):
            make_config(timeout_seconds=0)

    # -- T3b --
    def test_t3b_timeout_validation_rejects_above_300(self):
        """T3: Timeout > 300 is rejected."""
        with pytest.raises(ConfigurationError):
            make_config(timeout_seconds=301)

    # -- T4 --
    def test_t4_timeout_1_is_valid(self):
        """T4: Timeout=1 is the minimum valid value."""
        cfg = make_config(timeout_seconds=1)
        assert cfg.timeout_seconds == 1

    # -- T5 --
    def test_t5_timeout_300_is_valid(self):
        """T5: Timeout=300 is the maximum valid value."""
        cfg = make_config(timeout_seconds=300)
        assert cfg.timeout_seconds == 300

    # -- T6 --
    def test_t6_request_within_timeout_succeeds(self):
        """T6: A request that completes within the timeout succeeds."""
        client = make_client()
        result = client._execute_with_retry(lambda: "ok")
        assert result == "ok"

    # -- T7 --
    def test_t7_request_exceeding_timeout_raises(self):
        """T7: A request that raises TimeoutError is surfaced."""
        client = make_client(make_config(max_retries=0))

        def timeout_func():
            raise _BuiltinTimeoutError("Request timed out")

        with pytest.raises(_BuiltinTimeoutError):
            client._execute_with_retry(timeout_func)

    # -- T8 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_t8_timeout_error_triggers_retry(self, mock_sleep):
        """T8: TimeoutError is classified as transient and triggers retry."""
        client = make_client(make_config(max_retries=2))
        call_count = 0

        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise _BuiltinTimeoutError("timed out")
            return "recovered"

        result = client._execute_with_retry(flaky)
        assert result == "recovered"
        assert call_count == 3
        # Two retries => two sleeps
        assert mock_sleep.call_count == 2

    # -- T9 --
    def test_t9_adaptive_timeout_increases_for_slow_instance(self):
        """T9: Adaptive timeout increases when latency is high (2s+)."""
        metrics = AdaptiveMetrics()
        for _ in range(15):
            metrics.record_latency(2500.0, success=True)

        config = metrics.get_adaptive_config()
        # P95 ~2500ms * 2.0 / 1000 = 5s -> clamped to MIN_TIMEOUT(5)
        assert config.recommended_timeout >= 5

    # -- T10 --
    def test_t10_adaptive_timeout_decreases_for_fast_instance(self):
        """T10: Adaptive timeout decreases when latency is low (<50ms)."""
        metrics = AdaptiveMetrics()
        for _ in range(15):
            metrics.record_latency(40.0, success=True)

        config = metrics.get_adaptive_config()
        # P95 ~40ms -> timeout = 0 -> clamped to MIN_TIMEOUT=5
        assert config.recommended_timeout == 5

    # -- T11 --
    def test_t11_adaptive_timeout_floor_never_below_10(self):
        """T11: _maybe_adapt_timeout floor is 10s (max(10, ...))."""
        metrics = AdaptiveMetrics()
        for _ in range(15):
            metrics.record_latency(30.0, success=True)

        client = make_client(make_config(timeout_seconds=60), adaptive_metrics=metrics)
        # Force the 5th-call adaptation check
        client._adapt_success_count = 4  # next increment -> 5, triggers check

        client._maybe_adapt_timeout()
        assert client._effective_timeout >= 10

    # -- T12 --
    def test_t12_adaptive_timeout_ceiling_never_above_300(self):
        """T12: _maybe_adapt_timeout ceiling is 300s."""
        metrics = AdaptiveMetrics()
        for _ in range(15):
            metrics.record_latency(200_000.0, success=True)

        client = make_client(make_config(timeout_seconds=60), adaptive_metrics=metrics)
        client._adapt_success_count = 4

        client._maybe_adapt_timeout()
        assert client._effective_timeout <= 300

    # -- T13 --
    def test_t13_adaptive_requires_10_samples(self):
        """T13: Adaptive timeout does not adjust with fewer than 10 samples."""
        metrics = AdaptiveMetrics()
        for _ in range(9):
            metrics.record_latency(5000.0, success=True)

        client = make_client(make_config(timeout_seconds=60), adaptive_metrics=metrics)
        client._adapt_success_count = 4

        client._maybe_adapt_timeout()
        assert client._effective_timeout == 60

    # -- T14 --
    def test_t14_adaptive_no_change_within_25_percent(self):
        """T14: Adaptive timeout does not adjust if change is <= 25%."""
        metrics = AdaptiveMetrics()
        # We want recommended ~= current (60). P95 * 2 / 1000 = recommended.
        # For recommended=55: P95=27500ms. 55 is within 25% of 60.
        for _ in range(15):
            metrics.record_latency(27500.0, success=True)

        config = metrics.get_adaptive_config()
        # Verify recommended is within 25% of 60
        assert abs(config.recommended_timeout - 60) / 60 <= 0.25, (
            f"Test setup issue: recommended={config.recommended_timeout}"
        )

        client = make_client(make_config(timeout_seconds=60), adaptive_metrics=metrics)
        client._adapt_success_count = 4

        client._maybe_adapt_timeout()
        assert client._effective_timeout == 60

    # -- T15 --
    def test_t15_adapted_timeout_updates_pycti_client_in_place(self):
        """T15: When timeout adapts, pycti client.requests_timeout is updated."""
        metrics = AdaptiveMetrics()
        for _ in range(15):
            metrics.record_latency(100_000.0, success=True)

        client = make_client(make_config(timeout_seconds=60), adaptive_metrics=metrics)
        mock_pycti = MagicMock()
        client._client = mock_pycti
        client._adapt_success_count = 4

        client._maybe_adapt_timeout()

        new_timeout = client._effective_timeout
        assert new_timeout != 60
        assert mock_pycti.requests_timeout == new_timeout

    # -- T16 --
    def test_t16_connect_uses_effective_timeout(self):
        """T16: connect() uses _effective_timeout, not config.timeout_seconds."""
        config = make_config(timeout_seconds=60)
        client = OpenCTIClient(config)
        client._effective_timeout = 90
        client._client = None  # Force fresh connection

        mock_pycti_module = MagicMock()
        mock_api_client_class = MagicMock()
        mock_pycti_module.OpenCTIApiClient = mock_api_client_class

        with patch.dict("sys.modules", {"pycti": mock_pycti_module}):
            client.connect()

        # Verify requests_timeout was passed as 90 (the effective, not 60)
        _, kwargs = mock_api_client_class.call_args
        assert kwargs["requests_timeout"] == 90

    # -- T17 --
    def test_t17_get_network_status_shows_both_timeouts(self):
        """T17: get_network_status returns both config and effective timeout."""
        config = make_config(timeout_seconds=60)
        client = make_client(config)
        client._effective_timeout = 90

        status = client.get_network_status()
        assert status["current_config"]["timeout_seconds"] == 60
        assert status["current_config"]["effective_timeout_seconds"] == 90


# =============================================================================
# RETRY AND BACKOFF (R1 - R20)
# =============================================================================

class TestRetryAndBackoff:
    """Tests R1 through R20: retry on transient errors, backoff, exhaustion."""

    # -- R1 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r1_retry_on_connection_error(self, mock_sleep):
        """R1: Retry on ConnectionError (up to max_retries)."""
        client = make_client(make_config(max_retries=2))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise _BuiltinConnectionError("connection reset")
            return "success"

        result = client._execute_with_retry(flaky)
        assert result == "success"
        assert attempts == 3

    # -- R2 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r2_retry_on_timeout_error(self, mock_sleep):
        """R2: Retry on TimeoutError."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise _BuiltinTimeoutError("timed out")
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R3 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r3_retry_on_http_429(self, mock_sleep):
        """R3: Retry on HTTP 429 (rate limited)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise FakeHTTPError(429)
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R4 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r4_retry_on_http_500(self, mock_sleep):
        """R4: Retry on HTTP 500 (internal server error)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise FakeHTTPError(500)
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R5 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r5_retry_on_http_502(self, mock_sleep):
        """R5: Retry on HTTP 502 (bad gateway)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise FakeHTTPError(502)
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R6 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r6_retry_on_http_503(self, mock_sleep):
        """R6: Retry on HTTP 503 (service unavailable)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise FakeHTTPError(503)
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R7 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r7_retry_on_http_504(self, mock_sleep):
        """R7: Retry on HTTP 504 (gateway timeout)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise FakeHTTPError(504)
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R8 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r8_retry_on_http_408(self, mock_sleep):
        """R8: Retry on HTTP 408 (request timeout)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise FakeHTTPError(408)
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R9 --
    def test_r9_no_retry_on_http_401(self):
        """R9: No retry on HTTP 401 (authentication failure)."""
        client = make_client(make_config(max_retries=3))
        attempts = 0

        def auth_fail():
            nonlocal attempts
            attempts += 1
            raise FakeHTTPError(401)

        with pytest.raises(FakeHTTPError):
            client._execute_with_retry(auth_fail)
        assert attempts == 1

    # -- R10 --
    def test_r10_no_retry_on_http_403(self):
        """R10: No retry on HTTP 403 (forbidden)."""
        client = make_client(make_config(max_retries=3))
        attempts = 0

        def forbidden():
            nonlocal attempts
            attempts += 1
            raise FakeHTTPError(403)

        with pytest.raises(FakeHTTPError):
            client._execute_with_retry(forbidden)
        assert attempts == 1

    # -- R11 --
    def test_r11_no_retry_on_validation_error(self):
        """R11: No retry on ValidationError -- fail immediately."""
        client = make_client(make_config(max_retries=3))
        attempts = 0

        def bad_input():
            nonlocal attempts
            attempts += 1
            raise ValidationError("bad input")

        with pytest.raises(ValidationError):
            client._execute_with_retry(bad_input)
        assert attempts == 1

    # -- R12 --
    @patch("opencti_mcp.client.random.uniform", return_value=0.0)
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r12_exponential_backoff_pattern(self, mock_sleep, mock_random):
        """R12: Backoff delay follows base * 2^attempt pattern."""
        config = make_config(max_retries=3, retry_base_delay=1.0, retry_max_delay=100.0)
        client = make_client(config)

        def always_fail():
            raise _BuiltinConnectionError("fail")

        with pytest.raises(_BuiltinConnectionError):
            client._execute_with_retry(always_fail)

        # 4 attempts total (0..3), 3 sleeps (after attempts 0, 1, 2)
        assert mock_sleep.call_count == 3

        delays = [c.args[0] for c in mock_sleep.call_args_list]
        # With jitter uniform returning 0.0: jitter = delay * 0.0 = 0
        # attempt 0: 1.0 * 2^0 = 1.0
        # attempt 1: 1.0 * 2^1 = 2.0
        # attempt 2: 1.0 * 2^2 = 4.0
        assert delays[0] == pytest.approx(1.0, abs=0.01)
        assert delays[1] == pytest.approx(2.0, abs=0.01)
        assert delays[2] == pytest.approx(4.0, abs=0.01)

    # -- R13 --
    @patch("opencti_mcp.client.random.uniform", return_value=0.0)
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r13_backoff_capped_at_max_delay(self, mock_sleep, mock_random):
        """R13: Backoff is capped at retry_max_delay (30s by default)."""
        config = make_config(max_retries=6, retry_base_delay=1.0, retry_max_delay=30.0)
        client = make_client(config)

        def always_fail():
            raise _BuiltinConnectionError("fail")

        with pytest.raises(_BuiltinConnectionError):
            client._execute_with_retry(always_fail)

        delays = [c.args[0] for c in mock_sleep.call_args_list]
        for d in delays:
            assert d <= 30.0 + 0.01

    # -- R14 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r14_all_retries_exhausted_raises_last_exception(self, mock_sleep):
        """R14: When all retries are exhausted, the last exception is raised."""
        config = make_config(max_retries=2)
        client = make_client(config)

        call_count = 0

        def always_fail():
            nonlocal call_count
            call_count += 1
            raise _BuiltinConnectionError(f"fail-{call_count}")

        with pytest.raises(_BuiltinConnectionError, match="fail-3"):
            client._execute_with_retry(always_fail)

    # -- R15 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r15_retry_on_ssl_error(self, mock_sleep):
        """R15: Retry on SSLError (transient cert issue)."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise SSLError("ssl handshake failed")
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R16 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r16_retry_on_proxy_error(self, mock_sleep):
        """R16: Retry on ProxyError."""
        client = make_client(make_config(max_retries=1))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise ProxyError("proxy down")
            return "ok"

        result = client._execute_with_retry(flaky)
        assert result == "ok"
        assert attempts == 2

    # -- R17 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r17_success_after_retry_records_success_in_cb(self, mock_sleep):
        """R17: Successful request after retry records success in circuit breaker."""
        client = make_client(make_config(max_retries=2))
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise _BuiltinConnectionError("fail")
            return "ok"

        client._execute_with_retry(flaky)
        assert client._circuit_breaker.state == CircuitState.CLOSED
        assert client._circuit_breaker._failure_count == 0

    # -- R18 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r18_failure_after_all_retries_records_failure_in_cb(self, mock_sleep):
        """R18: Failed request after all retries records failure in circuit breaker."""
        config = make_config(max_retries=1, circuit_breaker_threshold=10)
        client = make_client(config)

        def always_fail():
            raise _BuiltinConnectionError("fail")

        with pytest.raises(_BuiltinConnectionError):
            client._execute_with_retry(always_fail)

        assert client._circuit_breaker._failure_count >= 1

    # -- R19 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r19_adapt_timeout_called_only_on_success(self, mock_sleep):
        """R19: _maybe_adapt_timeout is called only after success, not failure."""
        config = make_config(max_retries=0)
        client = make_client(config)

        with patch.object(client, "_maybe_adapt_timeout") as mock_adapt:
            # Failure path
            def fail_func():
                raise _BuiltinConnectionError("fail")

            with pytest.raises(_BuiltinConnectionError):
                client._execute_with_retry(fail_func)
            mock_adapt.assert_not_called()

            # Success path
            client._execute_with_retry(lambda: "ok")
            mock_adapt.assert_called_once()

    # -- R20 --
    @patch("opencti_mcp.client.time_module.sleep")
    def test_r20_first_attempt_has_no_delay(self, mock_sleep):
        """R20: First attempt (attempt=0) has no sleep delay before it."""
        config = make_config(max_retries=1)
        client = make_client(config)
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise _BuiltinConnectionError("fail")
            return "ok"

        client._execute_with_retry(flaky)
        # Only 1 sleep (between attempt 0 failure and attempt 1), not before attempt 0
        assert mock_sleep.call_count == 1


# =============================================================================
# CIRCUIT BREAKER (CB1 - CB12)
# =============================================================================

class TestCircuitBreaker:
    """Tests CB1 through CB12: states, transitions, configuration."""

    # -- CB1 --
    def test_cb1_starts_closed(self):
        """CB1: Circuit breaker starts in CLOSED state."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        assert cb.state == CircuitState.CLOSED

    # -- CB2 --
    def test_cb2_closed_allows_requests(self):
        """CB2: CLOSED state allows requests (allow_request returns True)."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        assert cb.allow_request() is True

    # -- CB3 --
    def test_cb3_opens_after_threshold_failures(self):
        """CB3: CLOSED -> OPEN after threshold consecutive failures."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED  # Not yet at threshold

        cb.record_failure()  # Third failure hits threshold
        assert cb.state == CircuitState.OPEN

    # -- CB4 --
    def test_cb4_open_rejects_requests(self):
        """CB4: OPEN state rejects requests (allow_request returns False)."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    # -- CB5 --
    def test_cb5_open_to_half_open_after_recovery_timeout(self):
        """CB5: OPEN -> HALF_OPEN after recovery_timeout seconds."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        time.sleep(1.1)
        assert cb.state == CircuitState.HALF_OPEN

    # -- CB6 --
    def test_cb6_half_open_allows_one_probe(self):
        """CB6: HALF_OPEN allows exactly one probe request."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        cb.record_failure()
        time.sleep(1.1)

        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    # -- CB7 --
    def test_cb7_half_open_success_closes_circuit(self):
        """CB7: HALF_OPEN + success -> CLOSED."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        cb.record_failure()
        time.sleep(1.1)

        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    # -- CB8 --
    def test_cb8_half_open_failure_reopens_circuit(self):
        """CB8: HALF_OPEN + failure -> OPEN."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        cb.record_failure()
        time.sleep(1.1)

        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    # -- CB9 --
    def test_cb9_reset_returns_to_closed_from_open(self):
        """CB9: Manual reset() returns to CLOSED from OPEN."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_cb9_reset_returns_to_closed_from_half_open(self):
        """CB9: Manual reset() returns to CLOSED from HALF_OPEN."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        cb.record_failure()
        time.sleep(1.1)
        assert cb.state == CircuitState.HALF_OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED

    # -- CB10 --
    def test_cb10_force_reconnect_resets_circuit_breaker(self):
        """CB10: force_reconnect resets the circuit breaker to CLOSED."""
        client = make_client(make_config(circuit_breaker_threshold=1))
        client._circuit_breaker.record_failure()
        assert client._circuit_breaker.state == CircuitState.OPEN

        client.force_reconnect()
        assert client._circuit_breaker.state == CircuitState.CLOSED

    # -- CB11 --
    def test_cb11_env_var_customizes_threshold(self, monkeypatch):
        """CB11: OPENCTI_CIRCUIT_THRESHOLD env var customizes threshold."""
        monkeypatch.setenv("OPENCTI_CIRCUIT_THRESHOLD", "10")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        cfg = Config.load()
        assert cfg.circuit_breaker_threshold == 10

        cb = CircuitBreaker(
            failure_threshold=cfg.circuit_breaker_threshold,
            recovery_timeout=60,
        )
        for _ in range(9):
            cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    # -- CB12 --
    def test_cb12_env_var_customizes_recovery_timeout(self, monkeypatch):
        """CB12: OPENCTI_CIRCUIT_TIMEOUT env var customizes recovery timeout."""
        monkeypatch.setenv("OPENCTI_CIRCUIT_TIMEOUT", "120")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        cfg = Config.load()
        assert cfg.circuit_breaker_timeout == 120


# =============================================================================
# Additional Edge-Case and Integration Tests
# =============================================================================

class TestTransientErrorClassification:
    """Verify _is_transient_error classification logic."""

    def test_all_transient_error_names_recognized(self):
        """Every error name in TRANSIENT_ERRORS is classified as transient."""
        client = make_client()
        for name in TRANSIENT_ERRORS:
            exc_class = type(name, (Exception,), {})
            assert client._is_transient_error(exc_class("test")), (
                f"{name} should be transient"
            )

    def test_all_transient_http_codes_recognized(self):
        """Every HTTP code in TRANSIENT_HTTP_CODES is classified as transient."""
        client = make_client()
        for code in TRANSIENT_HTTP_CODES:
            err = FakeHTTPError(code)
            assert client._is_transient_error(err), f"HTTP {code} should be transient"

    def test_non_transient_http_codes_not_retried(self):
        """Non-transient HTTP codes (401, 403, 404) are NOT transient."""
        client = make_client()
        for code in [401, 403, 404, 405, 422]:
            err = FakeHTTPError(code)
            assert not client._is_transient_error(err), (
                f"HTTP {code} should NOT be transient"
            )

    def test_validation_error_not_transient(self):
        """ValidationError is not classified as transient."""
        client = make_client()
        assert not client._is_transient_error(ValidationError("bad"))

    def test_nested_cause_classified(self):
        """Error with transient __cause__ is classified as transient."""
        client = make_client()
        outer = RuntimeError("wrapper")
        # Create a cause whose __name__ is in TRANSIENT_ERRORS
        inner = _BuiltinConnectionError("reset")
        outer.__cause__ = inner
        assert client._is_transient_error(outer)


class TestAuthErrorClassification:
    """Verify _is_auth_error classification logic."""

    def test_http_401_is_auth_error(self):
        """HTTP 401 is classified as auth error."""
        client = make_client()
        err = MagicMock()
        err.response = MagicMock()
        err.response.status_code = 401
        assert client._is_auth_error(err) is True

    def test_http_403_is_auth_error(self):
        """HTTP 403 is classified as auth error."""
        client = make_client()
        err = MagicMock()
        err.response = MagicMock()
        err.response.status_code = 403
        assert client._is_auth_error(err) is True

    def test_http_500_is_not_auth_error(self):
        """HTTP 500 is NOT an auth error."""
        client = make_client()
        err = MagicMock()
        err.response = MagicMock()
        err.response.status_code = 500
        err.__str__ = lambda self: "server error"
        assert client._is_auth_error(err) is False

    def test_unauthorized_message_is_auth_error(self):
        """Error with 'unauthorized' in message is classified as auth error."""
        client = make_client()
        err = ValueError("Unauthorized access")
        assert client._is_auth_error(err) is True

    def test_invalid_token_message_is_auth_error(self):
        """Error with 'invalid token' in message is classified as auth error."""
        client = make_client()
        err = RuntimeError("Invalid token provided")
        assert client._is_auth_error(err) is True

    def test_generic_error_is_not_auth_error(self):
        """Generic errors are NOT classified as auth errors."""
        client = make_client()
        err = RuntimeError("something broke")
        assert client._is_auth_error(err) is False

    @patch("opencti_mcp.client.time_module.sleep")
    def test_auth_error_does_not_record_circuit_failure(self, mock_sleep):
        """Auth errors do NOT increment circuit breaker failure count."""
        client = make_client(make_config(max_retries=0, circuit_breaker_threshold=2))

        auth_err = Exception("Unauthorized")
        auth_err.response = MagicMock()
        auth_err.response.status_code = 401

        for _ in range(5):
            with pytest.raises(Exception):
                client._execute_with_retry(lambda: (_ for _ in ()).throw(auth_err))

        # Circuit should still be closed
        assert client._circuit_breaker.state == CircuitState.CLOSED
        assert client._circuit_breaker._failure_count == 0


class TestCircuitBreakerIntegration:
    """Integration tests: circuit breaker with _execute_with_retry."""

    def test_open_circuit_fails_fast(self):
        """When circuit is open, _execute_with_retry fails immediately."""
        client = make_client(make_config(circuit_breaker_threshold=1))
        client._circuit_breaker.record_failure()
        assert client._circuit_breaker.state == CircuitState.OPEN

        with pytest.raises(OCTIConnectionError, match="circuit breaker open"):
            client._execute_with_retry(lambda: "should not run")

    @patch("opencti_mcp.client.time_module.sleep")
    def test_circuit_trips_after_repeated_failures(self, mock_sleep):
        """Circuit trips after enough failed retry-exhaustion cycles."""
        config = make_config(max_retries=0, circuit_breaker_threshold=2)
        client = make_client(config)

        def always_fail():
            raise _BuiltinConnectionError("fail")

        # First call records 1 failure
        with pytest.raises(_BuiltinConnectionError):
            client._execute_with_retry(always_fail)
        assert client._circuit_breaker.state == CircuitState.CLOSED

        # Second call records 2nd failure -> trips circuit
        with pytest.raises(_BuiltinConnectionError):
            client._execute_with_retry(always_fail)
        assert client._circuit_breaker.state == CircuitState.OPEN

        # Third call -> circuit open, fails fast with OCTI ConnectionError
        with pytest.raises(OCTIConnectionError, match="circuit breaker open"):
            client._execute_with_retry(always_fail)


class TestBackoffCalculation:
    """Direct tests for _calculate_backoff method."""

    @patch("opencti_mcp.client.random.uniform", return_value=0.15)
    def test_backoff_with_jitter(self, mock_uniform):
        """Backoff includes 10-20% jitter."""
        config = make_config(retry_base_delay=2.0, retry_max_delay=100.0)
        client = make_client(config)

        # attempt 0: base * 2^0 = 2.0, jitter = 2.0 * 0.15 = 0.3 -> 2.3
        delay = client._calculate_backoff(0)
        assert delay == pytest.approx(2.3, abs=0.01)

        # attempt 2: base * 2^2 = 8.0, jitter = 8.0 * 0.15 = 1.2 -> 9.2
        delay = client._calculate_backoff(2)
        assert delay == pytest.approx(9.2, abs=0.01)

    @patch("opencti_mcp.client.random.uniform", return_value=0.1)
    def test_backoff_capping(self, mock_uniform):
        """Backoff is capped at retry_max_delay before jitter is added."""
        config = make_config(retry_base_delay=1.0, retry_max_delay=10.0)
        client = make_client(config)

        # attempt 10: 1.0 * 2^10 = 1024 -> capped at 10.0, jitter 10.0*0.1=1.0 -> 11.0
        delay = client._calculate_backoff(10)
        assert delay == pytest.approx(11.0, abs=0.01)


class TestAdaptiveMetricsUnit:
    """Unit tests for AdaptiveMetrics edge cases."""

    def test_insufficient_samples_returns_defaults(self):
        """With < 5 samples, returns conservative defaults."""
        metrics = AdaptiveMetrics()
        metrics.record_latency(100.0, success=True)
        config = metrics.get_adaptive_config()
        assert config.recommended_timeout == 60
        assert config.latency_classification == "unknown"

    def test_sufficient_samples_calculates_real_values(self):
        """With >= 5 samples, calculates real adaptive values."""
        metrics = AdaptiveMetrics()
        for _ in range(10):
            metrics.record_latency(500.0, success=True)
        config = metrics.get_adaptive_config()
        assert config.recommended_timeout == 5
        assert config.latency_classification in ("excellent", "good", "acceptable")

    def test_success_rate_impacts_retry_recommendations(self):
        """Low success rate increases recommended retries."""
        metrics = AdaptiveMetrics()
        # 50% success rate with enough samples
        for _ in range(10):
            metrics.record_latency(500.0, success=True)
        for _ in range(10):
            metrics.record_latency(500.0, success=False)

        config = metrics.get_adaptive_config()
        # With < 90% success rate, recommended_max_retries should be 5
        assert config.recommended_max_retries == 5
