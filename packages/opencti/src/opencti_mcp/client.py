"""OpenCTI API client for threat intelligence queries.

This module provides a high-level interface to OpenCTI, abstracting
the GraphQL API behind simple Python methods.

Security:
- All queries use pycti's parameterized methods (no SQL/GraphQL injection)
- Connection timeouts prevent hanging
- Rate limiting prevents abuse
- Response sizes are bounded
"""

from __future__ import annotations

import logging
import random
import threading
import time as time_module
from collections import deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from time import monotonic
from typing import Any

from .adaptive import AdaptiveMetrics, get_global_metrics
from .cache import NOT_FOUND, CacheManager, TTLCache, generate_cache_key
from .config import Config
from .errors import ConnectionError, QueryError, RateLimitError, ValidationError
from .feature_flags import get_feature_flags
from .validation import (
    MAX_IOC_LENGTH,
    MAX_QUERY_LENGTH,
    normalize_hash,
    truncate_response,
    validate_days,
    validate_length,
    validate_limit,
)

# =============================================================================
# Constants
# =============================================================================

MAX_RELATIONSHIPS = 50  # Max relationships to fetch per entity
HEALTH_CHECK_TTL = 30  # Seconds to cache health check result

# Transient errors that should trigger retry.
# These are network/connection issues that may resolve on retry:
# - ConnectionError/ConnectionResetError/ConnectionRefusedError/ConnectionAbortedError:
#   Server closed connection, refused, or aborted - may recover
# - TimeoutError: Request timed out - server may be temporarily overloaded
# - OSError: Low-level socket errors - often transient network issues
# - BrokenPipeError: Connection dropped mid-request - retry with fresh connection
# - RequestException/HTTPError: requests library errors - covers various HTTP issues
# - SSLError: SSL handshake failures - may be transient certificate/negotiation issues
# - ProxyError: Proxy connection failed - proxy may recover
# - ChunkedEncodingError/ContentDecodingError: Incomplete response - server hiccup
TRANSIENT_ERRORS = frozenset(
    {
        "ConnectionError",
        "TimeoutError",
        "OSError",
        "RequestException",
        "HTTPError",
        "ConnectionResetError",
        "BrokenPipeError",
        "ConnectionRefusedError",
        "ConnectionAbortedError",
        "SSLError",
        "ProxyError",
        "ChunkedEncodingError",
        "ContentDecodingError",
    }
)

# HTTP status codes that indicate transient failures
TRANSIENT_HTTP_CODES = frozenset({408, 429, 500, 502, 503, 504})


logger = logging.getLogger(__name__)


# =============================================================================
# Circuit Breaker
# =============================================================================


class CircuitState(Enum):
    """Circuit breaker states for type-safe state management."""

    CLOSED = "closed"  # Normal operation, requests go through
    OPEN = "open"  # Service unhealthy, requests fail immediately
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker pattern for failing fast on unhealthy services.

    States:
    - CLOSED: Normal operation, requests go through
    - OPEN: Service unhealthy, requests fail immediately
    - HALF_OPEN: Testing if service recovered

    Production use: Prevents cascading failures when OpenCTI is down
    by failing fast instead of waiting for timeouts on every request.

    Uses monotonic time to be immune to system clock adjustments.
    """

    def __init__(self, failure_threshold: int, recovery_timeout: int) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                # Check if recovery timeout has passed
                if monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
            return self._state

    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return True  # Allow one test request
        return False  # OPEN - fail fast

    def record_success(self) -> None:
        """Record a successful request."""
        with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Record a failed request."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = monotonic()

            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "Circuit breaker opened",
                    extra={
                        "failures": self._failure_count,
                        "threshold": self.failure_threshold,
                        "recovery_timeout": self.recovery_timeout,
                    },
                )

    def reset(self) -> None:
        """Reset circuit to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0


# =============================================================================
# Rate Limiter
# =============================================================================


class RateLimiter:
    """Thread-safe sliding window rate limiter.

    Thread safety: Uses a lock to protect the calls deque from
    concurrent access when used with asyncio.to_thread().

    Uses monotonic time to be immune to system clock adjustments.
    """

    def __init__(self, max_calls: int, window_seconds: int) -> None:
        self.max_calls = max_calls
        self.window = window_seconds
        self.calls: deque[float] = deque()
        self._lock = threading.Lock()

    def check(self) -> bool:
        """Check if call is allowed (thread-safe)."""
        with self._lock:
            now = monotonic()
            self._cleanup_unlocked(now)
            return len(self.calls) < self.max_calls

    def record(self) -> None:
        """Record a call (thread-safe)."""
        with self._lock:
            self.calls.append(monotonic())

    def check_and_record(self) -> bool:
        """Atomically check and record if allowed (thread-safe).

        Returns True if call was allowed and recorded, False if rate limited.
        """
        with self._lock:
            now = monotonic()
            self._cleanup_unlocked(now)
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            return False

    def wait_time(self) -> float:
        """Return seconds to wait before next call allowed (thread-safe)."""
        with self._lock:
            if self.max_calls <= 0:
                return float(self.window)
            now = monotonic()
            self._cleanup_unlocked(now)
            if len(self.calls) < self.max_calls:
                return 0.0
            if not self.calls:
                return 0.0
            oldest = self.calls[0]
            return max(0.0, oldest + self.window - now)

    def _cleanup_unlocked(self, now: float) -> None:
        """Remove old calls outside window. Must be called with lock held."""
        cutoff = now - self.window
        while self.calls and self.calls[0] < cutoff:
            self.calls.popleft()


# =============================================================================
# OpenCTI Client
# =============================================================================


class OpenCTIClient:
    """Client for querying OpenCTI threat intelligence.

    Thread-safe: Can be used from multiple async contexts via to_thread.

    Features:
    - Connection caching with timeout enforcement
    - Thread-safe rate limiting
    - Exponential backoff retry with configurable attempts
    - Circuit breaker for failing fast
    - Health check caching
    - SSL/TLS verification (configurable)
    - Adaptive metrics for dynamic configuration

    Production considerations:
    - Remote instances should use higher timeouts (60-120s)
    - Circuit breaker prevents cascading failures
    - Exponential backoff respects server load during recovery
    - Adaptive metrics adjust recommendations for geographically distributed users
    """

    def __init__(
        self, config: Config, adaptive_metrics: AdaptiveMetrics | None = None
    ) -> None:
        self.config = config
        self._client: Any = None
        self._client_lock = threading.Lock()
        self._query_limiter = RateLimiter(
            max_calls=config.rate_limit_queries, window_seconds=60
        )
        self._enrichment_limiter = RateLimiter(
            max_calls=config.rate_limit_enrichment, window_seconds=3600
        )
        # Health check cache
        self._health_cache: tuple[bool, float] | None = None

        # Circuit breaker for failing fast
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=config.circuit_breaker_threshold,
            recovery_timeout=config.circuit_breaker_timeout,
        )

        # Adaptive metrics for network-aware configuration
        # Use provided instance or fall back to global singleton
        self._adaptive_metrics = adaptive_metrics or get_global_metrics()
        self._effective_timeout = config.timeout_seconds
        self._adapt_success_count = 0

        # Feature flags
        self._feature_flags = get_feature_flags()

        # Response metadata (for cache/degradation info)
        self._last_response_from_cache = False
        self._last_response_degraded = False

        # Response caches (if caching enabled)
        self._cache_manager = CacheManager()
        if (
            self._feature_flags.response_caching
            or self._feature_flags.graceful_degradation
        ):
            self._init_caches()

    def _init_caches(self) -> None:
        """Initialize response caches.

        Cache TTLs chosen based on data volatility:
        - Search results: Short (60s) - users expect fresh results
        - Entity lookups: Medium (300s) - metadata changes less frequently
        - IOC lookups: Short (60s) - threat intel should be current
        - Negative cache: Shorter (30s) - recheck for new data
        """
        # Search results cache
        self._search_cache: TTLCache[Any] = TTLCache(
            ttl_seconds=60, negative_ttl_seconds=30, max_size=500, name="search"
        )
        self._cache_manager.register("search", self._search_cache)

        # Entity lookup cache (by ID)
        self._entity_cache: TTLCache[Any] = TTLCache(
            ttl_seconds=300, negative_ttl_seconds=60, max_size=1000, name="entity"
        )
        self._cache_manager.register("entity", self._entity_cache)

        # IOC context cache
        self._ioc_cache: TTLCache[Any] = TTLCache(
            ttl_seconds=60, negative_ttl_seconds=30, max_size=500, name="ioc"
        )
        self._cache_manager.register("ioc", self._ioc_cache)

        logger.info("Response caches initialized")

    def _get_cached(self, cache: TTLCache[Any], key: str) -> tuple[bool, Any]:
        """Get cached response if available.

        Returns:
            (found, value) - found=True if cache hit (even negative)
        """
        if not self._feature_flags.response_caching:
            return (False, None)

        found, value = cache.get(key)
        if found:
            if value is NOT_FOUND:
                logger.debug(f"Cache negative hit: {key[:16]}...")
            else:
                logger.debug(f"Cache hit: {key[:16]}...")
        return (found, value)

    def _cache_response(self, cache: TTLCache[Any], key: str, value: Any) -> None:
        """Store response in cache."""
        if not self._feature_flags.response_caching:
            return
        cache.set(key, value)

    def _cache_negative(self, cache: TTLCache[Any], key: str) -> None:
        """Store negative cache entry (not found)."""
        if not self._feature_flags.negative_caching:
            return
        cache.set_negative(key)

    def _get_fallback(self, cache: TTLCache[Any], key: str) -> tuple[bool, Any, bool]:
        """Get cached response for graceful degradation.

        Only used when service is unavailable (circuit open or request failed).
        Uses get_stale() to return expired entries that regular get() would
        discard — stale data is better than no data during an outage.

        Returns:
            (found, value, is_degraded) tuple
        """
        if not self._feature_flags.graceful_degradation:
            return (False, None, False)

        found, value = cache.get_stale(key)
        if found and value is not NOT_FOUND:
            logger.info(
                f"Graceful degradation: using cached response for {key[:16]}..."
            )
            return (True, value, True)

        return (False, None, False)

    def get_cache_stats(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all caches."""
        return self._cache_manager.get_all_stats()

    def clear_all_caches(self) -> dict[str, int]:
        """Clear all response caches."""
        return self._cache_manager.clear_all()

    def get_last_response_metadata(self) -> dict[str, Any]:
        """Get metadata about the last response.

        Returns:
            dict with:
                - from_cache: True if last response was from cache
                - degraded: True if last response was degraded (stale cache)
        """
        return {
            "from_cache": self._last_response_from_cache,
            "degraded": self._last_response_degraded,
        }

    def _reset_response_metadata(self) -> None:
        """Reset response metadata before a new query."""
        self._last_response_from_cache = False
        self._last_response_degraded = False

    def _check_rate_limit(self, limiter: RateLimiter, limit_type: str) -> None:
        """Check rate limit and raise if exceeded (thread-safe)."""
        if not limiter.check_and_record():
            wait = limiter.wait_time()
            raise RateLimitError(wait, limit_type)

    def _is_transient_error(self, error: Exception) -> bool:
        """Check if error is transient and should trigger retry."""
        error_name = type(error).__name__

        # Check error type name
        if error_name in TRANSIENT_ERRORS:
            return True

        # Check for HTTP status codes in response errors
        if hasattr(error, "response") and hasattr(error.response, "status_code"):
            if error.response.status_code in TRANSIENT_HTTP_CODES:
                return True

        # Check nested exception causes
        if error.__cause__ and type(error.__cause__).__name__ in TRANSIENT_ERRORS:
            return True

        return False

    @staticmethod
    def _is_auth_error(error: Exception) -> bool:
        """Check if error is an authentication/authorization failure.

        Auth errors indicate configuration problems (bad token, wrong
        permissions), NOT server health issues. They should not count
        toward circuit breaker failure threshold.
        """
        # Check HTTP status codes 401/403
        if hasattr(error, "response") and hasattr(error.response, "status_code"):
            if error.response.status_code in (401, 403):
                return True

        # Check error type names commonly used for auth failures
        error_name = type(error).__name__
        if error_name in ("AuthenticationError", "AuthorizationError"):
            return True

        # Check error message patterns
        error_msg = str(error).lower()
        if any(
            kw in error_msg
            for kw in ("unauthorized", "forbidden", "authentication", "invalid token")
        ):
            return True

        return False

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff delay with jitter.

        Uses exponential backoff: base_delay * 2^attempt
        Capped at retry_max_delay.
        Adds random jitter to prevent thundering herd.
        """
        delay = self.config.retry_base_delay * (2**attempt)
        delay = min(delay, self.config.retry_max_delay)

        # Add 10-20% jitter to prevent synchronized retries
        jitter = delay * random.uniform(0.1, 0.2)
        return delay + jitter

    def _maybe_adapt_timeout(self) -> None:
        """Apply adaptive timeout if metrics warrant a change.

        Checks every 5 successful requests. Only adapts after 10+ samples
        and when the recommended timeout differs by >25% from current.
        Updates the pycti client's timeout in-place (no reconnect needed).
        """
        self._adapt_success_count += 1
        if self._adapt_success_count % 5 != 0:
            return

        adaptive = self._adaptive_metrics.get_adaptive_config()
        if adaptive.probe_count < 10:
            return

        recommended = adaptive.recommended_timeout
        current = self._effective_timeout

        if current > 0 and abs(recommended - current) / current > 0.25:
            new_timeout = max(10, min(recommended, 300))
            old_timeout = self._effective_timeout
            self._effective_timeout = new_timeout
            logger.info(
                f"Adaptive timeout adjusted: {old_timeout}s -> {new_timeout}s",
                extra={
                    "old_timeout": old_timeout,
                    "new_timeout": new_timeout,
                    "sample_count": adaptive.probe_count,
                    "success_rate": adaptive.success_rate,
                },
            )
            with self._client_lock:
                if self._client is not None:
                    self._client.requests_timeout = new_timeout

    def _execute_with_retry(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Execute function with exponential backoff retry.

        Production resilience:
        - Exponential backoff prevents overwhelming recovering server
        - Circuit breaker fails fast when service is down
        - Max retries limit prevents infinite loops
        - Jitter prevents thundering herd problem
        - Adaptive metrics track latency for dynamic recommendations
        """
        # Check circuit breaker first
        if not self._circuit_breaker.allow_request():
            logger.warning("Circuit breaker open, failing fast")
            raise ConnectionError("OpenCTI unavailable (circuit breaker open)")

        last_exception: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                attempt_start = time_module.time()
                result = func(*args, **kwargs)

                # Success - record it and track latency
                self._circuit_breaker.record_success()
                self._adaptive_metrics.record_request(
                    start_time=attempt_start, success=True
                )
                self._maybe_adapt_timeout()
                return result

            except Exception as e:
                last_exception = e

                # Record the failure in adaptive metrics (per-attempt time)
                self._adaptive_metrics.record_request(
                    start_time=attempt_start, success=False, error_type=type(e).__name__
                )

                # Check if this is a transient error worth retrying
                if not self._is_transient_error(e):
                    # Non-transient error - don't retry.
                    # Only record circuit breaker failure for server errors,
                    # NOT for auth/validation errors (which indicate config
                    # problems, not server health issues).
                    if not self._is_auth_error(e):
                        self._circuit_breaker.record_failure()
                    raise

                # Log the transient failure
                logger.warning(
                    f"Transient failure (attempt {attempt + 1}/{self.config.max_retries + 1})",
                    extra={
                        "error_type": type(e).__name__,
                        "attempt": attempt + 1,
                        "max_retries": self.config.max_retries,
                    },
                )

                # Check if we have retries left
                if attempt >= self.config.max_retries:
                    self._circuit_breaker.record_failure()
                    logger.error(
                        "Max retries exhausted",
                        extra={"attempts": attempt + 1, "error_type": type(e).__name__},
                    )
                    raise

                # Wait with exponential backoff before retry
                delay = self._calculate_backoff(attempt)
                logger.info(f"Retrying in {delay:.2f}s...")
                time_module.sleep(delay)

                # Reset timing for next attempt (backoff already applied above)

        # Should not reach here, but just in case
        if last_exception:
            raise last_exception
        raise ConnectionError("Unexpected retry loop exit")

    def connect(self) -> Any:
        """Establish connection to OpenCTI (thread-safe).

        Returns cached client if already connected.
        Configures timeout and SSL verification from config.

        Production notes:
        - Set ssl_verify=True for remote instances
        - Increase timeout for high-latency connections
        """
        with self._client_lock:
            if self._client is not None:
                return self._client

            try:
                from pycti import OpenCTIApiClient

                self._client = OpenCTIApiClient(
                    self.config.opencti_url,
                    self.config.opencti_token.get_secret_value(),
                    log_level="error",
                    requests_timeout=self._effective_timeout,
                    ssl_verify=self.config.ssl_verify,
                )
                return self._client

            except ImportError as e:
                raise ConnectionError(
                    "pycti not installed. Run: pip install pycti"
                ) from e
            except Exception as e:
                # Don't leak connection details
                logger.error(f"Failed to connect to OpenCTI: {e}")
                raise ConnectionError(f"Connection failed: {type(e).__name__}") from e

    def reconnect(self) -> Any:
        """Force reconnection to OpenCTI.

        Use when connection becomes stale or after network changes.
        """
        with self._client_lock:
            self._client = None
        return self.connect()

    def is_available(self) -> bool:
        """Check if OpenCTI is available (with caching).

        Caches result for HEALTH_CHECK_TTL seconds to avoid
        excessive health check queries.

        Also respects circuit breaker state.
        """
        now = monotonic()

        # Check circuit breaker - if open, service is unavailable
        if not self._circuit_breaker.allow_request():
            return False

        # Check cache
        if self._health_cache is not None:
            cached_result, cached_time = self._health_cache
            if now - cached_time < HEALTH_CHECK_TTL:
                return cached_result

        # Perform actual check
        try:
            client = self.connect()
            # Simple query to verify connection
            client.stix_cyber_observable.list(first=1)
            result = True
            self._circuit_breaker.record_success()
        except Exception:
            result = False
            self._circuit_breaker.record_failure()

        # Cache result
        self._health_cache = (result, monotonic())
        return result

    def clear_health_cache(self) -> None:
        """Clear the health check cache."""
        self._health_cache = None

    def reset_circuit_breaker(self) -> None:
        """Reset circuit breaker to closed state.

        Use after manual verification that service is healthy.
        """
        self._circuit_breaker.reset()
        self.clear_health_cache()

    def force_reconnect(self) -> None:
        """Force reconnection to OpenCTI.

        This method:
        1. Clears the health cache
        2. Resets the circuit breaker
        3. Resets adaptive metrics

        Use when:
        - Token has been rotated
        - Configuration has changed
        - Recovering from persistent errors
        - Manual intervention needed
        """
        logger.info("Forcing reconnection to OpenCTI")
        self.clear_health_cache()
        self._circuit_breaker.reset()
        self._adaptive_metrics.reset()
        self._client = None  # Force fresh connect() on next request
        logger.info(
            "Reconnection complete - caches cleared, client reset, circuit breaker reset"
        )

    # =========================================================================
    # Startup Validation and Version Checking
    # =========================================================================

    def validate_startup(self, skip_connectivity: bool = False) -> dict[str, Any]:
        """Validate configuration and connectivity at startup.

        Performs comprehensive checks:
        1. Configuration validation (already done by Config.load)
        2. API connectivity test
        3. Token validity (via simple query)
        4. OpenCTI version check
        5. Security warnings (HTTP for remote)

        Args:
            skip_connectivity: Skip connectivity test (for testing)

        Returns:
            dict with validation results:
                - valid: True if all critical checks passed
                - warnings: List of non-critical warnings
                - errors: List of critical errors
                - opencti_version: Server version if available
                - platform_version: Platform version if available

        Raises:
            ConfigurationError: If critical validation fails
        """
        result: dict[str, Any] = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "opencti_version": None,
            "platform_version": None,
        }

        # Check for HTTP on non-local servers
        url = self.config.opencti_url.lower()
        if url.startswith("http://") and not self._is_local_url(url):
            result["warnings"].append(
                "Using unencrypted HTTP for remote server. Consider HTTPS."
            )
            logger.warning(
                "Security warning: Using HTTP for remote OpenCTI server",
                extra={"url_scheme": "http"},
            )

        if skip_connectivity:
            return result

        # Test connectivity and token validity
        try:
            client = self.connect()

            # Try to get version info - this validates connectivity and token
            version_info = self._get_opencti_version(client)
            if version_info:
                result["opencti_version"] = version_info.get("version")
                result["platform_version"] = version_info.get("platform_version")

                # Check version compatibility
                self._check_version_compatibility(version_info, result)

            # Verify we can actually query
            client.stix_cyber_observable.list(first=1)
            self._circuit_breaker.record_success()

            logger.info(
                "Startup validation passed",
                extra={
                    "opencti_version": result["opencti_version"],
                    "warning_count": len(result["warnings"]),
                },
            )

        except Exception as e:
            error_msg = f"Connectivity test failed: {type(e).__name__}"
            result["errors"].append(error_msg)
            result["valid"] = False
            self._circuit_breaker.record_failure()

            logger.error(
                "Startup validation failed",
                extra={"error": str(e), "error_type": type(e).__name__},
            )

        return result

    def _is_local_url(self, url: str) -> bool:
        """Check if URL points to localhost."""
        from urllib.parse import urlparse

        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            return False
        return hostname in {"localhost", "127.0.0.1", "::1"}

    def _get_opencti_version(self, client: Any) -> dict[str, str] | None:
        """Get OpenCTI server version information.

        Returns:
            dict with version info or None if unavailable
        """
        try:
            # Try to get version from the about query
            # This is a lightweight query that returns server info
            if hasattr(client, "query"):
                query = """
                query {
                    about {
                        version
                        dependencies {
                            name
                            version
                        }
                    }
                }
                """
                response = client.query(query)
                if response and "data" in response and "about" in response["data"]:
                    about = response["data"]["about"]
                    version_info = {"version": about.get("version")}

                    # Find platform version in dependencies
                    deps = about.get("dependencies", [])
                    for dep in deps:
                        if dep.get("name") == "@opencti/platform":
                            version_info["platform_version"] = dep.get("version")
                            break

                    return version_info
        except Exception as e:
            logger.debug(f"Could not get OpenCTI version: {e}")

        return None

    def _check_version_compatibility(
        self, version_info: dict[str, str], result: dict[str, Any]
    ) -> None:
        """Check version compatibility and add warnings if needed.

        Known compatibility:
        - pycti 6.x works with OpenCTI 6.x
        - Major version mismatches may cause issues
        """
        version = version_info.get("version", "")
        if not version:
            return

        try:
            # Parse major version
            major = int(version.split(".")[0])

            # pycti 6.x is designed for OpenCTI 6.x
            # Warn if major version doesn't match
            if major < 5:
                result["warnings"].append(
                    f"OpenCTI version {version} is older than expected. "
                    "Some features may not work correctly."
                )
            elif major > 6:
                result["warnings"].append(
                    f"OpenCTI version {version} is newer than this client. "
                    "Consider updating opencti-mcp for full compatibility."
                )

        except (ValueError, IndexError):
            # Can't parse version - not critical
            pass

    def get_server_info(self) -> dict[str, Any]:
        """Get OpenCTI server information.

        Returns version and capability information for diagnostics.
        """
        try:
            client = self.connect()
            version_info = self._get_opencti_version(client) or {}

            return {
                "url": self.config.opencti_url,
                "version": version_info.get("version"),
                "platform_version": version_info.get("platform_version"),
                "available": self.is_available(),
                "circuit_breaker_state": self._circuit_breaker.state.value,
            }
        except Exception as e:
            return {
                "url": self.config.opencti_url,
                "version": None,
                "available": False,
                "error": type(e).__name__,
            }

    # =========================================================================
    # Network Status and Adaptive Metrics
    # =========================================================================

    def get_network_status(self) -> dict[str, Any]:
        """Get current network status and adaptive recommendations.

        Returns status including:
        - Circuit breaker state
        - Latency statistics (P50, P95, P99)
        - Success rate
        - Recommended timeout/retry settings based on observed conditions

        Use this for:
        - Monitoring network health to OpenCTI
        - Debugging connectivity issues
        - Tuning timeout/retry settings for specific environments
        """
        adaptive_status = self._adaptive_metrics.get_status()
        config = self._adaptive_metrics.get_adaptive_config()

        return {
            "circuit_breaker": {
                "state": self._circuit_breaker.state.value,
                "failure_threshold": self._circuit_breaker.failure_threshold,
                "recovery_timeout_seconds": self._circuit_breaker.recovery_timeout,
            },
            "adaptive_metrics": adaptive_status,
            "current_config": {
                "timeout_seconds": self.config.timeout_seconds,
                "effective_timeout_seconds": self._effective_timeout,
                "max_retries": self.config.max_retries,
                "retry_base_delay": self.config.retry_base_delay,
            },
            "recommendations": {
                "timeout_seconds": config.recommended_timeout,
                "retry_delay": config.recommended_retry_delay,
                "max_retries": config.recommended_max_retries,
                "circuit_threshold": config.recommended_circuit_threshold,
                "latency_classification": config.latency_classification,
                "success_rate": config.success_rate,
                "sample_count": config.probe_count,
            },
        }

    def start_adaptive_probing(self) -> None:
        """Start background probing for adaptive metrics.

        Periodically sends lightweight queries to measure latency
        and adjust recommendations. Recommended for production with
        remote OpenCTI instances.
        """
        self._adaptive_metrics.start_background_probing(self)

    def stop_adaptive_probing(self) -> None:
        """Stop background probing."""
        self._adaptive_metrics.stop_background_probing()

    # =========================================================================
    # Search Methods
    # =========================================================================

    def _build_filters(
        self,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
    ) -> dict[str, Any] | None:
        """Build OpenCTI filter object from filter parameters.

        Args:
            labels: Filter by labels
            confidence_min: Minimum confidence threshold (0-100)
            created_after: ISO date string for created >= filter
            created_before: ISO date string for created <= filter

        Returns:
            OpenCTI filter dict or None if no filters
        """
        filters = []

        if labels:
            # Labels filter - match any of the specified labels
            filters.append(
                {
                    "key": "objectLabel",
                    "values": labels[:10],  # Limit to 10 labels
                    "operator": "eq",
                    "mode": "or",
                }
            )

        if confidence_min is not None:
            if 0 <= confidence_min <= 100:
                filters.append(
                    {
                        "key": "confidence",
                        "values": [str(confidence_min)],
                        "operator": "gte",
                    }
                )

        if created_after:
            # Normalize timestamp format
            ts = created_after.replace("+00:00", "Z")
            if not ts.endswith("Z"):
                ts += "T00:00:00Z"
            filters.append({"key": "created", "values": [ts], "operator": "gte"})

        if created_before:
            ts = created_before.replace("+00:00", "Z")
            if not ts.endswith("Z"):
                ts += "T23:59:59Z"
            filters.append({"key": "created", "values": [ts], "operator": "lte"})

        if not filters:
            return None

        return {"mode": "and", "filters": filters, "filterGroups": []}

    def search_indicators(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for indicators (IOCs).

        Args:
            query: Search term
            limit: Max results
            offset: Skip first N results (for pagination)
            labels: Filter by labels
            confidence_min: Minimum confidence threshold (0-100)
            created_after: ISO date for created >= filter
            created_before: ISO date for created <= filter
            _skip_rate_limit: Internal flag for unified_search

        Returns:
            List of formatted indicator results
        """
        # Defense in depth - validate again
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))  # Cap offset at 500

        # Generate cache key
        cache_key = generate_cache_key(
            "indicators",
            query,
            limit,
            offset,
            labels=labels,
            confidence_min=confidence_min,
            created_after=created_after,
            created_before=created_before,
        )

        # Check cache first (if caching enabled)
        if hasattr(self, "_search_cache"):
            found, cached = self._get_cached(self._search_cache, cache_key)
            if found and cached is not NOT_FOUND:
                self._last_response_from_cache = True
                return cached

        # Check if circuit breaker allows request
        if not self._circuit_breaker.allow_request():
            # Try graceful degradation - return cached result if available
            if hasattr(self, "_search_cache"):
                found, cached, degraded = self._get_fallback(
                    self._search_cache, cache_key
                )
                if found:
                    self._last_response_from_cache = True
                    self._last_response_degraded = True
                    return cached
            # No cached data available
            raise ConnectionError("OpenCTI unavailable (circuit breaker open)")

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()
        self._last_response_from_cache = False
        self._last_response_degraded = False

        try:
            kwargs: dict[str, Any] = {
                "search": query,
                "first": limit + offset,  # Fetch extra for offset
                "orderBy": "created",
                "orderMode": "desc",
            }

            # Add filters if provided
            filters = self._build_filters(
                labels, confidence_min, created_after, created_before
            )
            if filters:
                kwargs["filters"] = filters

            results = self._execute_with_retry(client.indicator.list, **kwargs)

            # Apply offset
            results = (results or [])[offset : offset + limit]
            formatted = self._format_indicators(results)

            # Cache the results
            if hasattr(self, "_search_cache"):
                self._cache_response(self._search_cache, cache_key, formatted)

            return formatted

        except Exception as e:
            # On failure, try graceful degradation
            if hasattr(self, "_search_cache"):
                found, cached, degraded = self._get_fallback(
                    self._search_cache, cache_key
                )
                if found:
                    logger.warning(
                        f"Indicator search failed, returning cached result: {e}"
                    )
                    self._last_response_from_cache = True
                    self._last_response_degraded = True
                    return cached

            logger.error(f"Indicator search failed: {e}")
            raise QueryError(f"Indicator search failed: {type(e).__name__}") from e

    def search_threat_actors(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for threat actors and APT groups.

        Note: APT groups are often stored as IntrusionSet in STIX.
        """
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = []

            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}

            # Add filters if provided
            filters = self._build_filters(
                labels, confidence_min, created_after, created_before
            )
            if filters:
                kwargs["filters"] = filters

            # Search IntrusionSet (where most APTs are)
            intrusion_sets = (
                self._execute_with_retry(client.intrusion_set.list, **kwargs) or []
            )
            results.extend(intrusion_sets)

            # Also search ThreatActorGroup
            threat_actors = (
                self._execute_with_retry(client.threat_actor_group.list, **kwargs) or []
            )
            results.extend(threat_actors)

            # Deduplicate by id (name-based dedup can drop distinct actors)
            seen = set()
            unique = []
            for r in results:
                entity_id = r.get("id")
                if not entity_id or entity_id not in seen:
                    if entity_id:
                        seen.add(entity_id)
                    unique.append(r)

            # Apply offset and limit
            return self._format_threat_actors(unique[offset : offset + limit])

        except Exception as e:
            logger.error(f"Threat actor search failed: {e}")
            raise QueryError(f"Threat actor search failed: {type(e).__name__}") from e

    def search_malware(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for malware families."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}

            filters = self._build_filters(
                labels, confidence_min, created_after, created_before
            )
            if filters:
                kwargs["filters"] = filters

            results = self._execute_with_retry(client.malware.list, **kwargs) or []

            results = results[offset : offset + limit]
            return self._format_malware(results)

        except Exception as e:
            logger.error(f"Malware search failed: {e}")
            raise QueryError(f"Malware search failed: {type(e).__name__}") from e

    def search_attack_patterns(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for MITRE ATT&CK techniques."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}

            # Attack patterns don't have confidence, so exclude it from filters
            filters = self._build_filters(labels, None, created_after, created_before)
            if filters:
                kwargs["filters"] = filters

            results = (
                self._execute_with_retry(client.attack_pattern.list, **kwargs) or []
            )

            results = results[offset : offset + limit]
            return self._format_attack_patterns(results)

        except Exception as e:
            logger.error(f"Attack pattern search failed: {e}")
            raise QueryError(f"Attack pattern search failed: {type(e).__name__}") from e

    def search_vulnerabilities(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for vulnerabilities (CVEs)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}

            filters = self._build_filters(labels, None, created_after, created_before)
            if filters:
                kwargs["filters"] = filters

            results = (
                self._execute_with_retry(client.vulnerability.list, **kwargs) or []
            )

            results = results[offset : offset + limit]
            return self._format_vulnerabilities(results)

        except Exception as e:
            logger.error(f"Vulnerability search failed: {e}")
            raise QueryError(f"Vulnerability search failed: {type(e).__name__}") from e

    def search_reports(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for threat intelligence reports."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {
                "search": query,
                "first": limit + offset,
                "orderBy": "published",
                "orderMode": "desc",
            }

            filters = self._build_filters(
                labels, confidence_min, created_after, created_before
            )
            if filters:
                kwargs["filters"] = filters

            results = self._execute_with_retry(client.report.list, **kwargs) or []

            results = results[offset : offset + limit]
            return self._format_reports(results)

        except Exception as e:
            logger.error(f"Report search failed: {e}")
            raise QueryError(f"Report search failed: {type(e).__name__}") from e

    def search_campaigns(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for campaigns."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {
                "search": query,
                "first": limit + offset,
                "orderBy": "created",
                "orderMode": "desc",
            }

            filters = self._build_filters(
                labels, confidence_min, created_after, created_before
            )
            if filters:
                kwargs["filters"] = filters

            results = self._execute_with_retry(client.campaign.list, **kwargs) or []

            results = results[offset : offset + limit]
            return self._format_campaigns(results)

        except Exception as e:
            logger.error(f"Campaign search failed: {e}")
            raise QueryError(f"Campaign search failed: {type(e).__name__}") from e

    def search_tools(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for tools (legitimate software used maliciously)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}

            filters = self._build_filters(labels, None, created_after, created_before)
            if filters:
                kwargs["filters"] = filters

            results = self._execute_with_retry(client.tool.list, **kwargs) or []

            results = results[offset : offset + limit]
            return self._format_tools(results)

        except Exception as e:
            logger.error(f"Tool search failed: {e}")
            raise QueryError(f"Tool search failed: {type(e).__name__}") from e

    def search_infrastructure(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for infrastructure (C2, hosting, etc.)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}

            filters = self._build_filters(labels, None, created_after, created_before)
            if filters:
                kwargs["filters"] = filters

            results = (
                self._execute_with_retry(client.infrastructure.list, **kwargs) or []
            )

            results = results[offset : offset + limit]
            return self._format_infrastructure(results)

        except Exception as e:
            logger.error(f"Infrastructure search failed: {e}")
            raise QueryError(f"Infrastructure search failed: {type(e).__name__}") from e

    def search_incidents(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for incidents."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {
                "search": query,
                "first": limit + offset,
                "orderBy": "created",
                "orderMode": "desc",
            }

            filters = self._build_filters(
                labels, confidence_min, created_after, created_before
            )
            if filters:
                kwargs["filters"] = filters

            results = self._execute_with_retry(client.incident.list, **kwargs) or []

            results = results[offset : offset + limit]
            return self._format_incidents(results)

        except Exception as e:
            logger.error(f"Incident search failed: {e}")
            raise QueryError(f"Incident search failed: {type(e).__name__}") from e

    def search_observables(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        observable_types: list[str] | None = None,
        labels: list[str] | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        _skip_rate_limit: bool = False,
    ) -> list[dict[str, Any]]:
        """Search for observables (SCOs - IPs, domains, hashes, etc.).

        Args:
            query: Search term
            limit: Max results
            offset: Skip first N results (for pagination)
            observable_types: Filter by types (e.g., ["IPv4-Addr", "Domain-Name"])
            labels: Filter by labels
            created_after: ISO date for created >= filter
            created_before: ISO date for created <= filter
        """
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)
        offset = max(0, min(offset, 500))

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            kwargs: dict[str, Any] = {"search": query, "first": limit + offset}
            if observable_types:
                kwargs["types"] = observable_types

            # Observables don't have confidence, so exclude it
            filters = self._build_filters(labels, None, created_after, created_before)
            if filters:
                kwargs["filters"] = filters

            results = (
                self._execute_with_retry(client.stix_cyber_observable.list, **kwargs)
                or []
            )

            results = results[offset : offset + limit]
            return self._format_observables(results)

        except Exception as e:
            logger.error(f"Observable search failed: {e}")
            raise QueryError(f"Observable search failed: {type(e).__name__}") from e

    def search_sightings(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for sightings (detection events)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = (
                self._execute_with_retry(
                    client.stix_sighting_relationship.list,
                    search=query,
                    first=limit,
                    orderBy="created",
                    orderMode="desc",
                )
                or []
            )
            return self._format_sightings(results)

        except Exception as e:
            logger.error(f"Sighting search failed: {e}")
            raise QueryError(f"Sighting search failed: {type(e).__name__}") from e

    def search_organizations(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for organizations."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            # Organizations are stored as Identity with type "Organization"
            results = (
                self._execute_with_retry(
                    client.identity.list,
                    search=query,
                    first=limit,
                    types=["Organization"],
                )
                or []
            )
            return self._format_organizations(results)

        except Exception as e:
            logger.error(f"Organization search failed: {e}")
            raise QueryError(f"Organization search failed: {type(e).__name__}") from e

    def search_sectors(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for sectors/industries."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            # Sectors are stored as Identity with type "Sector"
            results = (
                self._execute_with_retry(
                    client.identity.list, search=query, first=limit, types=["Sector"]
                )
                or []
            )
            return self._format_sectors(results)

        except Exception as e:
            logger.error(f"Sector search failed: {e}")
            raise QueryError(f"Sector search failed: {type(e).__name__}") from e

    def search_locations(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for locations (countries, regions, cities)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = (
                self._execute_with_retry(
                    client.location.list, search=query, first=limit
                )
                or []
            )
            return self._format_locations(results)

        except Exception as e:
            logger.error(f"Location search failed: {e}")
            raise QueryError(f"Location search failed: {type(e).__name__}") from e

    def search_courses_of_action(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for courses of action (mitigations)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = (
                self._execute_with_retry(
                    client.course_of_action.list, search=query, first=limit
                )
                or []
            )
            return self._format_courses_of_action(results)

        except Exception as e:
            logger.error(f"Course of action search failed: {e}")
            raise QueryError(
                f"Course of action search failed: {type(e).__name__}"
            ) from e

    def search_groupings(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for groupings (analysis containers)."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = (
                self._execute_with_retry(
                    client.grouping.list,
                    search=query,
                    first=limit,
                    orderBy="created",
                    orderMode="desc",
                )
                or []
            )
            return self._format_groupings(results)

        except Exception as e:
            logger.error(f"Grouping search failed: {e}")
            raise QueryError(f"Grouping search failed: {type(e).__name__}") from e

    def search_notes(
        self, query: str, limit: int = 10, _skip_rate_limit: bool = False
    ) -> list[dict[str, Any]]:
        """Search for analyst notes."""
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit)

        if not _skip_rate_limit:
            self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = (
                self._execute_with_retry(
                    client.note.list,
                    search=query,
                    first=limit,
                    orderBy="created",
                    orderMode="desc",
                )
                or []
            )
            return self._format_notes(results)

        except Exception as e:
            logger.error(f"Note search failed: {e}")
            raise QueryError(f"Note search failed: {type(e).__name__}") from e

    def unified_search(
        self,
        query: str,
        limit: int = 5,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
    ) -> dict[str, Any]:
        """Search across all entity types.

        Rate limiting: Counts as a single query slot despite searching
        multiple entity types, to avoid exhausting the rate limit.

        Args:
            query: Search term
            limit: Max results per entity type (default: 5)
            offset: Skip first N results (for pagination)
            labels: Filter by labels
            confidence_min: Minimum confidence threshold (0-100)
            created_after: ISO date for created >= filter
            created_before: ISO date for created <= filter
        """
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(limit, max_value=20)
        offset = max(0, min(offset, 500))

        # Single rate limit check for entire unified search
        self._check_rate_limit(self._query_limiter, "query")

        # Skip individual rate limit checks since we already checked
        result = {
            "query": query,
            "indicators": self.search_indicators(
                query,
                limit,
                offset,
                labels,
                confidence_min,
                created_after,
                created_before,
                _skip_rate_limit=True,
            ),
            "threat_actors": self.search_threat_actors(
                query,
                limit,
                offset,
                labels,
                confidence_min,
                created_after,
                created_before,
                _skip_rate_limit=True,
            ),
            "malware": self.search_malware(
                query,
                limit,
                offset,
                labels,
                confidence_min,
                created_after,
                created_before,
                _skip_rate_limit=True,
            ),
            "attack_patterns": self.search_attack_patterns(
                query,
                limit,
                offset,
                labels,
                created_after,
                created_before,
                _skip_rate_limit=True,
            ),
            "vulnerabilities": self.search_vulnerabilities(
                query,
                limit,
                offset,
                labels,
                created_after,
                created_before,
                _skip_rate_limit=True,
            ),
            "reports": self.search_reports(
                query,
                limit,
                offset,
                labels,
                confidence_min,
                created_after,
                created_before,
                _skip_rate_limit=True,
            ),
        }

        return truncate_response(result)

    # =========================================================================
    # Context Methods
    # =========================================================================

    def get_indicator_context(self, ioc: str) -> dict[str, Any]:
        """Get full context for an IOC including relationships.

        Searches both Indicators and Observables to ensure complete coverage.
        """
        validate_length(ioc, MAX_IOC_LENGTH, "IOC")

        self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            # Search for indicators first
            results = (
                self._execute_with_retry(client.indicator.list, search=ioc, first=5)
                or []
            )

            # Also search observables if no indicators found
            observables = []
            if not results:
                observables = (
                    self._execute_with_retry(
                        client.stix_cyber_observable.list, search=ioc, first=5
                    )
                    or []
                )

            if not results and not observables:
                return {"found": False, "ioc": ioc}

            # Use indicator if available, otherwise observable
            if results:
                entity = results[0]
                entity_type = "indicator"
            else:
                entity = observables[0]
                entity_type = "observable"

            context = {
                "found": True,
                "ioc": ioc,
                "entity_type": entity_type,
                "type": entity.get(
                    "pattern_type", entity.get("entity_type", "unknown")
                ),
                "name": entity.get("name", entity.get("value", "")),
                "description": entity.get("description", "")[:500]
                if entity.get("description")
                else "",
                "created": entity.get("created", ""),
                "confidence": entity.get("confidence", 0),
                "labels": self._extract_labels(entity),
                "related_threat_actors": [],
                "related_malware": [],
                "mitre_techniques": [],
                "source": "opencti",
            }

            # Get relationships
            try:
                relations = (
                    self._execute_with_retry(
                        client.stix_core_relationship.list,
                        fromId=entity.get("id"),
                        first=MAX_RELATIONSHIPS,
                    )
                    or []
                )

                for rel in relations:
                    target = rel.get("to", {})
                    target_type = target.get("entity_type", "")
                    target_name = target.get("name", "")

                    if target_type in ("Threat-Actor-Group", "Intrusion-Set"):
                        context["related_threat_actors"].append(target_name)
                    elif target_type == "Malware":
                        context["related_malware"].append(target_name)
                    elif target_type == "Attack-Pattern":
                        mitre_id = target.get("x_mitre_id", "")
                        if mitre_id:
                            context["mitre_techniques"].append(mitre_id)
                        else:
                            context["mitre_techniques"].append(target_name)

            except Exception as e:
                logger.warning(f"Failed to get relationships: {e}")

            return context

        except Exception as e:
            logger.error(f"IOC context lookup failed: {e}")
            raise QueryError(f"IOC context lookup failed: {type(e).__name__}") from e

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        """Get any entity by its OpenCTI ID.

        Args:
            entity_id: OpenCTI entity ID (UUID format)

        Returns:
            Entity details or None if not found
        """
        validate_length(entity_id, 100, "entity_id")

        self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            # Use stix_domain_object.read for SDOs
            entity = self._execute_with_retry(
                client.stix_domain_object.read, id=entity_id
            )

            if entity:
                return self._format_entity(entity)

            # Try SCO if SDO not found
            entity = self._execute_with_retry(
                client.stix_cyber_observable.read, id=entity_id
            )

            if entity:
                return self._format_entity(entity)

            # Try relationship
            entity = self._execute_with_retry(
                client.stix_core_relationship.read, id=entity_id
            )

            if entity:
                return self._format_relationship(entity)

            return None

        except Exception as e:
            logger.error(f"Get entity failed: {e}")
            raise QueryError(f"Get entity failed: {type(e).__name__}") from e

    def get_relationships(
        self,
        entity_id: str,
        direction: str = "both",
        relationship_types: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get relationships for an entity.

        Args:
            entity_id: Source entity ID
            direction: 'from' (outgoing), 'to' (incoming), or 'both'
            relationship_types: Filter by types (e.g., ['indicates', 'uses'])
            limit: Max results

        Returns:
            List of relationship details
        """
        validate_length(entity_id, 100, "entity_id")
        limit = validate_limit(limit, max_value=MAX_RELATIONSHIPS)

        self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            results = []

            # Get outgoing relationships (from this entity)
            if direction in ("from", "both"):
                kwargs: dict[str, Any] = {"fromId": entity_id, "first": limit}
                if relationship_types:
                    kwargs["relationship_type"] = relationship_types

                outgoing = (
                    self._execute_with_retry(
                        client.stix_core_relationship.list, **kwargs
                    )
                    or []
                )
                results.extend(outgoing)

            # Get incoming relationships (to this entity)
            if direction in ("to", "both"):
                kwargs = {"toId": entity_id, "first": limit}
                if relationship_types:
                    kwargs["relationship_type"] = relationship_types

                incoming = (
                    self._execute_with_retry(
                        client.stix_core_relationship.list, **kwargs
                    )
                    or []
                )
                results.extend(incoming)

            # Deduplicate first, then slice to limit
            seen_ids = set()
            unique = []
            for r in results:
                rel_id = r.get("id")
                if not rel_id or rel_id not in seen_ids:
                    if rel_id:
                        seen_ids.add(rel_id)
                    unique.append(r)

            return [self._format_relationship(r) for r in unique[:limit]]

        except Exception as e:
            logger.error(f"Get relationships failed: {e}")
            raise QueryError(f"Get relationships failed: {type(e).__name__}") from e

    def get_recent_indicators(
        self, days: int = 7, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Get indicators from the last N days."""
        days = validate_days(days)
        limit = validate_limit(limit)

        self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            # OpenCTI expects Z suffix
            since = since.replace("+00:00", "Z")

            results = (
                self._execute_with_retry(
                    client.indicator.list,
                    first=limit,
                    orderBy="created",
                    orderMode="desc",
                    filters={
                        "mode": "and",
                        "filters": [
                            {"key": "created", "values": [since], "operator": "gte"}
                        ],
                        "filterGroups": [],
                    },
                )
                or []
            )

            return self._format_indicators(results)

        except Exception as e:
            logger.error(f"Recent indicators query failed: {e}")
            raise QueryError(
                f"Recent indicators query failed: {type(e).__name__}"
            ) from e

    # =========================================================================
    # Hash Lookup
    # =========================================================================

    def lookup_hash(self, hash_value: str) -> dict[str, Any] | None:
        """Look up a file hash in OpenCTI."""
        hash_normalized = normalize_hash(hash_value)

        self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            # Search indicators with this hash
            indicators = (
                self._execute_with_retry(
                    client.indicator.list,
                    filters={
                        "mode": "and",
                        "filters": [
                            {
                                "key": "pattern",
                                "values": [hash_normalized],
                                "operator": "contains",
                            }
                        ],
                        "filterGroups": [],
                    },
                    first=5,
                )
                or []
            )

            if indicators:
                return {
                    "found": True,
                    "hash": hash_value,
                    "confidence": "high",
                    "indicators": len(indicators),
                    "malware_family": indicators[0].get("name"),
                    "source": "opencti",
                }

            # Also check observables
            files = (
                self._execute_with_retry(
                    client.stix_cyber_observable.list,
                    types=["StixFile"],
                    filters={
                        "mode": "or",
                        "filters": [
                            {"key": "hashes.MD5", "values": [hash_normalized]},
                            {"key": "hashes.SHA-1", "values": [hash_normalized]},
                            {"key": "hashes.SHA-256", "values": [hash_normalized]},
                        ],
                        "filterGroups": [],
                    },
                    first=5,
                )
                or []
            )

            if files:
                return {
                    "found": True,
                    "hash": hash_value,
                    "confidence": "medium",
                    "observables": len(files),
                    "source": "opencti",
                }

            return None

        except Exception as e:
            logger.error(f"Hash lookup failed: {e}")
            return None

    # =========================================================================
    # Enrichment Methods
    # =========================================================================

    def list_enrichment_connectors(self) -> list[dict[str, Any]]:
        """List available enrichment connectors."""
        self._check_rate_limit(self._query_limiter, "query")

        client = self.connect()

        try:
            query = """
            query ConnectorsList {
              connectors {
                id
                name
                connector_type
                connector_scope
                auto
                active
              }
            }
            """
            result = self._execute_with_retry(client.query, query)
            connectors = result.get("data", {}).get("connectors", [])

            enrichment = []
            for c in connectors:
                if c.get("connector_type") == "INTERNAL_ENRICHMENT":
                    enrichment.append(
                        {
                            "id": c.get("id"),
                            "name": c.get("name"),
                            "scope": c.get("connector_scope", []),
                            "auto": c.get("auto", False),
                            "active": c.get("active", False),
                        }
                    )

            return enrichment

        except Exception as e:
            logger.error(f"Failed to list connectors: {e}")
            raise QueryError(f"Failed to list connectors: {type(e).__name__}") from e

    def trigger_enrichment(self, entity_id: str, connector_id: str) -> dict[str, Any]:
        """Trigger enrichment for an entity via a specific connector.

        Args:
            entity_id: Entity to enrich
            connector_id: Enrichment connector to use

        Returns:
            Status of enrichment request
        """
        validate_length(entity_id, 100, "entity_id")
        validate_length(connector_id, 100, "connector_id")

        # Use enrichment rate limiter (more restrictive)
        self._check_rate_limit(self._enrichment_limiter, "enrichment")

        client = self.connect()

        try:
            # Use GraphQL mutation to trigger enrichment
            mutation = """
            mutation AskForEnrichment($id: ID!, $connectorId: ID!) {
              stixCoreObjectEdit(id: $id) {
                askEnrichment(connectorId: $connectorId) {
                  id
                  connector {
                    name
                  }
                  status
                }
              }
            }
            """
            result = self._execute_with_retry(
                client.query, mutation, {"id": entity_id, "connectorId": connector_id}
            )

            enrichment_data = (
                result.get("data", {})
                .get("stixCoreObjectEdit", {})
                .get("askEnrichment", {})
            )

            return {
                "success": True,
                "entity_id": entity_id,
                "connector_id": connector_id,
                "connector_name": enrichment_data.get("connector", {}).get("name", ""),
                "work_id": enrichment_data.get("id", ""),
                "status": enrichment_data.get("status", "pending"),
            }

        except Exception as e:
            logger.error(f"Trigger enrichment failed: {e}")
            raise QueryError(f"Trigger enrichment failed: {type(e).__name__}") from e

    # =========================================================================
    # Write Operations (with safety controls)
    # =========================================================================

    def create_indicator(
        self,
        name: str,
        pattern: str,
        pattern_type: str = "stix",
        description: str = "",
        confidence: int = 50,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new indicator (IOC).

        Safety: Uses enrichment rate limiter (stricter). Creates are logged.

        Args:
            name: Indicator name
            pattern: STIX pattern (e.g., "[ipv4-addr:value = '192.168.1.1']")
            pattern_type: Pattern type (default: "stix")
            description: Description of the indicator
            confidence: Confidence level 0-100 (default: 50)
            labels: Optional labels to apply

        Returns:
            Created indicator details
        """
        # Validate inputs
        validate_length(name, 256, "name")
        validate_length(pattern, 2048, "pattern")
        validate_length(description, 5000, "description")

        if confidence < 0 or confidence > 100:
            confidence = max(0, min(100, confidence))

        # Use enrichment limiter for writes (more restrictive)
        self._check_rate_limit(self._enrichment_limiter, "write")

        client = self.connect()

        try:
            logger.info(f"Creating indicator: {name}")

            result = self._execute_with_retry(
                client.indicator.create,
                name=name,
                pattern=pattern,
                pattern_type=pattern_type,
                description=description,
                confidence=confidence,
                x_opencti_main_observable_type="Unknown",
            )

            if result:
                indicator_id = result.get("id", "")

                # Add labels if provided
                if labels and indicator_id:
                    for label in labels[:10]:  # Limit labels
                        try:
                            client.stix_domain_object.add_label(
                                id=indicator_id, label_name=label
                            )
                        except Exception as e:
                            logger.warning(f"Failed to add label {label}: {e}")

                return {
                    "success": True,
                    "id": indicator_id,
                    "name": result.get("name", ""),
                    "pattern": result.get("pattern", "")[:200],
                    "created": result.get("created", ""),
                }

            return {"success": False, "error": "No result returned"}

        except Exception as e:
            logger.error(f"Create indicator failed: {e}")
            raise QueryError(f"Create indicator failed: {type(e).__name__}") from e

    def create_note(
        self,
        content: str,
        entity_ids: list[str],
        note_types: list[str] | None = None,
        confidence: int = 75,
        likelihood: int | None = None,
    ) -> dict[str, Any]:
        """Create a note attached to one or more entities.

        Safety: Uses enrichment rate limiter (stricter). Creates are logged.

        Args:
            content: Note content (analyst observations)
            entity_ids: List of entity IDs to attach note to
            note_types: Note types (e.g., ["analysis", "assessment"])
            confidence: Confidence level 0-100 (default: 75)
            likelihood: Likelihood of assessment (1-100, optional)

        Returns:
            Created note details
        """
        # Validate inputs
        validate_length(content, 10000, "content")
        if not content.strip():
            raise ValidationError("Note content cannot be empty")
        if not entity_ids:
            raise ValidationError("At least one entity_id is required")
        if len(entity_ids) > 20:
            raise ValidationError("Maximum 20 entity_ids allowed")

        if confidence < 0 or confidence > 100:
            confidence = max(0, min(100, confidence))

        # Use enrichment limiter for writes
        self._check_rate_limit(self._enrichment_limiter, "write")

        client = self.connect()

        try:
            logger.info(f"Creating note for {len(entity_ids)} entities")

            # Create the note
            result = self._execute_with_retry(
                client.note.create,
                content=content,
                note_types=note_types or ["analysis"],
                confidence=confidence,
                likelihood=likelihood,
                objects=entity_ids,
            )

            if result:
                return {
                    "success": True,
                    "id": result.get("id", ""),
                    "content": result.get("content", "")[:500],
                    "created": result.get("created", ""),
                    "attached_to": len(entity_ids),
                }

            return {"success": False, "error": "No result returned"}

        except Exception as e:
            logger.error(f"Create note failed: {e}")
            raise QueryError(f"Create note failed: {type(e).__name__}") from e

    def create_sighting(
        self,
        indicator_id: str,
        sighted_by_id: str,
        first_seen: str | None = None,
        last_seen: str | None = None,
        count: int = 1,
        description: str = "",
        confidence: int = 75,
    ) -> dict[str, Any]:
        """Create a sighting (detection event).

        Records that an indicator was observed by an identity/organization.

        Safety: Uses enrichment rate limiter (stricter). Creates are logged.

        Args:
            indicator_id: ID of the indicator that was sighted
            sighted_by_id: ID of the identity/organization that observed it
            first_seen: First observation timestamp (ISO format)
            last_seen: Last observation timestamp (ISO format)
            count: Number of times sighted (default: 1)
            description: Sighting description
            confidence: Confidence level 0-100 (default: 75)

        Returns:
            Created sighting details
        """
        # Validate inputs
        validate_length(indicator_id, 100, "indicator_id")
        validate_length(sighted_by_id, 100, "sighted_by_id")
        validate_length(description, 5000, "description")

        if confidence < 0 or confidence > 100:
            confidence = max(0, min(100, confidence))
        if count < 1:
            count = 1

        # Use enrichment limiter for writes
        self._check_rate_limit(self._enrichment_limiter, "write")

        client = self.connect()

        try:
            logger.info(f"Creating sighting: {indicator_id} -> {sighted_by_id}")

            # Use current time if not provided
            if not first_seen:
                first_seen = (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                )
            if not last_seen:
                last_seen = first_seen

            result = self._execute_with_retry(
                client.stix_sighting_relationship.create,
                fromId=indicator_id,
                toId=sighted_by_id,
                first_seen=first_seen,
                last_seen=last_seen,
                count=count,
                description=description,
                confidence=confidence,
            )

            if result:
                return {
                    "success": True,
                    "id": result.get("id", ""),
                    "first_seen": result.get("first_seen", ""),
                    "last_seen": result.get("last_seen", ""),
                    "count": result.get("attribute_count", count),
                    "created": result.get("created", ""),
                }

            return {"success": False, "error": "No result returned"}

        except Exception as e:
            logger.error(f"Create sighting failed: {e}")
            raise QueryError(f"Create sighting failed: {type(e).__name__}") from e

    # =========================================================================
    # Formatting Methods
    # =========================================================================

    def _extract_labels(self, entity: dict) -> list[str]:
        """Extract labels from entity."""
        labels = entity.get("objectLabel", [])
        return [
            lbl.get("value") if isinstance(lbl, dict) else str(lbl) for lbl in labels
        ]

    def _format_indicators(self, results: list) -> list[dict[str, Any]]:
        """Format indicator results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "indicator",
                    "name": r.get("name", ""),
                    "pattern": r.get("pattern", "")[:200] if r.get("pattern") else "",
                    "pattern_type": r.get("pattern_type", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "confidence": r.get("confidence", 0),
                    "created": r.get("created", ""),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_threat_actors(self, results: list) -> list[dict[str, Any]]:
        """Format threat actor results."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append(
                {
                    "type": "threat_actor",
                    "name": r.get("name", ""),
                    "aliases": aliases[:10],  # Limit aliases
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "sophistication": r.get("sophistication", ""),
                    "resource_level": r.get("resource_level", ""),
                    "primary_motivation": r.get("primary_motivation", ""),
                    "goals": (r.get("goals") or [])[:5],
                }
            )
        return formatted

    def _format_malware(self, results: list) -> list[dict[str, Any]]:
        """Format malware results."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append(
                {
                    "type": "malware",
                    "name": r.get("name", ""),
                    "aliases": aliases[:10],
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "malware_types": r.get("malware_types") or [],
                    "is_family": r.get("is_family", False),
                    "capabilities": (r.get("capabilities") or [])[:10],
                }
            )
        return formatted

    def _format_attack_patterns(self, results: list) -> list[dict[str, Any]]:
        """Format attack pattern results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "attack_pattern",
                    "name": r.get("name", ""),
                    "mitre_id": r.get("x_mitre_id", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "kill_chain_phases": [
                        p.get("phase_name") if isinstance(p, dict) else str(p)
                        for p in r.get("killChainPhases", [])
                    ][:10],
                    "platforms": (r.get("x_mitre_platforms") or [])[:10],
                }
            )
        return formatted

    def _format_vulnerabilities(self, results: list) -> list[dict[str, Any]]:
        """Format vulnerability results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "vulnerability",
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "cvss_score": r.get("x_opencti_cvss_base_score", ""),
                    "cvss_severity": r.get("x_opencti_cvss_base_severity", ""),
                }
            )
        return formatted

    def _format_reports(self, results: list) -> list[dict[str, Any]]:
        """Format report results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "report",
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "published": r.get("published", ""),
                    "report_types": r.get("report_types", []),
                    "confidence": r.get("confidence", 0),
                }
            )
        return formatted

    def _format_campaigns(self, results: list) -> list[dict[str, Any]]:
        """Format campaign results."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append(
                {
                    "type": "campaign",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "aliases": aliases[:10],
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "first_seen": r.get("first_seen", ""),
                    "last_seen": r.get("last_seen", ""),
                    "objective": r.get("objective", ""),
                    "confidence": r.get("confidence", 0),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_tools(self, results: list) -> list[dict[str, Any]]:
        """Format tool results (legitimate tools used maliciously)."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append(
                {
                    "type": "tool",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "aliases": aliases[:10],
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "tool_types": r.get("tool_types") or [],
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_infrastructure(self, results: list) -> list[dict[str, Any]]:
        """Format infrastructure results."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append(
                {
                    "type": "infrastructure",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "aliases": aliases[:10],
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "infrastructure_types": r.get("infrastructure_types") or [],
                    "first_seen": r.get("first_seen", ""),
                    "last_seen": r.get("last_seen", ""),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_incidents(self, results: list) -> list[dict[str, Any]]:
        """Format incident results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "incident",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "incident_type": r.get("incident_type", ""),
                    "severity": r.get("severity", ""),
                    "source": r.get("source", ""),
                    "first_seen": r.get("first_seen", ""),
                    "last_seen": r.get("last_seen", ""),
                    "objective": r.get("objective", ""),
                    "confidence": r.get("confidence", 0),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_observables(self, results: list) -> list[dict[str, Any]]:
        """Format observable (SCO) results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "observable",
                    "id": r.get("id", ""),
                    "entity_type": r.get("entity_type", ""),
                    "observable_value": r.get("observable_value", r.get("value", "")),
                    "created": r.get("created", ""),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_sightings(self, results: list) -> list[dict[str, Any]]:
        """Format sighting results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "sighting",
                    "id": r.get("id", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "first_seen": r.get("first_seen", ""),
                    "last_seen": r.get("last_seen", ""),
                    "count": r.get("attribute_count", 1),
                    "from_entity": r.get("from", {}).get("name", ""),
                    "from_type": r.get("from", {}).get("entity_type", ""),
                    "to_entity": r.get("to", {}).get("name", ""),
                    "to_type": r.get("to", {}).get("entity_type", ""),
                    "confidence": r.get("confidence", 0),
                }
            )
        return formatted

    def _format_organizations(self, results: list) -> list[dict[str, Any]]:
        """Format organization results."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append(
                {
                    "type": "organization",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "aliases": aliases[:10],
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "contact_information": r.get("contact_information", ""),
                    "sectors": [
                        s.get("name", "")
                        for s in r.get("sectors", [])
                        if isinstance(s, dict)
                    ][:5],
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_sectors(self, results: list) -> list[dict[str, Any]]:
        """Format sector results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "sector",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_locations(self, results: list) -> list[dict[str, Any]]:
        """Format location results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "location",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "location_type": r.get(
                        "x_opencti_location_type", r.get("entity_type", "")
                    ),
                    "latitude": r.get("latitude"),
                    "longitude": r.get("longitude"),
                    "country": r.get("country", ""),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_courses_of_action(self, results: list) -> list[dict[str, Any]]:
        """Format course of action (mitigation) results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "course_of_action",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "mitre_id": r.get("x_mitre_id", ""),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_groupings(self, results: list) -> list[dict[str, Any]]:
        """Format grouping results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "grouping",
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "description": r.get("description", "")[:500]
                    if r.get("description")
                    else "",
                    "context": r.get("context", ""),
                    "created": r.get("created", ""),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_notes(self, results: list) -> list[dict[str, Any]]:
        """Format note results."""
        formatted = []
        for r in results:
            formatted.append(
                {
                    "type": "note",
                    "id": r.get("id", ""),
                    "content": r.get("content", "")[:1000] if r.get("content") else "",
                    "authors": (r.get("authors") or [])[:5],
                    "created": r.get("created", ""),
                    "note_types": r.get("note_types") or [],
                    "likelihood": r.get("likelihood"),
                    "confidence": r.get("confidence", 0),
                    "labels": self._extract_labels(r),
                }
            )
        return formatted

    def _format_entity(self, entity: dict) -> dict[str, Any]:
        """Format a generic entity for output."""
        entity_type = entity.get("entity_type", "unknown")

        # Common fields
        result = {
            "id": entity.get("id", ""),
            "entity_type": entity_type,
            "name": entity.get(
                "name", entity.get("value", entity.get("observable_value", ""))
            ),
            "description": entity.get("description", "")[:500]
            if entity.get("description")
            else "",
            "created": entity.get("created", ""),
            "modified": entity.get("modified", ""),
            "confidence": entity.get("confidence"),
            "labels": self._extract_labels(entity),
            "external_references": [
                {"source": ref.get("source_name", ""), "url": ref.get("url", "")}
                for ref in entity.get("externalReferences", [])[:5]
            ],
        }

        # Type-specific fields
        if entity_type in ("Threat-Actor-Group", "Intrusion-Set"):
            result["aliases"] = entity.get("aliases", [])[:10]
            result["sophistication"] = entity.get("sophistication")
            result["resource_level"] = entity.get("resource_level")
            result["primary_motivation"] = entity.get("primary_motivation")
        elif entity_type == "Malware":
            result["aliases"] = entity.get("aliases", [])[:10]
            result["malware_types"] = entity.get("malware_types", [])
            result["is_family"] = entity.get("is_family")
        elif entity_type == "Attack-Pattern":
            result["mitre_id"] = entity.get("x_mitre_id", "")
            result["kill_chain_phases"] = [
                p.get("phase_name") if isinstance(p, dict) else str(p)
                for p in entity.get("killChainPhases", [])
            ][:10]
        elif entity_type == "Indicator":
            result["pattern"] = entity.get("pattern", "")[:200]
            result["pattern_type"] = entity.get("pattern_type", "")
            result["valid_from"] = entity.get("valid_from")
            result["valid_until"] = entity.get("valid_until")
        elif entity_type == "Vulnerability":
            result["cvss_score"] = entity.get("x_opencti_cvss_base_score")
            result["cvss_severity"] = entity.get("x_opencti_cvss_base_severity")
        elif entity_type == "Campaign":
            result["aliases"] = entity.get("aliases", [])[:10]
            result["first_seen"] = entity.get("first_seen")
            result["last_seen"] = entity.get("last_seen")
            result["objective"] = entity.get("objective")
        elif entity_type == "Report":
            result["published"] = entity.get("published")
            result["report_types"] = entity.get("report_types", [])
        elif entity_type in (
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Url",
            "StixFile",
        ):
            result["observable_value"] = entity.get(
                "observable_value", entity.get("value", "")
            )

        return result

    def _format_relationship(self, rel: dict) -> dict[str, Any]:
        """Format a relationship for output."""
        from_entity = rel.get("from", {})
        to_entity = rel.get("to", {})

        return {
            "id": rel.get("id", ""),
            "relationship_type": rel.get("relationship_type", ""),
            "description": rel.get("description", "")[:500]
            if rel.get("description")
            else "",
            "from": {
                "id": from_entity.get("id", ""),
                "type": from_entity.get("entity_type", ""),
                "name": from_entity.get("name", from_entity.get("value", "")),
            },
            "to": {
                "id": to_entity.get("id", ""),
                "type": to_entity.get("entity_type", ""),
                "name": to_entity.get("name", to_entity.get("value", "")),
            },
            "start_time": rel.get("start_time"),
            "stop_time": rel.get("stop_time"),
            "confidence": rel.get("confidence"),
            "created": rel.get("created", ""),
        }
