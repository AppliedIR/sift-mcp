"""Adaptive network metrics for production resilience.

Automatically adjusts timeouts, retry delays, and circuit breaker thresholds
based on observed network conditions. Essential for geographically distributed
users connecting to cloud-hosted OpenCTI (Azure, AWS, etc.).

Features:
- Periodic latency probing with configurable intervals
- Sliding window percentile calculations (P50, P95, P99)
- Adaptive timeout adjustment based on observed latency
- Success rate tracking for circuit breaker tuning
- Geographic-aware recommendations

Usage:
    from opencti_mcp.adaptive import AdaptiveMetrics

    metrics = AdaptiveMetrics()
    metrics.start_background_probing(client)

    # Get current recommendations
    config = metrics.get_adaptive_config()
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Probe settings
DEFAULT_PROBE_INTERVAL = 60  # Seconds between probes
MIN_PROBE_INTERVAL = 10  # Minimum probe interval
MAX_PROBE_INTERVAL = 300  # Maximum probe interval

# Metric windows
LATENCY_WINDOW_SIZE = 100  # Number of samples to keep
SUCCESS_WINDOW_SIZE = 50  # Number of success/fail samples

# Adaptive thresholds
MIN_TIMEOUT = 5  # Minimum timeout (seconds)
MAX_TIMEOUT = 300  # Maximum timeout (seconds)
TIMEOUT_PERCENTILE = 95  # Use P95 latency for timeout
TIMEOUT_BUFFER_MULTIPLIER = 2.0  # Multiply P95 by this for timeout

MIN_RETRY_DELAY = 0.5  # Minimum retry delay (seconds)
MAX_RETRY_DELAY = 60.0  # Maximum retry delay (seconds)

# Latency classifications (milliseconds)
LATENCY_EXCELLENT = 100  # < 100ms = excellent
LATENCY_GOOD = 300  # < 300ms = good
LATENCY_ACCEPTABLE = 1000  # < 1s = acceptable
LATENCY_POOR = 3000  # < 3s = poor
# >= 3s = critical


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ProbeResult:
    """Result of a single probe."""

    timestamp: float
    latency_ms: float
    success: bool
    error_type: str | None = None


@dataclass
class LatencyStats:
    """Latency statistics from collected samples."""

    sample_count: int
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    stddev_ms: float

    def classification(self) -> str:
        """Classify latency quality."""
        p95 = self.p95_ms
        if p95 < LATENCY_EXCELLENT:
            return "excellent"
        elif p95 < LATENCY_GOOD:
            return "good"
        elif p95 < LATENCY_ACCEPTABLE:
            return "acceptable"
        elif p95 < LATENCY_POOR:
            return "poor"
        else:
            return "critical"


@dataclass
class AdaptiveConfig:
    """Dynamically computed configuration based on metrics."""

    recommended_timeout: int
    recommended_retry_delay: float
    recommended_max_retries: int
    recommended_circuit_threshold: int

    latency_classification: str
    success_rate: float
    probe_count: int

    # Raw stats for debugging
    latency_stats: LatencyStats | None = None
    last_probe_time: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "recommended_timeout": self.recommended_timeout,
            "recommended_retry_delay": self.recommended_retry_delay,
            "recommended_max_retries": self.recommended_max_retries,
            "recommended_circuit_threshold": self.recommended_circuit_threshold,
            "latency_classification": self.latency_classification,
            "success_rate": round(self.success_rate, 3),
            "probe_count": self.probe_count,
            "latency_p95_ms": self.latency_stats.p95_ms if self.latency_stats else None,
            "latency_mean_ms": self.latency_stats.mean_ms
            if self.latency_stats
            else None,
        }


# =============================================================================
# Sliding Window Metrics
# =============================================================================


class SlidingWindowMetrics:
    """Thread-safe sliding window for metric collection."""

    def __init__(self, max_size: int) -> None:
        self._samples: deque[float] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def add(self, value: float) -> None:
        """Add a sample."""
        with self._lock:
            self._samples.append(value)

    def get_samples(self) -> list[float]:
        """Get copy of current samples."""
        with self._lock:
            return list(self._samples)

    def count(self) -> int:
        """Get number of samples."""
        with self._lock:
            return len(self._samples)

    def clear(self) -> None:
        """Clear all samples."""
        with self._lock:
            self._samples.clear()

    def percentile(self, p: float) -> float | None:
        """Calculate percentile (0-100)."""
        samples = self.get_samples()
        if not samples:
            return None

        sorted_samples = sorted(samples)
        index = (p / 100) * (len(sorted_samples) - 1)
        lower = int(index)
        upper = min(lower + 1, len(sorted_samples) - 1)
        weight = index - lower

        return sorted_samples[lower] * (1 - weight) + sorted_samples[upper] * weight

    def statistics(self) -> LatencyStats | None:
        """Calculate comprehensive statistics."""
        samples = self.get_samples()
        if len(samples) < 2:
            return None

        return LatencyStats(
            sample_count=len(samples),
            min_ms=min(samples),
            max_ms=max(samples),
            mean_ms=statistics.mean(samples),
            median_ms=statistics.median(samples),
            p95_ms=self.percentile(95) or 0,
            p99_ms=self.percentile(99) or 0,
            stddev_ms=statistics.stdev(samples) if len(samples) > 1 else 0,
        )


class SuccessRateTracker:
    """Track success/failure rate over a sliding window."""

    def __init__(self, max_size: int) -> None:
        self._results: deque[bool] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def record_success(self) -> None:
        """Record a successful operation."""
        with self._lock:
            self._results.append(True)

    def record_failure(self) -> None:
        """Record a failed operation."""
        with self._lock:
            self._results.append(False)

    def success_rate(self) -> float:
        """Calculate success rate (0.0 to 1.0)."""
        with self._lock:
            if not self._results:
                return 1.0  # Assume healthy if no data
            return sum(1 for r in self._results if r) / len(self._results)

    def count(self) -> int:
        """Get number of samples."""
        with self._lock:
            return len(self._results)

    def clear(self) -> None:
        """Clear all samples."""
        with self._lock:
            self._results.clear()


# =============================================================================
# Adaptive Metrics Engine
# =============================================================================


class AdaptiveMetrics:
    """Adaptive metrics collection and configuration recommendation.

    Continuously monitors OpenCTI connectivity and adjusts configuration
    recommendations based on observed network conditions.

    Thread-safe: Can be used from multiple async contexts.
    """

    def __init__(
        self,
        probe_interval: float = DEFAULT_PROBE_INTERVAL,
        latency_window: int = LATENCY_WINDOW_SIZE,
        success_window: int = SUCCESS_WINDOW_SIZE,
    ) -> None:
        self.probe_interval = max(
            MIN_PROBE_INTERVAL, min(probe_interval, MAX_PROBE_INTERVAL)
        )

        self._latency_metrics = SlidingWindowMetrics(latency_window)
        self._success_tracker = SuccessRateTracker(success_window)

        self._probe_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_probe_time: float | None = None
        self._probe_func: Callable[[], ProbeResult] | None = None

        # Lock for probe results
        self._lock = threading.Lock()
        self._recent_probes: deque[ProbeResult] = deque(maxlen=10)

    def record_latency(self, latency_ms: float, success: bool = True) -> None:
        """Record a latency measurement from an actual query.

        Call this from the client after each query to feed real-world
        latency data into the adaptive system.
        """
        self._latency_metrics.add(latency_ms)
        if success:
            self._success_tracker.record_success()
        else:
            self._success_tracker.record_failure()

    def record_request(
        self, start_time: float, success: bool, error_type: str | None = None
    ) -> None:
        """Record a request with timing.

        Args:
            start_time: time.time() when request started
            success: Whether request succeeded
            error_type: Type of error if failed
        """
        latency_ms = (time.time() - start_time) * 1000

        self._latency_metrics.add(latency_ms)
        if success:
            self._success_tracker.record_success()
        else:
            self._success_tracker.record_failure()

        with self._lock:
            self._recent_probes.append(
                ProbeResult(
                    timestamp=time.time(),
                    latency_ms=latency_ms,
                    success=success,
                    error_type=error_type,
                )
            )

    def get_latency_stats(self) -> LatencyStats | None:
        """Get current latency statistics."""
        return self._latency_metrics.statistics()

    def get_success_rate(self) -> float:
        """Get current success rate (0.0 to 1.0)."""
        return self._success_tracker.success_rate()

    def get_adaptive_config(self) -> AdaptiveConfig:
        """Calculate adaptive configuration based on current metrics.

        Returns recommended settings based on observed latency and success rate.
        """
        stats = self.get_latency_stats()
        success_rate = self.get_success_rate()

        if stats is None or stats.sample_count < 5:
            # Not enough data - return conservative defaults
            return AdaptiveConfig(
                recommended_timeout=60,
                recommended_retry_delay=2.0,
                recommended_max_retries=3,
                recommended_circuit_threshold=5,
                latency_classification="unknown",
                success_rate=success_rate,
                probe_count=self._latency_metrics.count(),
                latency_stats=stats,
                last_probe_time=self._last_probe_time,
            )

        # Calculate adaptive timeout: P95 * buffer, clamped to reasonable range
        timeout = int(stats.p95_ms / 1000 * TIMEOUT_BUFFER_MULTIPLIER)
        timeout = max(MIN_TIMEOUT, min(timeout, MAX_TIMEOUT))

        # Calculate adaptive retry delay based on latency variability
        # Higher variability = longer initial delay
        retry_delay = max(
            MIN_RETRY_DELAY, min(stats.p95_ms / 1000 * 0.5, MAX_RETRY_DELAY)
        )

        # Adjust retries based on success rate
        if success_rate >= 0.99:
            max_retries = 2  # Very reliable - fewer retries needed
        elif success_rate >= 0.95:
            max_retries = 3  # Good - normal retries
        elif success_rate >= 0.90:
            max_retries = 4  # Some issues - more retries
        else:
            max_retries = 5  # Unreliable - max retries

        # Adjust circuit breaker threshold based on success rate
        if success_rate >= 0.99:
            circuit_threshold = 10  # Very reliable - high tolerance
        elif success_rate >= 0.95:
            circuit_threshold = 5  # Good - normal threshold
        elif success_rate >= 0.90:
            circuit_threshold = 3  # Issues - lower threshold
        else:
            circuit_threshold = 2  # Unreliable - trip quickly

        return AdaptiveConfig(
            recommended_timeout=timeout,
            recommended_retry_delay=round(retry_delay, 2),
            recommended_max_retries=max_retries,
            recommended_circuit_threshold=circuit_threshold,
            latency_classification=stats.classification(),
            success_rate=success_rate,
            probe_count=stats.sample_count,
            latency_stats=stats,
            last_probe_time=self._last_probe_time,
        )

    def reset(self) -> None:
        """Reset all metrics to initial state.

        Use after forced reconnection or significant configuration changes.
        """
        with self._lock:
            # Clear existing samples by creating new instances with same window sizes
            latency_window = (
                self._latency_metrics._samples.maxlen or LATENCY_WINDOW_SIZE
            )
            success_window = (
                self._success_tracker._results.maxlen or SUCCESS_WINDOW_SIZE
            )
            self._latency_metrics = SlidingWindowMetrics(latency_window)
            self._success_tracker = SuccessRateTracker(success_window)
            self._recent_probes.clear()
            self._last_probe_time = None
            logger.info("Adaptive metrics reset")

    def _default_probe(self, client: Any) -> ProbeResult:
        """Default probe function using client health check."""
        start = time.monotonic()
        try:
            # Use a lightweight query
            client.connect().stix_cyber_observable.list(first=1)
            latency_ms = (time.monotonic() - start) * 1000
            return ProbeResult(
                timestamp=time.time(),
                latency_ms=latency_ms,
                success=True,
            )
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            return ProbeResult(
                timestamp=time.time(),
                latency_ms=latency_ms,
                success=False,
                error_type=type(e).__name__,
            )

    def _probe_loop(self, client: Any) -> None:
        """Background probe loop."""
        logger.info(
            f"Starting adaptive metrics probe (interval: {self.probe_interval}s)"
        )

        while not self._stop_event.is_set():
            try:
                result = self._default_probe(client)
                self._last_probe_time = result.timestamp

                self._latency_metrics.add(result.latency_ms)
                if result.success:
                    self._success_tracker.record_success()
                else:
                    self._success_tracker.record_failure()

                with self._lock:
                    self._recent_probes.append(result)

                # Log periodic status
                if self._latency_metrics.count() % 10 == 0:
                    config = self.get_adaptive_config()
                    logger.info(
                        f"Adaptive metrics: latency={config.latency_classification}, "
                        f"success_rate={config.success_rate:.1%}, "
                        f"recommended_timeout={config.recommended_timeout}s"
                    )

            except Exception as e:
                logger.warning(f"Probe failed: {e}")

            # Wait for next probe interval
            self._stop_event.wait(self.probe_interval)

        logger.info("Adaptive metrics probe stopped")

    def start_background_probing(self, client: Any) -> None:
        """Start background probing thread.

        Args:
            client: OpenCTIClient instance to probe
        """
        if self._probe_thread is not None and self._probe_thread.is_alive():
            logger.warning("Background probing already running")
            return

        self._stop_event.clear()
        self._probe_thread = threading.Thread(
            target=self._probe_loop,
            args=(client,),
            daemon=True,
            name="opencti-adaptive-probe",
        )
        self._probe_thread.start()

    def stop_background_probing(self) -> None:
        """Stop background probing thread."""
        self._stop_event.set()
        if self._probe_thread is not None:
            self._probe_thread.join(timeout=5)
            self._probe_thread = None

    def get_recent_probes(self) -> list[ProbeResult]:
        """Get recent probe results for debugging."""
        with self._lock:
            return list(self._recent_probes)

    def clear_metrics(self) -> None:
        """Clear all collected metrics."""
        self._latency_metrics.clear()
        self._success_tracker.clear()
        with self._lock:
            self._recent_probes.clear()

    def get_status(self) -> dict[str, Any]:
        """Get current status for monitoring/debugging."""
        config = self.get_adaptive_config()
        recent = self.get_recent_probes()

        return {
            "probing_active": self._probe_thread is not None
            and self._probe_thread.is_alive(),
            "probe_interval": self.probe_interval,
            "sample_count": self._latency_metrics.count(),
            "last_probe_time": datetime.fromtimestamp(
                self._last_probe_time, tz=timezone.utc
            ).isoformat()
            if self._last_probe_time
            else None,
            "recent_probe_results": [
                {
                    "latency_ms": round(p.latency_ms, 1),
                    "success": p.success,
                    "error": p.error_type,
                }
                for p in recent[-5:]
            ],
            "recommendations": config.to_dict(),
        }


# =============================================================================
# Global Metrics Instance
# =============================================================================

_global_metrics: AdaptiveMetrics | None = None
_global_lock = threading.Lock()


def get_global_metrics() -> AdaptiveMetrics:
    """Get or create the global adaptive metrics instance."""
    global _global_metrics
    with _global_lock:
        if _global_metrics is None:
            _global_metrics = AdaptiveMetrics()
        return _global_metrics


def reset_global_metrics() -> None:
    """Reset the global metrics instance."""
    global _global_metrics
    with _global_lock:
        if _global_metrics is not None:
            _global_metrics.stop_background_probing()
            _global_metrics = None
