"""Tests for adaptive metrics module."""

from __future__ import annotations

import threading
import time

from opencti_mcp.adaptive import (
    LATENCY_ACCEPTABLE,
    LATENCY_EXCELLENT,
    LATENCY_GOOD,
    LATENCY_POOR,
    AdaptiveConfig,
    AdaptiveMetrics,
    LatencyStats,
    SlidingWindowMetrics,
    SuccessRateTracker,
    get_global_metrics,
    reset_global_metrics,
)

# =============================================================================
# Sliding Window Metrics Tests
# =============================================================================


class TestSlidingWindowMetrics:
    """Tests for SlidingWindowMetrics class."""

    def test_add_and_get_samples(self):
        """Add samples and retrieve them."""
        metrics = SlidingWindowMetrics(max_size=10)

        metrics.add(100.0)
        metrics.add(200.0)
        metrics.add(150.0)

        samples = metrics.get_samples()
        assert samples == [100.0, 200.0, 150.0]

    def test_max_size_enforced(self):
        """Window size is enforced."""
        metrics = SlidingWindowMetrics(max_size=3)

        for i in range(5):
            metrics.add(float(i))

        samples = metrics.get_samples()
        assert len(samples) == 3
        assert samples == [2.0, 3.0, 4.0]

    def test_count(self):
        """Count returns correct number of samples."""
        metrics = SlidingWindowMetrics(max_size=10)

        assert metrics.count() == 0

        metrics.add(100.0)
        metrics.add(200.0)

        assert metrics.count() == 2

    def test_clear(self):
        """Clear removes all samples."""
        metrics = SlidingWindowMetrics(max_size=10)

        metrics.add(100.0)
        metrics.add(200.0)
        metrics.clear()

        assert metrics.count() == 0
        assert metrics.get_samples() == []

    def test_percentile_empty(self):
        """Percentile returns None for empty window."""
        metrics = SlidingWindowMetrics(max_size=10)
        assert metrics.percentile(50) is None

    def test_percentile_single_sample(self):
        """Percentile works with single sample."""
        metrics = SlidingWindowMetrics(max_size=10)
        metrics.add(100.0)

        assert metrics.percentile(50) == 100.0
        assert metrics.percentile(95) == 100.0

    def test_percentile_multiple_samples(self):
        """Percentile calculated correctly."""
        metrics = SlidingWindowMetrics(max_size=100)

        # Add samples 1-100
        for i in range(1, 101):
            metrics.add(float(i))

        # P50 should be around 50
        p50 = metrics.percentile(50)
        assert p50 is not None
        assert 49 <= p50 <= 51

        # P95 should be around 95
        p95 = metrics.percentile(95)
        assert p95 is not None
        assert 94 <= p95 <= 96

    def test_statistics_needs_two_samples(self):
        """Statistics returns None with fewer than 2 samples."""
        metrics = SlidingWindowMetrics(max_size=10)

        assert metrics.statistics() is None

        metrics.add(100.0)
        assert metrics.statistics() is None

        metrics.add(200.0)
        assert metrics.statistics() is not None

    def test_statistics_calculated_correctly(self):
        """Statistics calculated correctly."""
        metrics = SlidingWindowMetrics(max_size=100)

        # Add samples
        for i in [100, 200, 300, 400, 500]:
            metrics.add(float(i))

        stats = metrics.statistics()
        assert stats is not None
        assert stats.sample_count == 5
        assert stats.min_ms == 100.0
        assert stats.max_ms == 500.0
        assert stats.mean_ms == 300.0
        assert stats.median_ms == 300.0

    def test_thread_safety(self):
        """Metrics are thread-safe under concurrent access."""
        metrics = SlidingWindowMetrics(max_size=1000)
        results = []

        def add_samples():
            for i in range(100):
                metrics.add(float(i))
                results.append(True)

        threads = [threading.Thread(target=add_samples) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All additions should have succeeded
        assert len(results) == 1000
        # Count should match (window capped at 1000)
        assert metrics.count() == 1000


# =============================================================================
# Success Rate Tracker Tests
# =============================================================================


class TestSuccessRateTracker:
    """Tests for SuccessRateTracker class."""

    def test_starts_with_100_percent(self):
        """Empty tracker assumes 100% success."""
        tracker = SuccessRateTracker(max_size=10)
        assert tracker.success_rate() == 1.0

    def test_record_success(self):
        """Recording successes updates rate."""
        tracker = SuccessRateTracker(max_size=10)

        tracker.record_success()
        tracker.record_success()

        assert tracker.success_rate() == 1.0

    def test_record_failure(self):
        """Recording failures updates rate."""
        tracker = SuccessRateTracker(max_size=10)

        tracker.record_success()
        tracker.record_failure()

        assert tracker.success_rate() == 0.5

    def test_sliding_window(self):
        """Old results fall out of window."""
        tracker = SuccessRateTracker(max_size=3)

        # Fill with failures
        tracker.record_failure()
        tracker.record_failure()
        tracker.record_failure()
        assert tracker.success_rate() == 0.0

        # Add successes to push out failures
        tracker.record_success()
        tracker.record_success()
        tracker.record_success()

        assert tracker.success_rate() == 1.0

    def test_count(self):
        """Count returns correct number of samples."""
        tracker = SuccessRateTracker(max_size=10)

        assert tracker.count() == 0

        tracker.record_success()
        tracker.record_failure()

        assert tracker.count() == 2

    def test_clear(self):
        """Clear removes all samples."""
        tracker = SuccessRateTracker(max_size=10)

        tracker.record_success()
        tracker.record_failure()
        tracker.clear()

        assert tracker.count() == 0
        assert tracker.success_rate() == 1.0  # Back to default


# =============================================================================
# Latency Stats Tests
# =============================================================================


class TestLatencyStats:
    """Tests for LatencyStats class."""

    def test_classification_excellent(self):
        """Classify excellent latency."""
        stats = LatencyStats(
            sample_count=10,
            min_ms=50,
            max_ms=90,
            mean_ms=70,
            median_ms=70,
            p95_ms=LATENCY_EXCELLENT - 10,  # Below excellent threshold
            p99_ms=95,
            stddev_ms=10,
        )
        assert stats.classification() == "excellent"

    def test_classification_good(self):
        """Classify good latency."""
        stats = LatencyStats(
            sample_count=10,
            min_ms=100,
            max_ms=290,
            mean_ms=200,
            median_ms=200,
            p95_ms=LATENCY_EXCELLENT + 50,  # Between excellent and good
            p99_ms=280,
            stddev_ms=50,
        )
        assert stats.classification() == "good"

    def test_classification_acceptable(self):
        """Classify acceptable latency."""
        stats = LatencyStats(
            sample_count=10,
            min_ms=300,
            max_ms=900,
            mean_ms=600,
            median_ms=600,
            p95_ms=LATENCY_GOOD + 200,  # Between good and acceptable
            p99_ms=850,
            stddev_ms=100,
        )
        assert stats.classification() == "acceptable"

    def test_classification_poor(self):
        """Classify poor latency."""
        stats = LatencyStats(
            sample_count=10,
            min_ms=1000,
            max_ms=2900,
            mean_ms=2000,
            median_ms=2000,
            p95_ms=LATENCY_ACCEPTABLE + 500,  # Between acceptable and poor
            p99_ms=2800,
            stddev_ms=300,
        )
        assert stats.classification() == "poor"

    def test_classification_critical(self):
        """Classify critical latency."""
        stats = LatencyStats(
            sample_count=10,
            min_ms=3000,
            max_ms=5000,
            mean_ms=4000,
            median_ms=4000,
            p95_ms=LATENCY_POOR + 500,  # Above poor threshold
            p99_ms=4800,
            stddev_ms=500,
        )
        assert stats.classification() == "critical"


# =============================================================================
# Adaptive Config Tests
# =============================================================================


class TestAdaptiveConfig:
    """Tests for AdaptiveConfig class."""

    def test_to_dict(self):
        """Config can be converted to dictionary."""
        config = AdaptiveConfig(
            recommended_timeout=30,
            recommended_retry_delay=2.0,
            recommended_max_retries=3,
            recommended_circuit_threshold=5,
            latency_classification="good",
            success_rate=0.95,
            probe_count=100,
        )

        result = config.to_dict()

        assert result["recommended_timeout"] == 30
        assert result["recommended_retry_delay"] == 2.0
        assert result["recommended_max_retries"] == 3
        assert result["latency_classification"] == "good"
        assert result["success_rate"] == 0.95

    def test_to_dict_with_stats(self):
        """Config includes latency stats when available."""
        stats = LatencyStats(
            sample_count=10,
            min_ms=50,
            max_ms=200,
            mean_ms=100,
            median_ms=100,
            p95_ms=180,
            p99_ms=195,
            stddev_ms=30,
        )

        config = AdaptiveConfig(
            recommended_timeout=30,
            recommended_retry_delay=2.0,
            recommended_max_retries=3,
            recommended_circuit_threshold=5,
            latency_classification="good",
            success_rate=0.95,
            probe_count=10,
            latency_stats=stats,
        )

        result = config.to_dict()

        assert result["latency_p95_ms"] == 180
        assert result["latency_mean_ms"] == 100


# =============================================================================
# Adaptive Metrics Tests
# =============================================================================


class TestAdaptiveMetrics:
    """Tests for AdaptiveMetrics class."""

    def test_default_config_with_no_data(self):
        """Returns conservative defaults with insufficient data."""
        metrics = AdaptiveMetrics()

        config = metrics.get_adaptive_config()

        assert config.recommended_timeout == 60  # Conservative default
        assert config.latency_classification == "unknown"
        assert config.probe_count < 5

    def test_record_latency(self):
        """Record latency updates metrics."""
        metrics = AdaptiveMetrics()

        for i in range(10):
            metrics.record_latency(100.0 + i * 10, success=True)

        stats = metrics.get_latency_stats()
        assert stats is not None
        assert stats.sample_count == 10

    def test_record_request(self):
        """Record request with timing."""
        metrics = AdaptiveMetrics()

        start = time.time() - 0.1  # 100ms ago
        metrics.record_request(start, success=True)

        assert metrics._latency_metrics.count() == 1
        assert metrics._success_tracker.count() == 1

    def test_record_request_failure(self):
        """Record request failure."""
        metrics = AdaptiveMetrics()

        start = time.time() - 0.1
        metrics.record_request(start, success=False, error_type="TimeoutError")

        assert metrics._success_tracker.success_rate() == 0.0

        probes = metrics.get_recent_probes()
        assert len(probes) == 1
        assert probes[0].success is False
        assert probes[0].error_type == "TimeoutError"

    def test_adaptive_timeout_calculation(self):
        """Timeout recommendation based on P95 latency."""
        metrics = AdaptiveMetrics()

        # Add samples with P95 around 5000ms (5s)
        for i in range(20):
            metrics.record_latency(5000.0, success=True)

        config = metrics.get_adaptive_config()

        # Timeout should be P95 * buffer (2.0), so around 10s
        # Clamped to min 5s
        assert config.recommended_timeout >= 5
        assert config.recommended_timeout <= 300

    def test_adaptive_retries_high_success_rate(self):
        """Fewer retries recommended for high success rate."""
        metrics = AdaptiveMetrics()

        # Add samples with 100% success
        for i in range(50):
            metrics.record_latency(100.0, success=True)

        config = metrics.get_adaptive_config()

        assert config.recommended_max_retries <= 3

    def test_adaptive_retries_low_success_rate(self):
        """More retries recommended for low success rate."""
        metrics = AdaptiveMetrics()

        # Add samples with 80% success
        for i in range(40):
            metrics.record_latency(100.0, success=True)
        for i in range(10):
            metrics.record_latency(100.0, success=False)

        config = metrics.get_adaptive_config()

        assert config.recommended_max_retries >= 4

    def test_adaptive_circuit_threshold_high_success(self):
        """Higher circuit threshold for reliable service."""
        metrics = AdaptiveMetrics()

        # Add samples with 99%+ success
        for i in range(100):
            metrics.record_latency(100.0, success=True)

        config = metrics.get_adaptive_config()

        assert config.recommended_circuit_threshold >= 5

    def test_adaptive_circuit_threshold_low_success(self):
        """Lower circuit threshold for unreliable service."""
        metrics = AdaptiveMetrics()

        # Add samples with 85% success
        for i in range(85):
            metrics.record_latency(100.0, success=True)
        for i in range(15):
            metrics.record_latency(100.0, success=False)

        config = metrics.get_adaptive_config()

        assert config.recommended_circuit_threshold <= 3

    def test_get_status(self):
        """Get status returns comprehensive info."""
        metrics = AdaptiveMetrics()

        # Add some data
        for i in range(10):
            metrics.record_latency(100.0 + i, success=True)

        status = metrics.get_status()

        assert "probing_active" in status
        assert "probe_interval" in status
        assert "sample_count" in status
        assert "recommendations" in status
        assert status["sample_count"] == 10

    def test_clear_metrics(self):
        """Clear metrics resets all data."""
        metrics = AdaptiveMetrics()

        for i in range(10):
            metrics.record_latency(100.0, success=True)

        metrics.clear_metrics()

        assert metrics._latency_metrics.count() == 0
        assert metrics._success_tracker.count() == 0

    def test_probe_interval_clamped(self):
        """Probe interval is clamped to valid range."""
        # Too low
        metrics_low = AdaptiveMetrics(probe_interval=1)
        assert metrics_low.probe_interval >= 10

        # Too high
        metrics_high = AdaptiveMetrics(probe_interval=1000)
        assert metrics_high.probe_interval <= 300


# =============================================================================
# Global Metrics Tests
# =============================================================================


class TestGlobalMetrics:
    """Tests for global metrics singleton."""

    def test_get_global_metrics_returns_same_instance(self):
        """get_global_metrics returns singleton."""
        reset_global_metrics()

        metrics1 = get_global_metrics()
        metrics2 = get_global_metrics()

        assert metrics1 is metrics2

    def test_reset_global_metrics(self):
        """reset_global_metrics creates new instance."""
        metrics1 = get_global_metrics()
        reset_global_metrics()
        metrics2 = get_global_metrics()

        assert metrics1 is not metrics2

    def test_global_metrics_isolated_per_test(self):
        """Reset between tests for isolation."""
        reset_global_metrics()
        metrics = get_global_metrics()

        # Should start fresh
        assert metrics._latency_metrics.count() == 0
