"""Performance tests for OpenCTI MCP.

Covers:
- Response time benchmarks
- Memory usage patterns
- Rate limiter efficiency
- Circuit breaker response times
- Large result set handling
- Concurrent request simulation
- Validation performance
- Truncation performance
"""

from __future__ import annotations

import time
import sys
import threading
import pytest
from unittest.mock import patch, MagicMock
from opencti_mcp.validation import (
    validate_length,
    validate_ioc,
    validate_uuid,
    validate_labels,
    validate_stix_pattern,
    validate_observable_types,
    validate_date_filter,
    truncate_response,
    sanitize_for_log,
    MAX_QUERY_LENGTH,
    MAX_IOC_LENGTH,
)
from opencti_mcp.client import RateLimiter, CircuitBreaker
from opencti_mcp.config import Config, SecretStr


# =============================================================================
# Validation Performance Tests
# =============================================================================

class TestValidationPerformance:
    """Test validation function performance."""

    def test_length_validation_performance(self):
        """Length validation is O(1) regardless of input size."""
        sizes = [100, 1000, 10000, 100000]
        times = []

        for size in sizes:
            input_str = "a" * size
            iterations = 1000

            start = time.perf_counter()
            for _ in range(iterations):
                try:
                    validate_length(input_str, MAX_QUERY_LENGTH, "test")
                except Exception:
                    pass
            elapsed = time.perf_counter() - start
            times.append(elapsed / iterations)

        # All sizes should have similar timing (within 500x to account for
        # CPU scheduling variance during large test suite runs)
        assert max(times) < min(times) * 500, f"Times varied too much: {times}"

    def test_uuid_validation_performance(self):
        """UUID validation is fast."""
        valid_uuid = "12345678-1234-1234-1234-123456789abc"
        invalid_uuid = "not-a-valid-uuid-at-all"
        iterations = 10000

        # Valid UUID
        start = time.perf_counter()
        for _ in range(iterations):
            validate_uuid(valid_uuid, "id")
        valid_time = (time.perf_counter() - start) / iterations

        # Invalid UUID
        start = time.perf_counter()
        for _ in range(iterations):
            try:
                validate_uuid(invalid_uuid, "id")
            except Exception:
                pass
        invalid_time = (time.perf_counter() - start) / iterations

        # Both should be very fast (< 100 microseconds)
        assert valid_time < 0.0001, f"Valid UUID took {valid_time}s"
        assert invalid_time < 0.0001, f"Invalid UUID took {invalid_time}s"

    def test_ioc_validation_performance(self):
        """IOC validation is fast for all types."""
        iocs = [
            "192.168.1.1",  # IPv4
            "2001:db8::1",  # IPv6
            "192.168.1.0/24",  # CIDR
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
            "example.com",  # Domain
            "https://example.com/path",  # URL
            "CVE-2024-1234",  # CVE
            "T1003.001",  # MITRE
        ]

        iterations = 1000
        for ioc in iocs:
            start = time.perf_counter()
            for _ in range(iterations):
                validate_ioc(ioc)
            elapsed = (time.perf_counter() - start) / iterations

            # Should be very fast (< 100 microseconds)
            assert elapsed < 0.0001, f"IOC '{ioc}' validation took {elapsed}s"

    def test_label_validation_performance(self):
        """Label validation scales linearly."""
        iterations = 1000

        # Single label
        start = time.perf_counter()
        for _ in range(iterations):
            validate_labels(["apt"])
        single_time = (time.perf_counter() - start) / iterations

        # 10 labels
        labels_10 = [f"label-{i}" for i in range(10)]
        start = time.perf_counter()
        for _ in range(iterations):
            validate_labels(labels_10)
        ten_time = (time.perf_counter() - start) / iterations

        # Should scale roughly linearly (10x labels = ~10x time, with tolerance)
        assert ten_time < single_time * 20, f"Label validation doesn't scale: {single_time} vs {ten_time}"

    def test_stix_pattern_validation_performance(self):
        """STIX pattern validation is fast."""
        patterns = [
            "[ipv4-addr:value = '1.1.1.1']",
            "[file:hashes.'SHA-256' = 'abc123']",
            "[domain-name:value = 'malware.com'] OR [url:value LIKE '%malware%']",
        ]

        iterations = 1000
        for pattern in patterns:
            start = time.perf_counter()
            for _ in range(iterations):
                validate_stix_pattern(pattern)
            elapsed = (time.perf_counter() - start) / iterations

            # Should be fast (< 100 microseconds)
            assert elapsed < 0.0001, f"Pattern validation took {elapsed}s"

    def test_date_validation_performance(self):
        """Date validation is fast."""
        dates = [
            "2024-01-01",
            "2024-01-01T12:00:00Z",
            "2024-01-01T12:00:00.123Z",
            "2024-01-01T12:00:00+05:30",
        ]

        iterations = 1000
        for date in dates:
            start = time.perf_counter()
            for _ in range(iterations):
                validate_date_filter(date, "test")
            elapsed = (time.perf_counter() - start) / iterations

            # Should be fast (< 100 microseconds)
            assert elapsed < 0.0001, f"Date validation took {elapsed}s"


# =============================================================================
# Truncation Performance Tests
# =============================================================================

class TestTruncationPerformance:
    """Test truncation function performance."""

    def test_small_response_fast(self):
        """Small responses are processed quickly."""
        data = {
            "id": "123",
            "name": "test",
            "description": "A short description",
            "items": [1, 2, 3, 4, 5],
        }

        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            truncate_response(data)
        elapsed = (time.perf_counter() - start) / iterations

        # Should be very fast (< 1ms)
        assert elapsed < 0.001, f"Small response took {elapsed}s"

    def test_large_response_reasonable(self):
        """Large responses are processed in reasonable time."""
        data = {
            "id": "123",
            "name": "test",
            "description": "x" * 10000,
            "items": [{"id": i, "name": f"item-{i}"} for i in range(1000)],
        }

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            truncate_response(data)
        elapsed = (time.perf_counter() - start) / iterations

        # Should complete in reasonable time (< 100ms)
        assert elapsed < 0.1, f"Large response took {elapsed}s"

    def test_deeply_nested_response(self):
        """Deeply nested responses don't cause slowdown."""
        # Create nested structure
        data = {"level": 0}
        current = data
        for i in range(50):
            current["nested"] = {"level": i + 1, "data": "x" * 100}
            current = current["nested"]

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            truncate_response(data)
        elapsed = (time.perf_counter() - start) / iterations

        # Should be reasonable (< 50ms)
        assert elapsed < 0.05, f"Nested response took {elapsed}s"


# =============================================================================
# Rate Limiter Performance Tests
# =============================================================================

class TestRateLimiterPerformance:
    """Test rate limiter performance."""

    def test_rate_limiter_check_fast(self):
        """Rate limiter checks are fast."""
        limiter = RateLimiter(max_calls=1000, window_seconds=60)

        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            limiter.check()
        elapsed = (time.perf_counter() - start) / iterations

        # Should be very fast (< 10 microseconds)
        assert elapsed < 0.00001, f"Rate check took {elapsed}s"

    def test_rate_limiter_record_fast(self):
        """Rate limiter recording is fast."""
        limiter = RateLimiter(max_calls=100000, window_seconds=60)

        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            limiter.check_and_record()
        elapsed = (time.perf_counter() - start) / iterations

        # Should be fast (< 100 microseconds)
        assert elapsed < 0.0001, f"Rate record took {elapsed}s"

    def test_rate_limiter_cleanup_efficient(self):
        """Rate limiter cleanup is efficient."""
        limiter = RateLimiter(max_calls=10000, window_seconds=0.001)  # Very short window

        # Fill up the limiter
        for _ in range(5000):
            limiter.check_and_record()

        # Wait for window to expire
        time.sleep(0.01)

        # Next check should trigger cleanup
        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            limiter.check_and_record()
        elapsed = (time.perf_counter() - start) / iterations

        # Should still be fast even with cleanup
        assert elapsed < 0.001, f"Rate limiter with cleanup took {elapsed}s"

    def test_rate_limiter_concurrent_performance(self):
        """Rate limiter performs well under concurrent access."""
        limiter = RateLimiter(max_calls=10000, window_seconds=60)
        results = []
        lock = threading.Lock()

        def worker():
            local_times = []
            for _ in range(100):
                start = time.perf_counter()
                limiter.check_and_record()
                local_times.append(time.perf_counter() - start)
            with lock:
                results.extend(local_times)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        avg_time = sum(results) / len(results)
        max_time = max(results)

        # Average should be fast
        assert avg_time < 0.001, f"Average rate check took {avg_time}s"
        # Max should be reasonable (< 10ms even with contention)
        assert max_time < 0.01, f"Max rate check took {max_time}s"


# =============================================================================
# Circuit Breaker Performance Tests
# =============================================================================

class TestCircuitBreakerPerformance:
    """Test circuit breaker performance."""

    def test_circuit_breaker_check_fast(self):
        """Circuit breaker checks are fast."""
        cb = CircuitBreaker(failure_threshold=10, recovery_timeout=60)

        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            cb.allow_request()
        elapsed = (time.perf_counter() - start) / iterations

        # Should be very fast (< 10 microseconds)
        assert elapsed < 0.00001, f"Circuit check took {elapsed}s"

    def test_circuit_breaker_state_transitions_fast(self):
        """Circuit breaker state transitions are fast."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.001)

        iterations = 100  # Reduced iterations for faster test
        start = time.perf_counter()
        for _ in range(iterations):
            cb.record_failure()
            time.sleep(0.002)  # Let it transition to half-open
            cb.allow_request()
            cb.record_success()
        elapsed = time.perf_counter() - start

        # Total time should be close to sleep time (2ms * 100 = 0.2s)
        # State transition overhead should be minimal
        overhead = elapsed - (0.002 * iterations)
        assert overhead < 0.5, f"State transition overhead was {overhead}s"


# =============================================================================
# Log Sanitization Performance Tests
# =============================================================================

class TestLogSanitizationPerformance:
    """Test log sanitization performance."""

    def test_sanitize_string_fast(self):
        """String sanitization is fast."""
        test_strings = [
            "normal string",
            "string\nwith\nnewlines",
            "string with unicode: 你好",
            "x" * 1000,
        ]

        for s in test_strings:
            iterations = 1000
            start = time.perf_counter()
            for _ in range(iterations):
                sanitize_for_log(s)
            elapsed = (time.perf_counter() - start) / iterations

            # Should be fast (< 100 microseconds)
            assert elapsed < 0.0001, f"Sanitize '{s[:20]}...' took {elapsed}s"

    def test_sanitize_dict_fast(self):
        """Dict sanitization is fast."""
        data = {
            "normal": "value",
            "token": "secret-value",
            "nested": {
                "password": "hidden",
                "data": "visible",
            },
            "list": [1, 2, 3, "four", "five"],
        }

        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            sanitize_for_log(data)
        elapsed = (time.perf_counter() - start) / iterations

        # Should be fast (< 1ms)
        assert elapsed < 0.001, f"Dict sanitize took {elapsed}s"


# =============================================================================
# Memory Usage Tests
# =============================================================================

class TestMemoryUsage:
    """Test memory usage patterns."""

    def test_truncation_reduces_memory(self):
        """Truncation reduces memory footprint."""
        # Create large data
        large_data = {
            "description": "x" * 100000,
            "items": list(range(10000)),
            "nested": {"data": "y" * 50000},
        }

        # Get size before truncation
        import json
        original_size = len(json.dumps(large_data))

        # Truncate
        truncated = truncate_response(large_data)
        truncated_size = len(json.dumps(truncated))

        # Truncated should be significantly smaller
        assert truncated_size < original_size / 10, (
            f"Truncation didn't reduce size enough: {original_size} -> {truncated_size}"
        )

    def test_validation_no_memory_leak(self):
        """Validation doesn't leak memory."""
        import gc

        # Force garbage collection
        gc.collect()
        baseline = len(gc.get_objects())

        # Run many validations
        for _ in range(10000):
            try:
                validate_length("x" * 10000, 100, "test")
            except Exception:
                pass
            validate_ioc("192.168.1.1")
            validate_uuid("12345678-1234-1234-1234-123456789abc", "id")

        # Force garbage collection again
        gc.collect()
        after = len(gc.get_objects())

        # Object count shouldn't grow significantly
        growth = after - baseline
        assert growth < 1000, f"Object count grew by {growth}"


# =============================================================================
# Concurrent Access Performance Tests
# =============================================================================

class TestConcurrentPerformance:
    """Test concurrent access performance."""

    def test_concurrent_validation(self):
        """Validation handles concurrent access efficiently."""
        results = []
        lock = threading.Lock()

        def worker():
            local_times = []
            for _ in range(100):
                start = time.perf_counter()
                validate_ioc("192.168.1.1")
                validate_uuid("12345678-1234-1234-1234-123456789abc", "id")
                validate_labels(["label1", "label2"])
                local_times.append(time.perf_counter() - start)
            with lock:
                results.extend(local_times)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        avg_time = sum(results) / len(results)
        max_time = max(results)

        # Average should be fast
        assert avg_time < 0.001, f"Average validation took {avg_time}s"
        # Max should be reasonable
        assert max_time < 0.01, f"Max validation took {max_time}s"


# =============================================================================
# Benchmark Tests (for reference)
# =============================================================================

class TestBenchmarks:
    """Benchmark tests for performance baseline."""

    @pytest.mark.benchmark
    def test_benchmark_ioc_validation(self):
        """Benchmark IOC validation."""
        iocs = [
            "192.168.1.1",
            "d41d8cd98f00b204e9800998ecf8427e",
            "example.com",
            "https://example.com/path",
            "CVE-2024-1234",
        ]

        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            for ioc in iocs:
                validate_ioc(ioc)
        elapsed = time.perf_counter() - start

        ops_per_second = (iterations * len(iocs)) / elapsed
        print(f"\nIOC validation: {ops_per_second:.0f} ops/sec")
        # Low threshold to account for CI/VM/container variability
        assert ops_per_second > 10000, "IOC validation too slow"

    @pytest.mark.benchmark
    def test_benchmark_uuid_validation(self):
        """Benchmark UUID validation."""
        uuid = "12345678-1234-1234-1234-123456789abc"

        iterations = 100000
        start = time.perf_counter()
        for _ in range(iterations):
            validate_uuid(uuid, "id")
        elapsed = time.perf_counter() - start

        ops_per_second = iterations / elapsed
        print(f"\nUUID validation: {ops_per_second:.0f} ops/sec")
        # Low threshold to account for CI/VM/container variability
        assert ops_per_second > 10000, "UUID validation too slow"

    @pytest.mark.benchmark
    def test_benchmark_truncation(self):
        """Benchmark response truncation."""
        data = {
            "id": "123",
            "name": "test",
            "description": "x" * 1000,
            "items": [{"id": i} for i in range(100)],
        }

        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            truncate_response(data)
        elapsed = time.perf_counter() - start

        ops_per_second = iterations / elapsed
        print(f"\nTruncation: {ops_per_second:.0f} ops/sec")
        assert ops_per_second > 1000, "Truncation too slow"

    @pytest.mark.benchmark
    def test_benchmark_rate_limiter(self):
        """Benchmark rate limiter."""
        limiter = RateLimiter(max_calls=1000000, window_seconds=60)

        iterations = 100000
        start = time.perf_counter()
        for _ in range(iterations):
            limiter.check_and_record()
        elapsed = time.perf_counter() - start

        ops_per_second = iterations / elapsed
        print(f"\nRate limiter: {ops_per_second:.0f} ops/sec")
        assert ops_per_second > 100000, "Rate limiter too slow"
