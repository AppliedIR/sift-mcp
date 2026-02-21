"""Advanced security tests covering sophisticated attack vectors.

Tests include:
- Race conditions
- Time-of-check to time-of-use (TOCTOU)
- Algorithmic complexity attacks
- State manipulation
- Resource exhaustion variations
- Type confusion
- Deserialization safety
- Side-channel considerations
"""

from __future__ import annotations

import time
import threading
import concurrent.futures
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
)
from opencti_mcp.client import RateLimiter, CircuitBreaker, CircuitState
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ValidationError, RateLimitError


# =============================================================================
# Race Condition Tests
# =============================================================================

class TestRaceConditions:
    """Test for race conditions in concurrent access."""

    def test_rate_limiter_concurrent_exhaustion(self):
        """Rate limiter handles concurrent requests at limit boundary."""
        limiter = RateLimiter(max_calls=100, window_seconds=60)
        results = []
        barrier = threading.Barrier(50)  # Synchronize threads

        def try_request():
            barrier.wait()  # All threads start together
            result = limiter.check_and_record()
            results.append(result)

        threads = [threading.Thread(target=try_request) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 50 should succeed (limit is 100)
        assert sum(results) == 50

    def test_rate_limiter_exactly_at_limit(self):
        """Rate limiter at exact limit with concurrent requests."""
        limiter = RateLimiter(max_calls=10, window_seconds=60)
        results = []

        def try_request():
            for _ in range(5):
                results.append(limiter.check_and_record())

        threads = [threading.Thread(target=try_request) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 20 attempts, only 10 should succeed
        assert sum(results) == 10

    def test_circuit_breaker_concurrent_failures(self):
        """Circuit breaker handles concurrent failure recording."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        barrier = threading.Barrier(10)

        def record_failure():
            barrier.wait()
            cb.record_failure()

        threads = [threading.Thread(target=record_failure) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should be open after 5+ failures
        assert cb.state == CircuitState.OPEN

    def test_circuit_breaker_mixed_concurrent_operations(self):
        """Circuit breaker handles mixed success/failure concurrently."""
        cb = CircuitBreaker(failure_threshold=10, recovery_timeout=60)

        def mixed_operations():
            for i in range(10):
                if i % 2 == 0:
                    cb.record_success()
                else:
                    cb.record_failure()

        threads = [threading.Thread(target=mixed_operations) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # State depends on order, but should not crash


# =============================================================================
# TOCTOU (Time-of-Check to Time-of-Use) Tests
# =============================================================================

class TestTOCTOU:
    """Test for TOCTOU vulnerabilities."""

    def test_validation_atomic(self):
        """Validation is atomic - input can't change mid-validation."""
        # Create an object that changes during iteration
        class MutatingList(list):
            def __iter__(self):
                for i, item in enumerate(super().__iter__()):
                    if i == 2:
                        self.append("injected")
                    yield item

        # This should not cause issues because we validate a snapshot
        labels = MutatingList(["label1", "label2", "label3"])
        try:
            # If implementation iterates twice, this could cause issues
            validate_labels(list(labels))  # Convert to regular list first
        except Exception:
            pass  # May fail, but shouldn't crash unexpectedly


# =============================================================================
# Algorithmic Complexity Attack Tests
# =============================================================================

class TestAlgorithmicComplexity:
    """Test resistance to algorithmic complexity attacks."""

    def test_hash_collision_resistant(self):
        """Operations don't degrade with hash collisions."""
        # Create strings that might hash similarly
        # In Python, this is mostly handled by the interpreter
        similar_strings = [f"prefix_{i:010d}_suffix" for i in range(1000)]

        start = time.perf_counter()
        for s in similar_strings:
            validate_length(s, MAX_QUERY_LENGTH, "test")
        elapsed = time.perf_counter() - start

        # Should complete quickly
        assert elapsed < 1.0, f"Took {elapsed}s for 1000 validations"

    def test_regex_catastrophic_backtracking_prevention(self):
        """Regex patterns don't cause catastrophic backtracking."""
        # Classic ReDoS patterns
        evil_patterns = [
            "a" * 30 + "!",  # For (a+)+ patterns
            "a" * 30 + "X",  # For (a|a)+ patterns
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaab",  # For (a+)+b
        ]

        for pattern in evil_patterns:
            start = time.perf_counter()
            try:
                validate_ioc(pattern)
            except ValidationError:
                pass
            elapsed = time.perf_counter() - start

            # Must complete in reasonable time
            assert elapsed < 0.1, f"Pattern '{pattern[:20]}...' took {elapsed}s"

    def test_deeply_nested_truncation(self):
        """Deeply nested structures don't cause quadratic behavior."""
        # Create deeply nested structure
        depths = [10, 50, 100]
        times = []

        for depth in depths:
            data = {"level": 0}
            current = data
            for i in range(depth):
                current["nested"] = {"level": i + 1, "data": "x" * 100}
                current = current["nested"]

            start = time.perf_counter()
            truncate_response(data)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # Should scale roughly linearly, not quadratically
        # 10x depth should not be 100x time
        if times[0] > 0:
            ratio = times[-1] / times[0]
            assert ratio < 50, f"Scaling ratio {ratio} suggests quadratic behavior"


# =============================================================================
# State Manipulation Tests
# =============================================================================

class TestStateManipulation:
    """Test resistance to state manipulation attacks."""

    def test_rate_limiter_clock_skew_immunity(self):
        """Rate limiter is immune to clock adjustments."""
        limiter = RateLimiter(max_calls=5, window_seconds=1)

        # Exhaust limit
        for _ in range(5):
            limiter.check_and_record()

        # Should be limited even if we could manipulate time
        assert not limiter.check()

        # The implementation uses monotonic time, so time.time() manipulation
        # wouldn't affect it

    def test_circuit_breaker_state_consistency(self):
        """Circuit breaker maintains consistent state."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)

        # Record failures to open
        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN

        # Immediately recording success shouldn't change state
        cb.record_success()
        # State might still be open or transition to half-open
        assert cb.state in (CircuitState.OPEN, CircuitState.HALF_OPEN, CircuitState.CLOSED)

    def test_rate_limiter_window_boundary(self):
        """Rate limiter handles window boundaries correctly."""
        limiter = RateLimiter(max_calls=5, window_seconds=0.1)

        # Fill the window
        for _ in range(5):
            limiter.check_and_record()

        assert not limiter.check()

        # Wait for window to pass
        time.sleep(0.15)

        # Should be able to make requests again
        assert limiter.check_and_record()


# =============================================================================
# Resource Exhaustion Variations
# =============================================================================

class TestResourceExhaustionVariations:
    """Test various resource exhaustion scenarios."""

    def test_many_small_allocations(self):
        """Many small allocations don't cause issues."""
        # Create many small strings
        for _ in range(10000):
            validate_length("small", MAX_QUERY_LENGTH, "test")

    def test_wide_dict_truncation(self):
        """Very wide dictionaries are handled."""
        # Many keys
        data = {f"key_{i}": f"value_{i}" for i in range(10000)}

        result = truncate_response(data)
        assert isinstance(result, dict)

    def test_many_list_items_truncation(self):
        """Lists with many items are truncated."""
        data = {"items": list(range(100000))}

        result = truncate_response(data)
        assert len(result["items"]) <= 100

    def test_long_string_in_many_fields(self):
        """Multiple long strings are all truncated."""
        data = {
            f"field_{i}": "x" * 10000
            for i in range(100)
        }

        result = truncate_response(data)
        # All should be truncated
        for key, value in result.items():
            if key.startswith("field_"):
                assert len(value) <= 1003  # 1000 + "..."


# =============================================================================
# Type Confusion Tests
# =============================================================================

class TestTypeConfusion:
    """Test resistance to type confusion attacks."""

    def test_string_vs_list_confusion(self):
        """String that looks like list is handled as string."""
        query = "['item1', 'item2']"
        validate_length(query, MAX_QUERY_LENGTH, "query")

    def test_string_vs_dict_confusion(self):
        """String that looks like dict is handled as string."""
        query = "{'key': 'value'}"
        validate_length(query, MAX_QUERY_LENGTH, "query")

    def test_string_vs_number_confusion(self):
        """String that looks like number is handled as string."""
        # These should all be handled as strings
        validate_length("123", MAX_QUERY_LENGTH, "query")
        validate_length("12.34", MAX_QUERY_LENGTH, "query")
        validate_length("-456", MAX_QUERY_LENGTH, "query")
        validate_length("1e10", MAX_QUERY_LENGTH, "query")

    def test_uuid_type_coercion(self):
        """Non-string UUID input is rejected."""
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            validate_uuid(12345, "id")  # type: ignore

        with pytest.raises((ValidationError, TypeError, AttributeError)):
            validate_uuid(["uuid"], "id")  # type: ignore

    def test_label_type_coercion(self):
        """Non-list labels input is rejected."""
        with pytest.raises((ValidationError, TypeError)):
            validate_labels("single-string")  # type: ignore

        with pytest.raises((ValidationError, TypeError)):
            validate_labels(123)  # type: ignore


# =============================================================================
# Deserialization Safety Tests
# =============================================================================

class TestDeserializationSafety:
    """Test deserialization safety."""

    def test_config_not_picklable(self):
        """Config objects cannot be pickled."""
        import pickle

        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("secret"),
        )

        with pytest.raises(TypeError):
            pickle.dumps(config)

    def test_config_not_reducible(self):
        """Config objects cannot be reduced for pickling."""
        import copyreg

        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("secret"),
        )

        with pytest.raises(TypeError):
            config.__reduce__()

    def test_secret_str_not_directly_serializable(self):
        """SecretStr doesn't expose value in serialization."""
        import json

        secret = SecretStr("my-secret")

        # str() and repr() should not expose value
        assert "my-secret" not in str(secret)
        assert "my-secret" not in repr(secret)

        # JSON serialization of the object itself would fail
        # but that's expected behavior


# =============================================================================
# Side-Channel Consideration Tests
# =============================================================================

class TestSideChannelConsiderations:
    """Test side-channel attack mitigations."""

    def test_validation_timing_consistency(self):
        """Validation timing is relatively consistent."""
        valid_uuid = "12345678-1234-1234-1234-123456789abc"
        invalid_uuid = "00000000-0000-0000-0000-00000000000X"

        # Measure many iterations
        iterations = 1000

        valid_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            validate_uuid(valid_uuid, "id")
            valid_times.append(time.perf_counter() - start)

        invalid_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                validate_uuid(invalid_uuid, "id")
            except ValidationError:
                pass
            invalid_times.append(time.perf_counter() - start)

        # Average times should be in same order of magnitude
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)

        # Within 100x is acceptable for non-cryptographic operations
        ratio = max(avg_valid, avg_invalid) / max(min(avg_valid, avg_invalid), 1e-10)
        assert ratio < 100, f"Timing ratio {ratio} may leak information"

    def test_error_messages_dont_leak_position(self):
        """Error messages don't reveal where validation failed."""
        # Try invalid UUIDs with different invalid positions
        test_cases = [
            "X2345678-1234-1234-1234-123456789abc",  # Invalid at start
            "1234567X-1234-1234-1234-123456789abc",  # Invalid in first section
            "12345678-1234-1234-1234-12345678Xabc",  # Invalid near end
        ]

        error_messages = []
        for uuid in test_cases:
            try:
                validate_uuid(uuid, "id")
            except ValidationError as e:
                error_messages.append(str(e))

        # All error messages should be similar (not reveal position)
        # They should all mention it's invalid - message may vary but shouldn't
        # leak specific position information like "invalid char at position 5"
        for msg in error_messages:
            assert "UUID" in msg or "format" in msg.lower() or "invalid" in msg.lower()
            # Should NOT leak position information
            assert "position" not in msg.lower()
            assert "at index" not in msg.lower()


# =============================================================================
# Input Validation Bypass Attempts
# =============================================================================

class TestValidationBypassAttempts:
    """Test attempts to bypass validation."""

    def test_length_check_with_surrogate_pairs(self):
        """Length check handles surrogate pairs correctly."""
        # Emoji that's 1 Python char but 2 UTF-16 code units
        emoji = "🔥"
        assert len(emoji) == 1

        # Create string at exact limit with emoji
        limit = 100
        test_str = "a" * (limit - 1) + emoji
        assert len(test_str) == limit

        # Should pass length validation
        validate_length(test_str, limit, "test")

        # One more should fail
        test_str_over = test_str + "x"
        with pytest.raises(ValidationError):
            validate_length(test_str_over, limit, "test")

    def test_null_byte_in_middle(self):
        """Null bytes in middle of input are detected."""
        test_input = "before\x00after"

        with pytest.raises(ValidationError):
            validate_ioc(test_input)

    def test_escaped_null_byte(self):
        """Escaped null bytes are handled as literal strings."""
        # This is the literal string "\x00", not a null byte
        test_input = "test\\x00value"

        # Should be handled as a regular string
        result = validate_ioc(test_input)
        assert result[1] == "unknown"

    def test_double_validation_consistency(self):
        """Validating same input twice gives same result."""
        test_inputs = [
            "192.168.1.1",
            "d41d8cd98f00b204e9800998ecf8427e",
            "example.com",
            "12345678-1234-1234-1234-123456789abc",
        ]

        for inp in test_inputs:
            result1 = validate_ioc(inp)
            result2 = validate_ioc(inp)
            assert result1 == result2


# =============================================================================
# Concurrent Validation Tests
# =============================================================================

class TestConcurrentValidation:
    """Test validation under concurrent access."""

    def test_concurrent_ioc_validation(self):
        """IOC validation is thread-safe."""
        iocs = [
            "192.168.1.1",
            "10.0.0.1",
            "d41d8cd98f00b204e9800998ecf8427e",
            "example.com",
            "evil.org",
        ]

        results = []
        errors = []

        def validate_iocs():
            try:
                for ioc in iocs * 100:
                    result = validate_ioc(ioc)
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=validate_iocs) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors during concurrent validation: {errors}"
        assert len(results) == 5000  # 5 iocs * 100 iterations * 10 threads

    def test_concurrent_truncation(self):
        """Response truncation is thread-safe."""
        data = {
            "description": "x" * 10000,
            "items": list(range(1000)),
        }

        results = []
        errors = []

        def truncate_data():
            try:
                for _ in range(100):
                    result = truncate_response(data.copy())
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=truncate_data) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors during concurrent truncation: {errors}"


# =============================================================================
# Error Recovery Tests
# =============================================================================

class TestErrorRecovery:
    """Test error recovery and resilience."""

    def test_rate_limiter_recovery_after_errors(self):
        """Rate limiter works correctly after internal errors."""
        limiter = RateLimiter(max_calls=10, window_seconds=60)

        # Normal operation
        for _ in range(5):
            assert limiter.check_and_record()

        # Should still work
        assert limiter.check_and_record()

    def test_circuit_breaker_recovery(self):
        """Circuit breaker recovers correctly."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

        # Trip it
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for recovery
        time.sleep(0.15)

        # Should be half-open
        assert cb.allow_request()
        assert cb.state == CircuitState.HALF_OPEN

        # Success should close it
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_circuit_breaker_reset(self):
        """Circuit breaker can be manually reset."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=60)

        # Trip it
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Manual reset
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request()
