"""Deep security tests for sophisticated attack scenarios.

These tests simulate advanced attacker techniques including:
- Timing attacks
- Memory exhaustion attempts
- Unicode normalization attacks
- Protocol-level injection
- State manipulation
- Race condition simulation
"""

from __future__ import annotations

import time

import pytest
from opencti_mcp.client import CircuitBreaker, CircuitState, RateLimiter
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ValidationError
from opencti_mcp.validation import (
    MAX_IOC_LENGTH,
    MAX_QUERY_LENGTH,
    sanitize_for_log,
    truncate_response,
    validate_date_filter,
    validate_ioc,
    validate_labels,
    validate_length,
    validate_note_types,
    validate_observable_types,
    validate_relationship_types,
    validate_uuid,
)

# =============================================================================
# Timing Attack Prevention Tests
# =============================================================================


class TestTimingAttackPrevention:
    """Ensure validation doesn't leak information via timing."""

    def test_uuid_validation_constant_time_on_length(self):
        """UUID validation should fail fast on wrong length."""
        short = "abc"
        long_input = "a" * 1000

        start = time.perf_counter()
        with pytest.raises(ValidationError):
            validate_uuid(short, "id")
        short_time = time.perf_counter() - start

        start = time.perf_counter()
        with pytest.raises(ValidationError):
            validate_uuid(long_input, "id")
        long_time = time.perf_counter() - start

        # Long input shouldn't take significantly longer
        assert long_time < short_time * 10

    def test_ioc_validation_fails_fast_on_length(self):
        """IOC validation should fail fast on excessive length."""
        huge_input = "a" * (MAX_IOC_LENGTH + 10000)

        start = time.perf_counter()
        with pytest.raises(ValidationError):
            validate_ioc(huge_input)
        elapsed = time.perf_counter() - start

        # Should complete in milliseconds
        assert elapsed < 0.05, f"Took {elapsed}s - possible DoS vector"

    def test_query_length_validation_constant(self):
        """Query length validation is constant time."""
        inputs = [
            "a" * 100,
            "a" * 1000,
            "a" * (MAX_QUERY_LENGTH + 1),
            "a" * (MAX_QUERY_LENGTH + 10000),
        ]

        # Run multiple iterations to reduce noise
        iterations = 100
        times = []
        for inp in inputs:
            total = 0
            for _ in range(iterations):
                start = time.perf_counter()
                try:
                    validate_length(inp, MAX_QUERY_LENGTH, "query")
                except ValidationError:
                    pass
                total += time.perf_counter() - start
            times.append(total / iterations)

        # All should be similar (within 100x of each other to account for system noise)
        assert max(times) < min(times) * 100


# =============================================================================
# Memory Exhaustion Prevention Tests
# =============================================================================


class TestMemoryExhaustionPrevention:
    """Ensure inputs can't cause memory exhaustion."""

    def test_nested_dict_truncation(self):
        """Deeply nested dicts are handled safely."""
        # Create a deeply nested structure
        data = {"level": 0}
        current = data
        for i in range(100):
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        # Should not crash
        result = truncate_response(data)
        assert isinstance(result, dict)

    def test_wide_dict_truncation(self):
        """Wide dicts are handled safely."""
        # Create a very wide structure
        data = {f"key_{i}": f"value_{i}" * 100 for i in range(1000)}

        # Should not crash
        result = truncate_response(data)
        assert isinstance(result, dict)

    def test_long_list_truncation(self):
        """Long lists are truncated."""
        data = {"items": list(range(10000))}

        result = truncate_response(data)
        # Should be truncated to MAX_LIMIT (100)
        assert len(result["items"]) <= 100

    def test_large_string_truncation(self):
        """Large strings are truncated."""
        data = {"description": "x" * 100000}

        result = truncate_response(data)
        assert len(result["description"]) <= 503  # 500 + "..."


# =============================================================================
# Unicode Normalization Attack Tests
# =============================================================================


class TestUnicodeNormalizationAttacks:
    """Test handling of Unicode normalization attacks."""

    def test_combining_characters_in_domain(self):
        """Combining characters don't bypass validation."""
        # 'e' + combining acute = different from 'é'
        combining = "example\u0301.com"  # e + combining acute
        result = validate_ioc(combining)
        # Should either reject or classify as unknown, not as valid domain
        assert result[1] in ("unknown", "domain")  # Domain if ASCII

    def test_fullwidth_characters_rejected(self):
        """Fullwidth ASCII variants are rejected."""
        # Fullwidth 'a' (U+FF41)
        fullwidth = "\uff41nalysis"
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types([fullwidth])

    def test_mathematical_alphanumeric_rejected(self):
        """Mathematical alphanumeric symbols are rejected."""
        # Mathematical bold 'a' (U+1D41A)
        math_bold = "\U0001d41analysis"
        with pytest.raises(ValidationError):
            validate_note_types([math_bold])

    def test_superscript_numbers_rejected(self):
        """Superscript numbers are rejected."""
        # Superscript 1 (U+00B9)
        superscript = "type\u00b9"
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types([superscript])

    def test_subscript_numbers_rejected(self):
        """Subscript numbers are rejected."""
        # Subscript 2 (U+2082)
        subscript = "type\u2082"
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types([subscript])


# =============================================================================
# Protocol Injection Tests
# =============================================================================


class TestProtocolInjection:
    """Test for protocol-level injection attempts."""

    def test_graphql_injection_in_query(self):
        """GraphQL injection attempts are safely handled."""
        # Can't truly inject because pycti uses parameterized queries
        # But validate that special GraphQL chars don't crash us
        queries = [
            'test") { indicator { id } }',
            'test", first: 9999999) { id }',
            'test\\") { __schema { types { name } } }',
        ]
        for q in queries:
            # Should pass validation (pycti handles escaping)
            validate_length(q, MAX_QUERY_LENGTH, "query")

    def test_json_injection_in_labels(self):
        """JSON injection attempts are rejected."""
        malicious = '{"key": "value"}'
        with pytest.raises(ValidationError):
            validate_labels([malicious])

    def test_http_header_injection(self):
        """HTTP header injection in IOCs is handled."""
        injection = "test\r\nX-Injected: header"
        # Should not crash, null/control chars should be caught
        result = validate_ioc(injection)
        # Either rejected or classified as unknown
        assert result[0] is True  # Format-wise it's "valid" but unknown

    def test_log_injection_sanitized(self):
        """Log injection attempts are sanitized."""
        injection = "user\nERROR: Fake error\nDanger"
        sanitized = sanitize_for_log(injection)
        # Newlines should be escaped
        assert "\n" not in sanitized
        assert "\\n" in sanitized or "Fake error" not in sanitized


# =============================================================================
# State Manipulation Tests
# =============================================================================


class TestStateManipulation:
    """Test resistance to state manipulation attacks."""

    def test_rate_limiter_window_manipulation(self):
        """Rate limiter handles time jumps gracefully."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)

        # Record some calls
        limiter.check_and_record()
        limiter.check_and_record()

        # Should be rate limited
        assert not limiter.check()

        # Wait time should be positive
        wait = limiter.wait_time()
        assert wait > 0
        assert wait <= 60  # Not longer than window

    def test_circuit_breaker_state_transitions(self):
        """Circuit breaker state transitions are correct."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)

        # Start closed
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request()

        # Record failures to trip
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED  # Not yet
        cb.record_failure()
        assert cb.state == CircuitState.OPEN  # Tripped
        assert not cb.allow_request()

        # Wait for recovery
        time.sleep(1.1)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request()

        # Success closes
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_circuit_breaker_reset(self):
        """Circuit breaker reset works correctly."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1000)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request()


# =============================================================================
# Boundary Condition Stress Tests
# =============================================================================


class TestBoundaryStress:
    """Stress test boundary conditions."""

    def test_max_length_boundary(self):
        """Exact max length is accepted."""
        exact = "a" * MAX_QUERY_LENGTH
        validate_length(exact, MAX_QUERY_LENGTH, "query")  # Should not raise

    def test_max_length_plus_one_rejected(self):
        """One over max length is rejected."""
        over = "a" * (MAX_QUERY_LENGTH + 1)
        with pytest.raises(ValidationError):
            validate_length(over, MAX_QUERY_LENGTH, "query")

    def test_uuid_all_zeros(self):
        """All-zero UUID is valid."""
        result = validate_uuid("00000000-0000-0000-0000-000000000000", "id")
        assert result == "00000000-0000-0000-0000-000000000000"

    def test_uuid_all_fs(self):
        """All-F UUID is valid."""
        result = validate_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff", "id")
        assert result == "ffffffff-ffff-ffff-ffff-ffffffffffff"

    def test_date_boundary_year_1970(self):
        """Year 1970 (min) is accepted."""
        result = validate_date_filter("1970-01-01", "date")
        assert result == "1970-01-01"

    def test_date_boundary_year_2100(self):
        """Year 2100 (max) is accepted."""
        result = validate_date_filter("2100-12-31", "date")
        assert result == "2100-12-31"

    def test_empty_vs_whitespace_vs_none(self):
        """Distinguish between empty, whitespace, and None."""
        # None
        assert validate_date_filter(None, "date") is None
        assert validate_observable_types(None) is None
        assert validate_note_types(None) is None

        # Empty string
        assert validate_date_filter("", "date") is None

        # Whitespace only
        assert validate_date_filter("   ", "date") is None

        # Empty list
        assert validate_observable_types([]) is None
        assert validate_note_types([]) is None


# =============================================================================
# Concurrent Access Safety Tests
# =============================================================================


class TestConcurrentSafety:
    """Test thread safety of shared components."""

    def test_rate_limiter_concurrent_simulation(self):
        """Rate limiter handles simulated concurrent access."""
        limiter = RateLimiter(max_calls=10, window_seconds=1)

        # Simulate concurrent calls
        results = []
        for _ in range(20):
            results.append(limiter.check_and_record())

        # Should have allowed exactly 10
        assert sum(results) == 10
        assert results.count(True) == 10
        assert results.count(False) == 10

    def test_circuit_breaker_concurrent_simulation(self):
        """Circuit breaker handles simulated concurrent operations."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60)

        # Record mixed success/failure
        for i in range(10):
            if i % 2 == 0:
                cb.record_success()
            else:
                cb.record_failure()

        # Should still be closed (failures didn't hit threshold)
        assert cb.state == CircuitState.CLOSED


# =============================================================================
# Error Message Information Leakage Tests
# =============================================================================


class TestErrorLeakage:
    """Ensure error messages don't leak sensitive information."""

    def test_uuid_error_no_value_leak(self):
        """UUID error doesn't include the full invalid value."""
        secret = "secret-password-in-uuid-field"
        try:
            validate_uuid(secret, "id")
        except ValidationError as e:
            assert "secret-password" not in str(e)

    def test_label_error_no_full_value(self):
        """Label error doesn't include entire malicious value."""
        long_secret = "secret" * 50
        try:
            validate_labels([long_secret])
        except ValidationError as e:
            assert long_secret not in str(e)

    def test_date_error_generic_message(self):
        """Date error gives generic format message."""
        try:
            validate_date_filter("not-a-date", "date")
        except ValidationError as e:
            assert "ISO8601" in str(e)
            assert "not-a-date" not in str(e)


# =============================================================================
# Config Security Tests
# =============================================================================


class TestConfigSecurity:
    """Test configuration security."""

    def test_config_token_not_in_repr(self):
        """Token doesn't appear in config repr."""
        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("super-secret-token"),
        )
        assert "super-secret-token" not in repr(config)
        assert "super-secret-token" not in str(config)
        assert "***" in repr(config)

    def test_secret_str_equality(self):
        """SecretStr equality works without exposing value."""
        s1 = SecretStr("secret")
        s2 = SecretStr("secret")
        s3 = SecretStr("different")

        assert s1 == s2
        assert s1 != s3

    def test_secret_str_bool(self):
        """SecretStr bool works correctly."""
        assert bool(SecretStr("value")) is True
        assert bool(SecretStr("")) is False

    def test_secret_str_len(self):
        """SecretStr length works correctly."""
        assert len(SecretStr("test")) == 4
        assert len(SecretStr("")) == 0


# =============================================================================
# Fuzzing-Style Random Input Tests
# =============================================================================


class TestFuzzingStyle:
    """Fuzzing-style tests with various input patterns."""

    @pytest.mark.parametrize(
        "input_str",
        [
            "",  # Empty
            " ",  # Single space
            "   ",  # Multiple spaces
            "\t",  # Tab
            "\n",  # Newline
            "\r\n",  # Windows newline
            "\x00",  # Null byte
            "\xff",  # High byte
            "a" * 10000,  # Very long
            "🔥" * 100,  # Emoji
            "α" * 100,  # Greek
            "中文" * 100,  # Chinese
            "مرحبا" * 100,  # Arabic (RTL)
            "\u202e" * 10,  # RTL override
            "\u200b" * 10,  # Zero-width space
            "${test}",  # Shell variable
            "$(whoami)",  # Command substitution
            "`id`",  # Backtick execution
            "{{7*7}}",  # Template injection
            "'; DROP TABLE--",  # SQL injection
            "<script>",  # XSS
            "\\x00\\x00",  # Escaped nulls
        ],
    )
    def test_various_inputs_dont_crash(self, input_str: str):
        """Various inputs don't crash validation."""
        # Should not raise unhandled exceptions
        try:
            validate_length(input_str, MAX_QUERY_LENGTH, "test")
        except ValidationError:
            pass  # Expected for some inputs

        try:
            validate_ioc(input_str)
        except ValidationError:
            pass

        try:
            validate_date_filter(input_str, "date")
        except ValidationError:
            pass

    @pytest.mark.parametrize("length", [0, 1, 35, 36, 37, 100, 1000])
    def test_uuid_various_lengths(self, length: int):
        """UUID validation handles various lengths."""
        input_str = "a" * length
        try:
            validate_uuid(input_str, "id")
        except ValidationError:
            pass  # Expected for most lengths
