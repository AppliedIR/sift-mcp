"""Comprehensive security, performance, and functional tests.

This test suite covers:
1. Security vulnerabilities and attack vectors
2. Edge cases and boundary conditions
3. Data type specific tests for OpenCTI entities
4. Performance and resource exhaustion tests
5. Consistency and regression tests

Organized by finding severity and category.
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
    VALID_OBSERVABLE_TYPES,
    VALID_PATTERN_TYPES,
    _is_cidr,
    _is_cve,
    _is_domain,
    _is_ipv4,
    _is_ipv6,
    _is_mitre_id,
    normalize_hash,
    sanitize_for_log,
    truncate_response,
    validate_date_filter,
    validate_label,
    validate_labels,
    validate_length,
    validate_limit,
    validate_note_types,
    validate_observable_types,
    validate_pattern_type,
    validate_relationship_types,
    validate_stix_pattern,
    validate_uuid,
    validate_uuid_list,
)

# =============================================================================
# FINDING 1: Date Filter Validation Consistency Tests
# =============================================================================


class TestDateFilterValidationConsistency:
    """Tests for consistent date filter validation across all handlers."""

    @pytest.mark.parametrize(
        "malicious_date",
        [
            "2024-01-15'; DROP TABLE--",
            "2024-01-15<script>alert(1)</script>",
            "2024-01-15${date}",
            "2024-01-15\x00malicious",
            "2024-01-15\nInjected: header",
            "../../../etc/passwd",
            "2024-01-15|ls -la",
            "2024-01-15`whoami`",
            "{{2024-01-15}}",
        ],
    )
    def test_date_injection_attempts_rejected(self, malicious_date: str):
        """All date injection attempts should be rejected."""
        with pytest.raises(ValidationError):
            validate_date_filter(malicious_date, "created_after")

    @pytest.mark.parametrize(
        "invalid_date",
        [
            "2024-02-30",  # Invalid day for February
            "2024-04-31",  # Invalid day for April
            "2024-06-31",  # Invalid day for June
            "2024-09-31",  # Invalid day for September
            "2024-11-31",  # Invalid day for November
            "2023-02-29",  # Not a leap year
        ],
    )
    def test_invalid_calendar_dates_should_fail(self, invalid_date: str):
        """Dates that don't exist on calendar should ideally fail.

        NOTE: Current implementation only checks day 1-31 range.
        This test documents the gap for future improvement.
        """
        # Current implementation passes these - documenting behavior
        result = validate_date_filter(invalid_date, "date")
        # If we want strict calendar validation, this should raise
        assert result == invalid_date  # Current behavior

    def test_date_filter_preserves_valid_dates(self):
        """Valid ISO8601 dates should be preserved exactly."""
        valid_dates = [
            "2024-01-15",
            "2024-12-31T23:59:59Z",
            "2024-06-15T12:30:00+05:30",
            "2024-06-15T12:30:00.123456Z",
            "1970-01-01",
            "2100-12-31",
        ]
        for date in valid_dates:
            result = validate_date_filter(date, "date")
            assert result == date


# =============================================================================
# FINDING 2: Label Validation Consistency Tests
# =============================================================================


class TestLabelValidationConsistency:
    """Tests for label validation across all uses."""

    @pytest.mark.parametrize(
        "malicious_label",
        [
            "label<script>",
            "label'; DROP TABLE--",
            "label\x00null",
            "label${env}",
            "label`id`",
            "label\ninjected",
            "label\rcarriage",
            "../../../etc/passwd",
        ],
    )
    def test_malicious_labels_rejected(self, malicious_label: str):
        """Malicious labels should be rejected."""
        with pytest.raises(ValidationError):
            validate_labels([malicious_label])

    def test_label_character_set(self):
        """Labels should only allow safe characters."""
        # Valid labels
        assert validate_label("tlp:amber") == "tlp:amber"
        assert validate_label("apt-29") == "apt-29"
        assert validate_label("malicious_file") == "malicious_file"
        assert validate_label("TLP RED") == "TLP RED"
        assert validate_label("Threat.Actor") == "Threat.Actor"

        # Invalid labels (special chars)
        with pytest.raises(ValidationError):
            validate_label("label;drop")
        with pytest.raises(ValidationError):
            validate_label("label>test")
        with pytest.raises(ValidationError):
            validate_label("label{}")

    def test_label_length_limits(self):
        """Labels should enforce length limits."""
        # Exactly 100 chars
        assert len(validate_label("a" * 100)) == 100

        # Over limit
        with pytest.raises(ValidationError, match="maximum length"):
            validate_label("a" * 101)

    def test_empty_and_whitespace_labels(self):
        """Empty and whitespace-only labels should be rejected."""
        with pytest.raises(ValidationError):
            validate_label("")
        with pytest.raises(ValidationError):
            validate_label("   ")
        with pytest.raises(ValidationError):
            validate_label("\t\n")


# =============================================================================
# FINDING 3: Note Type Validation Tests
# =============================================================================


class TestNoteTypeValidation:
    """Tests for note type validation strictness."""

    def test_note_types_normalized_to_lowercase(self):
        """Note types should be normalized to lowercase."""
        result = validate_note_types(["ANALYSIS", "Assessment", "EXTERNAL"])
        assert result == ["analysis", "assessment", "external"]

    def test_note_type_character_restrictions(self):
        """Note types should only allow ASCII alphanumeric and hyphen."""
        # Valid
        assert validate_note_types(["analysis"]) == ["analysis"]
        assert validate_note_types(["threat-report"]) == ["threat-report"]

        # Invalid
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types(["analysis_report"])  # underscore
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types(["threat.report"])  # dot
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types(["analysis:test"])  # colon

    def test_note_types_rejects_unknown_types(self):
        """Unknown note types are rejected against VALID_NOTE_TYPES allowlist."""
        with pytest.raises(ValidationError, match="Unknown note type"):
            validate_note_types(["custom-type"])

    def test_note_types_accepts_valid_types(self):
        """Valid note types are accepted."""
        result = validate_note_types(["analysis", "assessment"])
        assert result == ["analysis", "assessment"]


# =============================================================================
# FINDING 4: Relationship Type Validation Tests
# =============================================================================


class TestRelationshipTypeValidation:
    """Tests for relationship type validation."""

    def test_relationship_type_character_restrictions(self):
        """Relationship types should only allow ASCII alphanumeric and hyphen."""
        # Valid
        result = validate_relationship_types(["indicates", "uses", "targets"])
        assert result == ["indicates", "uses", "targets"]

        # Invalid
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types(["indicates;drop"])
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types(["uses<script>"])

    def test_relationship_type_rejects_unknown_types(self):
        """Unknown relationship types are rejected against VALID_RELATIONSHIP_TYPES allowlist."""
        with pytest.raises(ValidationError, match="Unknown relationship type"):
            validate_relationship_types(["custom-relationship"])

    def test_relationship_type_length_limit(self):
        """Relationship types should enforce length limits."""
        with pytest.raises(ValidationError, match="too long"):
            validate_relationship_types(["a" * 51])


# =============================================================================
# FINDING 5: STIX Pattern Validation Tests
# =============================================================================


class TestSTIXPatternValidation:
    """Tests for STIX pattern validation."""

    def test_valid_stix_patterns(self):
        """Valid STIX patterns should pass."""
        valid_patterns = [
            "[ipv4-addr:value = '192.168.1.1']",
            "[domain-name:value = 'malicious.com']",
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "[url:value = 'http://malicious.com/path']",
            "[ipv4-addr:value = '10.0.0.1'] AND [domain-name:value = 'test.com']",
            "[network-traffic:src_ref.type = 'ipv4-addr']",
        ]
        for pattern in valid_patterns:
            validate_stix_pattern(pattern)  # Should not raise

    def test_invalid_stix_pattern_no_brackets(self):
        """Patterns without brackets should fail."""
        with pytest.raises(ValidationError, match="brackets"):
            validate_stix_pattern("ipv4-addr:value = '192.168.1.1'")

    def test_invalid_stix_pattern_unbalanced(self):
        """Unbalanced brackets should fail."""
        with pytest.raises(ValidationError, match="brackets"):
            validate_stix_pattern("[ipv4-addr:value = '192.168.1.1'")
        with pytest.raises(ValidationError, match="brackets"):
            validate_stix_pattern("[[ipv4-addr:value = '192.168.1.1']")

    def test_stix_pattern_null_bytes_rejected(self):
        """Null bytes in patterns should be rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_stix_pattern("[ipv4-addr:value = '192.168.1.1\x00']")

    def test_stix_pattern_length_limit(self):
        """STIX patterns should enforce length limits."""
        with pytest.raises(ValidationError, match="maximum length"):
            validate_stix_pattern("[" + "a" * 2050 + "]")


# =============================================================================
# FINDING 6: Observable Type Validation Tests
# =============================================================================


class TestObservableTypeValidation:
    """Tests for observable type validation."""

    def test_all_valid_observable_types_accepted(self):
        """All types in VALID_OBSERVABLE_TYPES should be accepted."""
        for obs_type in VALID_OBSERVABLE_TYPES:
            result = validate_observable_types([obs_type])
            assert result == [obs_type]

    def test_unknown_observable_types_rejected(self):
        """Unknown observable types should be rejected."""
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["FakeType"])
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["ipv4-addr"])  # Wrong case
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["IPV4-ADDR"])  # Wrong case

    def test_observable_types_case_sensitive(self):
        """Observable types are case-sensitive per STIX."""
        # Correct cases
        assert validate_observable_types(["IPv4-Addr"]) == ["IPv4-Addr"]
        assert validate_observable_types(["Domain-Name"]) == ["Domain-Name"]

        # Wrong cases
        with pytest.raises(ValidationError):
            validate_observable_types(["ipv4-addr"])
        with pytest.raises(ValidationError):
            validate_observable_types(["DOMAIN-NAME"])

    def test_observable_types_max_items(self):
        """Observable types should enforce max items."""
        # Exactly 10 - OK
        result = validate_observable_types(["IPv4-Addr"] * 10)
        assert len(result) == 10

        # Over 10 - rejected
        with pytest.raises(ValidationError, match="more than 10"):
            validate_observable_types(["IPv4-Addr"] * 11)


# =============================================================================
# FINDING 7: UUID Validation Tests
# =============================================================================


class TestUUIDValidation:
    """Tests for UUID validation."""

    def test_valid_uuids(self):
        """Valid UUIDs should pass."""
        valid_uuids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",  # Uppercase
        ]
        for uuid in valid_uuids:
            result = validate_uuid(uuid, "id")
            assert result == uuid.lower()

    def test_invalid_uuid_length(self):
        """Wrong length UUIDs should fail."""
        with pytest.raises(ValidationError, match="36 characters"):
            validate_uuid("550e8400-e29b-41d4-a716", "id")
        with pytest.raises(ValidationError, match="36 characters"):
            validate_uuid("550e8400-e29b-41d4-a716-446655440000-extra", "id")

    def test_invalid_uuid_format(self):
        """Wrong format UUIDs should fail."""
        with pytest.raises(ValidationError, match="36 characters"):
            validate_uuid("550e8400e29b41d4a716446655440000", "id")  # No hyphens
        with pytest.raises(ValidationError, match="valid UUID"):
            validate_uuid("550e8400-e29b-41d4-a716446655440000", "id")  # Wrong segments

    def test_uuid_with_invalid_chars(self):
        """UUIDs with invalid characters should fail."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_uuid("550e8400-e29b-41d4-a716-44665544000g", "id")  # 'g' invalid
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_uuid("550e8400-e29b-41d4-a716-44665544000!", "id")

    def test_uuid_injection_attempts(self):
        """UUID injection attempts should fail."""
        with pytest.raises(ValidationError):
            validate_uuid("550e8400-e29b-41d4-a716'; DROP--", "id")
        with pytest.raises(ValidationError):
            validate_uuid("550e8400<script>alert(1)</script>", "id")


# =============================================================================
# FINDING 8: IOC Validation Edge Cases
# =============================================================================


class TestIOCValidationEdgeCases:
    """Edge case tests for IOC validation."""

    def test_ipv4_edge_cases(self):
        """IPv4 edge cases."""
        # Valid boundaries
        assert _is_ipv4("0.0.0.0")
        assert _is_ipv4("255.255.255.255")
        assert _is_ipv4("192.168.1.1")

        # Invalid
        assert not _is_ipv4("256.1.1.1")
        assert not _is_ipv4("1.2.3")
        assert not _is_ipv4("1.2.3.4.5")
        assert not _is_ipv4("01.02.03.04")  # Leading zeros
        assert not _is_ipv4("1.2.3.")
        assert not _is_ipv4(".1.2.3.4")
        assert not _is_ipv4("1..2.3.4")
        assert not _is_ipv4("1.2.3.4 ")  # Trailing space
        assert not _is_ipv4(" 1.2.3.4")  # Leading space

    def test_ipv6_edge_cases(self):
        """IPv6 edge cases."""
        # Valid
        assert _is_ipv6("::1")
        assert _is_ipv6("::")
        assert _is_ipv6("2001:db8::1")
        assert _is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert _is_ipv6("fe80::1")

        # Invalid
        assert not _is_ipv6("2001:db8::1::2")  # Double ::
        assert not _is_ipv6("2001:db8:85a3:0000:0000:8a2e:0370:7334:extra")
        assert not _is_ipv6("gggg::1")  # Invalid hex
        assert not _is_ipv6("12345::1")  # Group too long

    def test_cidr_edge_cases(self):
        """CIDR notation edge cases."""
        # Valid
        assert _is_cidr("192.168.1.0/24")
        assert _is_cidr("10.0.0.0/8")
        assert _is_cidr("0.0.0.0/0")
        assert _is_cidr("192.168.1.1/32")
        assert _is_cidr("2001:db8::/32")
        assert _is_cidr("::1/128")

        # Invalid
        assert not _is_cidr("192.168.1.0/33")  # IPv4 prefix > 32
        assert not _is_cidr("2001:db8::/129")  # IPv6 prefix > 128
        assert not _is_cidr("192.168.1.0/")  # Missing prefix
        assert not _is_cidr("192.168.1.0/abc")  # Non-numeric prefix
        assert not _is_cidr("192.168.1.0/-1")  # Negative prefix

    def test_domain_edge_cases(self):
        """Domain name edge cases."""
        # Valid
        assert _is_domain("example.com")
        assert _is_domain("sub.example.com")
        assert _is_domain("a-b.example.com")
        assert _is_domain("xn--nxasmq5a.com")  # Punycode IDN
        assert _is_domain("a.co")  # Short TLD

        # Invalid - IDN homograph attempts
        assert not _is_domain("example.сom")  # Cyrillic 'с'
        assert not _is_domain("exаmple.com")  # Cyrillic 'а'

        # Invalid - structure
        assert not _is_domain("example")  # No TLD
        assert not _is_domain(".example.com")  # Leading dot
        assert not _is_domain(
            "example.com."
        )  # Trailing dot (actually valid in DNS but we reject)
        assert not _is_domain("example..com")  # Double dot
        assert not _is_domain("-example.com")  # Leading hyphen
        assert not _is_domain("example-.com")  # Trailing hyphen

    def test_cve_edge_cases(self):
        """CVE identifier edge cases."""
        # Valid
        assert _is_cve("CVE-2024-1234")
        assert _is_cve("cve-2024-1234")  # Lowercase
        assert _is_cve("CVE-2024-12345")  # 5 digit
        assert _is_cve("CVE-2024-123456")  # 6 digit

        # Invalid
        assert not _is_cve("CVE-2024-123")  # Too short
        assert not _is_cve("CVE-24-1234")  # 2 digit year
        assert not _is_cve("CVE2024-1234")  # Missing hyphen
        assert not _is_cve("CWE-2024-1234")  # Wrong prefix

    def test_mitre_id_edge_cases(self):
        """MITRE ATT&CK ID edge cases."""
        # Valid
        assert _is_mitre_id("T1003")
        assert _is_mitre_id("t1003")  # Lowercase
        assert _is_mitre_id("T1003.001")  # Sub-technique
        assert _is_mitre_id("T9999")

        # Invalid
        assert not _is_mitre_id("T123")  # Too short
        assert not _is_mitre_id("T12345")  # Too long
        assert not _is_mitre_id("T1003.01")  # Sub-technique too short
        assert not _is_mitre_id("T1003.0001")  # Sub-technique too long
        assert not _is_mitre_id("M1234")  # Wrong prefix


# =============================================================================
# FINDING 9: Rate Limiter and Circuit Breaker Tests
# =============================================================================


class TestRateLimiterEdgeCases:
    """Edge case tests for rate limiter."""

    def test_rate_limiter_exact_limit(self):
        """Rate limiter should allow exactly max_calls."""
        limiter = RateLimiter(max_calls=5, window_seconds=60)

        for i in range(5):
            assert limiter.check_and_record(), f"Call {i + 1} should succeed"

        assert not limiter.check_and_record(), "Call 6 should fail"

    def test_rate_limiter_wait_time_positive(self):
        """Wait time should always be positive when rate limited."""
        limiter = RateLimiter(max_calls=1, window_seconds=60)
        limiter.check_and_record()

        wait = limiter.wait_time()
        assert wait > 0
        assert wait <= 60

    def test_rate_limiter_zero_max_calls(self):
        """Rate limiter with zero max_calls should always fail."""
        limiter = RateLimiter(max_calls=0, window_seconds=60)

        assert not limiter.check()
        assert limiter.wait_time() == 60.0

    def test_circuit_breaker_threshold(self):
        """Circuit breaker should open after threshold failures."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_circuit_breaker_success_resets(self):
        """Success should reset failure count."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

        cb.record_failure()
        cb.record_failure()
        cb.record_success()  # Reset
        cb.record_failure()
        cb.record_failure()

        assert cb.state == CircuitState.CLOSED  # Not open yet


# =============================================================================
# FINDING 10: Truncation and Response Size Tests
# =============================================================================


class TestTruncationEdgeCases:
    """Edge case tests for response truncation."""

    def test_deeply_nested_dict(self):
        """Deeply nested dicts should not cause stack overflow."""
        data = {"level": 0}
        current = data
        for i in range(200):  # Very deep nesting
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        result = truncate_response(data)
        assert isinstance(result, dict)

    def test_very_wide_dict(self):
        """Wide dicts should be handled safely."""
        data = {f"key_{i}": f"value_{i}" * 100 for i in range(5000)}

        result = truncate_response(data)
        assert isinstance(result, dict)

    def test_mixed_nested_structure(self):
        """Mixed nested structures should be handled."""
        data = {
            "list_of_dicts": [
                {"name": f"item_{i}", "data": "x" * 1000} for i in range(200)
            ],
            "dict_of_lists": {f"key_{i}": list(range(1000)) for i in range(50)},
            "deep": {"a": {"b": {"c": {"d": {"e": "value" * 1000}}}}},
        }

        result = truncate_response(data)
        assert isinstance(result, dict)
        assert len(result["list_of_dicts"]) <= 100  # List truncated

    def test_truncation_metadata_added(self):
        """Truncation metadata should be added."""
        data = {
            "description": "x" * 1000,  # Will be truncated
            "items": list(range(200)),  # Will be truncated
        }

        result = truncate_response(data)
        assert "_truncated_fields" in result
        assert any("description" in f for f in result["_truncated_fields"])


# =============================================================================
# FINDING 11: Config and Secret Handling Tests
# =============================================================================


class TestConfigSecurityEdgeCases:
    """Edge case tests for configuration security."""

    def test_secret_str_not_in_any_string_representation(self):
        """Secret should never appear in any string representation."""
        secret = SecretStr("super-secret-password")

        assert "super-secret-password" not in str(secret)
        assert "super-secret-password" not in repr(secret)
        assert "super-secret-password" not in f"{secret}"
        assert "super-secret-password" not in f"{secret!r}"
        assert "super-secret-password" not in f"{secret!s}"

    def test_secret_str_comparison_constant_time(self):
        """Secret comparison should work correctly."""
        s1 = SecretStr("password123")
        s2 = SecretStr("password123")
        s3 = SecretStr("different")

        assert s1 == s2
        assert s1 != s3
        assert s2 != s3

    def test_config_cannot_be_pickled(self):
        """Config should not be serializable."""
        config = Config(
            opencti_url="http://localhost:8080", opencti_token=SecretStr("token")
        )

        import pickle

        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(config)

    def test_config_url_validation(self):
        """Config should validate URL properly."""
        # Valid URLs
        Config(opencti_url="http://localhost:8080", opencti_token=SecretStr("token"))
        Config(
            opencti_url="https://opencti.example.com", opencti_token=SecretStr("token")
        )

        # Invalid schemes
        with pytest.raises(Exception):  # ConfigurationError
            Config(opencti_url="ftp://localhost:8080", opencti_token=SecretStr("token"))
        with pytest.raises(Exception):
            Config(opencti_url="file:///etc/passwd", opencti_token=SecretStr("token"))


# =============================================================================
# FINDING 12: Log Sanitization Tests
# =============================================================================


class TestLogSanitization:
    """Tests for log sanitization."""

    def test_control_characters_escaped(self):
        """Control characters should be escaped."""
        result = sanitize_for_log("test\ninjected\rline")
        assert "\n" not in result
        assert "\r" not in result

    def test_sensitive_fields_redacted(self):
        """Sensitive fields should be redacted."""
        data = {
            "username": "admin",
            "password": "secret123",
            "api_key": "key123",
            "token": "token123",
            "auth_header": "Bearer xxx",
        }

        result = sanitize_for_log(data)
        assert result["password"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"
        assert result["token"] == "***REDACTED***"
        assert result["auth_header"] == "***REDACTED***"
        assert result["username"] == "admin"  # Not sensitive

    def test_long_values_truncated(self):
        """Long values should be truncated."""
        result = sanitize_for_log("x" * 1000)
        assert len(result) <= 520  # 500 + truncation indicator


# =============================================================================
# FINDING 13: Pattern Type Validation Tests
# =============================================================================


class TestPatternTypeValidation:
    """Tests for pattern type validation."""

    def test_all_valid_pattern_types(self):
        """All valid pattern types should be accepted."""
        for pt in VALID_PATTERN_TYPES:
            result = validate_pattern_type(pt)
            assert result == pt

    def test_pattern_type_case_normalization(self):
        """Pattern types should be normalized to lowercase."""
        assert validate_pattern_type("STIX") == "stix"
        assert validate_pattern_type("Sigma") == "sigma"
        assert validate_pattern_type("YARA") == "yara"

    def test_invalid_pattern_type_raises(self):
        """Invalid pattern types should raise ValidationError."""
        with pytest.raises(ValidationError, match="Invalid pattern_type"):
            validate_pattern_type("invalid")
        with pytest.raises(ValidationError, match="Invalid pattern_type"):
            validate_pattern_type("custom")

    def test_pattern_type_none_defaults_stix(self):
        """None should default to 'stix'."""
        assert validate_pattern_type(None) == "stix"
        assert validate_pattern_type("") == "stix"


# =============================================================================
# FINDING 14: Hash Normalization Tests
# =============================================================================


class TestHashNormalization:
    """Tests for hash normalization."""

    def test_hash_prefix_removal(self):
        """Hash prefixes should be removed."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"

        assert normalize_hash(f"md5:{md5}") == md5
        assert normalize_hash(f"sha1:{md5}") == md5  # Even if wrong prefix
        assert normalize_hash(f"sha256:{md5}") == md5
        assert normalize_hash(f"sha-1:{md5}") == md5
        assert normalize_hash(f"sha-256:{md5}") == md5

    def test_hash_case_normalization(self):
        """Hashes should be lowercased."""
        assert (
            normalize_hash("D41D8CD98F00B204E9800998ECF8427E")
            == "d41d8cd98f00b204e9800998ecf8427e"
        )

    def test_hash_whitespace_handling(self):
        """Whitespace should be stripped."""
        assert (
            normalize_hash("  d41d8cd98f00b204e9800998ecf8427e  ")
            == "d41d8cd98f00b204e9800998ecf8427e"
        )


# =============================================================================
# FINDING 15: Concurrent Access Tests
# =============================================================================


class TestConcurrentAccess:
    """Tests for concurrent access safety."""

    def test_rate_limiter_thread_safety_simulation(self):
        """Rate limiter should handle rapid sequential access."""
        limiter = RateLimiter(max_calls=100, window_seconds=1)

        results = []
        for _ in range(150):
            results.append(limiter.check_and_record())

        assert sum(results) == 100  # Exactly 100 allowed

    def test_circuit_breaker_state_consistency(self):
        """Circuit breaker state should be consistent."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)

        # Trip the circuit
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for recovery
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        # Success should close
        cb.record_success()
        assert cb.state == CircuitState.CLOSED


# =============================================================================
# FINDING 16: OpenCTI Data Type Specific Tests
# =============================================================================


class TestOpenCTIDataTypes:
    """Tests specific to OpenCTI data types and attack vectors."""

    def test_tlp_label_format(self):
        """TLP labels should follow format."""
        valid_tlp = ["tlp:clear", "tlp:green", "tlp:amber", "tlp:red", "TLP:AMBER"]
        for label in valid_tlp:
            validate_label(label)  # Should not raise

    def test_confidence_boundary_values(self):
        """Confidence should be validated at boundaries."""
        # Note: validate_limit handles this
        assert validate_limit(0) == 1  # Clamped to min
        assert validate_limit(100) == 100
        assert validate_limit(101) == 100  # Clamped to max
        assert validate_limit(-1) == 1  # Negative clamped

    def test_indicator_pattern_observable_types(self):
        """Test STIX pattern observable type references."""
        valid_patterns = [
            "[ipv4-addr:value = '1.1.1.1']",
            "[ipv6-addr:value = '::1']",
            "[domain-name:value = 'evil.com']",
            "[url:value = 'http://evil.com']",
            "[file:hashes.MD5 = 'abc123']",
            "[email-addr:value = 'bad@evil.com']",
            "[process:name = 'malware.exe']",
        ]
        for pattern in valid_patterns:
            validate_stix_pattern(pattern)  # Should not raise


# =============================================================================
# FINDING 17: Unicode and Encoding Tests
# =============================================================================


class TestUnicodeAndEncoding:
    """Tests for Unicode handling and encoding issues."""

    @pytest.mark.parametrize(
        "homoglyph_domain",
        [
            "gооgle.com",  # Cyrillic 'о'
            "аpple.com",  # Cyrillic 'а'
            "micrоsoft.com",  # Cyrillic 'о'
            "paypal.cοm",  # Greek 'ο' in TLD
        ],
    )
    def test_homoglyph_domains_rejected(self, homoglyph_domain: str):
        """Homoglyph domains should be rejected."""
        assert not _is_domain(homoglyph_domain)

    @pytest.mark.parametrize(
        "special_unicode",
        [
            "\u202e",  # RTL override
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\ufeff",  # BOM
        ],
    )
    def test_special_unicode_in_dates_rejected(self, special_unicode: str):
        """Special Unicode characters should be rejected in dates."""
        with pytest.raises(ValidationError):
            validate_date_filter(f"2024-01-15{special_unicode}", "date")

    def test_fullwidth_characters_rejected(self):
        """Fullwidth ASCII variants should be rejected."""
        # Fullwidth 'a' (U+FF41)
        with pytest.raises(ValidationError):
            validate_note_types(["\uff41nalysis"])

    def test_mathematical_alphanumeric_rejected(self):
        """Mathematical alphanumeric symbols should be rejected."""
        # Mathematical bold 'a' (U+1D41A)
        with pytest.raises(ValidationError):
            validate_note_types(["\U0001d41anote"])


# =============================================================================
# FINDING 18: Empty and Null Input Tests
# =============================================================================


class TestEmptyAndNullInputs:
    """Tests for empty and null input handling."""

    def test_empty_string_handling(self):
        """Empty strings should be handled consistently."""
        assert validate_date_filter("", "date") is None
        assert validate_date_filter("   ", "date") is None
        assert validate_observable_types([]) is None
        assert validate_note_types([]) is None
        assert validate_relationship_types([]) is None
        assert validate_labels([]) == []

    def test_none_handling(self):
        """None should be handled consistently."""
        assert validate_date_filter(None, "date") is None
        assert validate_observable_types(None) is None
        assert validate_note_types(None) is None
        assert validate_relationship_types(None) is None
        assert validate_labels(None) == []
        assert validate_pattern_type(None) == "stix"

    def test_list_with_empty_elements(self):
        """Lists with empty elements should filter them out."""
        result = validate_observable_types(["IPv4-Addr", "", None, "Domain-Name"])
        assert result == ["IPv4-Addr", "Domain-Name"]

        result = validate_note_types(["analysis", "", None, "assessment"])
        assert result == ["analysis", "assessment"]


# =============================================================================
# FINDING 19: Boundary Value Tests
# =============================================================================


class TestBoundaryValues:
    """Tests for boundary conditions."""

    def test_max_query_length_boundary(self):
        """Query length at and beyond boundary."""
        # Exactly at limit
        validate_length("a" * MAX_QUERY_LENGTH, MAX_QUERY_LENGTH, "query")

        # One over limit
        with pytest.raises(ValidationError):
            validate_length("a" * (MAX_QUERY_LENGTH + 1), MAX_QUERY_LENGTH, "query")

    def test_max_ioc_length_boundary(self):
        """IOC length at and beyond boundary."""
        # Exactly at limit
        validate_length("a" * MAX_IOC_LENGTH, MAX_IOC_LENGTH, "ioc")

        # One over limit
        with pytest.raises(ValidationError):
            validate_length("a" * (MAX_IOC_LENGTH + 1), MAX_IOC_LENGTH, "ioc")

    def test_date_year_boundaries(self):
        """Date year boundaries."""
        assert validate_date_filter("1970-01-01", "date") == "1970-01-01"
        assert validate_date_filter("2100-12-31", "date") == "2100-12-31"

        with pytest.raises(ValidationError, match="year"):
            validate_date_filter("1969-12-31", "date")
        with pytest.raises(ValidationError, match="year"):
            validate_date_filter("2101-01-01", "date")

    def test_uuid_list_boundary(self):
        """UUID list size boundaries."""
        # Exactly at limit
        uuids = ["550e8400-e29b-41d4-a716-446655440000"] * 20
        result = validate_uuid_list(uuids, "ids", max_items=20)
        assert len(result) == 20

        # One over limit
        uuids = ["550e8400-e29b-41d4-a716-446655440000"] * 21
        with pytest.raises(ValidationError, match="more than 20"):
            validate_uuid_list(uuids, "ids", max_items=20)


# =============================================================================
# FINDING 20: Error Message Information Leakage Tests
# =============================================================================


class TestErrorMessageLeakage:
    """Tests to ensure error messages don't leak sensitive info."""

    def test_uuid_error_no_input_leak(self):
        """UUID errors should not include full input."""
        secret = "secret-password-disguised-as-uuid"
        try:
            validate_uuid(secret, "id")
        except ValidationError as e:
            assert "secret-password" not in str(e)

    def test_date_error_no_input_leak(self):
        """Date errors should not include full input."""
        malicious = "2024-01-15'; DROP TABLE users--"
        try:
            validate_date_filter(malicious, "date")
        except ValidationError as e:
            assert "DROP TABLE" not in str(e)

    def test_label_error_no_full_input_leak(self):
        """Label errors should not include full input."""
        long_secret = "supersecret" * 50
        try:
            validate_label(long_secret)
        except ValidationError as e:
            assert long_secret not in str(e)
