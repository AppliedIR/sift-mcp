"""High-threat security tests for public deployment.

These tests verify security controls against sophisticated attackers.
They should NEVER be skipped or disabled in CI/CD.

Threat Model:
- Attackers have full knowledge of the codebase
- Attackers control MCP client input
- Attackers may attempt injection, DoS, and information disclosure
"""

from __future__ import annotations

import pytest
from opencti_mcp.errors import ValidationError
from opencti_mcp.validation import (
    MAX_QUERY_LENGTH,
    validate_ioc,
    validate_label,
    validate_labels,
    validate_length,
    validate_relationship_types,
    validate_stix_pattern,
    validate_uuid,
    validate_uuid_list,
)

# =============================================================================
# UUID Injection Tests
# =============================================================================


class TestUUIDInjection:
    """Test UUID validation against injection attempts."""

    def test_valid_uuid(self):
        """Valid UUIDs are accepted."""
        valid = "550e8400-e29b-41d4-a716-446655440000"
        result = validate_uuid(valid, "entity_id")
        assert result == valid.lower()

    def test_empty_uuid_rejected(self):
        """Empty UUID is rejected."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_uuid("", "entity_id")

    def test_short_uuid_rejected(self):
        """Short UUID is rejected."""
        with pytest.raises(ValidationError, match="36 characters"):
            validate_uuid("550e8400-e29b-41d4-a716", "entity_id")

    def test_long_uuid_rejected(self):
        """Long UUID is rejected (potential injection)."""
        with pytest.raises(ValidationError, match="36 characters"):
            validate_uuid("550e8400-e29b-41d4-a716-446655440000-extra", "entity_id")

    @pytest.mark.parametrize(
        "malicious",
        [
            "550e8400-e29b-41d4-a716-44665544000'",  # SQL injection
            "550e8400-e29b-41d4-a716-446655440000;",  # Command separator
            "550e8400-e29b-41d4-a716-44665544000\x00",  # Null byte
            "550e8400-e29b-41d4-a716-446655440000\n",  # Newline
            "550e8400-e29b-41d4-a716-446655440g00",  # Invalid hex
            "../../../etc/passwd/446655440000",  # Path traversal
            "${entity_id}-446655440000-446655",  # Template injection
            "{{7*7}}-e29b-41d4-a716-446655440000",  # SSTI
        ],
    )
    def test_injection_attempts_rejected(self, malicious: str):
        """Injection attempts are rejected."""
        with pytest.raises(ValidationError):
            validate_uuid(malicious, "entity_id")

    def test_wrong_format_rejected(self):
        """Wrong UUID format is rejected."""
        with pytest.raises(ValidationError, match="36 characters"):
            validate_uuid(
                "550e8400e29b41d4a716446655440000", "entity_id"
            )  # No hyphens (32 chars)

    def test_uuid_list_validation(self):
        """UUID list validation works."""
        valid_list = [
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ]
        result = validate_uuid_list(valid_list, "entity_ids")
        assert len(result) == 2
        assert all(uuid.islower() for uuid in result)

    def test_uuid_list_max_items(self):
        """UUID list max items is enforced."""
        many_uuids = ["550e8400-e29b-41d4-a716-446655440000"] * 25
        with pytest.raises(ValidationError, match="more than 20"):
            validate_uuid_list(many_uuids, "entity_ids")


# =============================================================================
# Label Injection Tests
# =============================================================================


class TestLabelInjection:
    """Test label validation against injection attempts."""

    def test_valid_label(self):
        """Valid labels are accepted."""
        assert validate_label("tlp:amber") == "tlp:amber"
        assert validate_label("malicious") == "malicious"
        assert validate_label("apt-29") == "apt-29"

    def test_empty_label_rejected(self):
        """Empty labels are rejected."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_label("")

    def test_long_label_rejected(self):
        """Long labels are rejected."""
        with pytest.raises(ValidationError, match="100 characters"):
            validate_label("x" * 101)

    @pytest.mark.parametrize(
        "malicious",
        [
            "label'; DROP TABLE indicators;--",  # SQL injection
            "label<script>alert(1)</script>",  # XSS
            "label\x00evil",  # Null byte
            "label$(whoami)",  # Command injection
            "label`id`",  # Command injection
            "label\n\rHTTP/1.1 200 OK",  # HTTP response splitting
        ],
    )
    def test_injection_in_labels_rejected(self, malicious: str):
        """Injection attempts in labels are rejected."""
        with pytest.raises(ValidationError):
            validate_label(malicious)

    def test_label_list_max_items(self):
        """Label list max items is enforced."""
        many_labels = ["label"] * 15
        with pytest.raises(ValidationError, match="more than 10"):
            validate_labels(many_labels)


# =============================================================================
# STIX Pattern Injection Tests
# =============================================================================


class TestSTIXPatternInjection:
    """Test STIX pattern validation against injection attempts."""

    def test_valid_pattern(self):
        """Valid STIX patterns are accepted."""
        validate_stix_pattern("[ipv4-addr:value = '192.168.1.1']")
        validate_stix_pattern("[domain-name:value = 'evil.com']")
        validate_stix_pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")

    def test_empty_pattern_rejected(self):
        """Empty patterns are rejected."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_stix_pattern("")

    def test_pattern_without_brackets_rejected(self):
        """Patterns without brackets are rejected."""
        with pytest.raises(ValidationError, match="enclosed in brackets"):
            validate_stix_pattern("ipv4-addr:value = '192.168.1.1'")

    def test_long_pattern_rejected(self):
        """Long patterns are rejected."""
        with pytest.raises(ValidationError, match="maximum length"):
            validate_stix_pattern("[" + "x" * 3000 + "]")

    def test_null_byte_in_pattern_rejected(self):
        """Null bytes in patterns are rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_stix_pattern("[ipv4-addr:value = '192.168.1.1\x00']")

    def test_unbalanced_brackets_rejected(self):
        """Unbalanced brackets are rejected."""
        # Missing closing bracket
        with pytest.raises(ValidationError, match="enclosed in brackets"):
            validate_stix_pattern("[ipv4-addr:value = '192.168.1.1'")
        # Extra opening bracket - detected as unbalanced
        with pytest.raises(ValidationError, match="unbalanced"):
            validate_stix_pattern("[[ipv4-addr:value = '192.168.1.1']")


# =============================================================================
# Relationship Type Injection Tests
# =============================================================================


class TestRelationshipTypeInjection:
    """Test relationship type validation."""

    def test_valid_types(self):
        """Valid relationship types are accepted."""
        result = validate_relationship_types(["indicates", "uses", "targets"])
        assert result == ["indicates", "uses", "targets"]

    def test_normalized_to_lowercase(self):
        """Types are normalized to lowercase."""
        result = validate_relationship_types(["INDICATES", "Uses"])
        assert result == ["indicates", "uses"]

    def test_max_types_enforced(self):
        """Max relationship types is enforced."""
        many_types = ["type"] * 25
        with pytest.raises(ValidationError, match="more than 20"):
            validate_relationship_types(many_types)

    def test_long_type_rejected(self):
        """Long relationship types are rejected."""
        with pytest.raises(ValidationError, match="too long"):
            validate_relationship_types(["x" * 100])

    @pytest.mark.parametrize(
        "malicious",
        [
            "indicates'; DROP TABLE--",
            "uses<script>",
            "targets\x00evil",
        ],
    )
    def test_injection_in_types_rejected(self, malicious: str):
        """Injection in relationship types is rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types([malicious])


# =============================================================================
# ReDoS Prevention Tests
# =============================================================================


class TestReDoSPrevention:
    """Test that regex-based validation is not vulnerable to ReDoS."""

    def test_long_input_fails_fast_on_length(self):
        """Long inputs fail on length before regex."""
        import time

        # Crafted to be slow if regex runs first
        evil = "a" * (MAX_QUERY_LENGTH + 10000)

        start = time.time()
        with pytest.raises(ValidationError):
            validate_length(evil, MAX_QUERY_LENGTH, "query")
        elapsed = time.time() - start

        # Should fail in milliseconds, not seconds
        assert elapsed < 0.1, f"Length check took {elapsed}s - possible ReDoS"

    def test_ioc_validation_length_first(self):
        """IOC validation checks length before pattern matching."""
        import time

        # Crafted to potentially cause backtracking
        evil = "a" * 5000 + "@" + "b" * 5000 + ".com"

        start = time.time()
        with pytest.raises(ValidationError):
            validate_ioc(evil)
        elapsed = time.time() - start

        # Should fail fast
        assert elapsed < 0.1, f"IOC validation took {elapsed}s - possible ReDoS"


# =============================================================================
# Information Disclosure Tests
# =============================================================================


class TestInformationDisclosure:
    """Test that errors don't leak sensitive information."""

    def test_uuid_error_doesnt_leak_value(self):
        """UUID validation errors don't include the malicious value."""
        malicious = "secret-password-in-uuid-field"
        try:
            validate_uuid(malicious, "entity_id")
        except ValidationError as e:
            assert "secret-password" not in str(e)
            assert "entity_id" in str(e)

    def test_label_error_doesnt_leak_full_value(self):
        """Label validation errors don't leak full malicious value."""
        malicious = "secret" * 100
        try:
            validate_label(malicious)
        except ValidationError as e:
            # Should mention length, not include full value
            assert "100 characters" in str(e)
            # Should not include entire malicious string
            assert malicious not in str(e)


# =============================================================================
# Boundary Condition Tests
# =============================================================================


class TestBoundaryConditions:
    """Test edge cases and boundary conditions."""

    def test_uuid_exactly_36_chars_valid(self):
        """UUID with exactly 36 chars is valid."""
        valid = "00000000-0000-0000-0000-000000000000"
        assert len(valid) == 36
        result = validate_uuid(valid, "id")
        assert result == valid

    def test_label_exactly_100_chars_valid(self):
        """Label with exactly 100 chars is valid."""
        valid = "a" * 100
        result = validate_label(valid)
        assert result == valid

    def test_label_101_chars_rejected(self):
        """Label with 101 chars is rejected."""
        with pytest.raises(ValidationError):
            validate_label("a" * 101)

    def test_empty_lists_handled(self):
        """Empty lists are handled safely."""
        assert validate_uuid_list(None, "ids") == []
        assert validate_uuid_list([], "ids") == []
        assert validate_labels(None) == []
        assert validate_labels([]) == []
        assert validate_relationship_types(None) is None
        assert validate_relationship_types([]) is None


# =============================================================================
# Unicode Security Tests
# =============================================================================


class TestUnicodeSecurity:
    """Test handling of Unicode edge cases."""

    def test_homoglyph_in_uuid_rejected(self):
        """Homoglyph characters in UUID are rejected."""
        # Using Cyrillic 'а' (U+0430) instead of Latin 'a'
        homoglyph = "550e8400-e29b-41d4-\u0430716-446655440000"
        with pytest.raises(ValidationError):
            validate_uuid(homoglyph, "id")

    def test_zero_width_chars_in_label_rejected(self):
        """Zero-width characters in labels are rejected."""
        # Zero-width space
        zwsp = "label\u200blabel"
        with pytest.raises(ValidationError):
            validate_label(zwsp)

    def test_rtl_override_in_ioc_handled(self):
        """RTL override characters don't cause issues."""
        rtl = "192.168.1.1\u202e"
        # Should be handled safely (either accepted or rejected cleanly)
        try:
            result = validate_ioc(rtl)
            # If accepted, should be a valid IOC type
            assert result[0] is True
        except ValidationError:
            # Rejection is also acceptable
            pass

    def test_homoglyph_in_domain_rejected(self):
        """Homoglyph characters in domains are rejected (IDN homograph attack)."""
        # Using Cyrillic 'а' (U+0430) instead of Latin 'a' in "example"
        homoglyph_domain = "ex\u0430mple.com"
        result = validate_ioc(homoglyph_domain)
        # Should NOT be recognized as a valid domain
        assert result[1] != "domain", f"Homoglyph domain accepted as: {result[1]}"

    def test_greek_letters_in_domain_rejected(self):
        """Greek letters in domains are rejected."""
        # Using Greek 'ο' (U+03BF) instead of Latin 'o'
        greek_domain = "g\u03bfogle.com"
        result = validate_ioc(greek_domain)
        assert result[1] != "domain", f"Greek letter domain accepted as: {result[1]}"

    def test_cyrillic_tld_rejected(self):
        """Cyrillic TLDs are rejected."""
        # Using Cyrillic 'с' (U+0441) and 'о' (U+043E) in .com
        cyrillic_tld = "example.\u0441\u043em"
        result = validate_ioc(cyrillic_tld)
        assert result[1] != "domain", f"Cyrillic TLD domain accepted as: {result[1]}"

    def test_homoglyph_in_relationship_type_rejected(self):
        """Homoglyph characters in relationship types are rejected."""
        # Using Cyrillic 'а' (U+0430) instead of Latin 'a' in "indicates"
        homoglyph_type = "indic\u0430tes"
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types([homoglyph_type])

    def test_unicode_digits_in_relationship_rejected(self):
        """Unicode digit lookalikes in relationship types are rejected."""
        # Using fullwidth digit '１' (U+FF11) instead of ASCII '1'
        unicode_digit = "type\uff11"
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_relationship_types([unicode_digit])

    def test_ascii_domain_accepted(self):
        """Valid ASCII domains are accepted."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "test-site.org",
            "a.co",
            "xn--nxasmq5b.com",  # Punycode IDN (valid ASCII representation)
        ]
        for domain in valid_domains:
            result = validate_ioc(domain)
            assert result[1] == "domain", f"Valid domain '{domain}' not recognized"

    def test_ascii_relationship_types_accepted(self):
        """Valid ASCII relationship types are accepted."""
        valid_types = ["indicates", "uses", "targets", "related-to"]
        result = validate_relationship_types(valid_types)
        assert result == valid_types
