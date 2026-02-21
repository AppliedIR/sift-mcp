"""Tests for input validation module."""

from __future__ import annotations

import pytest

from opencti_mcp.validation import (
    validate_length,
    validate_limit,
    validate_offset,
    validate_days,
    validate_ioc,
    validate_hash,
    normalize_hash,
    truncate_string,
    MAX_QUERY_LENGTH,
    MAX_IOC_LENGTH,
    MAX_LIMIT,
    MAX_OFFSET,
)
from opencti_mcp.errors import ValidationError

# Test data - defined locally to avoid import issues
VALID_IPV4 = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "255.255.255.255", "0.0.0.0"]
INVALID_IPV4 = ["256.1.1.1", "1.2.3", "1.2.3.4.5", "not.an.ip", "192.168.1", "01.02.03.04"]
VALID_MD5 = ["d41d8cd98f00b204e9800998ecf8427e", "a" * 32, "0" * 32, "f" * 32]
VALID_SHA1 = ["da39a3ee5e6b4b0d3255bfef95601890afd80709", "a" * 40]
VALID_SHA256 = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "a" * 64]
INVALID_HASHES = ["xyz123", "tooshort", "g" * 64, "a" * 31, "a" * 33]
VALID_DOMAINS = ["example.com", "sub.example.com", "deep.sub.example.com", "test-site.org", "my-test.co.uk"]
INVALID_DOMAINS = [".example.com", "example.", "example..com", "-example.com", "example-.com", "a"]
VALID_CVES = ["CVE-2024-3400", "cve-2021-44228", "CVE-2020-0001"]
VALID_MITRE_IDS = ["T1003", "T1003.001", "t1059", "T1059.003"]


# =============================================================================
# Length Validation
# =============================================================================

class TestLengthValidation:
    """Tests for validate_length function."""

    def test_valid_length(self):
        """Accept values within limit."""
        validate_length("hello", 10, "test")  # Should not raise

    def test_exact_limit(self):
        """Accept values at exact limit."""
        validate_length("a" * 100, 100, "test")  # Should not raise

    def test_exceeds_limit(self):
        """Reject values exceeding limit."""
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_length("a" * 101, 100, "test")

    def test_none_value(self):
        """Accept None values."""
        validate_length(None, 100, "test")  # Should not raise

    def test_empty_string(self):
        """Accept empty strings."""
        validate_length("", 100, "test")  # Should not raise


# =============================================================================
# Limit Validation
# =============================================================================

class TestLimitValidation:
    """Tests for validate_limit function."""

    def test_valid_limit(self):
        """Accept valid limits."""
        assert validate_limit(10) == 10
        assert validate_limit(50) == 50
        assert validate_limit(100) == 100

    def test_none_default(self):
        """None returns default."""
        assert validate_limit(None) == 10

    def test_clamp_high(self):
        """Clamp high values."""
        assert validate_limit(1000) == MAX_LIMIT

    def test_clamp_low(self):
        """Clamp low values."""
        assert validate_limit(0) == 1
        assert validate_limit(-1) == 1

    def test_custom_max(self):
        """Custom max value."""
        assert validate_limit(100, max_value=50) == 50


# =============================================================================
# Days Validation
# =============================================================================

class TestDaysValidation:
    """Tests for validate_days function."""

    def test_valid_days(self):
        """Accept valid days."""
        assert validate_days(7) == 7
        assert validate_days(30) == 30

    def test_none_default(self):
        """None returns default."""
        assert validate_days(None) == 7

    def test_clamp_high(self):
        """Clamp high values."""
        assert validate_days(1000) == 365

    def test_clamp_low(self):
        """Clamp low values."""
        assert validate_days(0) == 1


# =============================================================================
# Offset Validation
# =============================================================================

class TestOffsetValidation:
    """Tests for validate_offset function."""

    def test_valid_offset(self):
        """Accept valid offset values."""
        assert validate_offset(0) == 0
        assert validate_offset(100) == 100
        assert validate_offset(500) == 500

    def test_none_default(self):
        """None returns default of 0."""
        assert validate_offset(None) == 0

    def test_clamp_high(self):
        """Clamp high values to MAX_OFFSET."""
        assert validate_offset(1000) == MAX_OFFSET
        assert validate_offset(999999) == MAX_OFFSET

    def test_clamp_negative(self):
        """Clamp negative values to 0."""
        assert validate_offset(-1) == 0
        assert validate_offset(-100) == 0

    def test_custom_max(self):
        """Respect custom max_value."""
        assert validate_offset(200, max_value=100) == 100
        assert validate_offset(50, max_value=100) == 50

    def test_non_integer_conversion(self):
        """Convert string-like values to int."""
        assert validate_offset("100") == 100
        assert validate_offset("invalid") == 0


# =============================================================================
# IOC Validation
# =============================================================================

class TestIOCValidation:
    """Tests for validate_ioc function."""

    @pytest.mark.parametrize("ip", VALID_IPV4)
    def test_valid_ipv4(self, ip: str):
        """Accept valid IPv4 addresses."""
        is_valid, ioc_type = validate_ioc(ip)
        assert is_valid is True
        assert ioc_type == "ipv4"

    @pytest.mark.parametrize("ip", INVALID_IPV4)
    def test_invalid_ipv4_not_ipv4_type(self, ip: str):
        """Invalid IPv4 not detected as ipv4 type."""
        is_valid, ioc_type = validate_ioc(ip)
        assert ioc_type != "ipv4" or is_valid is False

    @pytest.mark.parametrize("hash_val", VALID_MD5)
    def test_valid_md5(self, hash_val: str):
        """Accept valid MD5 hashes."""
        is_valid, ioc_type = validate_ioc(hash_val)
        assert is_valid is True
        assert ioc_type == "md5"

    @pytest.mark.parametrize("hash_val", VALID_SHA1)
    def test_valid_sha1(self, hash_val: str):
        """Accept valid SHA1 hashes."""
        is_valid, ioc_type = validate_ioc(hash_val)
        assert is_valid is True
        assert ioc_type == "sha1"

    @pytest.mark.parametrize("hash_val", VALID_SHA256)
    def test_valid_sha256(self, hash_val: str):
        """Accept valid SHA256 hashes."""
        is_valid, ioc_type = validate_ioc(hash_val)
        assert is_valid is True
        assert ioc_type == "sha256"

    @pytest.mark.parametrize("domain", VALID_DOMAINS)
    def test_valid_domain(self, domain: str):
        """Accept valid domains."""
        is_valid, ioc_type = validate_ioc(domain)
        assert is_valid is True
        assert ioc_type == "domain"

    @pytest.mark.parametrize("cve", VALID_CVES)
    def test_valid_cve(self, cve: str):
        """Accept valid CVE IDs."""
        is_valid, ioc_type = validate_ioc(cve)
        assert is_valid is True
        assert ioc_type == "cve"

    @pytest.mark.parametrize("mitre_id", VALID_MITRE_IDS)
    def test_valid_mitre_id(self, mitre_id: str):
        """Accept valid MITRE technique IDs."""
        is_valid, ioc_type = validate_ioc(mitre_id)
        assert is_valid is True
        assert ioc_type == "mitre"

    def test_url_detection(self):
        """Detect URLs."""
        is_valid, ioc_type = validate_ioc("http://evil.com/malware")
        assert is_valid is True
        assert ioc_type == "url"

        is_valid, ioc_type = validate_ioc("https://evil.com/payload.exe")
        assert is_valid is True
        assert ioc_type == "url"

    def test_unknown_type(self):
        """Unknown types are accepted."""
        is_valid, ioc_type = validate_ioc("some random text")
        assert is_valid is True
        assert ioc_type == "unknown"


# =============================================================================
# Hash Validation
# =============================================================================

class TestHashValidation:
    """Tests for hash validation functions."""

    @pytest.mark.parametrize("hash_val", VALID_MD5 + VALID_SHA1 + VALID_SHA256)
    def test_valid_hashes(self, hash_val: str):
        """Accept valid hashes."""
        assert validate_hash(hash_val) is True

    @pytest.mark.parametrize("hash_val", INVALID_HASHES)
    def test_invalid_hashes(self, hash_val: str):
        """Reject invalid hashes."""
        assert validate_hash(hash_val) is False

    def test_normalize_hash_lowercase(self):
        """Normalize to lowercase."""
        result = normalize_hash("ABCDEF123456" + "0" * 20)
        assert result == "abcdef123456" + "0" * 20

    def test_normalize_hash_strip_prefix(self):
        """Strip algorithm prefix."""
        result = normalize_hash("md5:d41d8cd98f00b204e9800998ecf8427e")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"

        result = normalize_hash("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_normalize_hash_strip_whitespace(self):
        """Strip whitespace."""
        result = normalize_hash("  d41d8cd98f00b204e9800998ecf8427e  ")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"


# =============================================================================
# Truncation
# =============================================================================

class TestTruncation:
    """Tests for truncation functions."""

    def test_truncate_string_short(self):
        """Short strings unchanged."""
        assert truncate_string("hello", 10) == "hello"

    def test_truncate_string_exact(self):
        """Exact length unchanged."""
        assert truncate_string("hello", 5) == "hello"

    def test_truncate_string_long(self):
        """Long strings truncated with ellipsis."""
        result = truncate_string("hello world", 8)
        assert result == "hello..."
        assert len(result) == 8

    def test_truncate_string_none(self):
        """None returns None."""
        assert truncate_string(None, 10) is None


# =============================================================================
# IPv6 Validation
# =============================================================================

VALID_IPV6 = [
    "2001:db8::1",
    "::1",
    "fe80::1",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "2001:db8:85a3::8a2e:370:7334",
    "::",
    # Note: IPv4-mapped addresses like "::ffff:192.0.2.1" not supported
]

INVALID_IPV6 = [
    "2001:db8::1::2",  # Multiple ::
    "2001:db8:85a3:0000:0000:8a2e:0370:7334:extra",  # Too many groups
    "gggg::1",  # Invalid hex
    "12345::1",  # Group too long
]


class TestIPv6Validation:
    """Tests for IPv6 validation."""

    @pytest.mark.parametrize("ip", VALID_IPV6)
    def test_valid_ipv6(self, ip: str):
        """Accept valid IPv6 addresses."""
        is_valid, ioc_type = validate_ioc(ip)
        assert is_valid is True
        assert ioc_type == "ipv6"

    @pytest.mark.parametrize("ip", INVALID_IPV6)
    def test_invalid_ipv6_not_ipv6_type(self, ip: str):
        """Invalid IPv6 addresses should not be detected as ipv6."""
        is_valid, ioc_type = validate_ioc(ip)
        # Should still be valid (unknown type), just not ipv6
        assert ioc_type != "ipv6"


# =============================================================================
# CIDR Validation
# =============================================================================

VALID_CIDR = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "0.0.0.0/0",
    "192.168.1.1/32",
    "2001:db8::/32",
    "::1/128",
]

INVALID_CIDR = [
    "192.168.1.0/33",  # Prefix too large for IPv4
    "2001:db8::/129",  # Prefix too large for IPv6
    "192.168.1.0/",    # Missing prefix
    "192.168.1.0/abc",  # Non-numeric prefix
]


class TestCIDRValidation:
    """Tests for CIDR notation validation."""

    @pytest.mark.parametrize("cidr", VALID_CIDR)
    def test_valid_cidr(self, cidr: str):
        """Accept valid CIDR notation."""
        is_valid, ioc_type = validate_ioc(cidr)
        assert is_valid is True
        assert ioc_type == "cidr"

    @pytest.mark.parametrize("cidr", INVALID_CIDR)
    def test_invalid_cidr_not_cidr_type(self, cidr: str):
        """Invalid CIDR should not be detected as cidr type."""
        is_valid, ioc_type = validate_ioc(cidr)
        # Should still be valid (unknown type), just not cidr
        assert ioc_type != "cidr"


# =============================================================================
# Truncation Indicators
# =============================================================================

class TestTruncationIndicators:
    """Tests for truncation metadata."""

    def test_truncated_fields_tracked(self):
        """Truncated fields are tracked in metadata."""
        from opencti_mcp.validation import truncate_response

        data = {
            "description": "x" * 1000,  # Will be truncated
            "pattern": "y" * 500,       # Will be truncated
            "name": "short",            # Will not be truncated
        }

        result = truncate_response(data)

        assert "_truncated_fields" in result
        assert "description" in result["_truncated_fields"]
        assert "pattern" in result["_truncated_fields"]
        assert "name" not in result["_truncated_fields"]

    def test_no_truncation_no_metadata(self):
        """No truncation metadata when nothing truncated."""
        from opencti_mcp.validation import truncate_response

        data = {
            "description": "short",
            "name": "test",
        }

        result = truncate_response(data)

        assert "_truncated_fields" not in result
        assert "_truncated" not in result

    def test_list_truncation_tracked(self):
        """List truncation is tracked."""
        from opencti_mcp.validation import truncate_response, MAX_LIMIT

        data = {
            "items": list(range(MAX_LIMIT + 50)),
        }

        result = truncate_response(data)

        assert "_truncated_fields" in result
        assert any("items" in f for f in result["_truncated_fields"])
