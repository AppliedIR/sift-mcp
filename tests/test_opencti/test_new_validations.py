"""Comprehensive tests for new validation functions.

Tests cover:
- Observable type validation
- Note type validation
- Date filter validation
- Pattern type validation
- Deep edge cases and security scenarios
"""

from __future__ import annotations

import pytest
from opencti_mcp.errors import ValidationError
from opencti_mcp.validation import (
    VALID_PATTERN_TYPES,
    validate_date_filter,
    validate_note_types,
    validate_observable_types,
    validate_pattern_type,
)

# =============================================================================
# Observable Type Validation Tests
# =============================================================================


class TestObservableTypeValidation:
    """Test observable type validation."""

    def test_valid_observable_types(self):
        """Valid observable types are accepted."""
        valid = ["IPv4-Addr", "Domain-Name", "StixFile"]
        result = validate_observable_types(valid)
        assert result == valid

    def test_all_known_types_accepted(self):
        """All known observable types should be accepted."""
        # Test a subset to verify
        known_types = [
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "URL",
            "StixFile",
            "Email-Addr",
            "Mac-Addr",
            "Process",
            "User-Account",
        ]
        result = validate_observable_types(known_types)
        assert result == known_types

    def test_empty_list_returns_none(self):
        """Empty list returns None."""
        assert validate_observable_types([]) is None
        assert validate_observable_types(None) is None

    def test_unknown_type_rejected(self):
        """Unknown observable types are rejected."""
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["FakeType"])

    def test_case_sensitivity(self):
        """Observable types are case-sensitive (STIX compliance)."""
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["ipv4-addr"])  # Lowercase rejected
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["IPV4-ADDR"])  # Uppercase rejected

    def test_max_items_enforced(self):
        """Max items limit is enforced."""
        many_types = ["IPv4-Addr"] * 15
        with pytest.raises(ValidationError, match="more than 10"):
            validate_observable_types(many_types)

    def test_empty_strings_filtered(self):
        """Empty strings in list are filtered out."""
        result = validate_observable_types(["IPv4-Addr", "", "Domain-Name"])
        assert result == ["IPv4-Addr", "Domain-Name"]

    def test_non_string_elements_filtered(self):
        """Non-string elements are filtered out."""
        result = validate_observable_types(["IPv4-Addr", None, 123, "Domain-Name"])
        assert result == ["IPv4-Addr", "Domain-Name"]

    def test_non_list_rejected(self):
        """Non-list input is rejected."""
        with pytest.raises(ValidationError, match="must be a list"):
            validate_observable_types("IPv4-Addr")

    @pytest.mark.parametrize(
        "malicious",
        [
            "IPv4-Addr'; DROP TABLE--",
            "IPv4-Addr<script>",
            "IPv4-Addr\x00evil",
            "../../../etc/passwd",
            "${observable_type}",
        ],
    )
    def test_injection_attempts_rejected(self, malicious: str):
        """Injection attempts are rejected."""
        with pytest.raises(ValidationError):
            validate_observable_types([malicious])

    def test_whitespace_handling(self):
        """Whitespace is stripped from types."""
        result = validate_observable_types(["  IPv4-Addr  ", "Domain-Name  "])
        assert result == ["IPv4-Addr", "Domain-Name"]


# =============================================================================
# Note Type Validation Tests
# =============================================================================


class TestNoteTypeValidation:
    """Test note type validation."""

    def test_valid_note_types(self):
        """Valid note types are accepted."""
        valid = ["analysis", "assessment", "external"]
        result = validate_note_types(valid)
        assert result == valid

    def test_case_normalization(self):
        """Note types are normalized to lowercase."""
        result = validate_note_types(["ANALYSIS", "Assessment"])
        assert result == ["analysis", "assessment"]

    def test_empty_list_returns_none(self):
        """Empty list returns None."""
        assert validate_note_types([]) is None
        assert validate_note_types(None) is None

    def test_max_items_enforced(self):
        """Max items limit is enforced."""
        many_types = ["analysis"] * 10
        with pytest.raises(ValidationError, match="more than 5"):
            validate_note_types(many_types)

    def test_long_type_rejected(self):
        """Long note types are rejected."""
        with pytest.raises(ValidationError, match="too long"):
            validate_note_types(["a" * 60])

    def test_non_list_rejected(self):
        """Non-list input is rejected."""
        with pytest.raises(ValidationError, match="must be a list"):
            validate_note_types("analysis")

    @pytest.mark.parametrize(
        "malicious",
        [
            "analysis'; DROP TABLE--",
            "analysis<script>",
            "analysis\x00evil",
            "analysis`id`",
        ],
    )
    def test_injection_in_note_types_rejected(self, malicious: str):
        """Injection attempts in note types are rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types([malicious])

    def test_empty_strings_filtered(self):
        """Empty strings are filtered out."""
        result = validate_note_types(["analysis", "", "assessment"])
        assert result == ["analysis", "assessment"]

    def test_hyphenated_types_allowed(self):
        """Hyphenated types are allowed."""
        result = validate_note_types(["threat-report"])
        assert result == ["threat-report"]

    def test_unicode_rejected(self):
        """Unicode characters are rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types(["анализ"])  # Cyrillic


# =============================================================================
# Date Filter Validation Tests
# =============================================================================


class TestDateFilterValidation:
    """Test date filter validation."""

    def test_valid_date_only(self):
        """Valid date-only format is accepted."""
        result = validate_date_filter("2024-01-15", "created_after")
        assert result == "2024-01-15"

    def test_valid_datetime_z(self):
        """Valid datetime with Z timezone is accepted."""
        result = validate_date_filter("2024-01-15T10:30:00Z", "created_after")
        assert result == "2024-01-15T10:30:00Z"

    def test_valid_datetime_offset(self):
        """Valid datetime with offset timezone is accepted."""
        result = validate_date_filter("2024-01-15T10:30:00+05:30", "created_after")
        assert result == "2024-01-15T10:30:00+05:30"

    def test_valid_datetime_fractional(self):
        """Valid datetime with fractional seconds is accepted."""
        result = validate_date_filter("2024-01-15T10:30:00.123Z", "created_after")
        assert result == "2024-01-15T10:30:00.123Z"

    def test_none_returns_none(self):
        """None input returns None."""
        assert validate_date_filter(None, "date") is None

    def test_empty_string_returns_none(self):
        """Empty string returns None."""
        assert validate_date_filter("", "date") is None
        assert validate_date_filter("   ", "date") is None

    def test_invalid_format_rejected(self):
        """Invalid date formats are rejected."""
        with pytest.raises(ValidationError, match="ISO8601"):
            validate_date_filter("01-15-2024", "date")  # Wrong order
        with pytest.raises(ValidationError, match="ISO8601"):
            validate_date_filter("2024/01/15", "date")  # Wrong separator
        with pytest.raises(ValidationError, match="ISO8601"):
            validate_date_filter("yesterday", "date")  # Relative

    def test_invalid_month_rejected(self):
        """Invalid month is rejected."""
        with pytest.raises(ValidationError, match="month"):
            validate_date_filter("2024-13-15", "date")
        with pytest.raises(ValidationError, match="month"):
            validate_date_filter("2024-00-15", "date")

    def test_invalid_day_rejected(self):
        """Invalid day is rejected."""
        with pytest.raises(ValidationError, match="day"):
            validate_date_filter("2024-01-32", "date")
        with pytest.raises(ValidationError, match="day"):
            validate_date_filter("2024-01-00", "date")

    def test_invalid_year_rejected(self):
        """Invalid year range is rejected."""
        with pytest.raises(ValidationError, match="year"):
            validate_date_filter("1969-01-15", "date")
        with pytest.raises(ValidationError, match="year"):
            validate_date_filter("2101-01-15", "date")

    def test_invalid_hour_rejected(self):
        """Invalid hour is rejected."""
        with pytest.raises(ValidationError, match="hour"):
            validate_date_filter("2024-01-15T25:00:00Z", "date")

    def test_invalid_minute_rejected(self):
        """Invalid minute is rejected."""
        with pytest.raises(ValidationError, match="minute"):
            validate_date_filter("2024-01-15T12:60:00Z", "date")

    def test_invalid_second_rejected(self):
        """Invalid second is rejected."""
        with pytest.raises(ValidationError, match="second"):
            validate_date_filter("2024-01-15T12:30:60Z", "date")

    def test_null_byte_rejected(self):
        """Null bytes are rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_date_filter("2024-01-15\x00", "date")

    def test_long_value_rejected(self):
        """Long values are rejected."""
        with pytest.raises(ValidationError, match="too long"):
            validate_date_filter("2024-01-15" + "x" * 50, "date")

    def test_non_string_rejected(self):
        """Non-string input is rejected."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_date_filter(20240115, "date")

    @pytest.mark.parametrize(
        "malicious",
        [
            "2024-01-15'; DROP TABLE--",
            "2024-01-15<script>",
            "2024-01-15${date}",
        ],
    )
    def test_injection_attempts_rejected(self, malicious: str):
        """Injection attempts are rejected."""
        with pytest.raises(ValidationError):
            validate_date_filter(malicious, "date")

    def test_boundary_dates(self):
        """Boundary dates are accepted."""
        assert validate_date_filter("1970-01-01", "date") == "1970-01-01"
        assert validate_date_filter("2100-12-31", "date") == "2100-12-31"

    def test_whitespace_stripped(self):
        """Whitespace is stripped."""
        result = validate_date_filter("  2024-01-15  ", "date")
        assert result == "2024-01-15"


# =============================================================================
# Pattern Type Validation Tests
# =============================================================================


class TestPatternTypeValidation:
    """Test pattern type validation."""

    def test_valid_pattern_types(self):
        """Valid pattern types are accepted."""
        for pt in ["stix", "pcre", "sigma", "snort", "suricata", "yara"]:
            result = validate_pattern_type(pt)
            assert result == pt

    def test_case_normalization(self):
        """Pattern types are normalized to lowercase."""
        assert validate_pattern_type("STIX") == "stix"
        assert validate_pattern_type("Sigma") == "sigma"

    def test_none_defaults_to_stix(self):
        """None defaults to 'stix'."""
        assert validate_pattern_type(None) == "stix"

    def test_empty_string_defaults_to_stix(self):
        """Empty string defaults to 'stix'."""
        assert validate_pattern_type("") == "stix"
        assert validate_pattern_type("   ") == "stix"

    def test_invalid_type_rejected(self):
        """Invalid pattern types are rejected."""
        with pytest.raises(ValidationError, match="Invalid pattern_type"):
            validate_pattern_type("invalid")

    def test_non_string_rejected(self):
        """Non-string input is rejected."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_pattern_type(123)

    def test_all_valid_types_work(self):
        """All defined valid types work."""
        for pt in VALID_PATTERN_TYPES:
            result = validate_pattern_type(pt)
            assert result == pt


# =============================================================================
# Deep Edge Case Tests
# =============================================================================


class TestDeepEdgeCases:
    """Deep edge case testing for all validations."""

    def test_observable_type_boundary_max(self):
        """Exactly max items is allowed."""
        types = ["IPv4-Addr"] * 10
        result = validate_observable_types(types)
        assert len(result) == 10

    def test_observable_type_boundary_over(self):
        """One over max is rejected."""
        types = ["IPv4-Addr"] * 11
        with pytest.raises(ValidationError):
            validate_observable_types(types)

    def test_note_type_boundary_max(self):
        """Exactly max items is allowed."""
        types = ["analysis"] * 5
        result = validate_note_types(types)
        assert len(result) == 5

    def test_date_boundary_hour_23(self):
        """Hour 23 is valid."""
        result = validate_date_filter("2024-01-15T23:59:59Z", "date")
        assert result == "2024-01-15T23:59:59Z"

    def test_date_boundary_hour_00(self):
        """Hour 00 is valid."""
        result = validate_date_filter("2024-01-15T00:00:00Z", "date")
        assert result == "2024-01-15T00:00:00Z"

    def test_mixed_valid_invalid_observable_types(self):
        """Mix of valid and unknown types raises on first unknown."""
        with pytest.raises(ValidationError, match="Unknown observable type.*Unknown"):
            validate_observable_types(["IPv4-Addr", "Unknown", "Domain-Name"])

    def test_date_only_time_validation_skipped(self):
        """Date-only input skips time validation."""
        # This shouldn't try to validate hours/minutes/seconds
        result = validate_date_filter("2024-06-15", "date")
        assert result == "2024-06-15"

    def test_observable_empty_after_filtering(self):
        """All-empty list returns None after filtering."""
        result = validate_observable_types(["", "", None])
        assert result is None

    def test_note_empty_after_filtering(self):
        """All-empty note list returns None after filtering."""
        result = validate_note_types(["", None])
        assert result is None


# =============================================================================
# Unicode Security Tests for New Functions
# =============================================================================


class TestNewFunctionUnicodeSecurity:
    """Unicode security tests for new validation functions."""

    def test_observable_type_cyrillic_rejected(self):
        """Cyrillic lookalikes in observable types are rejected."""
        # 'а' is Cyrillic, not Latin
        with pytest.raises(ValidationError):
            validate_observable_types(["IPv4-\u0430ddr"])

    def test_note_type_homoglyph_rejected(self):
        """Homoglyphs in note types are rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_note_types(["\u0430nalysis"])  # Cyrillic 'а'

    def test_date_rtl_override_rejected(self):
        """RTL override in dates is rejected."""
        with pytest.raises(ValidationError):
            validate_date_filter("2024-01-15\u202e", "date")

    def test_date_zero_width_space_rejected(self):
        """Zero-width space in dates is rejected."""
        with pytest.raises(ValidationError):
            validate_date_filter("2024\u200b-01-15", "date")


# =============================================================================
# Integration-Style Tests
# =============================================================================


class TestValidationIntegration:
    """Integration-style tests combining multiple validations."""

    def test_realistic_observable_search(self):
        """Realistic observable search parameters."""
        types = validate_observable_types(["IPv4-Addr", "Domain-Name"])
        date_after = validate_date_filter("2024-01-01", "created_after")
        date_before = validate_date_filter("2024-12-31", "created_before")

        assert types == ["IPv4-Addr", "Domain-Name"]
        assert date_after == "2024-01-01"
        assert date_before == "2024-12-31"

    def test_realistic_create_note(self):
        """Realistic create note parameters."""
        note_types = validate_note_types(["analysis", "assessment"])
        pattern_type = validate_pattern_type("stix")

        assert note_types == ["analysis", "assessment"]
        assert pattern_type == "stix"
