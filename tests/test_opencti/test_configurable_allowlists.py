"""Tests for configurable allow-lists feature.

These tests verify that custom observable types and pattern types
can be configured via environment variables for customized OpenCTI instances.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from opencti_mcp.config import Config, _parse_set_env
from opencti_mcp.errors import ValidationError
from opencti_mcp.validation import (
    validate_observable_types,
    validate_pattern_type,
)

# =============================================================================
# Environment Variable Parsing Tests
# =============================================================================


class TestParseSetEnv:
    """Tests for _parse_set_env helper function."""

    def test_empty_env_returns_empty_frozenset(self):
        """Missing env var returns empty frozenset."""
        with patch.dict(os.environ, {}, clear=True):
            result = _parse_set_env("NONEXISTENT_VAR")
            assert result == frozenset()

    def test_empty_string_returns_empty_frozenset(self):
        """Empty string returns empty frozenset."""
        with patch.dict(os.environ, {"TEST_VAR": ""}):
            result = _parse_set_env("TEST_VAR")
            assert result == frozenset()

    def test_single_value(self):
        """Single value is parsed correctly."""
        with patch.dict(os.environ, {"TEST_VAR": "Custom-Type"}):
            result = _parse_set_env("TEST_VAR")
            assert result == frozenset({"Custom-Type"})

    def test_multiple_values(self):
        """Multiple comma-separated values are parsed."""
        with patch.dict(os.environ, {"TEST_VAR": "Type1,Type2,Type3"}):
            result = _parse_set_env("TEST_VAR")
            assert result == frozenset({"Type1", "Type2", "Type3"})

    def test_whitespace_stripped(self):
        """Whitespace around values is stripped."""
        with patch.dict(os.environ, {"TEST_VAR": "  Type1 , Type2  ,  Type3  "}):
            result = _parse_set_env("TEST_VAR")
            assert result == frozenset({"Type1", "Type2", "Type3"})

    def test_empty_values_filtered(self):
        """Empty values between commas are filtered out."""
        with patch.dict(os.environ, {"TEST_VAR": "Type1,,Type2,  ,Type3"}):
            result = _parse_set_env("TEST_VAR")
            assert result == frozenset({"Type1", "Type2", "Type3"})

    def test_case_preserved(self):
        """Case is preserved (not lowercased)."""
        with patch.dict(os.environ, {"TEST_VAR": "IPv4-Addr,Domain-Name"}):
            result = _parse_set_env("TEST_VAR")
            assert "IPv4-Addr" in result
            assert "Domain-Name" in result


# =============================================================================
# Config Loading Tests
# =============================================================================


class TestConfigExtraTypes:
    """Tests for Config loading of extra types."""

    def test_config_loads_extra_observable_types(self):
        """Config loads OPENCTI_EXTRA_OBSERVABLE_TYPES."""
        with patch.dict(
            os.environ,
            {
                "OPENCTI_TOKEN": "test-token",
                "OPENCTI_EXTRA_OBSERVABLE_TYPES": "Custom-IOC,Internal-Asset",
            },
        ):
            config = Config.load()
            assert "Custom-IOC" in config.extra_observable_types
            assert "Internal-Asset" in config.extra_observable_types

    def test_config_loads_extra_pattern_types(self):
        """Config loads OPENCTI_EXTRA_PATTERN_TYPES."""
        with patch.dict(
            os.environ,
            {
                "OPENCTI_TOKEN": "test-token",
                "OPENCTI_EXTRA_PATTERN_TYPES": "osquery,custom-sig",
            },
        ):
            config = Config.load()
            assert "osquery" in config.extra_pattern_types
            assert "custom-sig" in config.extra_pattern_types

    def test_config_default_extra_types_empty(self):
        """Extra types default to empty frozenset."""
        with patch.dict(os.environ, {"OPENCTI_TOKEN": "test-token"}, clear=True):
            # Clear the extra types env vars
            os.environ.pop("OPENCTI_EXTRA_OBSERVABLE_TYPES", None)
            os.environ.pop("OPENCTI_EXTRA_PATTERN_TYPES", None)
            config = Config.load()
            assert config.extra_observable_types == frozenset()
            assert config.extra_pattern_types == frozenset()


# =============================================================================
# Observable Type Validation Tests
# =============================================================================


class TestValidateObservableTypesWithExtras:
    """Tests for validate_observable_types with extra_types."""

    def test_standard_type_accepted_without_extras(self):
        """Standard STIX types work without extras."""
        result = validate_observable_types(["IPv4-Addr", "Domain-Name"])
        assert result == ["IPv4-Addr", "Domain-Name"]

    def test_unknown_type_rejected_without_extras(self):
        """Unknown types are rejected when no extras configured."""
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["Custom-IOC"])

    def test_custom_type_accepted_with_extras(self):
        """Custom types are accepted when in extra_types."""
        extra = frozenset({"Custom-IOC", "Internal-Asset"})
        result = validate_observable_types(
            ["Custom-IOC", "IPv4-Addr"], extra_types=extra
        )
        assert result == ["Custom-IOC", "IPv4-Addr"]

    def test_custom_type_only_accepted_with_extras(self):
        """Custom-only list is accepted with extras."""
        extra = frozenset({"Custom-IOC", "Internal-Asset"})
        result = validate_observable_types(
            ["Custom-IOC", "Internal-Asset"], extra_types=extra
        )
        assert "Custom-IOC" in result
        assert "Internal-Asset" in result

    def test_invalid_custom_type_still_rejected(self):
        """Types not in standard or extra are still rejected."""
        extra = frozenset({"Custom-IOC"})
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["Not-Configured"], extra_types=extra)

    def test_empty_extras_same_as_none(self):
        """Empty frozenset behaves same as None."""
        with pytest.raises(ValidationError, match="Unknown observable type"):
            validate_observable_types(["Custom-IOC"], extra_types=frozenset())

    def test_mixed_standard_and_custom(self):
        """Mix of standard and custom types works."""
        extra = frozenset({"Proprietary-Intel"})
        result = validate_observable_types(
            ["IPv4-Addr", "Proprietary-Intel", "StixFile"], extra_types=extra
        )
        assert len(result) == 3

    def test_case_sensitivity_preserved(self):
        """Custom type matching is case-sensitive."""
        extra = frozenset({"Custom-IOC"})
        # This should work
        result = validate_observable_types(["Custom-IOC"], extra_types=extra)
        assert result == ["Custom-IOC"]
        # This should fail (wrong case)
        with pytest.raises(ValidationError):
            validate_observable_types(["custom-ioc"], extra_types=extra)


# =============================================================================
# Pattern Type Validation Tests
# =============================================================================


class TestValidatePatternTypeWithExtras:
    """Tests for validate_pattern_type with extra_types."""

    def test_standard_type_accepted_without_extras(self):
        """Standard pattern types work without extras."""
        assert validate_pattern_type("stix") == "stix"
        assert validate_pattern_type("sigma") == "sigma"
        assert validate_pattern_type("yara") == "yara"

    def test_unknown_type_rejected_without_extras(self):
        """Unknown types are rejected when no extras configured."""
        with pytest.raises(ValidationError, match="Invalid pattern_type"):
            validate_pattern_type("osquery")

    def test_custom_type_accepted_with_extras(self):
        """Custom types are accepted when in extra_types."""
        extra = frozenset({"osquery", "custom-sig"})
        result = validate_pattern_type("osquery", extra_types=extra)
        assert result == "osquery"

    def test_case_insensitive_matching(self):
        """Pattern types are lowercased for comparison."""
        extra = frozenset({"OSQUERY", "Custom-Sig"})
        # Input is lowercased before comparison
        result = validate_pattern_type("OSQUERY", extra_types=extra)
        assert result == "osquery"

    def test_invalid_custom_type_still_rejected(self):
        """Types not in standard or extra are still rejected."""
        extra = frozenset({"osquery"})
        with pytest.raises(ValidationError, match="Invalid pattern_type"):
            validate_pattern_type("not-configured", extra_types=extra)

    def test_empty_extras_same_as_none(self):
        """Empty frozenset behaves same as None."""
        with pytest.raises(ValidationError, match="Invalid pattern_type"):
            validate_pattern_type("osquery", extra_types=frozenset())

    def test_error_message_includes_custom_types(self):
        """Error message lists allowed types including custom."""
        extra = frozenset({"osquery"})
        try:
            validate_pattern_type("invalid", extra_types=extra)
            pytest.fail("Expected ValidationError")
        except ValidationError as e:
            # Error message should include custom types
            assert "osquery" in str(e)

    def test_default_still_stix_with_extras(self):
        """Default is still 'stix' even with extras configured."""
        extra = frozenset({"osquery"})
        assert validate_pattern_type(None, extra_types=extra) == "stix"
        assert validate_pattern_type("", extra_types=extra) == "stix"


# =============================================================================
# Integration Tests
# =============================================================================


class TestConfigurableAllowListsIntegration:
    """Integration tests for the full flow."""

    def test_realistic_custom_observable_types(self):
        """Test with realistic custom observable types."""
        # Simulate an org that has internal asset types
        extra = frozenset(
            {
                "Internal-Host",
                "Cloud-Resource",
                "Employee-Account",
            }
        )

        result = validate_observable_types(
            ["Internal-Host", "IPv4-Addr", "Cloud-Resource"], extra_types=extra
        )
        assert len(result) == 3

    def test_realistic_custom_pattern_types(self):
        """Test with realistic custom pattern types."""
        # Simulate an org using osquery and kql
        extra = frozenset({"osquery", "kql", "splunk-spl"})

        assert validate_pattern_type("osquery", extra_types=extra) == "osquery"
        assert validate_pattern_type("kql", extra_types=extra) == "kql"
        # Standard types still work
        assert validate_pattern_type("stix", extra_types=extra) == "stix"

    def test_standard_types_not_affected_by_extras(self):
        """Adding extras doesn't affect standard type validation."""
        extra_obs = frozenset({"Custom-Type"})
        extra_pat = frozenset({"custom-rule"})

        # All standard types should still work
        for obs_type in ["IPv4-Addr", "Domain-Name", "StixFile", "URL"]:
            result = validate_observable_types([obs_type], extra_types=extra_obs)
            assert result == [obs_type]

        for pat_type in ["stix", "sigma", "yara", "snort"]:
            result = validate_pattern_type(pat_type, extra_types=extra_pat)
            assert result == pat_type


# =============================================================================
# Security Tests
# =============================================================================


class TestConfigurableAllowListsSecurity:
    """Security tests for configurable allow-lists."""

    def test_injection_in_extra_types_env_var(self):
        """Malicious env var content doesn't cause issues."""
        # Even if someone sets a weird value, it just becomes a string in the set
        with patch.dict(os.environ, {"TEST_VAR": "'; DROP TABLE--,<script>,${cmd}"}):
            result = _parse_set_env("TEST_VAR")
            # Values are parsed as-is, validation happens later
            assert "'; DROP TABLE--" in result

    def test_extra_types_dont_bypass_validation_rules(self):
        """Extra types still go through validation logic."""
        # Even with extras, other validation rules apply
        extra = frozenset({"Custom-Type"})

        # Too many items still rejected
        many_types = ["Custom-Type"] * 20
        with pytest.raises(ValidationError, match="Cannot specify more than"):
            validate_observable_types(many_types, extra_types=extra)

    def test_empty_string_in_extra_types(self):
        """Empty strings in env var are handled safely."""
        with patch.dict(os.environ, {"TEST_VAR": ",,,"}):
            result = _parse_set_env("TEST_VAR")
            assert result == frozenset()

    def test_unicode_in_extra_types(self):
        """Unicode in extra types is preserved (case-sensitive matching)."""
        extra = frozenset({"Тест-Type"})  # Cyrillic 'T'
        # Exact match required
        result = validate_observable_types(["Тест-Type"], extra_types=extra)
        assert result == ["Тест-Type"]
        # ASCII 'T' won't match Cyrillic 'Т'
        with pytest.raises(ValidationError):
            validate_observable_types(["Test-Type"], extra_types=extra)
