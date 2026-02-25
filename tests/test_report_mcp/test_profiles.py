"""Tests for report profile definitions."""

from report_mcp.profiles import PROFILES, STRIPPED_FINDING_FIELDS


class TestProfileDefinitions:
    """Validate profile data integrity."""

    def test_all_profiles_present(self):
        """Six profiles defined per spec."""
        expected = {"full", "executive", "timeline", "ioc", "findings", "status"}
        assert set(PROFILES.keys()) == expected

    def test_all_profiles_have_required_keys(self):
        """Every profile has description, data_keys, findings_mode, sections."""
        for name, profile in PROFILES.items():
            assert "description" in profile, f"{name} missing description"
            assert "data_keys" in profile, f"{name} missing data_keys"
            assert "findings_mode" in profile, f"{name} missing findings_mode"
            assert "sections" in profile, f"{name} missing sections"

    def test_section_types_valid(self):
        """Section types are data, narrative, or data_narrative."""
        valid = {"data", "narrative", "data_narrative"}
        for name, profile in PROFILES.items():
            for section in profile["sections"]:
                assert section["type"] in valid, (
                    f"{name} section '{section['name']}' has invalid "
                    f"type '{section['type']}'"
                )

    def test_zeltser_tools_present(self):
        """Every profile has a zeltser_tools list (may be empty)."""
        for name, profile in PROFILES.items():
            assert isinstance(profile.get("zeltser_tools"), list), (
                f"{name} missing zeltser_tools"
            )

    def test_stripped_fields_complete(self):
        """All spec'd internal fields are in the strip set."""
        required = {
            "provenance",
            "confidence",
            "supporting_commands",
            "content_hash",
            "evidence_ids",
            "staged",
            "modified_at",
            "approved_by",
            "approved_at",
            "rejected_by",
            "rejected_at",
            "rejection_reason",
            "verification",
        }
        assert required.issubset(STRIPPED_FINDING_FIELDS), (
            f"Missing: {required - STRIPPED_FINDING_FIELDS}"
        )
