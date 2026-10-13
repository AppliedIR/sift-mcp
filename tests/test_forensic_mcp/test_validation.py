"""Tests for discipline validation module."""

from forensic_mcp.discipline.validation import validate


def test_valid_finding():
    finding = {
        "title": "Test finding",
        "audit_ids": ["wt-2026-0219-001"],
        "observation": "Something was observed",
        "interpretation": "It might mean this",
        "confidence": "MEDIUM",
        "confidence_justification": "One source corroborates",
        "type": "finding",
    }
    result = validate(finding)
    assert result["valid"] is True


def test_missing_required_fields():
    result = validate({})
    assert result["valid"] is False
    assert (
        len(result["errors"]) >= 5
    )  # title, observation, interpretation, confidence, type + evidence + justification


def test_high_confidence_with_one_audit_id_has_no_count_warning():
    """Confidence is the analyst's judgment, not a count of audit ids."""
    finding = {
        "title": "Test",
        "audit_ids": ["wt-001"],
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "HIGH",
        "confidence_justification": "justified",
        "type": "finding",
        "event_timestamp": "2026-01-24T15:00:41Z",
    }
    assert validate(finding) == {"valid": True}  # no count warning


def test_attribution_with_one_audit_id_is_accepted():
    finding = {
        "title": "APT29 attribution",
        "audit_ids": ["wt-001"],
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "HIGH",
        "confidence_justification": "justified",
        "type": "attribution",
    }
    assert validate(finding) == {"valid": True}  # no count warning


def test_a_justification_is_still_required():
    finding = {
        "title": "Test",
        "audit_ids": ["wt-001", "wt-002"],
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "HIGH",
        "type": "finding",
        "event_timestamp": "2026-01-24T15:00:41Z",
    }
    result = validate(finding)
    assert result["valid"] is False
    assert result["errors"] == [
        "Missing confidence_justification (FD-005: confidence must be justified)"
    ]


def test_invalid_type():
    finding = {
        "title": "Test",
        "audit_ids": [],
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "LOW",
        "confidence_justification": "justified",
        "type": "guess",
    }
    result = validate(finding)
    assert result["valid"] is False
    assert any("Invalid type" in e for e in result["errors"])


def test_speculative_needs_no_evidence():
    finding = {
        "title": "Hypothesis",
        "audit_ids": [],
        "observation": "pattern observed",
        "interpretation": "might indicate X",
        "confidence": "SPECULATIVE",
        "confidence_justification": "based on experience",
        "type": "finding",
    }
    result = validate(finding)
    assert result["valid"] is True
