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


def test_high_confidence_needs_two_evidence():
    finding = {
        "title": "Test",
        "audit_ids": ["wt-001"],
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "HIGH",
        "confidence_justification": "justified",
        "type": "finding",
    }
    result = validate(finding)
    # HIGH confidence with single audit_id is now a warning, not an error
    assert result["valid"] is True
    assert any("2+" in w for w in result.get("warnings", []))


def test_attribution_needs_three_evidence():
    finding = {
        "title": "APT29 attribution",
        "audit_ids": ["wt-001", "rag-002"],
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "HIGH",
        "confidence_justification": "justified",
        "type": "attribution",
    }
    result = validate(finding)
    assert result["valid"] is False
    assert any("3 audit_ids" in e for e in result["errors"])


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
