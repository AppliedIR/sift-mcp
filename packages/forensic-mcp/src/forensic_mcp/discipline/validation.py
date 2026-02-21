"""Finding validation against forensic discipline rules.

Called internally by CaseManager.record_finding() and also
exposed as a standalone MCP tool for pre-submission checks.

Reads confidence definitions from forensic-knowledge YAML.
"""

from __future__ import annotations

from forensic_knowledge import loader


VALID_TYPES = {"finding", "attribution", "conclusion", "exclusion"}


def _get_confidence_defs() -> dict:
    """Load confidence definitions from FK (cached by loader)."""
    return loader.get_confidence_definitions()


def validate(finding: dict) -> dict:
    """Validate a finding against format and methodology standards.

    Returns {"valid": True} or {"valid": False, "errors": [...]}.
    """
    errors: list[str] = []
    confidence_defs = _get_confidence_defs()

    # Required fields
    required = ["title", "observation", "interpretation", "confidence", "type"]
    for field in required:
        if not finding.get(field):
            errors.append(f"Missing required field: {field}")

    # evidence_ids must be present and non-empty
    evidence_ids = finding.get("evidence_ids", [])
    if not isinstance(evidence_ids, list):
        errors.append("evidence_ids must be a list")
        evidence_ids = []

    # Type validation
    finding_type = finding.get("type", "")
    if finding_type and finding_type not in VALID_TYPES:
        errors.append(f"Invalid type '{finding_type}'. Must be one of: {sorted(VALID_TYPES)}")

    # Confidence validation
    confidence = finding.get("confidence", "").upper()
    valid_confidence = set(confidence_defs.keys())
    if confidence and confidence not in valid_confidence:
        errors.append(f"Invalid confidence '{confidence}'. Must be one of: {sorted(valid_confidence)}")

    # Confidence justification required
    if not finding.get("confidence_justification"):
        errors.append("Missing confidence_justification (FD-005: confidence must be justified)")

    # Evidence count by confidence level (FD-001, FD-007)
    if confidence in confidence_defs and not errors:
        min_required = confidence_defs[confidence]["min_evidence_ids"]
        if len(evidence_ids) < min_required:
            errors.append(
                f"Confidence {confidence} requires at least {min_required} evidence_id(s), "
                f"got {len(evidence_ids)}"
            )

    # Attribution requires 3+ evidence sources (FD-003)
    if finding_type == "attribution" and len(evidence_ids) < 3:
        errors.append(
            f"Attribution requires at least 3 evidence_ids (FD-003), got {len(evidence_ids)}"
        )

    if errors:
        return {"valid": False, "errors": errors}
    return {"valid": True}
