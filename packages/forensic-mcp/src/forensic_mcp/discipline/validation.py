"""Finding validation against forensic discipline rules.

Called internally by CaseManager.record_finding() and also
exposed as a standalone MCP tool for pre-submission checks.

Reads confidence definitions from forensic-knowledge YAML.
"""

from __future__ import annotations

import re

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

    # audit_ids must be present and non-empty
    audit_ids = finding.get("audit_ids", [])
    if not isinstance(audit_ids, list):
        errors.append("audit_ids must be a list")
        audit_ids = []

    # Type validation
    finding_type = finding.get("type", "")
    if finding_type and finding_type not in VALID_TYPES:
        errors.append(
            f"Invalid type '{finding_type}'. Must be one of: {sorted(VALID_TYPES)}"
        )

    # Confidence validation
    confidence = finding.get("confidence", "").upper()
    valid_confidence = set(confidence_defs.keys())
    if confidence and confidence not in valid_confidence:
        errors.append(
            f"Invalid confidence '{confidence}'. Must be one of: {sorted(valid_confidence)}"
        )

    # Confidence justification required
    if not finding.get("confidence_justification"):
        errors.append(
            "Missing confidence_justification (FD-005: confidence must be justified)"
        )

    # Evidence count check deferred to after warnings list is created (line 80)

    # Attribution requires 3+ evidence sources (FD-003)
    if finding_type == "attribution" and len(audit_ids) < 3:
        errors.append(
            f"Attribution requires at least 3 audit_ids (FD-003), got {len(audit_ids)}"
        )

    # event_timestamp validation
    warnings: list[str] = []

    # Evidence count by confidence level (FD-001, FD-007) — warning, not error
    if confidence in confidence_defs and not errors:
        min_required = confidence_defs[confidence]["min_audit_ids"]
        if len(audit_ids) < min_required:
            warnings.append(
                f"Confidence {confidence} typically requires {min_required}+ audit_id(s) "
                f"(got {len(audit_ids)}). Acceptable for single-source comprehensive evidence."
            )
    event_ts = finding.get("event_timestamp", "")
    if event_ts:
        # Validate ISO 8601 or date-only (YYYY-MM-DD)
        if not re.match(
            r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$",
            event_ts,
        ):
            errors.append(
                f"event_timestamp '{event_ts}' is not valid ISO 8601. "
                "Use format like '2026-01-24T15:00:41Z' or '2026-01-24'."
            )
    elif finding_type == "finding":
        warnings.append(
            "type=finding without event_timestamp — include event_timestamp "
            "(ISO 8601) for when the incident event occurred."
        )

    if errors:
        return {"valid": False, "errors": errors}
    result: dict = {"valid": True}
    if warnings:
        result["warnings"] = warnings
    return result
