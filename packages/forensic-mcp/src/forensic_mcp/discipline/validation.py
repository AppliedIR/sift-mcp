"""Finding validation against forensic discipline rules.

Called internally by CaseManager.record_finding() and also
exposed as a standalone MCP tool for pre-submission checks.

Reads confidence definitions from forensic-knowledge YAML.
"""

from __future__ import annotations

import json
import re

from forensic_knowledge import loader

VALID_TYPES = {"finding", "attribution", "conclusion", "exclusion"}

# ISO 8601 or date-only (YYYY-MM-DD): the timestamps findings and timeline
# events accept, the same on every Python version.
ISO_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"
)
ISO_TIMESTAMP_HINT = "Use format like '2026-01-24T15:00:41Z' or '2026-01-24'."

IOCS_REFUSED = (
    "which record_finding doesn't accept; nothing was recorded. Send a list of "
    'IOCs. An IOC is a string, or {"value": "<string>", "type": "<string>"}. '
    "(A flat mapping of key → IOC or list of IOCs is also accepted; its keys "
    "are dropped.) Put labels in the finding text, not in keys. Example: "
    'iocs=["<sha256>", {"value": "GadgetToJScript.bin", "type": "file:name"}]. '
    "Re-send the finding with iocs fixed."
)


def _get_confidence_defs() -> dict:
    """Load confidence definitions from FK (cached by loader)."""
    return loader.get_confidence_definitions()


def _kind(x) -> str:
    """The JSON kind of `x`, as an iocs refusal names it."""
    kinds = ((bool, "bool"), ((int, float), "number"), (str, "string"),
             (dict, "mapping"), (list, "list"), (type(None), "null"))  # fmt: skip
    return next((k for t, k in kinds if isinstance(x, t)), type(x).__name__)


def _ioc_item_error(item, path: str) -> str | None:
    """Where one IOC item leaves the accepted shapes, and what it holds there."""
    if _kind(item) in ("string", "number"):
        return None
    if not isinstance(item, dict):
        return f"`{path}` holds a {_kind(item)}"
    if "value" not in item:
        return f'`{path}` holds a mapping with no "value"'
    if _kind(item["value"]) not in ("string", "number"):
        return f"`{path}.value` holds a {_kind(item['value'])}"
    if "type" in item and not isinstance(item["type"], str):
        return f"`{path}.type` holds a {_kind(item['type'])}"
    return None


def _iocs_error(iocs) -> str | None:
    """The first place in `iocs` outside a list of IOCs or a flat mapping of key
    → IOC or list of IOCs, checked whole (before the 100-IOC cut)."""
    if iocs is None or iocs == [] or iocs == {}:
        return None
    if isinstance(iocs, list):
        items = [(f"iocs[{n}]", x) for n, x in enumerate(iocs)]
    elif isinstance(iocs, dict):
        items = []
        for key, vals in iocs.items():
            key = str(key)
            at = f"iocs.{key}" if re.fullmatch(r"[\w:-]{1,64}", key) else (
                "iocs[" + json.dumps(key[:64]).replace("`", "\\u0060") + "]"
            )  # fmt: skip
            if isinstance(vals, list):
                items += [(f"{at}[{n}]", x) for n, x in enumerate(vals)]
            elif vals is not None:
                items.append((at, vals))
    else:
        return f"`iocs` holds a {_kind(iocs)}"
    return next(filter(None, (_ioc_item_error(x, at) for at, x in items)), None)


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

    ioc_error = _iocs_error(finding.get("iocs"))
    if ioc_error:
        errors.append(f"iocs refused: {ioc_error}, {IOCS_REFUSED}")

    # event_timestamp validation
    warnings: list[str] = []
    event_ts = finding.get("event_timestamp", "")
    if event_ts:
        if not ISO_TIMESTAMP_RE.match(event_ts):
            errors.append(
                f"event_timestamp '{event_ts}' is not valid ISO 8601. {ISO_TIMESTAMP_HINT}"
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
