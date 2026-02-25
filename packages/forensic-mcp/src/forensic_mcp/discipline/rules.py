"""Forensic discipline rules — loaded from forensic-knowledge YAML.

Thin wrapper: all data comes from forensic-knowledge package.
Functions preserve the same API as before for backward compatibility.
"""

from __future__ import annotations

from forensic_knowledge import loader


def get_all_rules() -> list[dict]:
    return loader.get_rules()


def get_checkpoint(action_type: str) -> dict:
    result = loader.get_checkpoint(action_type)
    if result is None:
        # List valid types from the checkpoints data
        all_checkpoints = loader._load_yaml("discipline/checkpoints.yaml")
        valid_types = [
            c.get("action_type", c.get("name", ""))
            for c in all_checkpoints.get("checkpoints", [])
        ]
        return {
            "error": f"Unknown action type: {action_type}",
            "valid_types": valid_types,
        }
    return result


def get_evidence_standards_data() -> dict:
    return loader.get_evidence_standards()


def get_confidence_definitions_data() -> dict:
    return loader.get_confidence_definitions()


def get_anti_patterns_data() -> list[dict]:
    return loader.get_anti_patterns()


def get_evidence_template_data() -> dict:
    return loader.get_evidence_template()


def get_investigation_framework() -> dict:
    """Return the full investigation framework from forensic-knowledge."""
    result = loader.get_investigation_framework()
    if result is None:
        return {"error": "Investigation framework not found in forensic-knowledge data"}
    return result
