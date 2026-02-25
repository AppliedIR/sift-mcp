"""Tool interpretation guidance and corroboration suggestions.

Thin wrapper: all data comes from forensic-knowledge YAML.
Functions preserve the same API as before for backward compatibility.
"""

from __future__ import annotations

from forensic_knowledge import loader


def get_guidance(tool_name: str) -> dict:
    """Get interpretation guidance for a tool."""
    result = loader.get_tool_interpretation(tool_name)
    if result is None:
        # List available tools that have interpretations
        available = []
        for name in (
            "check_file",
            "check_process_tree",
            "search",
            "search_threat_intel",
        ):
            if loader.get_tool_interpretation(name) is not None:
                available.append(name)
        return {
            "error": f"No guidance available for '{tool_name}'",
            "available": sorted(available),
        }
    return result


def get_false_positives(tool_name: str, finding_type: str) -> dict:
    """Get false positive context for a tool/finding combination."""
    result = loader.get_false_positive_context(tool_name, finding_type)
    if result is None:
        return {
            "error": f"No false positive context for ({tool_name}, {finding_type})",
            "available": [
                "check_file/unknown_file",
                "check_process_tree/unexpected_parent",
            ],
        }
    return result


def get_corroboration(finding_type: str) -> list[dict]:
    """Get corroboration suggestions for a finding type."""
    result = loader.get_corroboration(finding_type)
    if result is None:
        available = []
        for ft in ("persistence", "lateral_movement", "malware", "credential_access"):
            if loader.get_corroboration(ft) is not None:
                available.append(ft)
        return [
            {
                "error": f"No corroboration map for '{finding_type}'",
                "available": sorted(available),
            }
        ]
    return result
