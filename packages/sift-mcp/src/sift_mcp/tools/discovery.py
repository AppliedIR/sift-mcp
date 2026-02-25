"""Tool discovery: list tools, suggest tools, check availability."""

from __future__ import annotations

import itertools
import logging

logger = logging.getLogger(__name__)
from forensic_knowledge import loader

from sift_mcp.catalog import get_tool_def, list_tools_in_catalog
from sift_mcp.environment import find_binary
from sift_mcp.response import DISCIPLINE_REMINDERS

# Alias mapping — common artifact names to FK artifact YAML names
ARTIFACT_ALIASES: dict[str, list[str]] = {
    "evtx": [
        "event_logs_security",
        "event_logs_system",
        "event_logs_sysmon",
        "event_logs_powershell",
    ],
    "evt": ["event_logs_security", "event_logs_system"],
    "event_log": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "event_logs": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "registry": ["registry_run_keys", "registry_services", "shellbags", "shimcache"],
    "mft": ["mft"],
    "prefetch": ["prefetch"],
    "usn": ["usn_journal"],
    "userassist": ["userassist"],
    "amcache": ["amcache"],
}

_suggest_counter = itertools.count(1)


def list_available_tools(category: str | None = None) -> list[dict]:
    """List cataloged tools with availability and FK enrichment status.

    Note: tools not in the catalog can also be executed via run_command.
    Cataloged tools get enriched responses (caveats, corroboration, field meanings).
    """
    tools = list_tools_in_catalog(category=category)
    results = []
    for t in tools:
        td = get_tool_def(t["name"])
        available = find_binary(td.binary) is not None if td else False
        entry = {**t, "available": available, "enriched": True}
        if td and available:
            entry["binary_path"] = find_binary(td.binary)
        results.append(entry)
    return results


def get_tool_help(tool_name: str) -> dict:
    """Get usage information for a specific tool."""
    td = get_tool_def(tool_name)
    if not td:
        return {"error": f"Tool '{tool_name}' not in catalog"}

    result = {
        "name": td.name,
        "binary": td.binary,
        "category": td.category,
        "description": td.description,
        "input_style": td.input_style,
        "input_flag": td.input_flag,
        "output_format": td.output_format,
        "timeout_seconds": td.timeout_seconds,
        "common_flags": td.common_flags,
        "available": find_binary(td.binary) is not None,
    }

    # Add FK knowledge
    try:
        fk = loader.get_tool(td.knowledge_name)
    except Exception as e:
        logger.debug("FK lookup failed for %s: %s", td.knowledge_name, e)
        fk = None
    if fk:
        result["caveats"] = fk.get("caveats", [])
        result["advisories"] = fk.get("advisories", [])
        result["artifacts_parsed"] = fk.get("artifacts_parsed", [])
        if fk.get("quick_start"):
            result["quick_start"] = fk["quick_start"]
        if fk.get("investigation_sequence"):
            result["investigation_sequence"] = fk["investigation_sequence"]
        if fk.get("field_meanings"):
            result["field_meanings"] = fk["field_meanings"]

    return result


def check_tools(tool_names: list[str] | None = None) -> dict:
    """Check availability of tools on the system."""
    if tool_names:
        results = {}
        for name in tool_names:
            td = get_tool_def(name)
            if td:
                path = find_binary(td.binary)
                results[name] = {"available": path is not None, "binary_path": path}
            else:
                results[name] = {
                    "available": False,
                    "note": "not in catalog — can execute but without FK enrichment",
                }
        return results

    # Check all
    tools = list_tools_in_catalog()
    results = {}
    for t in tools:
        td = get_tool_def(t["name"])
        if td:
            path = find_binary(td.binary)
            results[t["name"]] = {"available": path is not None, "binary_path": path}
    return results


def suggest_tools(artifact_type: str, question: str = "") -> dict:
    """Suggest tools based on artifact type, using FK knowledge.

    Returns an enriched envelope with suggestions, advisories, corroboration,
    cross-MCP checks, and discipline reminders.
    """
    # Resolve aliases
    artifact_names = ARTIFACT_ALIASES.get(artifact_type.lower(), [artifact_type])

    suggestions: list[dict] = []
    all_advisories: list[str] = []
    all_corroboration: dict[str, list[str]] = {}
    all_cross_mcp: list[dict] = []

    for art_name in artifact_names:
        try:
            artifact = loader.get_artifact(art_name)
        except Exception as e:
            logger.debug("FK artifact lookup failed for %s: %s", art_name, e)
            continue
        if not artifact:
            continue

        for tool_name in artifact.get("related_tools", []):
            # Avoid duplicates across aliases
            if any(s.get("tool") == tool_name for s in suggestions):
                continue
            td = get_tool_def(tool_name)
            try:
                fk = loader.get_tool(tool_name)
            except Exception as e:
                logger.debug("FK tool lookup failed for %s: %s", tool_name, e)
                fk = None
            entry = {
                "tool": tool_name,
                "artifact": art_name,
                "available": find_binary(td.binary) is not None if td else False,
                "description": fk.get("description", "") if fk else "",
                "what_it_reveals": artifact.get("proves", []),
                "what_it_does_not_reveal": artifact.get("does_not_prove", []),
            }
            suggestions.append(entry)

        # Advisories from does_not_prove
        for item in artifact.get("does_not_prove", []):
            advisory = f"This artifact does NOT prove: {item}"
            if advisory not in all_advisories:
                all_advisories.append(advisory)

        # Corroboration map
        for key, val in artifact.get("corroborate_with", {}).items():
            if key not in all_corroboration:
                all_corroboration[key] = []
            for ref in val:
                if ref not in all_corroboration[key]:
                    all_corroboration[key].append(ref)

        # Cross-MCP checks
        for check in artifact.get("cross_mcp_checks", []):
            if check not in all_cross_mcp:
                all_cross_mcp.append(check)

    if not suggestions:
        try:
            available = [a["name"] for a in loader.list_artifacts()]
        except Exception as e:
            logger.debug("FK list_artifacts failed: %s", e)
            available = []
        return {
            "suggestions": [],
            "info": f"No tools found for artifact type '{artifact_type}'",
            "available_artifacts": available,
        }

    call_num = next(_suggest_counter)
    return {
        "suggestions": suggestions,
        "advisories": all_advisories,
        "corroboration": all_corroboration,
        "cross_mcp_checks": all_cross_mcp,
        "discipline_reminder": DISCIPLINE_REMINDERS[
            call_num % len(DISCIPLINE_REMINDERS)
        ],
    }
