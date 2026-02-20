"""Tool discovery: list tools, suggest tools, check availability."""

from __future__ import annotations

from sift_mcp.catalog import list_tools_in_catalog, get_tool_def
from sift_mcp.environment import find_binary, get_environment_info
from forensic_knowledge import loader


def list_available_tools(category: str | None = None) -> list[dict]:
    """List all tools in the catalog with availability status."""
    tools = list_tools_in_catalog(category=category)
    results = []
    for t in tools:
        td = get_tool_def(t["name"])
        available = find_binary(td.binary) is not None if td else False
        entry = {**t, "available": available}
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
    fk = loader.get_tool(td.knowledge_name)
    if fk:
        result["caveats"] = fk.get("caveats", [])
        result["advisories"] = fk.get("advisories", [])
        result["artifacts_parsed"] = fk.get("artifacts_parsed", [])

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
                results[name] = {"available": False, "error": "not in catalog"}
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


def suggest_tools(artifact_type: str, question: str = "") -> list[dict]:
    """Suggest tools based on artifact type, using FK knowledge."""
    suggestions = []

    # Look up the artifact and find related tools
    artifact = loader.get_artifact(artifact_type)
    if artifact:
        for tool_name in artifact.get("related_tools", []):
            td = get_tool_def(tool_name)
            fk = loader.get_tool(tool_name)
            entry = {
                "tool": tool_name,
                "available": find_binary(td.binary) is not None if td else False,
                "description": fk.get("description", "") if fk else "",
                "what_it_reveals": artifact.get("proves", []),
                "what_it_does_not_reveal": artifact.get("does_not_prove", []),
            }
            suggestions.append(entry)

        # Add corroboration suggestions
        corr = artifact.get("corroborate_with", {})
        if corr:
            suggestions.append({
                "type": "corroboration",
                "to_confirm_execution": corr.get("for_execution", []),
                "to_confirm_presence": corr.get("for_presence", []),
                "to_build_timeline": corr.get("for_timeline", []),
            })

    if not suggestions:
        return [{"info": f"No tools found for artifact type '{artifact_type}'",
                 "available_artifacts": [a["name"] for a in loader.list_artifacts()]}]

    return suggestions
