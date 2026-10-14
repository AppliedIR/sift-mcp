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

# Layer 7b: SIFT limitations where wintools-mcp produces better results
_SIFT_LIMITATIONS: dict[str, str] = {
    "srum": (
        "SRUM parsing on SIFT uses Plaso (limited dirty-database handling). "
        "For reliable SRUM analysis, provision wintools-mcp with SrumECmd."
    ),
    "prefetch": (
        "Prefetch parsing on SIFT uses Plaso (misses execution counts, loaded DLLs). "
        "For complete prefetch analysis, provision wintools-mcp with PECmd."
    ),
    "registry": (
        "Registry parsing on SIFT has limited transaction log recovery. "
        "For dirty hives from KAPE live collection, provision wintools-mcp with RECmd."
    ),
    "digital_signatures": (
        "SIFT cannot verify Authenticode signatures. "
        "For signature verification, provision wintools-mcp with sigcheck."
    ),
}


def _wintools_available() -> bool:
    """Check if wintools-mcp is configured in gateway.yaml."""
    try:
        from pathlib import Path

        import yaml

        gw = yaml.safe_load((Path.home() / ".vhir" / "gateway.yaml").read_text()) or {}
        return "wintools-mcp" in gw.get("backends", {})
    except Exception:
        return False


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


def _recipes(td, version: str) -> dict:
    """The catalog's recipes for the installed `version`, and the others with
    the versions they were tested on. A version that can't be read matches
    none of them."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version

    try:
        installed = Version(version)
    except InvalidVersion:
        installed = None
    mine, others = [], []
    for r in td.recipes:
        try:  # a blank range is invalid, not "every version"
            fits = (
                installed is not None
                and bool(str(r["versions"]).strip())
                and installed in SpecifierSet(r["versions"])
            )
        except (InvalidSpecifier, KeyError, TypeError):
            fits = False
        if fits:
            mine.append(r)
        else:
            others.append(
                {
                    "task": r.get("task", ""),
                    "versions": r.get("versions", ""),
                    "note": f"tested on {r.get('versions', '?')} only",
                }  # fmt: skip
            )
    out: dict = {"recipes": mine}
    if others:
        out["other_recipes"] = others
    if td.recipes and not mine:
        tested = ", ".join(sorted({r.get("versions", "?") for r in td.recipes}))
        out["recipe_note"] = (
            f"no recipe for {version}; tested on {tested}. Use the tool's own "
            "help above."
        )
    return out


def get_tool_help(tool_name: str, subcommand: str = "") -> dict:
    """The installed tool's version, path and own help, with the catalog's
    recipes for that version."""
    from sift_mcp import tool_version

    td = get_tool_def(tool_name)
    if not td:
        return {"error": f"Tool '{tool_name}' not in catalog"}
    if subcommand and not tool_version.SUBCOMMAND.match(subcommand):
        return tool_version.help_text(td, subcommand)  # the refusal, run nothing

    result = {
        "name": td.name,
        "binary": td.binary,
        "category": td.category,
        "description": td.description,
        "input_style": td.input_style,
        "input_flag": td.input_flag,
        "output_format": td.output_format,
        "timeout_seconds": td.timeout_seconds,
    }
    found = tool_version.probe(td)
    result["available"] = bool(found)
    if found:
        result.update(found)
        result.update(tool_version.help_text(td, subcommand))
        result.update(_recipes(td, found["installed_version"]))
    elif td.recipes:
        result["other_recipes"] = _recipes(td, "")["other_recipes"]

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
    """Check availability of tools on the system, with each installed catalog
    tool's version and the path that runs."""
    from concurrent.futures import ThreadPoolExecutor

    from sift_mcp import tool_version

    def one(td) -> dict:
        found = tool_version.probe(td)
        if not found:
            return {"available": False, "binary_path": None}
        return {"available": True, "binary_path": find_binary(td.binary), **found}

    if tool_names:
        results = {}
        for name in tool_names:
            td = get_tool_def(name)
            if td:
                results[name] = one(td)
            else:
                results[name] = {
                    "available": False,
                    "note": "not in catalog — can execute but without FK enrichment",
                }
        return results

    # Check all, the probes side by side
    tds = [td for t in list_tools_in_catalog() if (td := get_tool_def(t["name"]))]
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip([td.name for td in tds], pool.map(one, tds), strict=True))


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

    # Layer 7b: add SIFT limitation advisories when wintools unavailable
    if not _wintools_available():
        for art_name in artifact_names:
            if art_name in _SIFT_LIMITATIONS:
                all_advisories.append(_SIFT_LIMITATIONS[art_name])

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
                # a catalog name (log2timeline, vol3) has its entry under the
                # catalog's knowledge name
                fk = loader.get_tool(td.knowledge_name if td else tool_name)
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
            available = loader.list_artifact_keys()
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
