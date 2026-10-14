"""Tool catalog: YAML-backed registry of approved forensic tools.

The catalog defines operational details (binary name, flags, timeout).
Interpretive knowledge (caveats, advisories) comes from forensic-knowledge.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_CATALOG_DIR: Path | None = None
_catalog_cache: dict[str, Any] = {}


def _find_catalog_dir() -> Path:
    """Locate the data/catalog directory."""
    global _CATALOG_DIR
    if _CATALOG_DIR is not None:
        return _CATALOG_DIR

    env = os.environ.get("SIFT_CATALOG_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            _CATALOG_DIR = p
            return p

    # Relative to this file: src/sift_mcp/catalog.py → ../../data/catalog/
    source = Path(__file__).resolve().parent.parent.parent / "data" / "catalog"
    if source.is_dir():
        _CATALOG_DIR = source
        return source

    raise FileNotFoundError("Cannot find sift-mcp catalog directory.")


@dataclass
class ToolDefinition:
    """A single tool entry from the catalog."""

    name: str
    binary: str
    category: str
    input_style: str = "flag"  # flag, positional, stdin
    input_flag: str = ""  # e.g. "-f" for input file
    output_format: str = "text"  # csv, json, text
    timeout_seconds: int = 600
    interactive: bool = False
    description: str = ""
    # Tested command lines: {task, versions (a range, e.g. ">=3.0,<4"), argv,
    # notes, checked_on}. get_tool_help gives those for the installed version
    recipes: list[dict] = field(default_factory=list)
    # How to ask the tool its version, tried before --version and -V ([]: run
    # it bare; "{interpreter}" first: its script's interpreter), and its
    # help (default: --help, then -h); `subcommand_help` is a subcommand's,
    # with {subcommand} in it
    version_argv: list[str] | None = None
    help_argv: list[str] = field(default_factory=list)
    subcommand_help: list[str] = field(default_factory=list)
    # FK tool name for knowledge lookup (defaults to binary name)
    fk_tool_name: str = ""
    # Its outputs are acquired evidence (a disk or memory image)
    acquisition: bool = False
    # Other names it goes by ("plaso", "Volatility 3"), matched as its name is
    aliases: list[str] = field(default_factory=list)
    # The names other versions install it under (plaso 20260720's pip entry
    # point log2timeline, for 20240308's log2timeline.py), matched as its
    # binary is and found when the binary isn't
    other_binaries: list[str] = field(default_factory=list)

    @property
    def binaries(self) -> list[str]:
        return [self.binary, *self.other_binaries]

    @property
    def knowledge_name(self) -> str:
        return self.fk_tool_name or self.binary


def load_catalog() -> dict[str, ToolDefinition]:
    """Load all catalog YAMLs, return {tool_name: ToolDefinition}."""
    if _catalog_cache:
        return _catalog_cache

    catalog_dir = _find_catalog_dir()
    try:
        yaml_files = sorted(catalog_dir.glob("*.yaml"))
    except PermissionError as e:
        logger.warning(
            "Permission denied reading catalog directory %s: %s", catalog_dir, e
        )
        return _catalog_cache

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning("Failed to parse catalog YAML %s: %s", yaml_file, e)
            continue
        except OSError as e:
            logger.warning("Failed to read catalog file %s: %s", yaml_file, e)
            continue

        if not doc or not isinstance(doc, dict):
            continue

        category = doc.get("category", yaml_file.stem)
        tools_list = doc.get("tools", [])
        if not isinstance(tools_list, list):
            logger.warning("'tools' key in %s is not a list, skipping", yaml_file)
            continue
        for tool_entry in tools_list:
            if not isinstance(tool_entry, dict):
                logger.warning("Tool entry in %s is not a dict, skipping", yaml_file)
                continue
            name = tool_entry.get("name")
            if not name:
                logger.warning(
                    "Tool entry in %s missing 'name' field, skipping", yaml_file
                )
                continue
            td = ToolDefinition(
                name=name,
                binary=tool_entry.get("binary", name),
                category=category,
                input_style=tool_entry.get("input_style", "flag"),
                input_flag=tool_entry.get("input_flag", ""),
                output_format=tool_entry.get("output_format", "text"),
                timeout_seconds=tool_entry.get("timeout_seconds", 600),
                interactive=tool_entry.get("interactive", False),
                description=tool_entry.get("description", ""),
                recipes=[dict(r) for r in tool_entry.get("recipes", None) or []],
                version_argv=(
                    None
                    if tool_entry.get("version_argv") is None
                    else [str(a) for a in tool_entry["version_argv"]]
                ),
                help_argv=[str(a) for a in tool_entry.get("help_argv") or []],
                subcommand_help=[
                    str(a) for a in tool_entry.get("subcommand_help") or []
                ],
                fk_tool_name=tool_entry.get("fk_tool_name", ""),
                acquisition=tool_entry.get("acquisition", False) is True,
                aliases=[str(a) for a in tool_entry.get("aliases", None) or []],
                other_binaries=[
                    str(b) for b in tool_entry.get("other_binaries", None) or []
                ],
            )
            _catalog_cache[name.lower()] = td

    return _catalog_cache


def get_tool_def(name: str) -> ToolDefinition | None:
    """Look up a tool by name, binary name or alias (case-insensitive)."""
    catalog = load_catalog()
    result = catalog.get(name.lower())
    if result:
        return result
    # Fallback: search by binary name (e.g., "rip.pl" → regripper), then by
    # another name it goes by (e.g., "plaso" → log2timeline)
    name_lower = name.lower()
    for td in catalog.values():
        if name_lower in (b.lower() for b in td.binaries):
            return td
    for td in catalog.values():
        if name_lower in (a.lower() for a in td.aliases):
            return td
    return None


def list_tools_in_catalog(category: str | None = None) -> list[dict]:
    """List catalog tools, optionally by category."""
    catalog = load_catalog()
    results = []
    for td in catalog.values():
        if category and td.category != category:
            continue
        results.append(
            {
                "name": td.name,
                "binary": td.binary,
                "category": td.category,
                "description": td.description,
            }
        )
    return results


def is_in_catalog(binary_name: str) -> bool:
    """Check if a binary is approved in the catalog."""
    catalog = load_catalog()
    name = binary_name.lower()
    return any(name in (b.lower() for b in td.binaries) for td in catalog.values())


_security_cache: dict | None = None


def load_security_policy() -> dict:
    """Load security policy from security.yaml in the catalog directory.

    Returns dict with keys: dangerous_flags (set), tool_allowed_flags (dict of sets),
    tool_blocked_flags (dict of sets), denied_binaries (frozenset),
    output_flags (frozenset), and per tool the output flags it adds and the
    global ones that are a switch for it (dicts of frozensets).
    """
    global _security_cache
    if _security_cache is not None:
        return _security_cache
    catalog_dir = _find_catalog_dir()
    security_file = catalog_dir / "security.yaml"
    try:
        with open(security_file, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise RuntimeError(
            f"Failed to load security policy from {security_file}: {e}. "
            "Security policy is required — cannot start with empty denylists."
        ) from e
    _security_cache = {
        "dangerous_flags": set(doc.get("dangerous_flags", [])),
        "tool_allowed_flags": {
            k: set(v) for k, v in doc.get("tool_allowed_flags", {}).items()
        },
        "tool_blocked_flags": {
            k: set(v) for k, v in doc.get("tool_blocked_flags", {}).items()
        },
        "denied_binaries": frozenset(doc.get("denied_binaries", [])),
        "output_flags": frozenset(doc.get("output_flags", [])),
        "tool_output_flags": {
            k: frozenset(v) for k, v in (doc.get("tool_output_flags") or {}).items()
        },
        "tool_switch_flags": {
            k: frozenset(v) for k, v in (doc.get("tool_switch_flags") or {}).items()
        },
    }
    return _security_cache


def clear_catalog_cache() -> None:
    """Clear catalog cache (for testing)."""
    global _CATALOG_DIR, _security_cache
    _catalog_cache.clear()
    _CATALOG_DIR = None
    _security_cache = None
