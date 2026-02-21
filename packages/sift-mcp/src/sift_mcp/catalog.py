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
    input_style: str = "flag"       # flag, positional, stdin
    input_flag: str = ""            # e.g. "-f" for input file
    output_format: str = "text"     # csv, json, text
    timeout_seconds: int = 600
    interactive: bool = False
    description: str = ""
    common_flags: list[dict] = field(default_factory=list)
    # FK tool name for knowledge lookup (defaults to binary name)
    fk_tool_name: str = ""

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
        logger.warning("Permission denied reading catalog directory %s: %s", catalog_dir, e)
        return _catalog_cache

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning("Failed to parse catalog YAML %s: %s", yaml_file, e)
            continue
        except OSError as e:
            logger.warning("Failed to read catalog file %s: %s", yaml_file, e)
            continue

        if not doc:
            continue

        category = doc.get("category", yaml_file.stem)
        for tool_entry in doc.get("tools", []):
            name = tool_entry.get("name")
            if not name:
                logger.warning("Tool entry in %s missing 'name' field, skipping", yaml_file)
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
                common_flags=tool_entry.get("common_flags", []),
                fk_tool_name=tool_entry.get("fk_tool_name", ""),
            )
            _catalog_cache[name.lower()] = td

    return _catalog_cache


def get_tool_def(name: str) -> ToolDefinition | None:
    """Look up a tool by name (case-insensitive)."""
    catalog = load_catalog()
    return catalog.get(name.lower())


def list_tools_in_catalog(category: str | None = None) -> list[dict]:
    """List catalog tools, optionally by category."""
    catalog = load_catalog()
    results = []
    for td in catalog.values():
        if category and td.category != category:
            continue
        results.append({
            "name": td.name,
            "binary": td.binary,
            "category": td.category,
            "description": td.description,
        })
    return results


def is_in_catalog(binary_name: str) -> bool:
    """Check if a binary is approved in the catalog."""
    catalog = load_catalog()
    return any(td.binary.lower() == binary_name.lower() for td in catalog.values())


def clear_catalog_cache() -> None:
    """Clear catalog cache (for testing)."""
    global _CATALOG_DIR
    _catalog_cache.clear()
    _CATALOG_DIR = None
