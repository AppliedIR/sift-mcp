"""YAML knowledge loader with in-memory caching.

Loads artifact, tool, and discipline YAML from the bundled data/ directory.
Uses importlib.resources to locate files within the installed package,
with a fallback to the source tree for development.
"""

from __future__ import annotations

import importlib.resources
import os
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Data directory resolution
# ---------------------------------------------------------------------------

_DATA_DIR: Path | None = None


def _find_data_dir() -> Path:
    """Locate the data/ directory — installed package or source tree."""
    global _DATA_DIR
    if _DATA_DIR is not None:
        return _DATA_DIR

    # 1. Explicit env override (for testing)
    env_path = os.environ.get("FK_DATA_DIR")
    if env_path:
        p = Path(env_path)
        if p.is_dir():
            _DATA_DIR = p
            return _DATA_DIR

    # 2. Relative to this file (source tree layout: src/forensic_knowledge/loader.py → ../../data/)
    source_data = Path(__file__).resolve().parent.parent.parent / "data"
    if source_data.is_dir():
        _DATA_DIR = source_data
        return _DATA_DIR

    # 3. importlib.resources (installed package — shared-data lands in site-packages)
    try:
        ref = importlib.resources.files("forensic_knowledge") / "data"
        p = Path(str(ref))
        if p.is_dir():
            _DATA_DIR = p
            return _DATA_DIR
    except (TypeError, FileNotFoundError):
        pass

    raise FileNotFoundError(
        "Cannot find forensic-knowledge data directory. "
        "Set FK_DATA_DIR or install the package."
    )


# ---------------------------------------------------------------------------
# YAML cache
# ---------------------------------------------------------------------------

_cache: dict[str, Any] = {}


def _load_yaml(rel_path: str) -> Any:
    """Load a YAML file relative to the data directory, with caching."""
    if rel_path in _cache:
        return _cache[rel_path]

    full_path = _find_data_dir() / rel_path
    if not full_path.exists():
        return None

    with open(full_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    _cache[rel_path] = data
    return data


def _load_all_in_dir(rel_dir: str) -> list[Any]:
    """Load all YAML files in a directory."""
    cache_key = f"__dir__{rel_dir}"
    if cache_key in _cache:
        return _cache[cache_key]

    data_dir = _find_data_dir() / rel_dir
    if not data_dir.is_dir():
        return []

    results = []
    for yaml_file in sorted(data_dir.glob("*.yaml")):
        with open(yaml_file, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if doc:
            results.append(doc)

    _cache[cache_key] = results
    return results


def clear_cache() -> None:
    """Clear the in-memory YAML cache."""
    global _DATA_DIR
    _cache.clear()
    _DATA_DIR = None


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _sanitize_name(name: str) -> str:
    """Validate name used in path construction. Raises ValueError on traversal."""
    if not name:
        raise ValueError("Name cannot be empty")
    if ".." in name or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError(f"Invalid name (path traversal characters): {name!r}")
    return name


# ---------------------------------------------------------------------------
# Artifact knowledge
# ---------------------------------------------------------------------------

def get_artifact(name: str) -> dict | None:
    """Load artifact knowledge by name (e.g., 'amcache')."""
    _sanitize_name(name)
    # Try platform-specific paths
    for platform in ("windows", "linux", "macos"):
        data = _load_yaml(f"artifacts/{platform}/{name}.yaml")
        if data is not None:
            return data
    return None


def list_artifacts(platform: str | None = None) -> list[dict]:
    """List artifacts, optionally filtered by platform."""
    results = []
    platforms = [platform] if platform else ["windows", "linux", "macos"]
    for plat in platforms:
        for artifact in _load_all_in_dir(f"artifacts/{plat}"):
            results.append({
                "name": artifact.get("name", ""),
                "description": artifact.get("description", ""),
                "platform": artifact.get("platform", plat),
            })
    return results


def get_artifacts_for_tool(tool_name: str) -> list[dict]:
    """Find artifacts that reference a specific tool in their related_tools."""
    results = []
    for platform in ("windows", "linux", "macos"):
        for artifact in _load_all_in_dir(f"artifacts/{platform}"):
            if tool_name in artifact.get("related_tools", []):
                results.append(artifact)
    return results


# ---------------------------------------------------------------------------
# Tool knowledge
# ---------------------------------------------------------------------------

def get_tool(name: str) -> dict | None:
    """Load tool knowledge by name (case-insensitive)."""
    name_lower = name.lower()
    for category_dir in _iter_tool_categories():
        for tool in _load_all_in_dir(f"tools/{category_dir}"):
            if tool.get("name", "").lower() == name_lower:
                return tool
    return None


def list_tools(category: str | None = None, platform: str | None = None) -> list[dict]:
    """List tools, optionally filtered by category and/or platform."""
    results = []
    categories = [category] if category else list(_iter_tool_categories())
    for cat in categories:
        for tool in _load_all_in_dir(f"tools/{cat}"):
            tool_platforms = tool.get("platform", [])
            if platform and platform not in tool_platforms:
                continue
            results.append({
                "name": tool.get("name", ""),
                "category": tool.get("category", cat),
                "description": tool.get("description", ""),
                "platform": tool_platforms,
            })
    return results


def _iter_tool_categories() -> list[str]:
    """List tool category subdirectories."""
    data_dir = _find_data_dir() / "tools"
    if not data_dir.is_dir():
        return []
    return sorted(d.name for d in data_dir.iterdir() if d.is_dir())


# ---------------------------------------------------------------------------
# Discipline knowledge
# ---------------------------------------------------------------------------

def get_rules() -> list[dict]:
    """Load all discipline rules."""
    data = _load_yaml("discipline/rules.yaml")
    return data.get("rules", []) if data else []


def get_playbook(name: str) -> dict | None:
    """Load a specific investigation playbook."""
    _sanitize_name(name)
    return _load_yaml(f"discipline/playbooks/{name}.yaml")


def list_playbooks() -> list[dict]:
    """List available playbooks."""
    results = []
    for pb in _load_all_in_dir("discipline/playbooks"):
        results.append({
            "name": pb.get("name", ""),
            "description": pb.get("description", ""),
            "phases": len(pb.get("phases", [])),
        })
    return results


def get_confidence_definitions() -> dict:
    """Load confidence level definitions."""
    data = _load_yaml("discipline/confidence.yaml")
    return data.get("levels", {}) if data else {}


def get_anti_patterns() -> list[dict]:
    """Load anti-pattern definitions."""
    data = _load_yaml("discipline/anti_patterns.yaml")
    return data.get("anti_patterns", []) if data else []


def get_evidence_standards() -> dict:
    """Load evidence classification standards."""
    data = _load_yaml("discipline/evidence_standards.yaml")
    return data.get("standards", {}) if data else {}


def get_evidence_template() -> dict:
    """Load evidence presentation template."""
    data = _load_yaml("discipline/evidence_template.yaml")
    return data.get("template", {}) if data else {}


def get_checkpoint(action_type: str) -> dict | None:
    """Load checkpoint requirements for a specific action type."""
    data = _load_yaml("discipline/checkpoints.yaml")
    if not data:
        return None
    for cp in data.get("checkpoints", []):
        if cp.get("action_type") == action_type:
            return cp
    return None


def list_checkpoints() -> list[dict]:
    """List all checkpoint action types."""
    data = _load_yaml("discipline/checkpoints.yaml")
    if not data:
        return []
    return [
        {"action_type": cp.get("action_type", ""), "description": cp.get("description", "")}
        for cp in data.get("checkpoints", [])
    ]


def get_corroboration(finding_type: str) -> list[dict] | None:
    """Load corroboration suggestions for a finding type."""
    data = _load_yaml("discipline/guidance/corroboration.yaml")
    if not data:
        return None
    return data.get("corroboration", {}).get(finding_type)


def get_false_positive_context(tool_name: str, finding_type: str) -> dict | None:
    """Load false positive context for a tool/finding combination."""
    data = _load_yaml("discipline/guidance/false_positives.yaml")
    if not data:
        return None
    key = f"{tool_name}/{finding_type}"
    return data.get("false_positives", {}).get(key)


def get_tool_interpretation(tool_name: str) -> dict | None:
    """Load tool interpretation guidance."""
    data = _load_yaml("discipline/guidance/tool_interpretation.yaml")
    if not data:
        return None
    return data.get("tools", {}).get(tool_name)


def get_collection_checklist(artifact_type: str) -> dict | None:
    """Load evidence collection checklist."""
    _sanitize_name(artifact_type)
    return _load_yaml(f"discipline/checklists/{artifact_type}.yaml")


def list_collection_checklists() -> list[str]:
    """List available collection checklists."""
    data_dir = _find_data_dir() / "discipline" / "checklists"
    if not data_dir.is_dir():
        return []
    return sorted(p.stem for p in data_dir.glob("*.yaml"))


def get_investigation_framework() -> dict | None:
    """Load the full investigation framework."""
    return _load_yaml("discipline/framework/investigation_framework.yaml")
