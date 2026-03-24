"""Shared utilities for SIFT-platform MCP servers."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_case_dir() -> str:
    """Resolve the active case directory.

    Resolution order: VHIR_CASE_DIR env var → ~/.vhir/active_case file → "".
    VHIR_CASE_DIR must be a directory containing CASE.yaml to be valid.
    If set but invalid, falls through to active_case.
    """
    case_dir = os.environ.get("VHIR_CASE_DIR", "").strip()
    if case_dir:
        p = Path(case_dir)
        if p.is_dir() and (p / "CASE.yaml").exists():
            return case_dir
        # Set but invalid — fall through to active_case
    active_file = Path.home() / ".vhir" / "active_case"
    if active_file.is_file():
        try:
            content = active_file.read_text().strip()
        except OSError:
            return ""
        if content:
            p = Path(content)
            if p.is_dir() and (p / "CASE.yaml").exists():
                return content
    return ""


def resolve_share_path(relative_path: str) -> Path | None:
    """Resolve a share-relative extraction path to a local mount point.

    When wintools-mcp writes an extraction file, it strips the VHIR_SHARE_ROOT
    prefix to produce a share-relative path (e.g., "extractions/output.csv").
    On the SIFT side, VHIR_SHARE_ROOT points to where the same SMB share is
    mounted locally (e.g., /mnt/wintools). This function joins the two to
    produce the full local path.

    Returns None if VHIR_SHARE_ROOT is not set.
    """
    share_root = os.environ.get("VHIR_SHARE_ROOT", "")
    if not share_root:
        return None
    return Path(share_root) / relative_path
