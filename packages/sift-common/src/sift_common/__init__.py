"""Shared utilities for SIFT-platform MCP servers."""

from __future__ import annotations

import os
from pathlib import Path

# The system's folders and Valhuntir's own keys: never read as evidence, even
# through a registered link (sift-mcp blocks them for every tool's input too)
SYSTEM_DIRS = ("/etc", "/proc", "/sys", "/dev", "/boot", "/var/lib/vhir")


def resolve_case_dir() -> str:
    """Resolve the active case directory.

    Resolution order: VHIR_CASE_DIR env var → ~/.vhir/active_case file → "".
    VHIR_CASE_DIR must be a directory containing CASE.yaml to be valid.
    If set but invalid, falls through to active_case.
    """
    from sift_common.audit import resolve_active_case

    res = resolve_active_case()
    return res.path if res.outcome == "case" else ""


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
