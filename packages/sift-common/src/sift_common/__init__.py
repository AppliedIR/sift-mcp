"""Shared utilities for SIFT-platform MCP servers."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_share_path(relative_path: str) -> Path | None:
    """Resolve a share-relative extraction path to a local mount point.

    When wintools-mcp writes an extraction file, it strips the AIIR_SHARE_ROOT
    prefix to produce a share-relative path (e.g., "extractions/output.csv").
    On the SIFT side, AIIR_SHARE_ROOT points to where the same SMB share is
    mounted locally (e.g., /mnt/wintools). This function joins the two to
    produce the full local path.

    Returns None if AIIR_SHARE_ROOT is not set.
    """
    share_root = os.environ.get("AIIR_SHARE_ROOT", "")
    if not share_root:
        return None
    return Path(share_root) / relative_path
