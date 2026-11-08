#!/usr/bin/env python3
"""
Project constants and path definitions.

Central location for project-wide constants, paths, and sentinel values.
All modules should derive paths from these constants rather than
computing them independently.
"""

from __future__ import annotations

import os
from pathlib import Path

# =============================================================================
# Project Structure
# =============================================================================

# Project root: two levels up from this file (src/rag_mcp/constants.py)
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Knowledge directory (can be overridden via RAG_KNOWLEDGE_DIR)
KNOWLEDGE_ROOT = Path(
    os.environ.get("RAG_KNOWLEDGE_DIR", PROJECT_ROOT / "knowledge")
).resolve()

# =============================================================================
# Managed Directory Sentinel
# =============================================================================

# Sentinel filename placed in directories managed by this project.
# safe_rmtree() requires this file to exist before deleting a directory.
# This prevents accidental deletion of arbitrary directories.
MANAGED_SENTINEL = ".rag_mcp_managed"

# =============================================================================
# Subdirectory Names
# =============================================================================

CHROMA_DIR_NAME = "chroma"
SOURCES_DIR_NAME = "sources"

# =============================================================================
# Release Bundle
# =============================================================================

# The one list of what a release bundle holds, paths under the data dir. The
# release build packs each and fails naming one that is missing; the install
# admits only these (and what lies under them).
BUNDLE_MEMBERS: tuple[str, ...] = (
    "chroma",
    "sources",
    "metadata.json",
    "user_state.json",
    "sources_state.json",
)

# =============================================================================
# Safety Boundaries
# =============================================================================

# Paths that should NEVER be deleted, even with --unsafe-paths
FORBIDDEN_PATHS = frozenset(
    [
        Path("/"),
        Path("/home"),
        Path("/root"),
        Path("/tmp"),
        Path("/var"),
        Path("/etc"),
        Path("/usr"),
        Path.home(),
        PROJECT_ROOT,  # Never delete the project itself
    ]
)

# Minimum path depth required for deletion (prevents deleting shallow paths)
MIN_DELETE_DEPTH = 3  # e.g., /path/to/project/data/chroma = depth 6
