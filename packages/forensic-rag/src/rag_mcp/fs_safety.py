#!/usr/bin/env python3
"""
Filesystem Safety Module - Guarded filesystem operations.

This module provides safe wrappers for destructive filesystem operations
to prevent accidental deletion of important data. All destructive operations
(rmtree, unlink) require:

1. Path is within an allowed root directory
2. Path is not a forbidden system path
3. Directory contains a sentinel file (.rag_mcp_managed)

Usage:
    from rag_mcp.fs_safety import safe_rmtree, safe_mkdir, create_sentinel

    # Create a managed directory
    safe_mkdir(some_path, root=DATA_ROOT)
    create_sentinel(some_path)

    # Later, safely remove it
    safe_rmtree(some_path, root=DATA_ROOT)  # Only works if sentinel exists
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Optional

from .constants import (
    DATA_ROOT,
    FORBIDDEN_PATHS,
    MANAGED_SENTINEL,
    MIN_DELETE_DEPTH,
)

logger = logging.getLogger(__name__)


class FilesystemSafetyError(Exception):
    """Raised when a filesystem operation violates safety rules."""
    pass


class PathNotWithinRootError(FilesystemSafetyError):
    """Raised when a path is not within the allowed root."""
    pass


class ForbiddenPathError(FilesystemSafetyError):
    """Raised when attempting to operate on a forbidden path."""
    pass


class MissingSentinelError(FilesystemSafetyError):
    """Raised when a directory lacks the required sentinel file."""
    pass


class PathTooShallowError(FilesystemSafetyError):
    """Raised when a path is too shallow (close to filesystem root)."""
    pass


def resolve_strict(path: Path) -> Path:
    """
    Resolve a path strictly, following symlinks and normalizing.

    Args:
        path: Path to resolve

    Returns:
        Fully resolved, absolute path

    Raises:
        FilesystemSafetyError: If path cannot be resolved
    """
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise FilesystemSafetyError(f"Cannot resolve path {path}: {e}")


def is_within(child: Path, parent: Path) -> bool:
    """
    Check if child path is within parent path.

    Both paths are resolved before comparison to handle symlinks.

    Args:
        child: Potential child path
        parent: Potential parent path

    Returns:
        True if child is within parent (or equal to parent)
    """
    try:
        child_resolved = resolve_strict(child)
        parent_resolved = resolve_strict(parent)
        # Use os.path.commonpath for reliable comparison
        return os.path.commonpath([child_resolved, parent_resolved]) == str(parent_resolved)
    except (ValueError, OSError):
        return False


def get_path_depth(path: Path) -> int:
    """
    Get the depth of a path (number of components).

    Args:
        path: Path to measure

    Returns:
        Number of path components
    """
    resolved = resolve_strict(path)
    return len(resolved.parts)


def is_forbidden_path(path: Path) -> bool:
    """
    Check if a path is in the forbidden paths list.

    Args:
        path: Path to check

    Returns:
        True if path is forbidden
    """
    resolved = resolve_strict(path)
    return resolved in FORBIDDEN_PATHS


def require_within_root(
    path: Path,
    root: Path,
    *,
    label: str = "path"
) -> Path:
    """
    Validate that a path is within a root directory.

    Args:
        path: Path to validate
        root: Root directory that must contain path
        label: Human-readable label for error messages

    Returns:
        Resolved path if valid

    Raises:
        PathNotWithinRootError: If path is not within root
        ForbiddenPathError: If path is a forbidden system path
    """
    resolved = resolve_strict(path)
    root_resolved = resolve_strict(root)

    if is_forbidden_path(resolved):
        raise ForbiddenPathError(
            f"{label} '{resolved}' is a forbidden system path"
        )

    if not is_within(resolved, root_resolved):
        raise PathNotWithinRootError(
            f"{label} '{resolved}' is not within root '{root_resolved}'"
        )

    return resolved


def require_sentinel(
    directory: Path,
    sentinel_name: str = MANAGED_SENTINEL
) -> None:
    """
    Require that a directory contains the managed sentinel file.

    Args:
        directory: Directory to check
        sentinel_name: Name of sentinel file to look for

    Raises:
        MissingSentinelError: If sentinel file is not present
        NotADirectoryError: If path is not a directory
    """
    resolved = resolve_strict(directory)

    if not resolved.is_dir():
        raise NotADirectoryError(f"Not a directory: {resolved}")

    sentinel_path = resolved / sentinel_name
    if not sentinel_path.exists():
        raise MissingSentinelError(
            f"Directory '{resolved}' is not managed by rag-mcp "
            f"(missing sentinel file '{sentinel_name}'). "
            f"Refusing to delete for safety."
        )


def create_sentinel(
    directory: Path,
    sentinel_name: str = MANAGED_SENTINEL
) -> Path:
    """
    Create a sentinel file in a directory to mark it as managed.

    Args:
        directory: Directory to mark as managed
        sentinel_name: Name of sentinel file to create

    Returns:
        Path to created sentinel file
    """
    resolved = resolve_strict(directory)
    sentinel_path = resolved / sentinel_name

    if not resolved.exists():
        raise FileNotFoundError(f"Directory does not exist: {resolved}")

    sentinel_path.touch()
    logger.debug(f"Created sentinel file: {sentinel_path}")
    return sentinel_path


def safe_mkdir(
    directory: Path,
    root: Optional[Path] = None,
    *,
    parents: bool = True,
    exist_ok: bool = True,
    create_sentinel: bool = True
) -> Path:
    """
    Safely create a directory within an allowed root.

    Args:
        directory: Directory to create
        root: Root directory that must contain the new directory
              (defaults to DATA_ROOT)
        parents: Create parent directories as needed
        exist_ok: Don't raise if directory already exists
        create_sentinel: Create sentinel file after creation

    Returns:
        Path to created directory

    Raises:
        PathNotWithinRootError: If directory would be outside root
        ForbiddenPathError: If directory is a forbidden path
    """
    if root is None:
        root = DATA_ROOT

    resolved = require_within_root(directory, root, label="directory")
    resolved.mkdir(parents=parents, exist_ok=exist_ok)

    if create_sentinel:
        sentinel_path = resolved / MANAGED_SENTINEL
        if not sentinel_path.exists():
            sentinel_path.touch()
            logger.debug(f"Created sentinel in: {resolved}")

    return resolved


def safe_rmtree(
    directory: Path,
    root: Optional[Path] = None,
    *,
    require_sentinel_file: bool = True,
    missing_ok: bool = False
) -> bool:
    """
    Safely remove a directory tree with multiple safety checks.

    Safety checks:
    1. Path must be within the specified root
    2. Path must not be a forbidden system path
    3. Path must be deep enough (MIN_DELETE_DEPTH)
    4. Directory must contain sentinel file (if require_sentinel_file=True)

    Args:
        directory: Directory to remove
        root: Root directory that must contain the target
              (defaults to DATA_ROOT)
        require_sentinel_file: Require sentinel file to exist
        missing_ok: Don't raise if directory doesn't exist

    Returns:
        True if directory was deleted, False if it didn't exist

    Raises:
        PathNotWithinRootError: If directory is not within root
        ForbiddenPathError: If directory is a forbidden path
        MissingSentinelError: If sentinel file is missing
        PathTooShallowError: If path is too shallow
    """
    if root is None:
        root = DATA_ROOT

    resolved = resolve_strict(directory)

    # Check if directory exists
    if not resolved.exists():
        if missing_ok:
            logger.debug(f"Directory does not exist (skipping): {resolved}")
            return False
        raise FileNotFoundError(f"Directory does not exist: {resolved}")

    # Safety check 1: Must be within root
    require_within_root(resolved, root, label="directory")

    # Safety check 2: Must not be forbidden
    if is_forbidden_path(resolved):
        raise ForbiddenPathError(
            f"Refusing to delete forbidden path: {resolved}"
        )

    # Safety check 3: Must be deep enough
    depth = get_path_depth(resolved)
    if depth < MIN_DELETE_DEPTH:
        raise PathTooShallowError(
            f"Path '{resolved}' is too shallow (depth {depth}, minimum {MIN_DELETE_DEPTH}). "
            f"Refusing to delete for safety."
        )

    # Safety check 4: Must have sentinel file
    if require_sentinel_file:
        require_sentinel(resolved)

    # All checks passed - safe to delete
    logger.info(f"Deleting managed directory: {resolved}")
    shutil.rmtree(resolved)
    return True


def safe_unlink(
    file_path: Path,
    root: Optional[Path] = None,
    *,
    missing_ok: bool = False
) -> bool:
    """
    Safely delete a single file within an allowed root.

    Args:
        file_path: File to delete
        root: Root directory that must contain the file
              (defaults to DATA_ROOT)
        missing_ok: Don't raise if file doesn't exist

    Returns:
        True if file was deleted, False if it didn't exist

    Raises:
        PathNotWithinRootError: If file is not within root
        ForbiddenPathError: If file is in a forbidden path
        IsADirectoryError: If path is a directory (use safe_rmtree)
    """
    if root is None:
        root = DATA_ROOT

    resolved = resolve_strict(file_path)

    if not resolved.exists():
        if missing_ok:
            return False
        raise FileNotFoundError(f"File does not exist: {resolved}")

    if resolved.is_dir():
        raise IsADirectoryError(
            f"Cannot unlink directory '{resolved}'. Use safe_rmtree instead."
        )

    require_within_root(resolved, root, label="file")

    logger.debug(f"Deleting file: {resolved}")
    resolved.unlink()
    return True
