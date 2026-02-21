#!/usr/bin/env python3
"""
Tests for filesystem safety module.

These tests verify that safe_rmtree and related functions properly
prevent accidental deletion of important directories.
"""

import os
import tempfile
from pathlib import Path

import pytest

from rag_mcp.fs_safety import (
    FilesystemSafetyError,
    ForbiddenPathError,
    MissingSentinelError,
    PathNotWithinRootError,
    PathTooShallowError,
    create_sentinel,
    get_path_depth,
    is_forbidden_path,
    is_within,
    require_sentinel,
    require_within_root,
    resolve_strict,
    safe_mkdir,
    safe_rmtree,
    safe_unlink,
)
from rag_mcp.constants import MANAGED_SENTINEL, MIN_DELETE_DEPTH


class TestResolveStrict:
    """Tests for resolve_strict function."""

    def test_resolves_absolute_path(self, tmp_path):
        """Absolute paths are resolved correctly."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        resolved = resolve_strict(test_dir)
        assert resolved.is_absolute()
        assert resolved == test_dir.resolve()

    def test_resolves_relative_path(self, tmp_path):
        """Relative paths are resolved to absolute."""
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            (tmp_path / "subdir").mkdir()
            resolved = resolve_strict(Path("subdir"))
            assert resolved.is_absolute()
            assert str(resolved).endswith("subdir")
        finally:
            os.chdir(original_cwd)


class TestIsWithin:
    """Tests for is_within function."""

    def test_child_is_within_parent(self, tmp_path):
        """Child directory is within parent."""
        parent = tmp_path / "parent"
        child = parent / "child"
        parent.mkdir()
        child.mkdir()
        assert is_within(child, parent) is True

    def test_parent_not_within_child(self, tmp_path):
        """Parent directory is not within child."""
        parent = tmp_path / "parent"
        child = parent / "child"
        parent.mkdir()
        child.mkdir()
        assert is_within(parent, child) is False

    def test_same_path_is_within(self, tmp_path):
        """A path is within itself."""
        assert is_within(tmp_path, tmp_path) is True

    def test_sibling_not_within(self, tmp_path):
        """Sibling directories are not within each other."""
        sibling1 = tmp_path / "sibling1"
        sibling2 = tmp_path / "sibling2"
        sibling1.mkdir()
        sibling2.mkdir()
        assert is_within(sibling1, sibling2) is False


class TestIsForbiddenPath:
    """Tests for is_forbidden_path function."""

    def test_root_is_forbidden(self):
        """Root path is forbidden."""
        assert is_forbidden_path(Path("/")) is True

    def test_home_is_forbidden(self):
        """Home directory is forbidden."""
        assert is_forbidden_path(Path.home()) is True

    def test_tmp_path_not_forbidden(self, tmp_path):
        """Temp paths are not forbidden."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        assert is_forbidden_path(test_dir) is False


class TestRequireWithinRoot:
    """Tests for require_within_root function."""

    def test_valid_path_within_root(self, tmp_path):
        """Valid path within root succeeds."""
        root = tmp_path / "root"
        child = root / "child"
        root.mkdir()
        child.mkdir()
        result = require_within_root(child, root)
        assert result == child.resolve()

    def test_path_outside_root_raises(self, tmp_path):
        """Path outside root raises PathNotWithinRootError."""
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        with pytest.raises(PathNotWithinRootError):
            require_within_root(outside, root)

    def test_forbidden_path_raises(self):
        """Forbidden paths raise ForbiddenPathError."""
        with pytest.raises(ForbiddenPathError):
            require_within_root(Path("/"), Path("/"))


class TestRequireSentinel:
    """Tests for require_sentinel function."""

    def test_sentinel_present_succeeds(self, tmp_path):
        """Directory with sentinel succeeds."""
        (tmp_path / MANAGED_SENTINEL).touch()
        require_sentinel(tmp_path)  # Should not raise

    def test_missing_sentinel_raises(self, tmp_path):
        """Directory without sentinel raises MissingSentinelError."""
        with pytest.raises(MissingSentinelError):
            require_sentinel(tmp_path)

    def test_not_directory_raises(self, tmp_path):
        """File path raises NotADirectoryError."""
        file_path = tmp_path / "file.txt"
        file_path.touch()
        with pytest.raises(NotADirectoryError):
            require_sentinel(file_path)


class TestCreateSentinel:
    """Tests for create_sentinel function."""

    def test_creates_sentinel_file(self, tmp_path):
        """Sentinel file is created."""
        result = create_sentinel(tmp_path)
        assert result.exists()
        assert result.name == MANAGED_SENTINEL

    def test_nonexistent_directory_raises(self, tmp_path):
        """Non-existent directory raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError):
            create_sentinel(nonexistent)


class TestSafeMkdir:
    """Tests for safe_mkdir function."""

    def test_creates_directory_with_sentinel(self, tmp_path):
        """Directory is created with sentinel."""
        new_dir = tmp_path / "new_dir"
        result = safe_mkdir(new_dir, root=tmp_path)
        assert result.exists()
        assert (result / MANAGED_SENTINEL).exists()

    def test_creates_nested_directories(self, tmp_path):
        """Nested directories are created."""
        nested = tmp_path / "a" / "b" / "c"
        result = safe_mkdir(nested, root=tmp_path)
        assert result.exists()

    def test_outside_root_raises(self, tmp_path):
        """Directory outside root raises error."""
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        with pytest.raises(PathNotWithinRootError):
            safe_mkdir(outside, root=root)


class TestSafeRmtree:
    """Tests for safe_rmtree function."""

    def test_deletes_managed_directory(self, tmp_path):
        """Managed directory is deleted."""
        # Create a deep enough path
        root = tmp_path
        managed = root / "a" / "b" / "c" / "managed"
        managed.mkdir(parents=True)
        (managed / MANAGED_SENTINEL).touch()
        (managed / "file.txt").touch()

        result = safe_rmtree(managed, root=root)
        assert result is True
        assert not managed.exists()

    def test_missing_sentinel_raises(self, tmp_path):
        """Directory without sentinel raises error."""
        root = tmp_path
        unmanaged = root / "a" / "b" / "c" / "unmanaged"
        unmanaged.mkdir(parents=True)

        with pytest.raises(MissingSentinelError):
            safe_rmtree(unmanaged, root=root)

    def test_outside_root_raises(self, tmp_path):
        """Directory outside root raises error."""
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        (outside / MANAGED_SENTINEL).touch()

        with pytest.raises(PathNotWithinRootError):
            safe_rmtree(outside, root=root)

    def test_shallow_path_raises(self, tmp_path):
        """Shallow paths raise PathTooShallowError."""
        # tmp_path itself is usually shallow
        (tmp_path / MANAGED_SENTINEL).touch()

        # The path depth check should fail for shallow paths
        depth = get_path_depth(tmp_path)
        if depth < MIN_DELETE_DEPTH:
            with pytest.raises(PathTooShallowError):
                safe_rmtree(tmp_path, root=tmp_path)

    def test_missing_ok_returns_false(self, tmp_path):
        """Non-existent directory with missing_ok returns False."""
        nonexistent = tmp_path / "a" / "b" / "c" / "nonexistent"
        result = safe_rmtree(nonexistent, root=tmp_path, missing_ok=True)
        assert result is False

    def test_missing_not_ok_raises(self, tmp_path):
        """Non-existent directory without missing_ok raises."""
        nonexistent = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError):
            safe_rmtree(nonexistent, root=tmp_path)

    def test_root_path_is_forbidden(self):
        """Cannot delete root path."""
        with pytest.raises((ForbiddenPathError, PathNotWithinRootError)):
            safe_rmtree(Path("/"), root=Path("/"))

    def test_home_path_is_forbidden(self):
        """Cannot delete home directory."""
        home = Path.home()
        with pytest.raises((ForbiddenPathError, PathNotWithinRootError)):
            safe_rmtree(home, root=home)


class TestSafeUnlink:
    """Tests for safe_unlink function."""

    def test_deletes_file_within_root(self, tmp_path):
        """File within root is deleted."""
        file_path = tmp_path / "file.txt"
        file_path.touch()
        result = safe_unlink(file_path, root=tmp_path)
        assert result is True
        assert not file_path.exists()

    def test_outside_root_raises(self, tmp_path):
        """File outside root raises error."""
        root = tmp_path / "root"
        outside = tmp_path / "outside.txt"
        root.mkdir()
        outside.touch()

        with pytest.raises(PathNotWithinRootError):
            safe_unlink(outside, root=root)

    def test_directory_raises(self, tmp_path):
        """Directory raises IsADirectoryError."""
        with pytest.raises(IsADirectoryError):
            safe_unlink(tmp_path, root=tmp_path)

    def test_missing_ok_returns_false(self, tmp_path):
        """Non-existent file with missing_ok returns False."""
        nonexistent = tmp_path / "nonexistent.txt"
        result = safe_unlink(nonexistent, root=tmp_path, missing_ok=True)
        assert result is False


class TestSymlinkSafety:
    """Tests for symlink attack prevention."""

    def test_symlink_escape_blocked(self, tmp_path):
        """Symlink pointing outside root is blocked."""
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        (outside / MANAGED_SENTINEL).touch()

        # Create symlink inside root pointing to outside
        symlink = root / "escape"
        symlink.symlink_to(outside)

        # Should fail because resolved path is outside root
        with pytest.raises(PathNotWithinRootError):
            safe_rmtree(symlink, root=root)


class TestPathDepth:
    """Tests for get_path_depth function."""

    def test_root_depth(self):
        """Root has depth 1."""
        assert get_path_depth(Path("/")) == 1

    def test_nested_depth(self, tmp_path):
        """Nested paths have correct depth."""
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        depth = get_path_depth(nested)
        # Should be tmp_path depth + 3
        assert depth == get_path_depth(tmp_path) + 3
