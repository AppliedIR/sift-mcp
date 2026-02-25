"""Tests for sift_mcp.environment."""

from sift_mcp.environment import find_binary, get_environment_info, is_wsl


class TestEnvironment:
    def test_is_wsl_returns_bool(self):
        assert isinstance(is_wsl(), bool)

    def test_get_environment_info(self):
        info = get_environment_info()
        assert "wsl" in info
        assert "platform" in info
        assert "python" in info

    def test_find_binary_ls(self):
        """ls should always be findable on Linux."""
        assert find_binary("ls") is not None

    def test_find_binary_nonexistent(self):
        assert find_binary("definitely_not_a_real_binary_xyz") is None
