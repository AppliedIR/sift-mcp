"""Tests for sift_mcp.tools.generic — catalog-gated execution."""

import pytest
from sift_mcp.tools.generic import run_command
from sift_mcp.exceptions import ToolNotInCatalogError
from sift_mcp.catalog import clear_catalog_cache


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestGenericRunCommand:
    def test_rejects_uncataloged_binary(self):
        with pytest.raises(ToolNotInCatalogError, match="not in the approved"):
            run_command(["rm", "-rf", "/"])

    def test_rejects_common_shell_commands(self):
        with pytest.raises(ToolNotInCatalogError):
            run_command(["bash", "-c", "echo hi"])

    def test_rejects_empty_command(self):
        with pytest.raises(ValueError, match="Empty command"):
            run_command([])

    def test_strips_path_prefix(self):
        """Binary with full path should still be checked against catalog."""
        with pytest.raises(ToolNotInCatalogError):
            run_command(["/usr/bin/rm", "file"])
