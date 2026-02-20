"""Tests for sift_mcp.tools.discovery."""

import pytest
from sift_mcp.tools.discovery import (
    list_available_tools, get_tool_help, check_tools, suggest_tools,
)
from sift_mcp.catalog import clear_catalog_cache


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestListTools:
    def test_list_all(self):
        tools = list_available_tools()
        assert len(tools) >= 15
        names = [t["name"] for t in tools]
        assert "AmcacheParser" in names

    def test_list_by_category(self):
        tools = list_available_tools(category="zimmerman")
        assert len(tools) == 12
        assert all(t["category"] == "zimmerman" for t in tools)

    def test_availability_field(self):
        tools = list_available_tools()
        for t in tools:
            assert "available" in t
            assert isinstance(t["available"], bool)


class TestGetToolHelp:
    def test_known_tool(self):
        help_info = get_tool_help("AmcacheParser")
        assert help_info["name"] == "AmcacheParser"
        assert "caveats" in help_info
        assert len(help_info["caveats"]) >= 1

    def test_unknown_tool(self):
        result = get_tool_help("nonexistent_tool")
        assert "error" in result


class TestCheckTools:
    def test_check_specific(self):
        result = check_tools(["AmcacheParser", "PECmd"])
        assert "AmcacheParser" in result
        assert "PECmd" in result

    def test_check_all(self):
        result = check_tools()
        assert len(result) >= 15


class TestSuggestTools:
    def test_suggest_for_amcache(self):
        suggestions = suggest_tools("amcache")
        assert len(suggestions) >= 1
        # Should include AmcacheParser
        tool_names = [s.get("tool", "") for s in suggestions]
        assert "AmcacheParser" in tool_names

    def test_suggest_includes_corroboration(self):
        suggestions = suggest_tools("amcache")
        corr = [s for s in suggestions if s.get("type") == "corroboration"]
        assert len(corr) == 1
        assert "to_confirm_execution" in corr[0]

    def test_suggest_unknown_artifact(self):
        result = suggest_tools("nonexistent_artifact")
        assert result[0].get("info") is not None
