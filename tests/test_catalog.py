"""Tests for sift_mcp.catalog — YAML tool catalog loader."""

import pytest
from sift_mcp.catalog import (
    load_catalog, get_tool_def, list_tools_in_catalog,
    is_in_catalog, clear_catalog_cache, ToolDefinition,
)


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestCatalogLoading:
    def test_load_catalog(self):
        catalog = load_catalog()
        assert len(catalog) >= 15  # zimmerman(12) + vol(1) + timeline(3)

    def test_get_tool_def_amcacheparser(self):
        td = get_tool_def("AmcacheParser")
        assert td is not None
        assert td.binary == "AmcacheParser"
        assert td.category == "zimmerman"
        assert td.output_format == "csv"
        assert td.input_flag == "-f"

    def test_get_tool_def_case_insensitive(self):
        td = get_tool_def("amcacheparser")
        assert td is not None
        assert td.name == "AmcacheParser"

    def test_get_tool_def_missing(self):
        assert get_tool_def("nonexistent_tool") is None

    def test_list_tools_all(self):
        tools = list_tools_in_catalog()
        assert len(tools) >= 15
        names = [t["name"] for t in tools]
        assert "AmcacheParser" in names

    def test_list_tools_by_category(self):
        tools = list_tools_in_catalog(category="zimmerman")
        assert len(tools) == 12
        assert all(t["category"] == "zimmerman" for t in tools)

    def test_is_in_catalog(self):
        assert is_in_catalog("AmcacheParser") is True
        assert is_in_catalog("rm") is False

    def test_tool_definition_knowledge_name(self):
        td = get_tool_def("AmcacheParser")
        assert td.knowledge_name == "AmcacheParser"

    def test_volatility_in_catalog(self):
        td = get_tool_def("vol3")
        assert td is not None
        assert td.category == "volatility"
        assert td.knowledge_name == "Volatility3"

    def test_hayabusa_in_catalog(self):
        td = get_tool_def("hayabusa")
        assert td is not None
        assert td.category == "timeline"
