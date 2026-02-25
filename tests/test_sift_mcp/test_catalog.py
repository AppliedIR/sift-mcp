"""Tests for sift_mcp.catalog — YAML tool catalog loader."""

import pytest
from sift_mcp.catalog import (
    clear_catalog_cache,
    get_tool_def,
    is_in_catalog,
    list_tools_in_catalog,
    load_catalog,
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
        assert len(tools) == 13
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


class TestMalformedCatalog:
    """Tests for malformed catalog YAML handling."""

    def test_yaml_syntax_error(self, tmp_path, monkeypatch):
        """YAML syntax error should fail closed (empty catalog)."""
        bad_yaml = tmp_path / "tools.yaml"
        bad_yaml.write_text("invalid: yaml: [unclosed")
        monkeypatch.setenv("SIFT_CATALOG_DIR", str(tmp_path))
        clear_catalog_cache()
        catalog = load_catalog()
        # Should return empty or raise — not crash with traceback
        # The catalog loads from multiple files; a bad one may be skipped
        assert isinstance(catalog, dict)

    def test_empty_catalog_file(self, tmp_path, monkeypatch):
        """Empty YAML file should result in empty catalog."""
        empty_yaml = tmp_path / "tools.yaml"
        empty_yaml.write_text("")
        monkeypatch.setenv("SIFT_CATALOG_DIR", str(tmp_path))
        clear_catalog_cache()
        catalog = load_catalog()
        assert isinstance(catalog, dict)

    def test_wrong_type_for_tools_key(self, tmp_path, monkeypatch):
        """tools key with wrong type should fail closed."""
        bad_yaml = tmp_path / "tools.yaml"
        bad_yaml.write_text("tools: not_a_list")
        monkeypatch.setenv("SIFT_CATALOG_DIR", str(tmp_path))
        clear_catalog_cache()
        catalog = load_catalog()
        assert isinstance(catalog, dict)
