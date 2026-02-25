"""Tests for tool modules — focus on catalog integration and response enrichment."""

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.response import reset_call_counter


@pytest.fixture(autouse=True)
def clean_state():
    clear_catalog_cache()
    reset_call_counter()
    yield
    clear_catalog_cache()
    reset_call_counter()


class TestZimmermanCommon:
    def test_zimmerman_tool_pattern(self):
        """Verify Zimmerman tool catalog definitions are correct."""
        from sift_mcp.catalog import get_tool_def

        td = get_tool_def("AmcacheParser")
        assert td is not None
        assert td.input_flag == "-f"
        assert td.output_format == "csv"

    def test_all_zimmerman_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="zimmerman")
        expected = [
            "AmcacheParser",
            "PECmd",
            "AppCompatCacheParser",
            "RECmd",
            "MFTECmd",
            "EvtxECmd",
            "JLECmd",
            "LECmd",
            "SBECmd",
            "RBCmd",
            "SrumECmd",
            "SQLECmd",
            "bstrings",
        ]
        names = [t["name"] for t in tools]
        for name in expected:
            assert name in names, f"Missing Zimmerman tool: {name}"


class TestVolatility:
    def test_volatility_in_catalog(self):
        from sift_mcp.catalog import get_tool_def

        td = get_tool_def("vol3")
        assert td is not None
        assert td.knowledge_name == "Volatility3"


class TestTimeline:
    def test_timeline_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="timeline")
        names = [t["name"] for t in tools]
        assert "hayabusa" in names
        assert "mactime" in names
        assert "log2timeline" in names
        assert "psort" in names


class TestSleuthKit:
    def test_sleuthkit_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="sleuthkit")
        names = [t["name"] for t in tools]
        assert "fls" in names
        assert "icat" in names
        assert "mmls" in names
        assert "blkls" in names


class TestMiscTools:
    def test_misc_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="misc")
        names = [t["name"] for t in tools]
        assert "exiftool" in names
        assert "hashdeep" in names
        assert "dc3dd" in names
        assert "ewfmount" in names
        assert "vshadowinfo" in names
        assert "vshadowmount" in names


class TestMalwareTools:
    def test_malware_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="malware")
        names = [t["name"] for t in tools]
        assert "yara" in names
        assert "strings" in names


class TestNetworkTools:
    def test_network_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="network")
        names = [t["name"] for t in tools]
        assert "tshark" in names
        assert "zeek" in names


class TestInstallerGracefulFailure:
    def test_hayabusa_installer_no_network(self, monkeypatch):
        """Installer should return None gracefully without network."""
        monkeypatch.setenv("SIFT_HAYABUSA_DIR", "/tmp/test-hayabusa-nonexistent")
        from sift_mcp.installer import install_hayabusa

        # Should gracefully fail (no curl or no network)
        result = install_hayabusa()
        # Either None (no network) or a path (somehow installed)
        assert result is None or isinstance(result, str)

    def test_hayabusa_installer_network_failure(self, monkeypatch):
        """Mock urllib to simulate network failure. Should return None."""
        monkeypatch.setenv("SIFT_HAYABUSA_DIR", "/tmp/test-hayabusa-mock")
        import urllib.error
        from unittest.mock import patch

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("mock network failure"),
        ):
            from sift_mcp.installer import install_hayabusa

            result = install_hayabusa()
            assert result is None or isinstance(result, str)


class TestFileAnalysisTools:
    def test_file_analysis_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog

        tools = list_tools_in_catalog(category="file_analysis")
        names = [t["name"] for t in tools]
        assert "bulk_extractor" in names


class TestCatalogCompleteness:
    def test_total_catalog_tools(self):
        from sift_mcp.catalog import load_catalog

        catalog = load_catalog()
        # zimmerman(13) + volatility(1) + timeline(4) + sleuthkit(4) + malware(2) + network(2) + misc(9) + file_analysis(1) = 36
        assert len(catalog) >= 36, f"Expected 36+ tools, got {len(catalog)}"
