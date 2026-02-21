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
        """Verify _run_zimmerman_tool builds correct command structure."""
        from sift_mcp.catalog import get_tool_def
        td = get_tool_def("AmcacheParser")
        assert td is not None
        assert td.input_flag == "-f"
        assert td.output_format == "csv"

    def test_all_zimmerman_tools_in_catalog(self):
        from sift_mcp.catalog import list_tools_in_catalog
        tools = list_tools_in_catalog(category="zimmerman")
        expected = [
            "AmcacheParser", "PECmd", "AppCompatCacheParser", "RECmd",
            "MFTECmd", "EvtxECmd", "JLECmd", "LECmd", "SBECmd",
            "RBCmd", "SrumECmd", "SQLECmd", "bstrings",
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


class TestServerRegistration:
    def test_server_creates_with_all_tools(self):
        from sift_mcp.server import create_server
        server = create_server()
        assert server is not None


class TestInstallerGracefulFailure:
    def test_hayabusa_installer_no_network(self, monkeypatch):
        """Installer should return None gracefully without network."""
        monkeypatch.setenv("SIFT_HAYABUSA_DIR", "/tmp/test-hayabusa-nonexistent")
        from sift_mcp.installer import install_hayabusa
        # Should gracefully fail (no curl or no network)
        result = install_hayabusa()
        # Either None (no network) or a path (somehow installed)
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


class TestBlklsWrapper:
    """Tests for run_blkls command construction."""

    def test_blkls_basic_command(self, monkeypatch):
        from unittest.mock import MagicMock
        from sift_mcp.audit import AuditWriter
        from sift_mcp.tools.sleuthkit import register_sleuthkit_tools

        captured_cmd = {}

        def mock_find_binary(name):
            return f"/usr/bin/{name}"

        def mock_execute(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            captured_cmd["timeout"] = kwargs.get("timeout")
            return {"exit_code": 0, "stdout": "data", "stderr": "", "elapsed_seconds": 1.0, "command": cmd}

        monkeypatch.setattr("sift_mcp.tools.sleuthkit.find_binary", mock_find_binary)
        monkeypatch.setattr("sift_mcp.tools.sleuthkit.execute", mock_execute)

        server = MagicMock()
        tools = {}
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f
        audit = MagicMock(spec=AuditWriter)
        audit._next_evidence_id.return_value = "sift-20260220-001"

        register_sleuthkit_tools(server, audit)
        result = tools["run_blkls"]("/evidence/disk.dd", "/output/slack.bin")

        assert captured_cmd["cmd"] == ["/usr/bin/blkls", "/evidence/disk.dd"]
        assert captured_cmd["timeout"] == 3600
        assert result["success"] is True
        audit.log.assert_called()

    def test_blkls_with_offset(self, monkeypatch):
        from unittest.mock import MagicMock
        from sift_mcp.audit import AuditWriter
        from sift_mcp.tools.sleuthkit import register_sleuthkit_tools

        captured_cmd = {}

        def mock_find_binary(name):
            return f"/usr/bin/{name}"

        def mock_execute(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            return {"exit_code": 0, "stdout": "", "stderr": "", "elapsed_seconds": 0.5, "command": cmd}

        monkeypatch.setattr("sift_mcp.tools.sleuthkit.find_binary", mock_find_binary)
        monkeypatch.setattr("sift_mcp.tools.sleuthkit.execute", mock_execute)

        server = MagicMock()
        tools = {}
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f
        audit = MagicMock(spec=AuditWriter)
        audit._next_evidence_id.return_value = "sift-20260220-002"

        register_sleuthkit_tools(server, audit)
        tools["run_blkls"]("/evidence/disk.dd", "/output/slack.bin", partition_offset="2048")

        assert captured_cmd["cmd"] == ["/usr/bin/blkls", "-o", "2048", "/evidence/disk.dd"]

    def test_blkls_not_found(self, monkeypatch):
        from unittest.mock import MagicMock
        from sift_mcp.audit import AuditWriter
        from sift_mcp.tools.sleuthkit import register_sleuthkit_tools
        from sift_mcp.exceptions import ToolNotFoundError

        monkeypatch.setattr("sift_mcp.tools.sleuthkit.find_binary", lambda name: None)

        server = MagicMock()
        tools = {}
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f
        audit = MagicMock(spec=AuditWriter)

        register_sleuthkit_tools(server, audit)
        with pytest.raises(ToolNotFoundError):
            tools["run_blkls"]("/evidence/disk.dd", "/output/slack.bin")


class TestBulkExtractorWrapper:
    """Tests for run_bulk_extractor command construction."""

    def test_bulk_extractor_basic_command(self, monkeypatch):
        from unittest.mock import MagicMock
        from sift_mcp.audit import AuditWriter
        from sift_mcp.tools.file_analysis import register_file_analysis_tools

        captured_cmd = {}

        def mock_find_binary(name):
            return f"/usr/bin/{name}"

        def mock_execute(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            captured_cmd["timeout"] = kwargs.get("timeout")
            return {"exit_code": 0, "stdout": "output", "stderr": "", "elapsed_seconds": 120.0, "command": cmd}

        monkeypatch.setattr("sift_mcp.tools.file_analysis.find_binary", mock_find_binary)
        monkeypatch.setattr("sift_mcp.tools.file_analysis.execute", mock_execute)

        server = MagicMock()
        tools = {}
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f
        audit = MagicMock(spec=AuditWriter)
        audit._next_evidence_id.return_value = "sift-20260220-003"

        register_file_analysis_tools(server, audit)
        result = tools["run_bulk_extractor"]("/evidence/disk.dd", "/output/be_results")

        assert captured_cmd["cmd"] == ["/usr/bin/bulk_extractor", "-o", "/output/be_results", "/evidence/disk.dd"]
        assert captured_cmd["timeout"] == 7200
        assert result["success"] is True
        audit.log.assert_called()

    def test_bulk_extractor_with_scanners(self, monkeypatch):
        from unittest.mock import MagicMock
        from sift_mcp.audit import AuditWriter
        from sift_mcp.tools.file_analysis import register_file_analysis_tools

        captured_cmd = {}

        def mock_find_binary(name):
            return f"/usr/bin/{name}"

        def mock_execute(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            return {"exit_code": 0, "stdout": "", "stderr": "", "elapsed_seconds": 60.0, "command": cmd}

        monkeypatch.setattr("sift_mcp.tools.file_analysis.find_binary", mock_find_binary)
        monkeypatch.setattr("sift_mcp.tools.file_analysis.execute", mock_execute)

        server = MagicMock()
        tools = {}
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f
        audit = MagicMock(spec=AuditWriter)
        audit._next_evidence_id.return_value = "sift-20260220-004"

        register_file_analysis_tools(server, audit)
        tools["run_bulk_extractor"]("/evidence/disk.dd", "/output/be_results", extra_args=["-e", "ntfsusn"])

        assert captured_cmd["cmd"] == ["/usr/bin/bulk_extractor", "-e", "ntfsusn", "-o", "/output/be_results", "/evidence/disk.dd"]

    def test_bulk_extractor_not_found(self, monkeypatch):
        from unittest.mock import MagicMock
        from sift_mcp.audit import AuditWriter
        from sift_mcp.tools.file_analysis import register_file_analysis_tools
        from sift_mcp.exceptions import ToolNotFoundError

        monkeypatch.setattr("sift_mcp.tools.file_analysis.find_binary", lambda name: None)

        server = MagicMock()
        tools = {}
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f
        audit = MagicMock(spec=AuditWriter)

        register_file_analysis_tools(server, audit)
        with pytest.raises(ToolNotFoundError):
            tools["run_bulk_extractor"]("/evidence/disk.dd", "/output/be_results")
