"""Tests for MCP server instruction strings."""

from sift_common.instructions import (
    FORENSIC_MCP,
    SIFT_MCP,
    WINTOOLS_MCP,
    GATEWAY,
    WINDOWS_TRIAGE,
    FORENSIC_RAG,
    OPENCTI,
)


class TestInstructionConstants:
    """Verify all instruction constants exist and contain key phrases."""

    def test_forensic_mcp_has_rule_zero(self):
        assert isinstance(FORENSIC_MCP, str)
        assert len(FORENSIC_MCP) > 100
        assert "RULE ZERO" in FORENSIC_MCP
        assert "investigation-framework" in FORENSIC_MCP

    def test_sift_mcp_has_evidence_sovereign(self):
        assert isinstance(SIFT_MCP, str)
        assert len(SIFT_MCP) > 100
        assert "EVIDENCE IS SOVEREIGN" in SIFT_MCP

    def test_wintools_mcp_has_evidence_sovereign(self):
        assert isinstance(WINTOOLS_MCP, str)
        assert len(WINTOOLS_MCP) > 100
        assert "EVIDENCE IS SOVEREIGN" in WINTOOLS_MCP
        assert "Zimmerman" in WINTOOLS_MCP

    def test_gateway_references_backends(self):
        assert isinstance(GATEWAY, str)
        assert len(GATEWAY) > 50
        assert "forensic-mcp" in GATEWAY
        assert "sift-mcp" in GATEWAY
        assert "investigation-framework" in GATEWAY

    def test_windows_triage_explains_unknown(self):
        assert isinstance(WINDOWS_TRIAGE, str)
        assert len(WINDOWS_TRIAGE) > 50
        assert "UNKNOWN" in WINDOWS_TRIAGE

    def test_forensic_rag_describes_search(self):
        assert isinstance(FORENSIC_RAG, str)
        assert len(FORENSIC_RAG) > 50
        assert "knowledge" in FORENSIC_RAG.lower()

    def test_opencti_describes_cti(self):
        assert isinstance(OPENCTI, str)
        assert len(OPENCTI) > 50
        assert "intelligence" in OPENCTI.lower()


class TestServerInstructionsWired:
    """Verify server constructors receive instructions."""

    def test_forensic_mcp_server_has_instructions(self):
        from forensic_mcp.server import create_server
        server = create_server()
        # FastMCP stores instructions on the underlying _mcp_server
        instructions = getattr(server, "instructions", None) or getattr(
            getattr(server, "_mcp_server", None), "instructions", None
        )
        assert instructions is not None
        assert "RULE ZERO" in instructions

    def test_sift_mcp_server_has_instructions(self):
        from sift_mcp.server import create_server
        server = create_server()
        instructions = getattr(server, "instructions", None) or getattr(
            getattr(server, "_mcp_server", None), "instructions", None
        )
        assert instructions is not None
        assert "EVIDENCE IS SOVEREIGN" in instructions
