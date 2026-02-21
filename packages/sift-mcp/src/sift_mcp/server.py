"""MCP server for SIFT workstation forensic tool execution."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from sift_mcp.audit import AuditWriter
from sift_mcp.response import build_response
from sift_mcp.exceptions import SiftError

logger = logging.getLogger(__name__)


def create_server() -> FastMCP:
    """Create and configure the sift MCP server with all tools."""
    server = FastMCP("sift-mcp")
    audit = AuditWriter(mcp_name="sift-mcp")

    # --- Discovery ---

    @server.tool()
    def list_available_tools(category: str = "") -> list[dict]:
        """List forensic tools available on this SIFT workstation, with availability status."""
        from sift_mcp.tools.discovery import list_available_tools as _list
        return _list(category=category or None)

    @server.tool()
    def get_tool_help(tool_name: str) -> dict:
        """Get usage information, flags, and caveats for a specific forensic tool."""
        from sift_mcp.tools.discovery import get_tool_help as _help
        result = _help(tool_name)
        audit.log(tool="get_tool_help", params={"tool_name": tool_name}, result_summary=result)
        return result

    @server.tool()
    def check_tools(tool_names: list[str] | None = None) -> dict:
        """Check which tools are installed and available on this system."""
        from sift_mcp.tools.discovery import check_tools as _check
        return _check(tool_names=tool_names)

    @server.tool()
    def suggest_tools(artifact_type: str, question: str = "") -> dict:
        """Suggest tools for analyzing a specific artifact type. Uses forensic-knowledge."""
        from sift_mcp.tools.discovery import suggest_tools as _suggest
        result = _suggest(artifact_type, question)
        audit.log(tool="suggest_tools", params={"artifact_type": artifact_type}, result_summary=result)
        return result

    # --- Generic Execution ---

    @server.tool()
    def run_command(command: list[str], purpose: str, timeout: int = 0, save_output: bool = False) -> dict:
        """Execute a catalog-approved forensic tool. Rejects unknown binaries.

        Args:
            command: Command as list of strings (e.g., ["AmcacheParser", "-f", "Amcache.hve", "--csv", "/tmp/out"]).
            purpose: Why this command is being run (audit trail).
            timeout: Override timeout in seconds (0 = default).
            save_output: Save stdout/stderr to files with SHA-256 hashes.
        """
        import time
        from sift_mcp.tools.generic import run_command as _run
        from sift_mcp.catalog import get_tool_def

        start = time.monotonic()
        evidence_id = audit._next_evidence_id()

        try:
            exec_result = _run(
                command,
                purpose=purpose,
                timeout=timeout or None,
                save_output=save_output,
            )
            elapsed = time.monotonic() - start

            # Determine FK tool name for knowledge enrichment
            binary = command[0].split("/")[-1]
            td = get_tool_def(binary)
            fk_name = td.knowledge_name if td else binary

            response = build_response(
                tool_name="run_command",
                success=exec_result["exit_code"] == 0,
                data=exec_result,
                evidence_id=evidence_id,
                output_format="text",
                elapsed_seconds=elapsed,
                exit_code=exec_result["exit_code"],
                command=command,
                fk_tool_name=fk_name,
            )

            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"exit_code": exec_result["exit_code"]},
                evidence_id=evidence_id,
                elapsed_ms=elapsed * 1000,
            )
            return response

        except SiftError as e:
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                evidence_id=evidence_id,
                error=str(e),
            )
            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(e)},
                evidence_id=evidence_id,
            )
            return response

    # --- Register tool-specific modules ---

    from sift_mcp.tools.zimmerman import register_zimmerman_tools
    from sift_mcp.tools.volatility import register_volatility_tools
    from sift_mcp.tools.timeline import register_timeline_tools
    from sift_mcp.tools.sleuthkit import register_sleuthkit_tools
    from sift_mcp.tools.malware import register_malware_tools
    from sift_mcp.tools.network import register_network_tools
    from sift_mcp.tools.file_analysis import register_file_analysis_tools
    from sift_mcp.tools.registry import register_registry_tools
    from sift_mcp.tools.hashing import register_hashing_tools
    from sift_mcp.tools.imaging import register_imaging_tools

    register_zimmerman_tools(server, audit)
    register_volatility_tools(server, audit)
    register_timeline_tools(server, audit)
    register_sleuthkit_tools(server, audit)
    register_malware_tools(server, audit)
    register_network_tools(server, audit)
    register_file_analysis_tools(server, audit)
    register_registry_tools(server, audit)
    register_hashing_tools(server, audit)
    register_imaging_tools(server, audit)

    return server
