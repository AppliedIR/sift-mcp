"""Volatility 3 — memory forensics."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.catalog import get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.security import sanitize_extra_args
from sift_mcp.parsers.json_parser import parse_json
from sift_mcp.response import build_response


def register_volatility_tools(server, audit: AuditWriter):
    """Register Volatility tools with the MCP server."""

    @server.tool()
    def run_volatility(
        memory_image: str,
        plugin: str,
        extra_args: list[str] | None = None,
        output_format: str = "json",
    ) -> dict:
        """Run a Volatility 3 plugin against a memory image.

        Common plugins: windows.pslist, windows.pstree, windows.netscan,
        windows.malfind, windows.cmdline, windows.handles, windows.dlllist,
        windows.hivelist, windows.hashdump, windows.filescan.
        """
        td = get_tool_def("vol3")
        if not td:
            raise ValueError("Volatility not in catalog")

        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError("vol/volatility3 not found. Install Volatility 3.")

        cmd = [binary_path, "-f", memory_image]
        if output_format == "json":
            cmd.extend(["-r", "json"])
        cmd.append(plugin)
        extra_args = sanitize_extra_args(extra_args or [], "run_volatility")
        cmd.extend(extra_args)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=td.timeout_seconds)

        # Parse output
        data = exec_result.get("stdout", "")
        parsed_format = "text"
        if output_format == "json" and exec_result["exit_code"] == 0 and data.strip():
            try:
                data = parse_json(data)
                parsed_format = "json"
            except Exception:
                pass  # Fall back to text

        response = build_response(
            tool_name="run_volatility",
            success=exec_result["exit_code"] == 0,
            data=data,
            evidence_id=evidence_id,
            output_format=parsed_format,
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="Volatility3",
        )

        audit.log(
            tool="run_volatility",
            params={"memory_image": memory_image, "plugin": plugin},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
            elapsed_ms=exec_result["elapsed_seconds"] * 1000,
        )

        return response
