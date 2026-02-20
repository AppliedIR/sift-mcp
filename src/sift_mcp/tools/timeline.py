"""Timeline tools — Hayabusa, Plaso, mactime."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.catalog import get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response
from sift_mcp.security import sanitize_extra_args


def register_timeline_tools(server, audit: AuditWriter):
    """Register timeline tools with the MCP server."""

    @server.tool()
    def run_hayabusa(
        evtx_dir: str,
        min_level: str = "medium",
        output_file: str = "",
        extra_args: list[str] | None = None,
    ) -> dict:
        """Run Hayabusa Sigma-based event log analyzer.

        min_level: informational, low, medium, high, critical
        """
        td = get_tool_def("hayabusa")
        if not td:
            raise ValueError("Hayabusa not in catalog")

        binary_path = find_binary(td.binary)
        if not binary_path:
            # Try installer
            from sift_mcp.installer import install_hayabusa
            binary_path = install_hayabusa()
            if not binary_path:
                raise ToolNotFoundError("Hayabusa not found and auto-install failed.")

        cmd = [binary_path, "csv-timeline", "-d", evtx_dir, "--min-level", min_level]
        if output_file:
            cmd.extend(["-o", output_file])
        extra_args = sanitize_extra_args(extra_args or [], "run_hayabusa")
        cmd.extend(extra_args)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=td.timeout_seconds)

        response = build_response(
            tool_name="run_hayabusa",
            success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="Hayabusa",
        )

        audit.log(
            tool="run_hayabusa",
            params={"evtx_dir": evtx_dir, "min_level": min_level},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
            elapsed_ms=exec_result["elapsed_seconds"] * 1000,
        )

        return response

    @server.tool()
    def run_mactime(body_file: str, date_range: str = "", extra_args: list[str] | None = None) -> dict:
        """Convert bodyfile to timeline using mactime (Sleuth Kit).

        date_range: optional YYYY-MM-DD..YYYY-MM-DD filter.
        """
        td = get_tool_def("mactime")
        if not td:
            raise ValueError("mactime not in catalog")

        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError("mactime not found. Install Sleuth Kit.")

        cmd = [binary_path, "-b", body_file]
        if date_range:
            cmd.extend(["-d", date_range])
        extra_args = sanitize_extra_args(extra_args or [], "run_mactime")
        cmd.extend(extra_args)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=td.timeout_seconds)

        response = build_response(
            tool_name="run_mactime",
            success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="mactime",
        )

        audit.log(
            tool="run_mactime",
            params={"body_file": body_file},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
            elapsed_ms=exec_result["elapsed_seconds"] * 1000,
        )

        return response
