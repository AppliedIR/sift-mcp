"""File analysis tools — exiftool."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.parsers.json_parser import parse_json
from sift_mcp.response import build_response


def register_file_analysis_tools(server, audit: AuditWriter):

    @server.tool()
    def run_exiftool(target: str, extra_args: list[str] = []) -> dict:
        """Extract metadata from files using ExifTool."""
        binary_path = find_binary("exiftool")
        if not binary_path:
            raise ToolNotFoundError("exiftool not found.")
        cmd = [binary_path, "-j"] + extra_args + [target]
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=300)
        data = exec_result.get("stdout", "")
        fmt = "text"
        if exec_result["exit_code"] == 0 and data.strip():
            try:
                data = parse_json(data)
                fmt = "json"
            except Exception:
                pass
        response = build_response(
            tool_name="run_exiftool", success=exec_result["exit_code"] == 0,
            data=data, evidence_id=evidence_id, output_format=fmt,
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="ExifTool",
        )
        audit.log(tool="run_exiftool", params={"target": target},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response
