"""Registry tools — regripper."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response


def register_registry_tools(server, audit: AuditWriter):

    @server.tool()
    def run_regripper(hive_file: str, plugin: str = "", extra_args: list[str] = []) -> dict:
        """Run RegRipper against a registry hive. Specify plugin or run all."""
        binary_path = find_binary("rip.pl") or find_binary("regripper")
        if not binary_path:
            raise ToolNotFoundError("regripper/rip.pl not found.")
        cmd = [binary_path, "-r", hive_file]
        if plugin:
            cmd.extend(["-p", plugin])
        else:
            cmd.append("-a")
        cmd.extend(extra_args)
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=600)
        response = build_response(
            tool_name="run_regripper", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""), evidence_id=evidence_id,
            output_format="text", elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="RegRipper",
        )
        audit.log(tool="run_regripper", params={"hive_file": hive_file, "plugin": plugin},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response
