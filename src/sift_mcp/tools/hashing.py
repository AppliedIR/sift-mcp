"""Hashing tools — hashdeep/md5deep."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response
from sift_mcp.security import sanitize_extra_args


def register_hashing_tools(server, audit: AuditWriter):

    @server.tool()
    def run_hashdeep(target: str, algorithm: str = "sha256", recursive: bool = True, extra_args: list[str] | None = None) -> dict:
        """Hash files with hashdeep. algorithm: md5, sha1, sha256."""
        binary_path = find_binary("hashdeep") or find_binary(f"{algorithm}deep")
        if not binary_path:
            raise ToolNotFoundError("hashdeep not found.")
        cmd = [binary_path]
        if recursive:
            cmd.append("-r")
        extra_args = sanitize_extra_args(extra_args or [], "run_hashdeep")
        cmd.extend(extra_args)
        cmd.append(target)
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=1200)
        response = build_response(
            tool_name="run_hashdeep", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""), evidence_id=evidence_id,
            output_format="text", elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="hashdeep",
        )
        audit.log(tool="run_hashdeep", params={"target": target, "algorithm": algorithm},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response
