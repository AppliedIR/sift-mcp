"""Imaging tools — dc3dd, ewfacquire."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response
from sift_mcp.security import sanitize_extra_args


_BLOCKED_DEVICE_PREFIXES = ("/dev/sd", "/dev/hd", "/dev/nvme", "/dev/vd", "/dev/xvd")


def register_imaging_tools(server, audit: AuditWriter):

    @server.tool()
    def run_dc3dd(source: str, destination: str, hash_algorithm: str = "sha256", extra_args: list[str] | None = None) -> dict:
        """Create forensic disk image with dc3dd (with inline hashing)."""
        # Block writing to system device nodes
        if any(destination.startswith(p) for p in _BLOCKED_DEVICE_PREFIXES):
            raise ValueError(f"Destination '{destination}' is a block device — writing to raw devices is blocked for safety")
        binary_path = find_binary("dc3dd")
        if not binary_path:
            raise ToolNotFoundError("dc3dd not found.")
        cmd = [binary_path, f"if={source}", f"of={destination}", f"hash={hash_algorithm}", "log=/dev/stderr"]
        extra_args = sanitize_extra_args(extra_args or [], "run_dc3dd")
        cmd.extend(extra_args)
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=7200)
        response = build_response(
            tool_name="run_dc3dd", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stderr", ""),  # dc3dd outputs to stderr
            evidence_id=evidence_id, output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="dc3dd",
        )
        audit.log(tool="run_dc3dd", params={"source": source, "destination": destination},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response

    @server.tool()
    def run_ewfacquire(source: str, target_prefix: str, extra_args: list[str] | None = None) -> dict:
        """Create E01 forensic image with ewfacquire."""
        binary_path = find_binary("ewfacquire")
        if not binary_path:
            raise ToolNotFoundError("ewfacquire not found. Install libewf.")
        extra_args = sanitize_extra_args(extra_args or [], "run_ewfacquire")
        cmd = [binary_path, "-t", target_prefix, "-u"] + extra_args + [source]
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=7200)
        response = build_response(
            tool_name="run_ewfacquire", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""), evidence_id=evidence_id,
            output_format="text", elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="ewfacquire",
        )
        audit.log(tool="run_ewfacquire", params={"source": source, "target_prefix": target_prefix},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response
