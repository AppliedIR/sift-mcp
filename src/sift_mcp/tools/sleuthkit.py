"""Sleuth Kit tools — disk image analysis."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response


def register_sleuthkit_tools(server, audit: AuditWriter):
    """Register Sleuth Kit tools."""

    @server.tool()
    def run_fls(image_file: str, inode: str = "", extra_args: list[str] = []) -> dict:
        """List files and directories in a disk image (fls). Supports deleted file recovery."""
        binary_path = find_binary("fls")
        if not binary_path:
            raise ToolNotFoundError("fls not found. Install Sleuth Kit.")

        cmd = [binary_path]
        cmd.extend(extra_args)
        cmd.append(image_file)
        if inode:
            cmd.append(inode)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=600)

        response = build_response(
            tool_name="run_fls",
            success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="fls",
        )

        audit.log(
            tool="run_fls", params={"image_file": image_file},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
        )
        return response

    @server.tool()
    def run_icat(image_file: str, inode: str, output_file: str = "", extra_args: list[str] = []) -> dict:
        """Extract a file by inode number from a disk image (icat)."""
        binary_path = find_binary("icat")
        if not binary_path:
            raise ToolNotFoundError("icat not found. Install Sleuth Kit.")

        cmd = [binary_path]
        cmd.extend(extra_args)
        cmd.extend([image_file, inode])

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=600, save_output=bool(output_file), save_dir=output_file or None)

        response = build_response(
            tool_name="run_icat",
            success=exec_result["exit_code"] == 0,
            data={"bytes_extracted": len(exec_result.get("stdout", ""))} if exec_result["exit_code"] == 0 else exec_result.get("stderr", ""),
            evidence_id=evidence_id,
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="icat",
        )

        audit.log(
            tool="run_icat", params={"image_file": image_file, "inode": inode},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
        )
        return response

    @server.tool()
    def run_blkls(image_file: str, partition_offset: str = "", extra_args: list[str] = []) -> dict:
        """Extract unallocated clusters from a disk image for carving (blkls)."""
        binary_path = find_binary("blkls")
        if not binary_path:
            raise ToolNotFoundError("blkls not found. Install Sleuth Kit.")

        cmd = [binary_path]
        if partition_offset:
            cmd.extend(["-o", partition_offset])
        cmd.extend(extra_args)
        cmd.append(image_file)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=3600)

        response = build_response(
            tool_name="run_blkls",
            success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="blkls",
        )

        audit.log(
            tool="run_blkls", params={"image_file": image_file, "partition_offset": partition_offset},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
        )
        return response

    @server.tool()
    def run_mmls(image_file: str, extra_args: list[str] = []) -> dict:
        """Display partition table layout of a disk image (mmls)."""
        binary_path = find_binary("mmls")
        if not binary_path:
            raise ToolNotFoundError("mmls not found. Install Sleuth Kit.")

        cmd = [binary_path]
        cmd.extend(extra_args)
        cmd.append(image_file)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=300)

        response = build_response(
            tool_name="run_mmls",
            success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="mmls",
        )

        audit.log(
            tool="run_mmls", params={"image_file": image_file},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
        )
        return response
