"""Sleuth Kit tools — disk image analysis."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.catalog import get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response
from sift_mcp.security import sanitize_extra_args, validate_input_path


def register_sleuthkit_tools(server, audit: AuditWriter):
    """Register Sleuth Kit tools."""

    @server.tool()
    def run_fls(image_file: str, inode: str = "", extra_args: list[str] | None = None) -> dict:
        """List files and directories in a disk image (fls). Supports deleted file recovery."""
        validate_input_path(image_file)
        td = get_tool_def("fls")
        if not td:
            raise ValueError("fls not in catalog")
        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError("fls not found. Install Sleuth Kit.")

        cmd = [binary_path]
        extra_args = sanitize_extra_args(extra_args or [], "fls")
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
    def run_icat(image_file: str, inode: str, output_file: str, extra_args: list[str] | None = None) -> dict:
        """Extract a file by inode number from a disk image (icat).

        output_file is required — icat produces binary output that must be saved to disk.
        """
        validate_input_path(image_file)
        td = get_tool_def("icat")
        if not td:
            raise ValueError("icat not in catalog")
        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError("icat not found. Install Sleuth Kit.")

        if not output_file:
            raise ValueError("output_file is required for icat (binary extraction tool)")

        cmd = [binary_path]
        extra_args = sanitize_extra_args(extra_args or [], "icat")
        cmd.extend(extra_args)
        cmd.extend([image_file, inode])

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=600, save_output=True, save_dir=output_file)

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
    def run_blkls(image_file: str, output_file: str, partition_offset: str = "", extra_args: list[str] | None = None) -> dict:
        """Extract unallocated clusters from a disk image for carving (blkls).

        output_file is required — blkls produces binary output that must be saved to disk.
        """
        validate_input_path(image_file)
        td = get_tool_def("blkls")
        if not td:
            raise ValueError("blkls not in catalog")
        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError("blkls not found. Install Sleuth Kit.")

        if not output_file:
            raise ValueError("output_file is required for blkls (binary extraction tool)")

        cmd = [binary_path]
        if partition_offset:
            cmd.extend(["-o", partition_offset])
        extra_args = sanitize_extra_args(extra_args or [], "blkls")
        cmd.extend(extra_args)
        cmd.append(image_file)

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=3600, save_output=True, save_dir=output_file)

        response = build_response(
            tool_name="run_blkls",
            success=exec_result["exit_code"] == 0,
            data={"output_file": output_file} if exec_result["exit_code"] == 0 else exec_result.get("stderr", ""),
            evidence_id=evidence_id,
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
    def run_mmls(image_file: str, extra_args: list[str] | None = None) -> dict:
        """Display partition table layout of a disk image (mmls)."""
        validate_input_path(image_file)
        td = get_tool_def("mmls")
        if not td:
            raise ValueError("mmls not in catalog")
        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError("mmls not found. Install Sleuth Kit.")

        cmd = [binary_path]
        extra_args = sanitize_extra_args(extra_args or [], "mmls")
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
