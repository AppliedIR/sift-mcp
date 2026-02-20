"""File analysis tools — exiftool, 7z, bulk_extractor."""

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

    @server.tool()
    def extract_archive(
        archive_path: str,
        output_dir: str = "",
        password: str = "",
        list_only: bool = False,
    ) -> dict:
        """Extract or list contents of compressed archives (7z, zip, gz, bz2, xz, tar, rar).

        Args:
            archive_path: Path to the archive file.
            output_dir: Directory to extract into (required for extraction, ignored for list_only).
            password: Password for encrypted archives (optional).
            list_only: If True, list contents without extracting.
        """
        binary_path = find_binary("7z")
        if not binary_path:
            raise ToolNotFoundError("7z not found. Install p7zip-full.")

        if list_only:
            cmd = [binary_path, "l", archive_path]
        else:
            if not output_dir:
                raise ValueError("output_dir is required for extraction. Specify where to extract.")
            cmd = [binary_path, "x", archive_path, f"-o{output_dir}", "-y"]

        if password:
            cmd.append(f"-p{password}")

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=3600)
        response = build_response(
            tool_name="extract_archive", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""), evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="7z",
        )
        audit.log(tool="extract_archive",
                   params={"archive_path": archive_path, "output_dir": output_dir, "list_only": list_only},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response

    @server.tool()
    def run_bulk_extractor(image_file: str, output_dir: str, extra_args: list[str] = []) -> dict:
        """Carve forensic records (emails, URLs, EXIF, network packets) from disk images or unallocated space (bulk_extractor).

        Args:
            image_file: Path to disk image, E01, or unallocated space file.
            output_dir: Output directory (must not already exist).
            extra_args: Additional flags (e.g., ["-e", "ntfsusn"] to enable specific scanners).
        """
        binary_path = find_binary("bulk_extractor")
        if not binary_path:
            raise ToolNotFoundError("bulk_extractor not found. Install bulk-extractor.")

        cmd = [binary_path]
        cmd.extend(extra_args)
        cmd.extend(["-o", output_dir, image_file])

        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=7200)

        response = build_response(
            tool_name="run_bulk_extractor",
            success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name="bulk_extractor",
        )

        audit.log(
            tool="run_bulk_extractor",
            params={"image_file": image_file, "output_dir": output_dir},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
        )
        return response
