"""Zimmerman tools — CSV-output forensic parsers.

Each tool function builds a command list, executes via the executor,
parses CSV output, and returns an enriched response envelope.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from sift_mcp.catalog import get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.parsers.csv_parser import parse_csv_file
from sift_mcp.response import build_response
from sift_mcp.security import sanitize_extra_args, validate_input_path


def _run_zimmerman_tool(
    tool_name: str,
    input_file: str,
    audit: AuditWriter,
    *,
    extra_flags: list[str] | None = None,
    output_dir: str | None = None,
    max_rows: int = 1000,
) -> dict:
    """Common pattern for Zimmerman CSV-output tools."""
    validate_input_path(input_file)
    td = get_tool_def(tool_name)
    if not td:
        raise ValueError(f"Tool '{tool_name}' not in catalog")

    binary_path = find_binary(td.binary)
    if not binary_path:
        raise ToolNotFoundError(f"{td.binary} not found. Install Zimmerman tools on SIFT.")

    # Sanitize extra flags
    if extra_flags:
        extra_flags = sanitize_extra_args(extra_flags, tool_name)

    # Use temp dir for CSV output if not specified
    _temp_cleanup = None
    if output_dir:
        csv_dir = output_dir
    else:
        _temp_cleanup = tempfile.TemporaryDirectory(prefix=f"sift_{tool_name.lower()}_")
        csv_dir = _temp_cleanup.name

    try:
        cmd = [binary_path, td.input_flag, input_file, "--csv", csv_dir]
        if extra_flags:
            cmd.extend(extra_flags)

        evidence_id = audit._next_evidence_id()

        exec_result = execute(cmd, timeout=td.timeout_seconds)

        # Find output CSV files
        parsed_data: dict[str, Any] = {}
        try:
            csv_files = sorted(Path(csv_dir).glob("*.csv"))
        except OSError as e:
            logger.warning("Failed to list CSV output in %s: %s", csv_dir, e)
            csv_files = []
        for csv_file in csv_files:
            try:
                parsed_data[csv_file.stem] = parse_csv_file(str(csv_file), max_rows=max_rows)
            except (OSError, FileNotFoundError) as e:
                logger.warning("Failed to parse CSV file %s: %s", csv_file, e)
                parsed_data[csv_file.stem] = {"error": str(e), "rows": [], "total_rows": 0}

        response = build_response(
            tool_name=f"run_{tool_name.lower()}",
            success=exec_result["exit_code"] == 0,
            data=parsed_data if parsed_data else exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="parsed_csv" if parsed_data else "text",
            elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name=td.knowledge_name,
        )

        if csv_files:
            response["output_files"] = [str(f) for f in csv_files]

        audit.log(
            tool=f"run_{tool_name.lower()}",
            params={"input_file": input_file, "output_dir": csv_dir},
            result_summary={"exit_code": exec_result["exit_code"], "csv_files": len(csv_files)},
            evidence_id=evidence_id,
            elapsed_ms=exec_result["elapsed_seconds"] * 1000,
        )

        return response
    finally:
        if _temp_cleanup:
            _temp_cleanup.cleanup()


