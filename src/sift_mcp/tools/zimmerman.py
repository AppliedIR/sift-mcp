"""Zimmerman tools — CSV-output forensic parsers.

Each tool function builds a command list, executes via the executor,
parses CSV output, and returns an enriched response envelope.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from sift_mcp.audit import AuditWriter
from sift_mcp.catalog import get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.parsers.csv_parser import parse_csv_file
from sift_mcp.response import build_response


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
    td = get_tool_def(tool_name)
    if not td:
        raise ValueError(f"Tool '{tool_name}' not in catalog")

    binary_path = find_binary(td.binary)
    if not binary_path:
        raise ToolNotFoundError(f"{td.binary} not found. Install Zimmerman tools on SIFT.")

    # Use temp dir for CSV output if not specified
    csv_dir = output_dir or tempfile.mkdtemp(prefix=f"sift_{tool_name.lower()}_")

    cmd = [binary_path, td.input_flag, input_file, "--csv", csv_dir]
    if extra_flags:
        cmd.extend(extra_flags)

    evidence_id = audit._next_evidence_id()

    exec_result = execute(cmd, timeout=td.timeout_seconds)

    # Find output CSV files
    parsed_data: dict[str, Any] = {}
    csv_files = sorted(Path(csv_dir).glob("*.csv"))
    for csv_file in csv_files:
        parsed_data[csv_file.stem] = parse_csv_file(str(csv_file), max_rows=max_rows)

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


def register_zimmerman_tools(server, audit: AuditWriter):
    """Register all Zimmerman tools with the MCP server."""

    @server.tool()
    def run_amcacheparser(input_file: str, output_dir: str = "") -> dict:
        """Parse Amcache.hve — proves file PRESENCE (not execution)."""
        return _run_zimmerman_tool("AmcacheParser", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_pecmd(input_file: str, output_dir: str = "") -> dict:
        """Parse Prefetch file — proves EXECUTION with timestamps and run count."""
        return _run_zimmerman_tool("PECmd", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_appcompatcacheparser(input_file: str, output_dir: str = "") -> dict:
        """Parse ShimCache from SYSTEM hive — proves file PRESENCE (not execution on Win10+)."""
        return _run_zimmerman_tool("AppCompatCacheParser", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_recmd(input_file: str, output_dir: str = "", batch_file: str = "") -> dict:
        """Parse registry hive with RECmd. Use batch_file for targeted extraction."""
        extra = ["--bn", batch_file] if batch_file else None
        return _run_zimmerman_tool("RECmd", input_file, audit, output_dir=output_dir or None, extra_flags=extra)

    @server.tool()
    def run_mftecmd(input_file: str, output_dir: str = "") -> dict:
        """Parse $MFT or $UsnJrnl — file system metadata and change journal."""
        return _run_zimmerman_tool("MFTECmd", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_evtxecmd(input_file: str, output_dir: str = "", maps_dir: str = "") -> dict:
        """Parse Windows Event Log (.evtx) files."""
        extra = ["--maps", maps_dir] if maps_dir else None
        return _run_zimmerman_tool("EvtxECmd", input_file, audit, output_dir=output_dir or None, extra_flags=extra)

    @server.tool()
    def run_jlecmd(input_file: str, output_dir: str = "") -> dict:
        """Parse Jump List files — tracks user file access per application."""
        return _run_zimmerman_tool("JLECmd", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_lecmd(input_file: str, output_dir: str = "") -> dict:
        """Parse LNK shortcut files — file access evidence with timestamps."""
        return _run_zimmerman_tool("LECmd", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_sbecmd(input_dir: str, output_dir: str = "") -> dict:
        """Parse ShellBags from registry hive directory — folder access evidence."""
        return _run_zimmerman_tool("SBECmd", input_dir, audit, output_dir=output_dir or None)

    @server.tool()
    def run_rbcmd(input_file: str, output_dir: str = "") -> dict:
        """Parse Recycle Bin $I files — deleted file evidence."""
        return _run_zimmerman_tool("RBCmd", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_srumecmd(input_file: str, output_dir: str = "") -> dict:
        """Parse SRUM database — application execution and network usage."""
        return _run_zimmerman_tool("SrumECmd", input_file, audit, output_dir=output_dir or None)

    @server.tool()
    def run_sqlecmd(input_file: str, output_dir: str = "") -> dict:
        """Parse SQLite databases (browser history, etc.)."""
        return _run_zimmerman_tool("SQLECmd", input_file, audit, output_dir=output_dir or None)
