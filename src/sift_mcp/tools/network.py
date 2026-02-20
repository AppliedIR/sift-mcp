"""Network analysis tools — tshark, zeek."""

from __future__ import annotations

from sift_mcp.audit import AuditWriter
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import ToolNotFoundError
from sift_mcp.executor import execute
from sift_mcp.response import build_response


def register_network_tools(server, audit: AuditWriter):

    @server.tool()
    def run_tshark(pcap_file: str, display_filter: str = "", fields: list[str] = [], extra_args: list[str] = []) -> dict:
        """Analyze PCAP with tshark (Wireshark CLI). Use display_filter for filtering."""
        binary_path = find_binary("tshark")
        if not binary_path:
            raise ToolNotFoundError("tshark not found. Install Wireshark/tshark.")
        cmd = [binary_path, "-r", pcap_file]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        for f in fields:
            cmd.extend(["-e", f])
        if fields:
            cmd.extend(["-T", "fields"])
        cmd.extend(extra_args)
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=600)
        response = build_response(
            tool_name="run_tshark", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""), evidence_id=evidence_id,
            output_format="text", elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="tshark",
        )
        audit.log(tool="run_tshark", params={"pcap_file": pcap_file, "display_filter": display_filter},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response

    @server.tool()
    def run_zeek(pcap_file: str, scripts: list[str] = [], extra_args: list[str] = []) -> dict:
        """Analyze PCAP with Zeek — generates protocol logs (conn, dns, http, ssl, etc.)."""
        binary_path = find_binary("zeek")
        if not binary_path:
            raise ToolNotFoundError("zeek not found.")
        cmd = [binary_path, "-r", pcap_file] + scripts + extra_args
        evidence_id = audit._next_evidence_id()
        exec_result = execute(cmd, timeout=1200)
        response = build_response(
            tool_name="run_zeek", success=exec_result["exit_code"] == 0,
            data=exec_result.get("stdout", ""), evidence_id=evidence_id,
            output_format="text", elapsed_seconds=exec_result["elapsed_seconds"],
            exit_code=exec_result["exit_code"], command=cmd, fk_tool_name="Zeek",
        )
        audit.log(tool="run_zeek", params={"pcap_file": pcap_file},
                   result_summary={"exit_code": exec_result["exit_code"]}, evidence_id=evidence_id)
        return response
