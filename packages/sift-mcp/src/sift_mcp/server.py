"""MCP server for SIFT workstation forensic tool execution."""

from __future__ import annotations

import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import SIFT_MCP as _INSTRUCTIONS

from sift_mcp.audit import AuditWriter
from sift_mcp.exceptions import SiftError
from sift_mcp.response import build_response

logger = logging.getLogger(__name__)

# Event IDs that indicate Security log context
_SECURITY_EVENT_IDS = frozenset(
    {"4624", "4625", "4634", "4648", "4672", "4688", "4720", "4732"}
)

# Filename keywords → artifact context for FK filtering
# Note: "operational" is NOT included — it's a generic channel suffix
# (TaskScheduler%4Operational, TerminalServices%4Operational, etc.)
_FILENAME_ARTIFACT_MAP = {
    "security": "event_logs_security",
    "system": "event_logs_system",
    "sysmon": "event_logs_sysmon",
    "powershell": "event_logs_powershell",
}


def _detect_artifact_context(command: list[str]) -> str | None:
    """Detect artifact context from command for FK advisory filtering.

    Returns an artifact name (e.g., "event_logs_security") to filter
    FK advisories, or None for no filtering (include all).
    """
    for i, token in enumerate(command):
        # Match --inc 4624, --inc 4624,4625, or --inc=4624
        value = None
        if token.startswith("--inc="):
            value = token.split("=", 1)[1]
        elif token == "--inc" and i + 1 < len(command):
            value = command[i + 1]
        if value:
            ids = set(value.replace(",", " ").split())
            if ids & _SECURITY_EVENT_IDS:
                return "event_logs_security"

    for token in command:
        if token.startswith("-"):
            continue
        basename = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        for keyword, artifact in _FILENAME_ARTIFACT_MAP.items():
            if keyword in basename:
                return artifact

    return None


def create_server() -> FastMCP:
    """Create and configure the sift MCP server with core tools."""
    server = FastMCP("sift-mcp", instructions=_INSTRUCTIONS)
    audit = AuditWriter(mcp_name="sift-mcp")

    # --- Discovery ---

    @server.tool()
    def list_available_tools(category: str = "") -> dict:
        """List forensic tools available on this SIFT workstation, with availability status."""
        from sift_mcp.tools.discovery import list_available_tools as _list

        tools = _list(category=category or None)
        return {"tools": tools, "count": len(tools)}

    @server.tool()
    def get_tool_help(tool_name: str) -> dict:
        """Get usage information, flags, and caveats for a specific forensic tool."""
        from sift_mcp.tools.discovery import get_tool_help as _help

        result = _help(tool_name)
        logged_id = audit.log(
            tool="get_tool_help", params={"tool_name": tool_name}, result_summary=result
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    @server.tool()
    def check_tools(tool_names: list[str] | None = None) -> dict:
        """Check which tools are installed and available on this system."""
        from sift_mcp.tools.discovery import check_tools as _check

        return _check(tool_names=tool_names)

    @server.tool()
    def suggest_tools(artifact_type: str, question: str = "") -> dict:
        """Suggest tools for analyzing a specific artifact type. Uses forensic-knowledge."""
        from sift_mcp.tools.discovery import suggest_tools as _suggest

        result = _suggest(artifact_type, question)
        logged_id = audit.log(
            tool="suggest_tools",
            params={"artifact_type": artifact_type},
            result_summary=result,
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    # --- Generic Execution ---

    @server.tool()
    def run_command(
        command: list[str],
        purpose: str,
        timeout: int = 0,
        save_output: bool = False,
        input_files: list[str] | None = None,
        preview_lines: int = 0,
        skip_enrichment: bool = False,
    ) -> dict:
        """Execute a forensic tool on this SIFT workstation.

        Most SIFT-installed tools can be executed including curl, wget, dd,
        fdisk, and python3. Only mkfs, shutdown, kill, and raw socket
        tools (nc/ncat) are blocked. Tools in the forensic catalog
        get enriched responses with caveats and corroboration suggestions.

        Args:
            command: Command as list of strings (e.g., ["AmcacheParser", "-f", "Amcache.hve", "--csv", "/tmp/out"]).
            purpose: Why this command is being run (audit trail).
            timeout: Override timeout in seconds (0 = default).
            save_output: Save stdout/stderr to files with SHA-256 hashes.
            input_files: Files this command reads. Pass the paths you
                referenced in the command. Server auto-detects as backup
                for cataloged tools.
            preview_lines: Max lines in inline preview for large outputs
                (0 = default ~10KB budget, max 200). Useful when you need
                more context from a grep or timeline query.
            skip_enrichment: Skip FK caveats/advisories/corroboration on
                repeat calls to the same tool (already in context from
                first call).
        """
        import hashlib
        import time

        from sift_mcp.catalog import get_tool_def
        from sift_mcp.tools.generic import run_command as _run

        start = time.monotonic()
        audit_id = audit._next_audit_id()

        # Detect input files: LLM-first, catalog-backup, parsed-fallback
        binary = command[0].split("/")[-1] if command else ""
        td = get_tool_def(binary)
        detection_method = ""
        detected_inputs: list[str] = []

        if input_files:
            detected_inputs = input_files
            detection_method = "llm"
        elif td and td.input_flag:
            # Cataloged tool: find flag in command, take next element
            try:
                idx = command.index(td.input_flag)
                if idx + 1 < len(command):
                    detected_inputs = [command[idx + 1]]
                    detection_method = "catalog"
            except ValueError:
                pass
        if not detected_inputs and not detection_method:
            # Fallback: check command tokens for existing files
            for token in command[1:]:
                if token.startswith("-"):
                    continue
                p = Path(token)
                if p.is_file():
                    detected_inputs.append(str(p))
            if detected_inputs:
                detection_method = "parsed"
            elif td and not td.input_flag:
                detection_method = ""  # Tool has no inputs (e.g., hostname)
            else:
                detection_method = "none"

        # Hash input files (chunked, 1GB cap)
        # Wrapped per-file — provenance must never block forensic work
        input_hashes: dict[str, str] = {}
        for fpath in detected_inputs:
            try:
                p = Path(fpath).resolve()
                if p.is_file():
                    if p.stat().st_size > 1_000_000_000:
                        input_hashes[str(p)] = "skipped:too_large"
                    else:
                        h = hashlib.sha256()
                        with open(p, "rb") as hf:
                            for chunk in iter(lambda: hf.read(65536), b""):
                                h.update(chunk)
                        input_hashes[str(p)] = h.hexdigest()
            except OSError:
                continue

        try:
            exec_result = _run(
                command,
                purpose=purpose,
                timeout=timeout or None,
                save_output=save_output,
                preview_lines=min(preview_lines, 200) if preview_lines else 0,
            )
            elapsed = time.monotonic() - start

            # FK tool name for knowledge enrichment (td already resolved above)
            fk_name = td.knowledge_name if td else binary

            # Detect artifact context for FK advisory filtering
            artifact_hint = _detect_artifact_context(command)

            # Use parsed preview for large output, raw result for small
            if exec_result.get("_parsed"):
                resp_data = exec_result["_parsed"]
                resp_format = exec_result["_output_format"]
            else:
                resp_data = exec_result
                resp_format = exec_result.get("_output_format", "text")

            response = build_response(
                tool_name="run_command",
                success=exec_result["exit_code"] == 0,
                data=resp_data,
                audit_id=audit_id,
                output_format=resp_format,
                elapsed_seconds=elapsed,
                exit_code=exec_result["exit_code"],
                command=command,
                fk_tool_name=fk_name,
                output_files=[exec_result["output_file"]]
                if exec_result.get("output_file")
                else None,
                extractions=exec_result.get("extractions"),
                skip_enrichment=skip_enrichment,
                artifact_context=artifact_hint,
            )

            # Add full output metadata if file was saved
            if exec_result.get("output_file"):
                response["full_output_path"] = exec_result["output_file"]
                response["full_output_sha256"] = exec_result.get("output_sha256")
                response["full_output_bytes"] = exec_result.get("stdout_total_bytes")

            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={
                    "exit_code": exec_result["exit_code"],
                    "output_file": exec_result.get("output_file", ""),
                    "output_sha256": exec_result.get("output_sha256", ""),
                    "stdout_bytes": exec_result.get("stdout_total_bytes", 0),
                    "stdout_head": (exec_result.get("stdout") or "")[:500],
                },
                audit_id=audit_id,
                elapsed_ms=elapsed * 1000,
                input_files=list(input_hashes.keys()) if input_hashes else None,
                input_sha256s=list(input_hashes.values()) if input_hashes else None,
                input_detection_method=detection_method,
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            _NO_INPUT_CMDS = {
                "echo",
                "date",
                "hostname",
                "whoami",
                "uname",
                "uptime",
                "pwd",
                "env",
                "id",
                "df",
                "free",
                "mount",
                "lsblk",
                "lscpu",
                "ps",
                "top",
                "w",
                "who",
                "last",
                "dmesg",
                "printenv",
            }
            if detection_method == "none" and binary not in _NO_INPUT_CMDS:
                response["input_files_warning"] = (
                    "Could not detect input files — pass input_files parameter "
                    "for provenance chain linking."
                )
            elif detection_method == "llm" and not input_hashes:
                response["input_files_warning"] = (
                    "input_files provided but none resolved to existing files. "
                    "Provenance chain will be incomplete."
                )
            return response

        except SiftError as e:
            elapsed = time.monotonic() - start
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=audit_id,
                error=str(e),
            )
            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(e)},
                audit_id=audit_id,
                elapsed_ms=elapsed * 1000,
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            return response
        except (ValueError, OSError, RuntimeError) as e:
            elapsed = time.monotonic() - start
            logger.warning("run_command unexpected error: %s: %s", type(e).__name__, e)
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=audit_id,
                error=str(e),
            )
            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(e)},
                audit_id=audit_id,
                elapsed_ms=elapsed * 1000,
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            return response
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error("run_command catch-all error: %s: %s", type(e).__name__, e)
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=audit_id,
                error=f"Unexpected error: {type(e).__name__}",
            )
            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": f"{type(e).__name__}: {e}"},
                audit_id=audit_id,
                elapsed_ms=elapsed * 1000,
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            return response

    return server
