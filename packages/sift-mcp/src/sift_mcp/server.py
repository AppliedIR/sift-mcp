"""MCP server for SIFT workstation forensic tool execution."""

from __future__ import annotations

import logging

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
        Deleting or overwriting case records, audit/ or evidence files is refused;
        bash -c, python -c, dd and a tool's own output options are not checked.

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
        import time

        from sift_mcp.catalog import get_tool_def
        from sift_mcp.tools.generic import run_command as _run

        start = time.monotonic()

        # The inputs are what the command names: each existing file or folder
        # it passes (bare, or as a --flag=value), never an output flag's value
        # and never the caller's list in their place
        from sift_mcp import command_files
        from sift_mcp.security import get_output_flags

        binary = command[0].split("/")[-1] if command else ""
        td = get_tool_def(binary)
        parsed = command_files.inputs(command, get_output_flags())
        if parsed:
            detection_method = "parsed"
        elif td and not td.input_flag:
            detection_method = ""  # Tool has no inputs (e.g., hostname)
        else:
            detection_method = "none"

        # Each input with where it is and its hash, with no size cap. A
        # registered file links to the registry by its path and isn't read; any
        # other is hashed in the call up to the inline limit, else in the
        # background (`pending:<job>` until its hash_complete entry); a folder
        # isn't hashed. Provenance must never block forensic work
        from sift_common import file_place, resolve_case_dir

        # One case per call, resolved as it starts: the audit id is minted for
        # it, and the output and the entry are kept in it, whatever case is
        # active when the command ends
        case_dir = resolve_case_dir()
        audit_dir = audit._get_audit_dir(case_dir)
        op_id = audit._next_audit_id(audit_dir) if audit_dir else None
        inputs: list[dict] = []
        registered: list[dict] = []  # [{path, sha256}], from the registry
        for fpath in parsed:
            rec, reg = file_place.input_record(case_dir, fpath, "run_command")
            inputs.append(rec)
            if reg:
                registered.append(reg)
        listed_files, listed_shas = file_place.listed(inputs, registered)

        try:
            exec_result = _run(
                command,
                purpose=purpose,
                timeout=timeout or None,
                save_output=save_output,
                preview_lines=min(preview_lines, 200) if preview_lines else 0,
                op_id=(lambda: op_id) if op_id else None,
                case_dir=case_dir,
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
                # The preview's own flag means "shorter than the output"; the
                # output itself may have been cut at the limit too
                if exec_result.get("truncated"):
                    resp_data["truncated"] = True
            else:
                resp_data = exec_result
                resp_format = exec_result.get("_output_format", "text")

            # Written first, to the call's case, with the id its output's
            # folder is named by; the response carries that id
            logged_id = audit.log(
                tool="run_command",
                audit_id=op_id,
                case_dir=case_dir,
                params={"command": command, "purpose": purpose},
                result_summary={
                    "exit_code": exec_result["exit_code"],
                    "output_file": exec_result.get("output_file", ""),
                    "output_sha256": exec_result.get("output_sha256", ""),
                    "output_sha256_scope": exec_result.get("output_sha256_scope", ""),
                    "stdout_bytes": exec_result.get("stdout_total_bytes", 0),
                    "stdout_head": (exec_result.get("stdout") or "")[:500],
                    **({"truncated": True} if exec_result.get("truncated") else {}),
                },
                elapsed_ms=elapsed * 1000,
                input_files=listed_files or None,
                input_sha256s=listed_shas if listed_files else None,
                input_detection_method=detection_method,
                extra={
                    **({"inputs": inputs} if inputs else {}),
                    **(
                        {"input_registered": registered}
                        if registered
                        else {}
                    ),
                }
                or None,
            )
            response = build_response(
                tool_name="run_command",
                success=exec_result["exit_code"] == 0,
                data=resp_data,
                audit_id=logged_id,
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

            response["output_sha256"] = exec_result.get("output_sha256", "")
            response["output_sha256_scope"] = exec_result.get("output_sha256_scope", "")
            # Add full output metadata if file was saved
            if exec_result.get("output_file"):
                response["full_output_path"] = exec_result["output_file"]
                response["full_output_sha256"] = exec_result.get("output_sha256")
                response["full_output_bytes"] = exec_result.get("stdout_total_bytes")

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
            elif detection_method == "llm" and not listed_files:
                response["input_files_warning"] = (
                    "input_files provided but none resolved to existing files. "
                    "Provenance chain will be incomplete."
                )
            return response

        except SiftError as e:
            elapsed = time.monotonic() - start
            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(e)},
                elapsed_ms=elapsed * 1000,
                audit_id=op_id,
                case_dir=case_dir,
            )
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=logged_id,
                error=str(e),
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            return response
        except (ValueError, OSError, RuntimeError) as e:
            elapsed = time.monotonic() - start
            logger.warning("run_command unexpected error: %s: %s", type(e).__name__, e)
            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(e)},
                elapsed_ms=elapsed * 1000,
                audit_id=op_id,
                case_dir=case_dir,
            )
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=logged_id,
                error=str(e),
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            return response
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error("run_command catch-all error: %s: %s", type(e).__name__, e)
            logged_id = audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": f"{type(e).__name__}: {e}"},
                elapsed_ms=elapsed * 1000,
                audit_id=op_id,
                case_dir=case_dir,
            )
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=logged_id,
                error=f"Unexpected error: {type(e).__name__}",
            )
            if logged_id is None:
                response["warning"] = "Audit write failed — action not recorded"
            return response

    return server
