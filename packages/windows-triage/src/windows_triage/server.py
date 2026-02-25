"""
Windows Triage MCP Server

A Model Context Protocol (MCP) server for OFFLINE forensic file and indicator
triage. Enables AI assistants to validate files, processes, and persistence
against curated Windows baselines - all running locally without external
API dependencies.

Architecture:
    - known_good.db: Ground truth baselines from clean Windows installations
    - context.db: Risk enrichment (LOLBins, vulnerable drivers, process rules)

For threat intelligence (hash/IOC reputation), use opencti-mcp separately.

Verdict System:
    - SUSPICIOUS: Anomaly detected (wrong path, spoofing, hash mismatch,
                  suspicious parent process, vulnerable driver)
    - EXPECTED_LOLBIN: In baseline but has abuse potential (LOLBin)
    - EXPECTED: In Windows baseline, no red flags
    - UNKNOWN: Not in any database (NEUTRAL - may be legitimate software)

Process Tree Validation:
    For cmd.exe, powershell.exe, and pwsh.exe, we use a blacklist approach
    with 80 suspicious parent processes across 12 categories:
    - Microsoft Office (macro malware, OLE exploits)
    - Browsers (drive-by downloads, browser exploits)
    - PDF Readers (malicious PDF exploitation)
    - Java (Log4j, deserialization attacks)
    - Collaboration apps (Teams, Slack, Zoom exploits)
    - Media players (malicious media exploits)
    - Archive tools (malicious archive exploits)
    - Text editors (no legitimate reason to spawn shells)
    - Image viewers (image-based exploits)
    - LOLBins (proxy execution techniques)
    - DCOM abuse (lateral movement via T1021.003)
    - System services (injection targets like lsass.exe, csrss.exe)

Key Design: UNKNOWN is neutral. Most third-party software won't be in our
baseline, and that's OK. Only flag as suspicious if actual indicators present.
"""

from __future__ import annotations

import atexit
import fnmatch
import json
import logging
import time
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import TextContent, Tool
from sift_common.instructions import WINDOWS_TRIAGE as _INSTRUCTIONS

from .analysis import (
    analyze_filename,
    calculate_file_verdict,
    calculate_hash_verdict,
    calculate_process_verdict,
    calculate_service_verdict,
    check_process_name_spoofing,
    detect_hash_algorithm,
    extract_filename,
    is_system_path,
    normalize_hash,
    normalize_path,
    validate_hash,
)
from .audit import AuditWriter, resolve_examiner
from .config import Config, ConfigurationError, get_config
from .db import ContextDB, KnownGoodDB, RegistryDB
from .exceptions import DatabaseError, ValidationError, WindowsTriageError
from .oplog import setup_logging
from .tool_metadata import DEFAULT_METADATA, TOOL_METADATA

logger = logging.getLogger(__name__)


def _validate_input_length(value: Any, max_length: int, field_name: str) -> None:
    """Validate input length to prevent resource exhaustion.

    Args:
        value: Input value to validate (must be string or None)
        max_length: Maximum allowed length
        field_name: Name of field for error message

    Raises:
        ValidationError: If input exceeds max_length
    """
    if value is not None and isinstance(value, str) and len(value) > max_length:
        raise ValidationError(
            f"{field_name} exceeds maximum length of {max_length} characters"
        )


def _validate_no_null_bytes(value: Any, field_name: str) -> None:
    """Validate input contains no null bytes.

    Args:
        value: Input value to validate
        field_name: Name of field for error message

    Raises:
        ValidationError: If input contains null bytes
    """
    if value is not None and isinstance(value, str) and "\x00" in value:
        raise ValidationError(f"{field_name} contains invalid null bytes")


# Forensic context for suspicious parent processes — explains why the
# parent-child relationship is suspicious, aiding investigator triage.
SUSPICIOUS_PARENT_CONTEXT = {
    "winword.exe": "Office macro execution — Office applications should not spawn command interpreters under normal operation. Check for VBA macros, DDE links, or exploit-based code execution.",
    "excel.exe": "Office macro execution — spreadsheet macros spawning shells indicates malicious macro executing commands.",
    "powerpnt.exe": "Office macro execution — presentation macros spawning shells indicates malicious content.",
    "outlook.exe": "Email client exploitation — Outlook spawning shells suggests embedded exploit or malicious attachment handler.",
    "chrome.exe": "Browser exploitation — browser spawning shells suggests drive-by download, browser exploit, or malicious extension.",
    "firefox.exe": "Browser exploitation — browser spawning shells suggests drive-by download or exploit.",
    "msedge.exe": "Browser exploitation — browser spawning shells suggests drive-by download or exploit.",
    "iexplore.exe": "Browser exploitation — IE spawning shells suggests ActiveX exploit or drive-by download.",
    "acrord32.exe": "PDF exploitation — PDF reader spawning shells suggests malicious PDF with embedded JavaScript or exploit.",
    "foxitreader.exe": "PDF exploitation — PDF reader spawning shells suggests malicious PDF content.",
    "mshta.exe": "HTA abuse — mshta.exe is commonly abused for script execution via .hta files.",
    "wscript.exe": "Script execution — Windows Script Host spawning shells indicates script-based malware.",
    "cscript.exe": "Script execution — Console Script Host spawning shells indicates script-based malware.",
}


class WindowsTriageServer:
    """MCP server for forensic triage operations."""

    def __init__(
        self,
        config: Config | None = None,
        known_good_path: Path | None = None,
        context_path: Path | None = None,
        registry_path: Path | None = None,
    ) -> None:
        """Initialize the forensic triage server.

        Args:
            config: Optional Config object. If not provided, loads from environment.
            known_good_path: Override path to known_good.db (for testing)
            context_path: Override path to context.db (for testing)
            registry_path: Override path to known_good_registry.db (for testing)

        Raises:
            ConfigurationError: If configuration is invalid
            DatabaseError: If databases cannot be opened
        """
        self.server = Server("windows-triage", instructions=_INSTRUCTIONS)
        self._start_time = time.time()

        # Load configuration
        self.config = config or get_config()

        # Resolve database paths (explicit paths override config)
        kg_path = known_good_path or self.config.known_good_db
        ctx_path = context_path or self.config.context_db
        reg_path = registry_path or self.config.registry_db

        # Initialize database connections with read-only mode and caching
        # Use read-only=True for production (safer), allow writes for testing
        if self.config.skip_db_validation:
            logger.warning(
                "WT_SKIP_DB_VALIDATION is set — database validation disabled. Not recommended for production."
            )
        # Tests use skip_db_validation=True to both skip file-exists checks
        # and enable writes for populating temporary databases
        read_only = not self.config.skip_db_validation
        cache_size = self.config.cache_size

        try:
            self.known_good_db = KnownGoodDB(
                kg_path, read_only=read_only, cache_size=cache_size
            )
            self.context_db = ContextDB(
                ctx_path, read_only=read_only, cache_size=cache_size
            )
            # Registry DB is optional - initialize but don't fail if missing
            self.registry_db: RegistryDB | None = None
            if reg_path.exists():
                self.registry_db = RegistryDB(
                    reg_path,
                    read_only=True,  # Always read-only
                    cache_size=cache_size,
                )

            # Startup validation: verify databases are accessible
            if not self.config.skip_db_validation:
                self._validate_databases()

        except DatabaseError:
            raise  # Re-raise our own errors unchanged
        except FileNotFoundError as e:
            raise DatabaseError(f"Database file not found: {e}") from e
        except PermissionError as e:
            raise DatabaseError(f"Permission denied accessing database: {e}") from e
        except Exception as e:
            raise DatabaseError(f"Failed to initialize databases: {e}") from e

        self._audit = AuditWriter("windows-triage-mcp")
        self._register_tools()

    def close_databases(self) -> None:
        """Close all database connections."""
        for db in (self.known_good_db, self.context_db, self.registry_db):
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass

    @staticmethod
    def _error_response(error_code: str, message: str) -> list[TextContent]:
        """Format error response consistently."""
        return [
            TextContent(
                type="text", text=json.dumps({"error": error_code, "message": message})
            )
        ]

    def _wrap_response(
        self,
        tool_name: str,
        arguments: dict,
        result: dict,
        evidence_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> dict:
        """Wrap tool result with evidence ID, caveats, and audit trail.

        Always generates evidence_id and writes audit — including for errors.
        """
        summary = result if "error" not in result else {"error": result["error"]}
        evidence_id = self._audit.log(
            tool=tool_name,
            params=arguments,
            result_summary=summary,
            evidence_id=evidence_id,
            elapsed_ms=elapsed_ms,
        )
        meta = TOOL_METADATA.get(tool_name, DEFAULT_METADATA)

        result["evidence_id"] = evidence_id
        result["examiner"] = resolve_examiner()
        if "error" not in result:
            result["caveats"] = meta["caveats"]
            result["interpretation_constraint"] = meta["interpretation_constraint"]
        return result

    def _validate_databases(self) -> None:
        """Validate that databases are accessible and have expected tables.

        Raises:
            DatabaseError: If validation fails
        """
        import sqlite3

        try:
            # Test known_good.db connectivity
            kg_stats = self.known_good_db.get_stats()
            logger.info(
                f"known_good.db: {kg_stats.get('files', 0)} files, "
                f"{kg_stats.get('hashes', 0)} hashes"
            )

            # Test context.db connectivity
            ctx_stats = self.context_db.get_stats()
            logger.info(
                f"context.db: {ctx_stats.get('lolbins', 0)} lolbins, "
                f"{ctx_stats.get('vulnerable_drivers', 0)} drivers"
            )

        except sqlite3.OperationalError as e:
            raise DatabaseError(f"SQLite error during validation: {e}") from e
        except sqlite3.DatabaseError as e:
            raise DatabaseError(f"Database corruption or format error: {e}") from e
        except Exception as e:
            raise DatabaseError(f"Database validation failed: {e}") from e

    def _register_tools(self) -> None:
        """Register all MCP tools with the server.

        Registers 13 forensic triage tools:
        - check_file: File baseline validation with LOLBin and hash checking
        - check_process_tree: Parent-child process relationship validation
        - check_service: Windows service baseline validation (requires os_version)
        - check_scheduled_task: Task baseline validation (requires os_version)
        - check_autorun: Registry autorun validation (requires os_version)
        - check_registry: Full registry baseline lookup (requires optional 12GB database)
        - check_hash: Vulnerable driver hash lookup
        - analyze_filename: Filename heuristics (Unicode, double extension, entropy)
        - check_lolbin: LOLBin lookup with abuse functions
        - check_hijackable_dll: DLL hijacking scenario lookup
        - check_pipe: Named pipe analysis for C2 detection
        - get_db_stats: Database statistics
        - get_health: Server health and uptime
        """

        @self.server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="check_file",
                    description="Check a file path/name against Windows baseline. Returns whether the file is expected on a clean Windows system.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Windows file path",
                            },
                            "hash": {
                                "type": "string",
                                "description": "Optional file hash (MD5/SHA1/SHA256)",
                            },
                            "os_version": {
                                "type": "string",
                                "description": "Optional OS filter (e.g., 'Windows 10')",
                            },
                        },
                        "required": ["path"],
                    },
                ),
                Tool(
                    name="check_process_tree",
                    description="Validate process parent-child relationship against expectations database.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "process_name": {
                                "type": "string",
                                "description": "Process name (e.g., 'svchost.exe')",
                            },
                            "parent_name": {
                                "type": "string",
                                "description": "Parent process name",
                            },
                            "path": {
                                "type": "string",
                                "description": "Optional executable path",
                            },
                            "user": {
                                "type": "string",
                                "description": "Optional user context",
                            },
                        },
                        "required": ["process_name", "parent_name"],
                    },
                ),
                Tool(
                    name="check_service",
                    description="Check if a Windows service exists in the baseline for a specific OS version. OS version is REQUIRED because services vary significantly between Windows versions - a legitimate service on Windows 10 1507 may not exist on Windows 11 and could indicate malicious activity if found there.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "service_name": {
                                "type": "string",
                                "description": "Service name (e.g., 'BITS', 'Spooler')",
                            },
                            "binary_path": {
                                "type": "string",
                                "description": "Service binary path - strongly recommended for hijacking detection",
                            },
                            "os_version": {
                                "type": "string",
                                "description": "Target OS version (e.g., 'W11_22H2', 'W10_21H2', 'Server2022'). REQUIRED for accurate results.",
                            },
                        },
                        "required": ["service_name", "os_version"],
                    },
                ),
                Tool(
                    name="check_scheduled_task",
                    description="Check if a scheduled task exists in the Windows baseline for a specific OS version. OS version is REQUIRED because scheduled tasks vary between Windows versions - legacy tasks may not exist on modern Windows.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "task_path": {
                                "type": "string",
                                "description": "Task path (e.g., '\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan')",
                            },
                            "os_version": {
                                "type": "string",
                                "description": "Target OS version (e.g., 'W11_22H2', 'W10_21H2'). REQUIRED for accurate results.",
                            },
                        },
                        "required": ["task_path", "os_version"],
                    },
                ),
                Tool(
                    name="check_autorun",
                    description="Check if a registry autorun entry exists in the baseline for a specific OS version. OS version is REQUIRED because autorun entries vary between Windows versions.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "key_path": {
                                "type": "string",
                                "description": "Registry key path (e.g., 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')",
                            },
                            "value_name": {
                                "type": "string",
                                "description": "Registry value name",
                            },
                            "os_version": {
                                "type": "string",
                                "description": "Target OS version (e.g., 'W11_22H2', 'W10_21H2'). REQUIRED for accurate results.",
                            },
                        },
                        "required": ["key_path", "os_version"],
                    },
                ),
                Tool(
                    name="check_registry",
                    description="Check if a registry key or value exists in the full registry baseline. Requires the optional known_good_registry.db (12GB). For persistence checks, use check_autorun instead.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "key_path": {
                                "type": "string",
                                "description": "Registry key path (e.g., 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion')",
                            },
                            "value_name": {
                                "type": "string",
                                "description": "Optional: specific value name to check",
                            },
                            "hive": {
                                "type": "string",
                                "description": "Optional: registry hive (SYSTEM, SOFTWARE, NTUSER, DEFAULT)",
                            },
                            "os_version": {
                                "type": "string",
                                "description": "Optional: filter by OS version",
                            },
                        },
                        "required": ["key_path"],
                    },
                ),
                Tool(
                    name="check_hash",
                    description="Check file hash against vulnerable driver database (LOLDrivers). For threat intelligence, use opencti-mcp separately.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hash": {
                                "type": "string",
                                "description": "File hash (MD5/SHA1/SHA256)",
                            }
                        },
                        "required": ["hash"],
                    },
                ),
                Tool(
                    name="analyze_filename",
                    description="Analyze a filename for suspicious characteristics: Unicode evasion, typosquatting, double extensions, known tools.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "Filename to analyze",
                            }
                        },
                        "required": ["filename"],
                    },
                ),
                Tool(
                    name="check_lolbin",
                    description="Check if a filename is a known LOLBin (Living Off The Land Binary) and get abuse information.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "Filename to check (e.g., 'certutil.exe')",
                            }
                        },
                        "required": ["filename"],
                    },
                ),
                Tool(
                    name="check_hijackable_dll",
                    description="Check if a DLL is vulnerable to DLL hijacking attacks.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "dll_name": {
                                "type": "string",
                                "description": "DLL filename (e.g., 'version.dll')",
                            }
                        },
                        "required": ["dll_name"],
                    },
                ),
                Tool(
                    name="check_pipe",
                    description="Check if a named pipe is suspicious (C2 indicator) or a known Windows pipe.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "pipe_name": {
                                "type": "string",
                                "description": "Named pipe name",
                            }
                        },
                        "required": ["pipe_name"],
                    },
                ),
                Tool(
                    name="get_db_stats",
                    description="Get database statistics.",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="get_health",
                    description="Get server health status including uptime, database connectivity, and cache statistics.",
                    inputSchema={"type": "object", "properties": {}},
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            evidence_id = self._audit._next_evidence_id()
            start = time.monotonic()
            try:
                # Input validation: check lengths and content
                if name == "check_file":
                    _validate_input_length(
                        arguments.get("path"), self.config.max_path_length, "path"
                    )
                    _validate_input_length(
                        arguments.get("hash"), self.config.max_hash_length, "hash"
                    )
                    _validate_no_null_bytes(arguments.get("path"), "path")
                    _validate_no_null_bytes(arguments.get("hash"), "hash")
                    result = await self._check_file(
                        arguments["path"],
                        arguments.get("hash"),
                        arguments.get("os_version"),
                    )
                elif name == "check_process_tree":
                    _validate_input_length(
                        arguments.get("process_name"),
                        self.config.max_path_length,
                        "process_name",
                    )
                    _validate_input_length(
                        arguments.get("parent_name"),
                        self.config.max_path_length,
                        "parent_name",
                    )
                    _validate_input_length(
                        arguments.get("path"), self.config.max_path_length, "path"
                    )
                    _validate_no_null_bytes(
                        arguments.get("process_name"), "process_name"
                    )
                    _validate_no_null_bytes(arguments.get("parent_name"), "parent_name")
                    result = await self._check_process_tree(
                        arguments["process_name"],
                        arguments["parent_name"],
                        arguments.get("path"),
                        arguments.get("user"),
                    )
                elif name == "check_service":
                    _validate_input_length(
                        arguments.get("service_name"),
                        self.config.max_service_name_length,
                        "service_name",
                    )
                    _validate_input_length(
                        arguments.get("binary_path"),
                        self.config.max_path_length,
                        "binary_path",
                    )
                    _validate_no_null_bytes(
                        arguments.get("service_name"), "service_name"
                    )
                    result = await self._check_service(
                        arguments["service_name"],
                        arguments.get("binary_path"),
                        arguments.get("os_version"),
                    )
                elif name == "check_scheduled_task":
                    _validate_input_length(
                        arguments.get("task_path"),
                        self.config.max_task_path_length,
                        "task_path",
                    )
                    _validate_no_null_bytes(arguments.get("task_path"), "task_path")
                    result = await self._check_scheduled_task(
                        arguments["task_path"], arguments.get("os_version")
                    )
                elif name == "check_autorun":
                    _validate_input_length(
                        arguments.get("key_path"),
                        self.config.max_key_path_length,
                        "key_path",
                    )
                    _validate_no_null_bytes(arguments.get("key_path"), "key_path")
                    result = await self._check_autorun(
                        arguments["key_path"],
                        arguments.get("value_name"),
                        arguments.get("os_version"),
                    )
                elif name == "check_registry":
                    _validate_input_length(
                        arguments.get("key_path"),
                        self.config.max_key_path_length,
                        "key_path",
                    )
                    _validate_input_length(
                        arguments.get("value_name"),
                        self.config.max_service_name_length,
                        "value_name",
                    )
                    _validate_input_length(arguments.get("hive"), 20, "hive")
                    _validate_input_length(
                        arguments.get("os_version"),
                        self.config.max_service_name_length,
                        "os_version",
                    )
                    _validate_no_null_bytes(arguments.get("key_path"), "key_path")
                    _validate_no_null_bytes(arguments.get("value_name"), "value_name")
                    _validate_no_null_bytes(arguments.get("hive"), "hive")
                    _validate_no_null_bytes(arguments.get("os_version"), "os_version")
                    result = await self._check_registry(
                        arguments["key_path"],
                        arguments.get("value_name"),
                        arguments.get("hive"),
                        arguments.get("os_version"),
                    )
                elif name == "check_hash":
                    _validate_input_length(
                        arguments.get("hash"), self.config.max_hash_length, "hash"
                    )
                    _validate_no_null_bytes(arguments.get("hash"), "hash")
                    result = await self._check_hash(arguments["hash"])
                elif name == "analyze_filename":
                    _validate_input_length(
                        arguments.get("filename"),
                        self.config.max_path_length,
                        "filename",
                    )
                    _validate_no_null_bytes(arguments.get("filename"), "filename")
                    result = await self._analyze_filename(arguments["filename"])
                elif name == "check_lolbin":
                    _validate_input_length(
                        arguments.get("filename"),
                        self.config.max_path_length,
                        "filename",
                    )
                    _validate_no_null_bytes(arguments.get("filename"), "filename")
                    result = await self._check_lolbin(arguments["filename"])
                elif name == "check_hijackable_dll":
                    _validate_input_length(
                        arguments.get("dll_name"),
                        self.config.max_path_length,
                        "dll_name",
                    )
                    _validate_no_null_bytes(arguments.get("dll_name"), "dll_name")
                    result = await self._check_hijackable_dll(arguments["dll_name"])
                elif name == "check_pipe":
                    _validate_input_length(
                        arguments.get("pipe_name"),
                        self.config.max_pipe_name_length,
                        "pipe_name",
                    )
                    _validate_no_null_bytes(arguments.get("pipe_name"), "pipe_name")
                    result = await self._check_pipe(arguments["pipe_name"])
                elif name == "get_db_stats":
                    result = await self._get_db_stats()
                elif name == "get_health":
                    result = await self._get_health()
                else:
                    result = {"error": f"Unknown tool: {name}"}

                elapsed_ms = (time.monotonic() - start) * 1000
                result = self._wrap_response(
                    name,
                    arguments,
                    result,
                    evidence_id=evidence_id,
                    elapsed_ms=elapsed_ms,
                )

                return [
                    TextContent(
                        type="text", text=json.dumps(result, indent=2, default=str)
                    )
                ]

            except ValidationError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.warning(f"Tool {name} validation failed: {e}")
                error_result = {"error": "validation_error", "message": str(e)}
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    evidence_id=evidence_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]
            except DatabaseError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error(f"Tool {name} database error: {e}")
                error_result = {
                    "error": "database_error",
                    "message": "A database error occurred. Check server logs.",
                }
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    evidence_id=evidence_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]
            except WindowsTriageError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error(f"Tool {name} error: {e}")
                error_result = {"error": "server_error", "message": str(e)}
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    evidence_id=evidence_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]
            except Exception:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.exception(f"Tool {name} internal error")
                error_result = {
                    "error": "internal_error",
                    "message": "An unexpected error occurred. Check server logs.",
                }
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    evidence_id=evidence_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

    # ========== TOOL IMPLEMENTATIONS ==========

    async def _check_file(
        self, path: str, hash_value: str | None = None, os_version: str | None = None
    ) -> dict[str, Any]:
        """Check file path/name against baseline."""
        # Defense in depth: validate even if call_tool already validated
        _validate_input_length(path, self.config.max_path_length, "path")
        _validate_input_length(hash_value, self.config.max_hash_length, "hash")

        normalized_path = normalize_path(path)
        filename = extract_filename(path)
        sys_path = is_system_path(path)

        # Check baseline (returns list)
        baseline_matches = self.known_good_db.lookup_by_path(
            normalized_path, os_version
        )
        path_in_baseline = len(baseline_matches) > 0

        # Check if filename exists anywhere in baseline
        filename_matches = self.known_good_db.lookup_by_filename(filename)
        filename_in_baseline = len(filename_matches) > 0

        # Check for LOLBin
        lolbin_info = self.context_db.check_lolbin(filename)

        # Analyze filename for suspicious patterns
        filename_analysis = analyze_filename(filename)
        findings = list(filename_analysis.get("findings", []))

        # Check for process name spoofing
        protected_names = self.context_db.get_protected_process_names()
        spoofing = check_process_name_spoofing(filename, protected_names)
        findings.extend(spoofing)

        # Check for known malicious tool patterns
        tool_match = self.context_db.check_suspicious_filename(filename)
        if tool_match:
            findings.append(
                {
                    "type": "known_tool",
                    "tool_name": tool_match.get("tool_name"),
                    "category": tool_match.get("category"),
                    "severity": tool_match.get("risk_level", "critical"),
                    "description": f"Known tool: {tool_match.get('tool_name', 'unknown')}",
                }
            )

        # Check if filename is a protected process name
        is_protected = filename.lower() in [p.lower() for p in protected_names]

        # For protected processes, check if path matches their specific valid_paths
        # (not just generic is_system_path)
        protected_path_valid = True  # Default to True for non-protected processes
        if is_protected:
            proc_info = self.context_db.get_expected_process(filename)
            if proc_info and proc_info.get("valid_paths"):
                valid_paths = proc_info["valid_paths"]
                # Check if normalized path matches any valid path
                protected_path_valid = False
                for valid_path in valid_paths:
                    # Handle wildcards (e.g., "\\programdata\\...\\*\\msmpeng.exe")
                    if "*" in valid_path:
                        if fnmatch.fnmatch(normalized_path, valid_path):
                            protected_path_valid = True
                            break
                    elif normalized_path == valid_path:
                        protected_path_valid = True
                        break

                if not protected_path_valid:
                    findings.append(
                        {
                            "type": "protected_process_wrong_path",
                            "severity": "critical",
                            "description": f"Protected process {filename} in unexpected path",
                            "expected_paths": valid_paths,
                            "actual_path": normalized_path,
                        }
                    )

        # Hash checks (optional) - local baseline validation only
        if hash_value and validate_hash(hash_value):
            hash_normalized = normalize_hash(hash_value)
            algorithm = detect_hash_algorithm(hash_normalized)

            # Check for hash mismatch with baseline
            if baseline_matches and algorithm:
                baseline_hashes = []
                for entry in baseline_matches:
                    if entry.get(algorithm):
                        baseline_hashes.append(entry[algorithm].lower())
                if baseline_hashes and hash_normalized.lower() not in baseline_hashes:
                    findings.append(
                        {
                            "type": "hash_mismatch",
                            "severity": "critical",
                            "description": "Hash does not match baseline - possible trojanized binary",
                        }
                    )

        # Calculate verdict using the proper verdict function
        # Note: For threat intel, use opencti-mcp separately
        verdict_result = calculate_file_verdict(
            path_in_baseline=path_in_baseline,
            filename_in_baseline=filename_in_baseline,
            is_system_path=sys_path,
            filename_findings=findings,
            lolbin_info=lolbin_info,
            is_protected_process=is_protected,
        )

        result = {
            "verdict": str(verdict_result.verdict),
            "reasons": verdict_result.reasons,
            "confidence": verdict_result.confidence,
            "path_in_baseline": path_in_baseline,
            "filename_in_baseline": filename_in_baseline,
            "is_system_path": sys_path,
        }

        if findings:
            result["findings"] = findings

        if lolbin_info:
            result["is_lolbin"] = True
            result["lolbin_functions"] = lolbin_info.get("functions", [])

        return result

    async def _check_process_tree(
        self,
        process_name: str,
        parent_name: str,
        path: str | None = None,
        user: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate process parent-child relationship.

        Uses three complementary approaches:
        1. Never-spawns (never_spawns_children): For injection targets like
           lsass.exe, dwm.exe, audiodg.exe - if these spawn ANY child process,
           it's critical and indicates process injection.
        2. Blacklist (suspicious_parents): For shells (cmd, powershell, pwsh),
           flags known-bad parents like Office apps, browsers, DCOM objects.
           80 suspicious parents total across 12 categories.
        3. Whitelist (valid_parents): For system processes like svchost.exe,
           flags if parent is NOT in the expected list.

        Args:
            process_name: Child process name (e.g., 'cmd.exe')
            parent_name: Parent process name (e.g., 'winword.exe')
            path: Optional executable path for validation
            user: Optional user context (SYSTEM vs user)

        Returns:
            Dict with verdict, findings, and confidence level.
            Finding types: 'injection_detected' (critical), 'suspicious_parent'
            (critical), or 'unexpected_parent' (high).
        """
        # Defense in depth: validate inputs
        _validate_input_length(
            process_name, self.config.max_path_length, "process_name"
        )
        _validate_input_length(parent_name, self.config.max_path_length, "parent_name")
        _validate_input_length(path, self.config.max_path_length, "path")
        _validate_input_length(user, self.config.max_service_name_length, "user")

        findings = []

        # Analyze process name for suspicious patterns (double extensions, entropy, etc.)
        filename_analysis = analyze_filename(process_name)
        findings.extend(filename_analysis.get("findings", []))

        # Check for process name spoofing (Unicode evasion, typosquatting)
        protected_names = self.context_db.get_protected_process_names()
        spoofing = check_process_name_spoofing(process_name, protected_names)
        findings.extend(spoofing)

        # Check if PARENT is a process that should NEVER spawn children (injection detection)
        parent_info = self.context_db.get_expected_process(parent_name)
        if parent_info and parent_info.get("never_spawns_children"):
            findings.append(
                {
                    "type": "injection_detected",
                    "severity": "critical",
                    "parent": parent_name,
                    "child": process_name,
                    "description": f"CRITICAL: {parent_name} should NEVER spawn child processes. "
                    f"This indicates process injection (e.g., credential theft, implant).",
                }
            )

        # Get expected process info
        proc_info = self.context_db.get_expected_process(process_name)

        if not proc_info:
            # Process not in expectations database
            verdict_result = calculate_process_verdict(
                process_known=False,
                parent_valid=True,
                path_valid=None,
                user_valid=None,
                findings=findings,
            )

            return {
                "verdict": str(verdict_result.verdict),
                "reasons": verdict_result.reasons,
                "confidence": verdict_result.confidence,
                "in_expectations_db": False,
                "findings": findings,
            }

        # Check for suspicious parents (blacklist approach)
        suspicious_parents = proc_info.get("suspicious_parents", [])
        parent_is_suspicious = False
        if suspicious_parents:
            parent_is_suspicious = parent_name.lower() in [
                p.lower() for p in suspicious_parents
            ]
            if parent_is_suspicious:
                desc = f"Suspicious parent process: {parent_name} spawning {process_name} is a common attack pattern"
                context = SUSPICIOUS_PARENT_CONTEXT.get(parent_name.lower(), "")
                if context:
                    desc += f". {context}"
                findings.append(
                    {
                        "type": "suspicious_parent",
                        "severity": "critical",
                        "parent": parent_name,
                        "description": desc,
                    }
                )

        # Validate parent against whitelist (if defined)
        valid_parents = proc_info.get("valid_parents") or []
        parent_valid = True  # Default to valid if no whitelist
        if valid_parents:
            parent_valid = parent_name.lower() in [p.lower() for p in valid_parents]
            if not parent_valid:
                findings.append(
                    {
                        "type": "unexpected_parent",
                        "severity": "high",
                        "expected": valid_parents,
                        "actual": parent_name,
                        "description": f"Unexpected parent: expected {valid_parents}, got {parent_name}",
                    }
                )

        # Validate path if provided
        path_valid = None
        if path:
            valid_paths = proc_info.get("valid_paths", [])
            if valid_paths:
                normalized = normalize_path(path)
                path_valid = any(normalized == normalize_path(p) for p in valid_paths)
                if not path_valid:
                    findings.append(
                        {
                            "type": "unexpected_path",
                            "severity": "high",
                            "expected": valid_paths,
                            "actual": path,
                            "description": "Unexpected executable path",
                        }
                    )

        # Validate user if provided
        user_valid = None
        if user:
            user_type = proc_info.get("user_type")
            if user_type == "SYSTEM":
                user_valid = user.upper() in [
                    "SYSTEM",
                    "LOCAL SERVICE",
                    "NETWORK SERVICE",
                    "NT AUTHORITY\\SYSTEM",
                ]
            elif user_type == "USER":
                user_valid = user.upper() not in [
                    "SYSTEM",
                    "LOCAL SERVICE",
                    "NETWORK SERVICE",
                ]
            else:
                user_valid = True

            if user_valid is False:
                findings.append(
                    {
                        "type": "unexpected_user",
                        "severity": "medium",
                        "expected_type": user_type,
                        "actual": user,
                        "description": f"Unexpected user context: expected {user_type}",
                    }
                )

        # Calculate verdict
        verdict_result = calculate_process_verdict(
            process_known=True,
            parent_valid=parent_valid and not parent_is_suspicious,
            path_valid=path_valid,
            user_valid=user_valid,
            findings=findings,
        )

        result = {
            "verdict": str(verdict_result.verdict),
            "reasons": verdict_result.reasons,
            "confidence": verdict_result.confidence,
            "in_expectations_db": True,
            "findings": findings,
        }

        if valid_parents:
            result["expected_parents"] = valid_parents
        if suspicious_parents:
            result["suspicious_parents"] = suspicious_parents
        if user:
            result["user_context"] = {
                "user": user,
                "expected_type": proc_info.get("user_type", "ANY"),
                "user_valid": user_valid,
            }

        return result

    async def _check_service(
        self,
        service_name: str,
        binary_path: str | None = None,
        os_version: str | None = None,
    ) -> dict[str, Any]:
        """Check if a service exists in the baseline."""
        # Defense in depth: validate inputs
        _validate_input_length(
            service_name, self.config.max_service_name_length, "service_name"
        )
        _validate_input_length(binary_path, self.config.max_path_length, "binary_path")
        _validate_input_length(
            os_version, self.config.max_service_name_length, "os_version"
        )

        # OS version is required for accurate results
        if not os_version:
            return {
                "error": "os_version is required",
                "message": "Service baselines vary significantly between Windows versions. A service that is legitimate on Windows 10 1507 may not exist on Windows 11 and could indicate malicious activity. Please provide the target OS version (e.g., W11_22H2, W10_21H2, Server2022).",
                "verdict": None,
                "lookup_performed": False,
            }

        # Lookup returns list
        baseline_matches = self.known_good_db.lookup_service(service_name, os_version)
        in_baseline = len(baseline_matches) > 0

        # Analyze binary path if provided
        binary_findings = []
        binary_path_matches = None

        if binary_path and in_baseline:
            baseline_binary = baseline_matches[0].get("binary_path_pattern")
            if baseline_binary:
                norm_provided = normalize_path(binary_path)
                norm_baseline = normalize_path(baseline_binary)
                binary_path_matches = norm_provided == norm_baseline

            # Analyze binary filename
            binary_filename = extract_filename(binary_path)
            analysis = analyze_filename(binary_filename)
            binary_findings = analysis.get("findings", [])

        # Calculate verdict
        verdict_result = calculate_service_verdict(
            service_in_baseline=in_baseline,
            binary_path_matches=binary_path_matches,
            binary_findings=binary_findings,
        )

        result = {
            "verdict": str(verdict_result.verdict),
            "reasons": verdict_result.reasons,
            "confidence": verdict_result.confidence,
            "in_baseline": in_baseline,
        }

        if in_baseline:
            result["baseline_info"] = {
                "display_name": baseline_matches[0].get("display_name"),
                "os_versions": baseline_matches[0].get("os_versions", []),
            }

        return result

    async def _check_scheduled_task(
        self, task_path: str, os_version: str | None = None
    ) -> dict[str, Any]:
        """Check if a scheduled task exists in baseline."""
        # Defense in depth: validate inputs
        _validate_input_length(task_path, self.config.max_task_path_length, "task_path")
        _validate_input_length(
            os_version, self.config.max_service_name_length, "os_version"
        )

        # OS version is required for accurate results
        if not os_version:
            return {
                "error": "os_version is required",
                "message": "Scheduled task baselines vary between Windows versions. Legacy tasks may not exist on modern Windows. Please provide the target OS version (e.g., W11_22H2, W10_21H2).",
                "verdict": None,
                "lookup_performed": False,
            }

        # Lookup returns list
        baseline_matches = self.known_good_db.lookup_task(task_path, os_version)
        in_baseline = len(baseline_matches) > 0

        if in_baseline:
            return {
                "verdict": "EXPECTED",
                "reasons": ["Task found in Windows baseline"],
                "confidence": "high",
                "in_baseline": True,
                "task_name": baseline_matches[0].get("task_name"),
                "os_versions": baseline_matches[0].get("os_versions", []),
            }

        # Check for suspicious locations
        findings = []
        task_lower = task_path.lower()
        if any(
            x in task_lower
            for x in ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\"]
        ):
            findings.append(
                {
                    "type": "suspicious_location",
                    "severity": "high",
                    "description": "Task in user-writable location",
                }
            )

        if findings:
            return {
                "verdict": "SUSPICIOUS",
                "reasons": ["Task in suspicious location"],
                "confidence": "medium",
                "in_baseline": False,
                "findings": findings,
            }

        return {
            "verdict": "UNKNOWN",
            "reasons": ["Task not in baseline (neutral - may be third-party software)"],
            "confidence": "low",
            "in_baseline": False,
        }

    async def _check_autorun(
        self,
        key_path: str,
        value_name: str | None = None,
        os_version: str | None = None,
    ) -> dict[str, Any]:
        """Check if an autorun entry exists in baseline."""
        # Defense in depth: validate inputs
        _validate_input_length(key_path, self.config.max_key_path_length, "key_path")
        _validate_input_length(
            value_name, self.config.max_service_name_length, "value_name"
        )
        _validate_input_length(
            os_version, self.config.max_service_name_length, "os_version"
        )

        # OS version is required for accurate results
        if not os_version:
            return {
                "error": "os_version is required",
                "message": "Autorun baselines vary between Windows versions. Please provide the target OS version (e.g., W11_22H2, W10_21H2).",
                "verdict": None,
                "lookup_performed": False,
            }

        # Lookup returns list
        baseline_matches = self.known_good_db.lookup_autorun(key_path, value_name)

        # Apply OS version filter
        baseline_matches = [
            m
            for m in baseline_matches
            if any(os_version.lower() in ov.lower() for ov in m.get("os_versions", []))
        ]

        in_baseline = len(baseline_matches) > 0

        if in_baseline:
            return {
                "verdict": "EXPECTED",
                "reasons": ["Autorun found in Windows baseline"],
                "confidence": "high",
                "in_baseline": True,
                "hive": baseline_matches[0].get("hive"),
                "os_versions": baseline_matches[0].get("os_versions", []),
            }

        # Check for high-risk persistence locations
        findings = []
        key_lower = key_path.lower()
        high_risk = ["currentversion\\run", "currentversion\\runonce", "winlogon"]
        if any(k in key_lower for k in high_risk):
            findings.append(
                {
                    "type": "high_risk_location",
                    "severity": "medium",
                    "description": "Common persistence registry location",
                }
            )

        if findings:
            return {
                "verdict": "SUSPICIOUS",
                "reasons": ["High-risk persistence location, not in baseline"],
                "confidence": "medium",
                "in_baseline": False,
                "findings": findings,
            }

        return {
            "verdict": "UNKNOWN",
            "reasons": [
                "Autorun not in baseline (neutral - may be legitimate software)"
            ],
            "confidence": "low",
            "in_baseline": False,
        }

    async def _check_registry(
        self,
        key_path: str,
        value_name: str | None = None,
        hive: str | None = None,
        os_version: str | None = None,
    ) -> dict[str, Any]:
        """Check registry key/value against full registry baseline.

        Requires the optional known_good_registry.db (12GB).
        For persistence checks (Run keys, etc.), use check_autorun instead.
        """
        # Check if registry database is available
        if self.registry_db is None or not self.registry_db.is_available():
            return {
                "error": "Registry database not available",
                "message": "The optional known_good_registry.db is not installed. See SETUP.md for installation instructions.",
                "verdict": None,
                "lookup_performed": False,
            }

        # Defense in depth: validate inputs
        _validate_input_length(key_path, self.config.max_key_path_length, "key_path")

        # Perform lookup
        if value_name:
            # Looking for specific value
            matches = self.registry_db.lookup_value(
                key_path, value_name, hive, os_version
            )
        else:
            # Looking for key (any values)
            matches = self.registry_db.lookup_key(key_path, hive, os_version)

        in_baseline = len(matches) > 0

        if in_baseline:
            # Collect unique OS versions and value info
            all_os_versions = set()
            values_found = []
            for m in matches:
                all_os_versions.update(m.get("os_versions", []))
                if m.get("value_name"):
                    values_found.append(
                        {
                            "name": m["value_name"],
                            "type": m.get("value_type"),
                            "hive": m.get("hive"),
                        }
                    )

            result = {
                "verdict": "EXPECTED",
                "reasons": ["Registry entry found in Windows baseline"],
                "confidence": "high",
                "in_baseline": True,
                "os_versions": sorted(list(all_os_versions))[
                    :10
                ],  # Limit for readability
                "os_version_count": len(all_os_versions),
                "match_count": len(matches),
            }

            if values_found:
                result["values"] = values_found[:10]  # Limit for readability
                result["value_count"] = len(values_found)

            return result

        return {
            "verdict": "UNKNOWN",
            "reasons": [
                "Registry entry not in baseline (neutral - may be legitimate software)"
            ],
            "confidence": "low",
            "in_baseline": False,
        }

    async def _check_hash(self, hash_value: str) -> dict[str, Any]:
        """Check hash against vulnerable driver database (offline only).

        For threat intelligence lookups, use opencti-mcp separately.
        """
        # Defense in depth: validate inputs
        _validate_input_length(hash_value, self.config.max_hash_length, "hash")

        if not validate_hash(hash_value):
            return {"error": "Invalid hash format", "verdict": "ERROR"}

        hash_normalized = normalize_hash(hash_value)
        algorithm = detect_hash_algorithm(hash_normalized)

        # Check vulnerable drivers (local database)
        driver_info = None
        is_vulnerable = False
        if algorithm:
            driver_info = self.context_db.check_vulnerable_driver(
                hash_normalized, algorithm
            )
            is_vulnerable = driver_info is not None

        # Calculate verdict
        verdict_result = calculate_hash_verdict(
            is_vulnerable_driver=is_vulnerable, driver_info=driver_info
        )

        result = {
            "verdict": str(verdict_result.verdict),
            "reasons": verdict_result.reasons,
            "confidence": verdict_result.confidence,
            "hash": hash_normalized,
            "algorithm": algorithm,
        }

        if driver_info:
            result["vulnerable_driver"] = driver_info

        return result

    async def _analyze_filename(self, filename: str) -> dict[str, Any]:
        """Analyze a filename for suspicious characteristics."""
        # Defense in depth: validate inputs
        _validate_input_length(filename, self.config.max_path_length, "filename")

        analysis = analyze_filename(filename)

        # Check against known tool patterns
        tool_match = self.context_db.check_suspicious_filename(filename)
        if tool_match:
            analysis["known_tool_match"] = {
                "tool_name": tool_match.get("tool_name"),
                "category": tool_match.get("category"),
                "risk_level": tool_match.get("risk_level"),
            }
            analysis["is_suspicious"] = True

        # Check for process spoofing
        protected_names = self.context_db.get_protected_process_names()
        spoofing = check_process_name_spoofing(filename, protected_names)
        if spoofing:
            analysis["findings"].extend(spoofing)
            analysis["is_suspicious"] = True

        return analysis

    async def _check_lolbin(self, filename: str) -> dict[str, Any]:
        """Check if a filename is a known LOLBin."""
        # Defense in depth: validate inputs
        _validate_input_length(filename, self.config.max_path_length, "filename")

        lolbin_info = self.context_db.check_lolbin(filename)

        if lolbin_info:
            return {
                "is_lolbin": True,
                "name": lolbin_info.get("name"),
                "description": lolbin_info.get("description"),
                "functions": lolbin_info.get("functions", []),
                "mitre_techniques": lolbin_info.get("mitre_techniques", []),
                "detection": lolbin_info.get("detection"),
            }

        return {"is_lolbin": False}

    async def _check_hijackable_dll(self, dll_name: str) -> dict[str, Any]:
        """Check if a DLL is vulnerable to hijacking attacks."""
        # Defense in depth: validate inputs
        _validate_input_length(dll_name, self.config.max_path_length, "dll_name")

        scenarios = self.context_db.check_hijackable_dll(dll_name)

        if not scenarios:
            return {"is_hijackable": False, "verdict": "UNKNOWN"}

        # Group by hijack type
        by_type = {}
        for scenario in scenarios:
            hijack_type = scenario.get("hijack_type", "unknown")
            if hijack_type not in by_type:
                by_type[hijack_type] = []
            by_type[hijack_type].append(
                {
                    "vulnerable_exe": scenario.get("vulnerable_exe"),
                    "vulnerable_exe_path": scenario.get("vulnerable_exe_path"),
                }
            )

        return {
            "is_hijackable": True,
            "verdict": "EXPECTED_LOLBIN",
            "total_scenarios": len(scenarios),
            "hijack_types": list(by_type.keys()),
            "scenarios_by_type": by_type,
            "mitre_technique": "T1574.001",
        }

    async def _check_pipe(self, pipe_name: str) -> dict[str, Any]:
        """Check if a named pipe is suspicious or known Windows pipe."""
        # Defense in depth: validate inputs
        _validate_input_length(pipe_name, self.config.max_pipe_name_length, "pipe_name")

        # Check for suspicious C2 pipes
        suspicious = self.context_db.check_suspicious_pipe(pipe_name)
        if suspicious:
            return {
                "verdict": "SUSPICIOUS",
                "is_suspicious": True,
                "tool_name": suspicious.get("tool_name"),
                "malware_family": suspicious.get("malware_family"),
                "description": suspicious.get("description"),
            }

        # Check if it's a known Windows pipe
        windows_pipe = self.context_db.check_windows_pipe(pipe_name)
        if windows_pipe:
            return {
                "verdict": "EXPECTED",
                "is_windows_pipe": True,
                "protocol": windows_pipe.get("protocol"),
                "service_name": windows_pipe.get("service_name"),
            }

        return {
            "verdict": "UNKNOWN",
            "is_suspicious": False,
            "is_windows_pipe": False,
        }

    async def _get_db_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        known_good_stats = self.known_good_db.get_stats()
        context_stats = self.context_db.get_stats()

        result = {
            "known_good_db": known_good_stats,
            "context_db": context_stats,
            "note": "For threat intelligence, use opencti-mcp separately",
        }

        # Add registry stats if available
        if self.registry_db and self.registry_db.is_available():
            result["registry_db"] = self.registry_db.get_stats()
        else:
            result["registry_db"] = {
                "available": False,
                "note": "Optional 12GB database not installed",
            }

        return result

    async def _get_health(self) -> dict[str, Any]:
        """Get server health status.

        Returns comprehensive health information including:
        - Server uptime
        - Database connectivity status
        - Cache statistics
        - Configuration summary
        """
        uptime_seconds = time.time() - self._start_time

        # Check database connectivity
        db_status = {"known_good": "unknown", "context": "unknown"}
        try:
            self.known_good_db.get_stats()
            db_status["known_good"] = "healthy"
        except Exception as e:
            logger.error(f"known_good health check failed: {e}")
            db_status["known_good"] = f"error: {type(e).__name__}"

        try:
            self.context_db.get_stats()
            db_status["context"] = "healthy"
        except Exception as e:
            logger.error(f"context health check failed: {e}")
            db_status["context"] = f"error: {type(e).__name__}"

        # Get cache statistics
        cache_stats = {
            "known_good_db": self.known_good_db.get_cache_stats(),
            "context_db": self.context_db.get_cache_stats(),
        }

        return {
            "status": "healthy"
            if all(v == "healthy" for v in db_status.values())
            else "degraded",
            "uptime_seconds": round(uptime_seconds, 2),
            "databases": db_status,
            "cache": cache_stats,
            "config": {
                "cache_size": self.config.cache_size,
                "log_level": self.config.log_level,
            },
        }

    async def run(self) -> None:
        """Run the MCP server using stdio transport.

        Starts the server and begins accepting MCP protocol messages over
        stdin/stdout. This method blocks until the server is stopped.

        The server handles tool calls from MCP clients, routing them to the
        appropriate handler methods registered during initialization.

        Raises:
            Exception: If the server encounters an unrecoverable error.
        """
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, write_stream, self.server.create_initialization_options()
            )


def main() -> None:
    """Entry point for the forensic triage MCP server.

    Initializes configuration from environment variables, sets up logging,
    creates the server instance, and runs the async event loop.

    Configuration is loaded via get_config() which reads WT_* environment
    variables. See config.py for available settings.

    Exit codes:
        0: Normal shutdown
        1: Configuration error (invalid WT_* variables)
        1: Database error (missing or invalid database files)
        1: Unexpected server error

    Environment Variables:
        WT_DATA_DIR: Base directory for databases (default: ./data)
        WT_KNOWN_GOOD_DB: Path to baseline database
        WT_CONTEXT_DB: Path to context database
        WT_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        WT_CACHE_SIZE: LRU cache size for lookups (default: 10000)
    """
    import asyncio

    # Load configuration from environment
    try:
        config = get_config()
    except ConfigurationError as e:
        logging.error(f"Configuration error: {e}")
        raise SystemExit(1) from e

    # Configure logging
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)
    setup_logging("windows-triage-mcp", level=log_level)

    logger.info("Starting windows-triage-mcp server")
    logger.info(f"  cache_size: {config.cache_size}")
    logger.info(f"  known_good_db: {config.known_good_db}")
    logger.info(f"  context_db: {config.context_db}")

    try:
        server = WindowsTriageServer(config=config)
        atexit.register(server.close_databases)
        asyncio.run(server.run())
    except DatabaseError as e:
        logger.error(f"Database error: {e}")
        raise SystemExit(1) from e
    except Exception as e:
        logger.exception(f"Server failed: {e}")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
