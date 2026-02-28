"""AIIR case management MCP server.

Exposes 14 tools wrapping aiir CLI _data() functions for LLM-callable
case management. No new logic — thin wrappers around tested code.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from aiir_cli.case_io import (
    export_bundle as _export_bundle,
)
from aiir_cli.case_io import (
    import_bundle as _import_bundle,
)
from aiir_cli.commands.audit_cmd import audit_summary_data
from aiir_cli.commands.evidence import (
    list_evidence_data,
    register_evidence_data,
    verify_evidence_data,
)
from aiir_cli.main import (
    _case_activate_data,
    _case_init_data,
    _case_list_data,
    _case_status_data,
)
from mcp.server.fastmcp import FastMCP
from sift_common.audit import AuditWriter, resolve_examiner
from sift_common.instructions import CASE_MCP as _INSTRUCTIONS
from sift_common.oplog import setup_logging

logger = logging.getLogger(__name__)

_MAX_NAME = 200
_MAX_TEXT = 10_000
_MAX_SHORT = 200


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len or containing null bytes."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")


def _resolve_case_dir(case_id: str = "") -> Path:
    """Resolve case directory without sys.exit.

    Same priority as aiir CLI get_case_dir(), but raises ValueError
    instead of calling sys.exit().

    Side effect: sets AIIR_CASE_DIR env var so AuditWriter can find
    the audit directory.
    """
    if case_id:
        if ".." in case_id or "/" in case_id or "\\" in case_id:
            raise ValueError(f"Invalid case ID: {case_id}")
        cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            raise ValueError(f"Case not found: {case_id}")
        os.environ["AIIR_CASE_DIR"] = str(case_dir)
        return case_dir

    env_dir = os.environ.get("AIIR_CASE_DIR")
    if env_dir:
        p = Path(env_dir)
        if not p.is_dir():
            raise ValueError(f"AIIR_CASE_DIR does not exist: {env_dir}")
        return p

    active_file = Path.home() / ".aiir" / "active_case"
    if active_file.exists():
        content = active_file.read_text().strip()
        if content:
            if os.path.isabs(content):
                case_dir = Path(content)
            else:
                if ".." in content or "/" in content or "\\" in content:
                    raise ValueError(f"Invalid case ID in active_case: {content}")
                cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
                case_dir = cases_dir / content
            if not case_dir.is_dir():
                raise ValueError(f"Case directory does not exist: {case_dir}")
            os.environ["AIIR_CASE_DIR"] = str(case_dir)
            return case_dir

    raise ValueError("No active case. Use case_init or case_activate first.")


def create_server() -> FastMCP:
    """Create and configure the case management MCP server."""
    server = FastMCP("case-mcp", instructions=_INSTRUCTIONS)
    audit = AuditWriter(mcp_name="case-mcp")

    server._audit = audit

    # ------------------------------------------------------------------
    # Tool 1: case_init (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def case_init(name: str, description: str = "") -> str:
        """Create a new case directory with the given name. The case ID
        is generated from the name and current timestamp.

        Confirm with the examiner before creating a case — this creates
        a permanent directory with case metadata.
        """
        try:
            _validate_str_length(name, "name", _MAX_NAME)
            _validate_str_length(description, "description", _MAX_TEXT)
            examiner = resolve_examiner()
            result = _case_init_data(
                name=name,
                examiner=examiner,
                description=description,
            )
            os.environ["AIIR_CASE_DIR"] = result["case_dir"]
            audit.log(
                tool="case_init",
                params={"name": name, "description": description},
                result_summary=result,
            )
            return json.dumps(result)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 2: case_activate (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def case_activate(case_id: str) -> str:
        """Switch the active case pointer to the specified case ID.

        Confirm with the examiner before switching cases — this changes
        which case all subsequent operations apply to.
        """
        try:
            result = _case_activate_data(case_id)
            os.environ["AIIR_CASE_DIR"] = result["case_dir"]
            audit.log(
                tool="case_activate",
                params={"case_id": case_id},
                result_summary=result,
            )
            return json.dumps(result)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 3: case_list (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def case_list() -> str:
        """List all cases in the cases directory with their status
        (open/closed) and whether each is the active case."""
        try:
            result = _case_list_data()
            return json.dumps(result)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 4: case_status (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def case_status(case_id: str = "") -> str:
        """Get detailed status of a case including finding counts,
        timeline entries, and TODO progress. Defaults to the active
        case if no case_id is provided."""
        try:
            case_dir = _resolve_case_dir(case_id)
            result = _case_status_data(case_dir)
            return json.dumps(result)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 5: evidence_register (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_register(path: str, description: str = "") -> str:
        """Register an evidence file with the active case. Computes
        SHA-256 hash and adds to evidence registry.

        Confirm with the examiner before registering.
        """
        try:
            _validate_str_length(description, "description", _MAX_TEXT)
            case_dir = _resolve_case_dir()
            examiner = resolve_examiner()
            result = register_evidence_data(
                case_dir=case_dir,
                path=path,
                examiner=examiner,
                description=description,
            )
            audit.log(
                tool="evidence_register",
                params={"path": path, "description": description},
                result_summary=result,
            )
            return json.dumps(result, default=str)
        except (ValueError, FileNotFoundError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 6: evidence_list (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_list() -> str:
        """List all registered evidence files in the active case with
        their SHA-256 hashes, registration dates, and descriptions."""
        try:
            case_dir = _resolve_case_dir()
            result = list_evidence_data(case_dir)
            return json.dumps(result, default=str)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 7: evidence_verify (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_verify() -> str:
        """Verify integrity of all registered evidence files by comparing
        current SHA-256 hashes against the registry. Reports OK, MODIFIED,
        MISSING, or ERROR for each file."""
        try:
            case_dir = _resolve_case_dir()
            result = verify_evidence_data(case_dir)
            return json.dumps(result)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 8: export_bundle (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def export_bundle(since: str = "") -> str:
        """Export case findings and timeline as a JSON bundle for
        collaboration. Optionally filter to items modified since a
        given ISO timestamp."""
        try:
            case_dir = _resolve_case_dir()
            result = _export_bundle(case_dir, since=since)
            audit.log(
                tool="export_bundle",
                params={"since": since},
                result_summary={
                    "findings": len(result.get("findings", [])),
                    "timeline": len(result.get("timeline", [])),
                },
            )
            return json.dumps(result, default=str)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 9: import_bundle (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def import_bundle(bundle_path: str) -> str:
        """Import a case data bundle from a JSON file, merging findings
        and timeline with the active case using last-write-wins.

        Confirm with the examiner before importing — this modifies case
        findings and timeline data.
        """
        try:
            case_dir = _resolve_case_dir()
            bundle_file = Path(bundle_path)
            if not bundle_file.exists():
                return json.dumps({"error": f"Bundle file not found: {bundle_path}"})
            bundle_data = json.loads(bundle_file.read_text())
            result = _import_bundle(case_dir, bundle_data)
            audit.log(
                tool="import_bundle",
                params={"bundle_path": bundle_path},
                result_summary=result,
            )
            return json.dumps(result)
        except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 10: audit_summary (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def audit_summary() -> str:
        """Get audit trail statistics for the active case including
        total entries, evidence IDs, and breakdowns by MCP and tool."""
        try:
            case_dir = _resolve_case_dir()
            result = audit_summary_data(case_dir)
            return json.dumps(result)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 11: record_action (SAFE — auto-committed, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def record_action(
        description: str,
        tool: str = "",
        command: str = "",
    ) -> str:
        """Log a supplemental action note to the case record.
        Auto-committed, no approval needed. Note: MCP tool calls are
        already captured by the automatic audit trail."""
        try:
            _validate_str_length(description, "description", _MAX_TEXT)
            _validate_str_length(tool, "tool", _MAX_SHORT)
            _validate_str_length(command, "command", _MAX_TEXT)
            case_dir = _resolve_case_dir()
            examiner = resolve_examiner()
            ts = datetime.now(timezone.utc).isoformat()

            # Match actions.jsonl format from CaseManager.record_action()
            entry: dict = {
                "ts": ts,
                "description": description,
                "examiner": examiner,
            }
            if tool:
                entry["tool"] = tool
            if command:
                entry["command"] = command

            try:
                with open(case_dir / "actions.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                return json.dumps(
                    {"status": "write_failed", "timestamp": ts, "error": str(e)}
                )

            audit.log(
                tool="record_action",
                params={"description": description},
                result_summary={"status": "recorded", "timestamp": ts},
            )
            return json.dumps({"status": "recorded", "timestamp": ts})
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 12: log_reasoning (SAFE — audit-only, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def log_reasoning(text: str) -> str:
        """Record analytical reasoning to the audit trail (no approval
        needed). Call when choosing what to examine next, forming a
        hypothesis, revising an interpretation, or ruling something out.
        Unrecorded reasoning is lost during context compaction."""
        _validate_str_length(text, "text", _MAX_TEXT)
        result = {"status": "logged"}
        audit.log(
            tool="log_reasoning",
            params={"text": text},
            result_summary=result,
            source="orchestrator",
        )
        return json.dumps(result)

    # ------------------------------------------------------------------
    # Tool 13: log_external_action (SAFE — audit-only, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def log_external_action(command: str, output_summary: str, purpose: str) -> str:
        """Record a tool execution performed outside this MCP server
        (e.g., via Bash or another backend). Response includes an evidence_id
        field that can be used in record_finding's evidence_ids list. Without
        this record, the action has no audit entry and findings cannot
        reference it."""
        _validate_str_length(command, "command", _MAX_TEXT)
        _validate_str_length(output_summary, "output_summary", _MAX_TEXT)
        _validate_str_length(purpose, "purpose", _MAX_TEXT)
        evidence_id = audit.log(
            tool="log_external_action",
            params={
                "command": command,
                "output_summary": output_summary,
                "purpose": purpose,
            },
            result_summary={"status": "logged"},
            source="orchestrator_voluntary",
        )
        result = {
            "status": "logged",
            "evidence_id": evidence_id,
            "note": "orchestrator_voluntary -- not independently verified",
        }
        return json.dumps(result)

    # ------------------------------------------------------------------
    # Tool 14: open_case_dashboard (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def open_case_dashboard() -> str:
        """Open the case review dashboard in the examiner's browser.

        Reads gateway config to build the dashboard URL with an auth
        token. The URL is always returned so it can be displayed as a
        clickable link even if the browser fails to open.
        """
        import webbrowser

        import yaml

        config_path = Path.home() / ".aiir" / "gateway.yaml"
        if not config_path.is_file():
            return json.dumps(
                {"error": "Gateway config not found (~/.aiir/gateway.yaml)"}
            )

        try:
            config = yaml.safe_load(config_path.read_text()) or {}
        except (yaml.YAMLError, OSError) as e:
            return json.dumps({"error": f"Cannot read gateway config: {e}"})

        gw = config.get("gateway", {})
        host = gw.get("host", "127.0.0.1")
        port = gw.get("port", 4508)
        tls = gw.get("tls", {})
        scheme = "https" if tls.get("certfile") else "http"

        if host == "0.0.0.0":
            host = "127.0.0.1"

        url = f"{scheme}://{host}:{port}/dashboard/"

        # Append bearer token as URL fragment, matching current examiner
        api_keys = config.get("api_keys", {})
        if isinstance(api_keys, dict) and api_keys:
            examiner = resolve_examiner()
            token = None
            for key, info in api_keys.items():
                if isinstance(info, dict) and info.get("examiner") == examiner:
                    token = key
                    break
            if token is None:
                token = next(iter(api_keys))
            url += f"#token={token}"

        try:
            webbrowser.open(url)
            status = "opened"
        except Exception:
            status = "browser_failed"

        audit.log(
            tool="open_case_dashboard",
            params={},
            result_summary={"status": status},
        )
        # Strip token from response — LLM should not see the bearer token.
        # The browser already received it via webbrowser.open().
        display_url = url.split("#")[0] if "#" in url else url
        return json.dumps({"url": display_url, "status": status})

    return server


def main() -> None:
    """Run the case-mcp server."""
    setup_logging("case-mcp")
    logger.info("Starting case-mcp server")
    server = create_server()
    server.run()
