"""Valhuntir case management MCP server.

Exposes 15 tools wrapping vhir CLI _data() functions for LLM-callable
case management. No new logic — thin wrappers around tested code.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from sift_common.audit import AuditWriter, resolve_examiner
from sift_common.instructions import CASE_MCP as _INSTRUCTIONS
from sift_common.oplog import setup_logging
from vhir_cli.case_io import (
    export_bundle as _export_bundle,
)
from vhir_cli.case_io import (
    import_bundle as _import_bundle,
)
from vhir_cli.commands.audit_cmd import audit_summary_data
from vhir_cli.commands.evidence import (
    list_evidence_data,
    register_evidence_data,
    verify_evidence_data,
)
from vhir_cli.commands.join import (
    _repoint_samba_share,
    notify_wintools_case_activated,
)
from vhir_cli.main import (
    _case_activate_data,
    _case_init_data,
    _case_list_data,
    _case_status_data,
    _set_case_wintools_permissions,
)

logger = logging.getLogger(__name__)

_DEFAULT_CASES_DIR = str(Path.home() / "cases")
_ACTIVE_CASE_FILE = Path.home() / ".vhir" / "active_case"
_MAX_NAME = 200
_MAX_TEXT = 10_000
_MAX_SHORT = 200


def _wintools_configured() -> bool:
    """Check if Samba sharing is set up (samba.yaml exists with share_name)."""
    import yaml

    p = Path.home() / ".vhir" / "samba.yaml"
    if not p.is_file():
        return False
    try:
        doc = yaml.safe_load(p.read_text())
        return bool(doc and doc.get("share_name"))
    except Exception:
        return False


def _build_platform_capabilities() -> dict:
    """Detect available backends for Layer 4 platform capabilities."""
    import importlib.util

    capabilities = {
        "opensearch": importlib.util.find_spec("opensearch_mcp") is not None,
        "remnux": False,
        "wintools": False,
        "forensic_rag": importlib.util.find_spec("rag_mcp") is not None,
        "opencti": importlib.util.find_spec("opencti_mcp") is not None,
        "sift_tools": True,
    }
    try:
        import yaml

        gw_path = Path.home() / ".vhir" / "gateway.yaml"
        if gw_path.exists():
            gw_config = yaml.safe_load(gw_path.read_text()) or {}
            backends = gw_config.get("backends", {})
            capabilities["remnux"] = "remnux-mcp" in backends
            capabilities["wintools"] = "wintools-mcp" in backends
    except Exception:
        pass
    # REMnux connects directly to client (not via gateway) — check .claude.json
    if not capabilities["remnux"]:
        try:
            import json

            claude_json = Path.home() / ".claude.json"
            if claude_json.exists():
                cj = json.loads(claude_json.read_text())
                mcp_servers = cj.get("mcpServers", {})
                capabilities["remnux"] = "remnux-mcp" in mcp_servers
        except Exception:
            pass

    guidance = ["Available investigation capabilities:"]
    guidance.append("- SIFT forensic tools via run_command (65+ tools)")
    if capabilities["opensearch"]:
        guidance.append(
            "- Evidence indexing: idx_ingest for structured querying at scale"
        )
    if capabilities["remnux"]:
        guidance.append("- Malware analysis: upload_from_host + analyze_file on REMnux")
    if capabilities["wintools"]:
        guidance.append(
            "- Windows offline analysis: run_windows_command on forensic workstation"
        )
    if capabilities["forensic_rag"]:
        guidance.append(
            "- Knowledge search: search_knowledge (Sigma, MITRE ATT&CK, KAPE)"
        )
    if capabilities["opencti"]:
        guidance.append("- Threat intel: lookup_ioc, search_threat_intel on OpenCTI")
    guidance.append("")
    guidance.append(
        "Do not rely solely on OpenSearch queries. "
        "Call suggest_tools(artifact_type='...') for deep analysis recommendations."
    )

    return {
        "platform_capabilities": capabilities,
        "investigation_guidance": "\n".join(guidance),
    }


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len, containing null bytes, or path traversal."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")
        if ".." in value:
            raise ValueError(f"{field} contains invalid path traversal")


def _resolve_case_dir(case_id: str = "") -> Path:
    """Resolve case directory without sys.exit.

    Same priority as vhir CLI get_case_dir(), but raises ValueError
    instead of calling sys.exit().

    Side effect: sets VHIR_CASE_DIR env var so AuditWriter can find
    the audit directory.
    """
    if case_id:
        if ".." in case_id or "/" in case_id or "\\" in case_id:
            raise ValueError(f"Invalid case ID: {case_id}")
        cases_dir = Path(os.environ.get("VHIR_CASES_DIR", _DEFAULT_CASES_DIR))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            raise ValueError(f"Case not found: {case_id}")
        return case_dir

    # Read active_case file first (detects case switches without restart)
    active_file = _ACTIVE_CASE_FILE
    if active_file.exists():
        try:
            content = active_file.read_text().strip()
        except OSError:
            content = ""
        if content:
            if os.path.isabs(content):
                case_dir = Path(content)
            else:
                if ".." in content or "/" in content or "\\" in content:
                    raise ValueError(f"Invalid case ID in active_case: {content}")
                cases_dir = Path(os.environ.get("VHIR_CASES_DIR", _DEFAULT_CASES_DIR))
                case_dir = cases_dir / content
            if case_dir.is_dir():
                return case_dir

    # Fallback: env var (containers, tests, non-standard deployments)
    env_dir = os.environ.get("VHIR_CASE_DIR")
    if env_dir:
        p = Path(env_dir)
        if not p.is_dir():
            raise ValueError(f"VHIR_CASE_DIR does not exist: {env_dir}")
        return p

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
    def case_init(
        name: str,
        description: str = "",
        case_id: str = "",
        share_wintools: bool | None = None,
        cases_dir: str = "",
    ) -> dict:
        """Create a new case directory with the given name. The case ID
        is auto-generated unless case_id is provided.

        Confirm with the examiner before creating a case — this creates
        a permanent directory with case metadata.

        Args:
            name: Case name.
            description: Optional case description.
            case_id: Custom case ID (default: auto-generated INC-YYYY-MMDDHHMMSS).
                Must match: alphanumeric, hyphens, underscores. Max 64 chars.
            share_wintools: Set case permissions for wintools access.
            cases_dir: Override cases root directory.
        """
        try:
            _validate_str_length(name, "name", _MAX_NAME)
            _validate_str_length(description, "description", _MAX_TEXT)
            _validate_str_length(cases_dir, "cases_dir", _MAX_NAME)
            if case_id:
                _validate_str_length(case_id, "case_id", 64)
                import re

                if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$", case_id):
                    return {
                        "error": "case_id must be alphanumeric with hyphens/underscores, "
                        "start with letter/digit, 2-64 chars"
                    }
            examiner = resolve_examiner()
            result = _case_init_data(
                name=name,
                examiner=examiner,
                description=description,
                cases_dir=cases_dir or None,
                case_id=case_id or None,
            )

            # Auto-detect wintools when share_wintools is None
            if share_wintools is None:
                share_wintools = _wintools_configured()
            if share_wintools and _wintools_configured():
                try:
                    _set_case_wintools_permissions(Path(result["case_dir"]))
                    _repoint_samba_share(Path(result["case_dir"]))
                    ok = notify_wintools_case_activated(result["case_id"])
                    result["wintools_shared"] = True
                    if not ok:
                        result.setdefault("warnings", []).append(
                            "Could not notify wintools-mcp of case activation. "
                            "Windows tools may not have access to this case."
                        )
                except Exception as e:
                    result["wintools_warning"] = (
                        f"Failed to set up wintools sharing: {e}"
                    )

            logged_id = audit.log(
                tool="case_init",
                params={"name": name, "description": description},
                result_summary=result,
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            result["next_steps"] = [
                "Ask the examiner what triggered this investigation",
                "Survey evidence: ls evidence/",
                "If OpenSearch tools available: offer to ingest evidence",
                "Run idx_case_summary for scope overview",
                "Check list_playbooks for investigation procedures",
            ]
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 2: case_activate (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def case_activate(case_id: str, cases_dir: str = "") -> dict:
        """Switch the active case pointer to the specified case ID.

        Confirm with the examiner before switching cases — this changes
        which case all subsequent operations apply to.

        Args:
            case_id: Case ID to activate.
            cases_dir: Override cases root directory.
        """
        try:
            _validate_str_length(cases_dir, "cases_dir", _MAX_NAME)
            result = _case_activate_data(case_id, cases_dir=cases_dir or None)

            # Repoint share and notify wintools
            case_path = Path(result["case_dir"])
            if _wintools_configured():
                try:
                    _set_case_wintools_permissions(case_path)
                    _repoint_samba_share(case_path)
                    ok = notify_wintools_case_activated(case_id)
                    result["wintools_shared"] = True
                    if not ok:
                        result.setdefault("warnings", []).append(
                            "Could not notify wintools-mcp of case activation. "
                            "Windows tools may not have access to this case."
                        )
                except Exception as e:
                    result["wintools_warning"] = f"Failed to update wintools share: {e}"

            logged_id = audit.log(
                tool="case_activate",
                params={"case_id": case_id},
                result_summary=result,
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"

            import importlib.util

            if importlib.util.find_spec("opensearch_mcp") is not None:
                result["opensearch_hint"] = (
                    "OpenSearch MCP tools are available. Call idx_case_summary "
                    "to see what's indexed, or offer to ingest new evidence."
                )
            result["next_steps"] = [
                "Ask the examiner for investigation context",
                "Survey evidence: ls evidence/",
                "Follow the INVESTIGATION STARTUP sequence in your instructions",
            ]
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 3: case_list (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def case_list() -> dict:
        """List all cases in the cases directory with their status
        (open/closed) and whether each is the active case."""
        try:
            result = _case_list_data()
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 4: case_status (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def case_status(case_id: str = "") -> dict:
        """Get detailed status of a case including finding counts,
        timeline entries, and TODO progress. Defaults to the active
        case if no case_id is provided."""
        try:
            case_dir = _resolve_case_dir(case_id)
            result = _case_status_data(case_dir)
            # Layer 4: platform capabilities detection
            result.update(_build_platform_capabilities())
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 5: evidence_register (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_register(path: str, description: str = "") -> dict:
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
            logged_id = audit.log(
                tool="evidence_register",
                params={"path": path, "description": description},
                result_summary=result,
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, FileNotFoundError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 6: evidence_list (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_list() -> dict:
        """List all registered evidence files in the active case with
        their SHA-256 hashes, registration dates, and descriptions."""
        try:
            case_dir = _resolve_case_dir()
            result = list_evidence_data(case_dir)
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 7: evidence_verify (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_verify() -> dict:
        """Verify integrity of all registered evidence files by comparing
        current SHA-256 hashes against the registry. Reports OK, MODIFIED,
        MISSING, or ERROR for each file."""
        try:
            case_dir = _resolve_case_dir()
            result = verify_evidence_data(case_dir)
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 8: export_bundle (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def export_bundle(since: str = "") -> dict:
        """Export case findings and timeline as a JSON bundle for
        collaboration. Optionally filter to items modified since a
        given ISO timestamp.

        WARNING: Returns full case data which may be large (30,000+ tokens).
        For investigation status, use case_status instead."""
        try:
            case_dir = _resolve_case_dir()
            result = _export_bundle(case_dir, since=since)
            logged_id = audit.log(
                tool="export_bundle",
                params={"since": since},
                result_summary={
                    "findings": len(result.get("findings", [])),
                    "timeline": len(result.get("timeline", [])),
                },
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 9: import_bundle (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def import_bundle(bundle_path: str) -> dict:
        """Import a case data bundle from a JSON file, merging findings
        and timeline with the active case using last-write-wins.

        Confirm with the examiner before importing — this modifies case
        findings and timeline data.
        """
        try:
            case_dir = _resolve_case_dir()
            bundle_file = Path(bundle_path).resolve()
            allowed_parents = [case_dir, Path("/tmp")]
            if not any(bundle_file.is_relative_to(p) for p in allowed_parents):
                return {"error": "Bundle path must be within case directory or /tmp"}
            if not bundle_file.exists():
                return {"error": f"Bundle file not found: {bundle_path}"}
            bundle_data = json.loads(bundle_file.read_text())
            result = _import_bundle(case_dir, bundle_data)
            logged_id = audit.log(
                tool="import_bundle",
                params={"bundle_path": bundle_path},
                result_summary=result,
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 10: audit_summary (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def audit_summary() -> dict:
        """Get audit trail statistics for the active case including
        total entries, evidence IDs, and breakdowns by MCP and tool."""
        try:
            case_dir = _resolve_case_dir()
            result = audit_summary_data(case_dir)
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 11: record_action (SAFE — auto-committed, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def record_action(
        description: str,
        tool: str = "",
        command: str = "",
        analyst_override: str = "",
    ) -> dict:
        """Log a supplemental action note to the case record.
        Auto-committed, no approval needed. Note: MCP tool calls are
        already captured by the automatic audit trail."""
        try:
            _validate_str_length(description, "description", _MAX_TEXT)
            _validate_str_length(tool, "tool", _MAX_SHORT)
            _validate_str_length(command, "command", _MAX_TEXT)
            _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
            case_dir = _resolve_case_dir()
            examiner = analyst_override or resolve_examiner()
            ts = datetime.now(timezone.utc).isoformat()

            # Write to actions.jsonl (adds source field not in CaseManager)
            entry: dict = {
                "ts": ts,
                "description": description,
                "examiner": examiner,
                "source": "mcp",
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
                return {"status": "write_failed", "timestamp": ts, "error": str(e)}

            logged_id = audit.log(
                tool="record_action",
                params={"description": description},
                result_summary={"status": "recorded", "timestamp": ts},
            )
            result = {"status": "recorded", "timestamp": ts}
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 12: log_reasoning (SAFE — audit-only, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def log_reasoning(text: str, analyst_override: str = "") -> dict:
        """Record analytical reasoning to the audit trail (no approval
        needed). Call when choosing what to examine next, forming a
        hypothesis, revising an interpretation, or ruling something out.
        Unrecorded reasoning is lost during context compaction."""
        _validate_str_length(text, "text", _MAX_TEXT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        result = {"status": "logged"}
        logged_id = audit.log(
            tool="log_reasoning",
            params={"text": text, "analyst_override": analyst_override},
            result_summary=result,
            source="orchestrator",
        )
        if logged_id is None:
            result["status"] = "write_failed"
            result["warning"] = "Audit write failed — reasoning not recorded"
        return result

    # ------------------------------------------------------------------
    # Tool 13: log_external_action (SAFE — audit-only, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def log_external_action(
        command: str, output_summary: str, purpose: str, analyst_override: str = ""
    ) -> dict:
        """Record a tool execution performed outside this MCP server
        (e.g., via Bash or another backend). Response includes an audit_id
        field that can be used in record_finding's audit_ids list. Without
        this record, the action has no audit entry and findings cannot
        reference it."""
        _validate_str_length(command, "command", _MAX_TEXT)
        _validate_str_length(output_summary, "output_summary", _MAX_TEXT)
        _validate_str_length(purpose, "purpose", _MAX_TEXT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        audit_id = audit.log(
            tool="log_external_action",
            params={
                "command": command,
                "output_summary": output_summary,
                "purpose": purpose,
                "analyst_override": analyst_override,
            },
            result_summary={"status": "logged"},
            source="orchestrator_voluntary",
        )
        result = {
            "status": "logged",
            "audit_id": audit_id,
            "note": "orchestrator_voluntary -- not independently verified",
        }
        if audit_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    # ------------------------------------------------------------------
    # Tool 15: backup_case (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def backup_case(destination: str, purpose: str = "") -> dict:
        """Back up case data files to a destination directory.

        Creates a timestamped backup of case metadata, findings, timeline,
        approvals, audit trails, and reports. Does NOT include evidence or
        extraction files (use 'vhir backup --all' for full backups).

        Confirm with the examiner before creating a backup.

        Args:
            destination: Directory to create the backup in.
            purpose: Why the backup is being made (audit trail).
        """
        from vhir_cli.commands.backup import create_backup_data

        try:
            _validate_str_length(destination, "destination", _MAX_NAME)
            _validate_str_length(purpose, "purpose", _MAX_TEXT)
            case_dir = _resolve_case_dir()
            examiner = resolve_examiner()

            result = create_backup_data(
                case_dir=case_dir,
                destination=destination,
                examiner=examiner,
                purpose=purpose,
            )

            # Strip CLI-only fields from MCP response
            result.pop("symlinks", None)
            result.pop("ledger_note", None)

            logged_id = audit.log(
                tool="backup_case",
                params={"destination": destination, "purpose": purpose},
                result_summary=result,
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 16: open_case_dashboard (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def open_case_dashboard() -> dict:
        """Open the Examiner Portal in the examiner's browser.

        Reads gateway config to build the portal URL with an auth
        token. The URL is always returned so it can be displayed as a
        clickable link even if the browser fails to open.
        """
        import webbrowser

        import yaml

        config_path = Path.home() / ".vhir" / "gateway.yaml"
        if not config_path.is_file():
            return {"error": "Gateway config not found (~/.vhir/gateway.yaml)"}

        try:
            config = yaml.safe_load(config_path.read_text()) or {}
        except (yaml.YAMLError, OSError) as e:
            return {"error": f"Cannot read gateway config: {e}"}

        gw = config.get("gateway", {})
        host = gw.get("host", "127.0.0.1")
        port = gw.get("port", 4508)
        tls = gw.get("tls", {})
        scheme = "https" if tls.get("certfile") else "http"

        if host == "0.0.0.0":
            host = "127.0.0.1"

        url = f"{scheme}://{host}:{port}/portal/"

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

        logged_id = audit.log(
            tool="open_case_dashboard",
            params={},
            result_summary={"status": status},
        )
        # Strip token from response — LLM should not see the bearer token.
        # The browser already received it via webbrowser.open().
        display_url = url.split("#")[0] if "#" in url else url
        result = {"url": display_url, "status": status}
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    return server


def main() -> None:
    """Run the case-mcp server."""
    setup_logging("case-mcp")
    logger.info("Starting case-mcp server")
    server = create_server()
    server.run()
