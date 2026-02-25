"""AIIR case management MCP server.

Exposes 10 tools wrapping aiir CLI _data() functions for LLM-callable
case management. No new logic — thin wrappers around tested code.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from sift_common.audit import AuditWriter, resolve_examiner
from sift_common.instructions import CASE_MCP as _INSTRUCTIONS
from sift_common.oplog import setup_logging

from aiir_cli.case_io import (
    export_bundle as _export_bundle,
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

logger = logging.getLogger(__name__)


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
        return Path(env_dir)

    active_file = Path.home() / ".aiir" / "active_case"
    if active_file.exists():
        content = active_file.read_text().strip()
        if content:
            if os.path.isabs(content):
                case_dir = Path(content)
            else:
                if ".." in content or "/" in content or "\\" in content:
                    raise ValueError(
                        f"Invalid case ID in active_case: {content}"
                    )
                cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
                case_dir = cases_dir / content
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
        SHA-256 hash, sets file to read-only (chmod 444), and adds to
        evidence registry.

        Confirm with the examiner before registering — this modifies
        file permissions and is difficult to undo.
        """
        try:
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
                return json.dumps(
                    {"error": f"Bundle file not found: {bundle_path}"}
                )
            bundle_data = json.loads(bundle_file.read_text())
            result = _import_bundle(case_dir, bundle_data)
            audit.log(
                tool="import_bundle",
                params={"bundle_path": bundle_path},
                result_summary=result,
            )
            return json.dumps(result)
        except (ValueError, FileNotFoundError, OSError,
                json.JSONDecodeError) as e:
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

    return server


def main() -> None:
    """Run the case-mcp server."""
    setup_logging("case-mcp")
    logger.info("Starting case-mcp server")
    server = create_server()
    server.run()
