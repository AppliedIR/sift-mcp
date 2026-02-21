"""MCP server for forensic investigation management."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from forensic_mcp.case.manager import CaseManager
from forensic_mcp.audit import AuditWriter

logger = logging.getLogger(__name__)


def _build_finding_considerations(finding: dict) -> list[str]:
    """Assemble pre-acceptance guidance for a staged finding."""
    from forensic_knowledge import loader

    considerations: list[str] = []

    # Self-check items from investigation framework (always included)
    # New format has {question, how} dicts; old format has plain strings
    framework = loader.get_investigation_framework()
    if framework:
        for item in framework.get("self_check", [])[:5]:
            if isinstance(item, dict):
                text = item.get("question", "")
                how = item.get("how", "")
                considerations.append(f"{text} → {how}" if how else text)
            else:
                considerations.append(item)

    # Anti-patterns relevant to the finding type
    finding_type = finding.get("type", "")
    anti_patterns = loader.get_anti_patterns()
    if finding_type == "attribution":
        for ap in anti_patterns:
            if ap["name"] == "premature_attribution":
                how = ap.get("how_to_avoid", "")
                msg = f"Anti-pattern: {ap['description']}"
                if how:
                    msg += f" How to avoid: {how}"
                considerations.append(msg)
    if finding_type == "exclusion":
        for ap in anti_patterns:
            if ap["name"] == "confirmation_bias":
                how = ap.get("how_to_avoid", "")
                msg = f"Anti-pattern: {ap['description']}"
                if how:
                    msg += f" How to avoid: {how}"
                considerations.append(msg)

    # Confidence-level requirements
    confidence = finding.get("confidence", "").upper()
    confidence_defs = loader.get_confidence_definitions()
    if confidence in confidence_defs:
        cd = confidence_defs[confidence]
        min_ev = cd.get("min_evidence_ids", 0)
        if min_ev >= 2:
            considerations.append(
                f"{confidence} confidence requires {min_ev}+ independent corroborating sources "
                f"— are yours truly independent?"
            )

    # Checkpoint requirements if finding type matches
    if finding_type in ("attribution", "exclusion", "conclusion"):
        checkpoint = loader.get_checkpoint(finding_type)
        if checkpoint and isinstance(checkpoint, dict) and "guidance" in checkpoint:
            considerations.append(checkpoint["guidance"])

    return considerations


def _build_validation_guidance(errors: list[str]) -> list[str]:
    """Enrich validation errors with rule citations."""
    guidance: list[str] = []
    for err in errors:
        if "evidence_id" in err.lower():
            guidance.append("FD-001: Every claim must reference at least one evidence_id from an actual tool call")
        if "confidence_justification" in err.lower():
            guidance.append("FD-005: Confidence must be justified — cite specific evidence for your confidence level")
        if "attribution" in err.lower() and "3" in err:
            guidance.append("FD-003: Attribution requires multiple corroborating TTPs, not just a single IOC match")
    return guidance


def create_server() -> FastMCP:
    """Create and configure the forensic MCP server with all tools."""
    server = FastMCP("forensic-mcp")
    manager = CaseManager()
    audit = AuditWriter(mcp_name="forensic-mcp")

    # --- Case Lifecycle ---

    @server.tool()
    def init_case(name: str, description: str = "", examiner: str = "", collaborative: bool = False) -> dict:
        """Create a new case directory with initialized docs. Returns case_id and investigation framework."""
        from forensic_mcp.discipline.rules import get_investigation_framework
        result = manager.init_case(name, description, examiner=examiner, collaborative=collaborative)
        audit.log(tool="init_case", params={"name": name, "examiner": examiner}, result_summary=result)

        # Attach condensed investigation framework so the LLM gets methodology at case start
        framework = get_investigation_framework()
        if "error" not in framework:
            result["investigation_framework"] = {
                "principles": framework.get("principles", []),
                "workflow": framework.get("workflow", []),
                "hitl_checkpoints": framework.get("hitl_checkpoints", []),
                "golden_rules": framework.get("golden_rules", []),
            }
        return result

    @server.tool()
    def close_case(case_id: str, summary: str = "") -> dict:
        """Close a case. Verifies all findings are approved."""
        result = manager.close_case(case_id, summary)
        audit.log(tool="close_case", params={"case_id": case_id}, result_summary=result)
        return result

    @server.tool()
    def get_case_status(case_id: str = "") -> dict:
        """Get investigation summary: findings by status, evidence count, timeline span."""
        return manager.get_case_status(case_id or None)

    @server.tool()
    def list_cases() -> list[dict]:
        """List all cases with status."""
        return manager.list_cases()

    @server.tool()
    def set_active_case(case_id: str) -> dict:
        """Set the active case for this session."""
        result = manager.set_active_case(case_id)
        audit.log(tool="set_active_case", params={"case_id": case_id}, result_summary=result)
        return result

    # --- Investigation Records ---

    @server.tool()
    def record_action(description: str, tool: str = "", command: str = "", analyst_override: str = "") -> dict:
        """Log action to the case actions log. Auto-committed, no approval needed."""
        result = manager.record_action(description, tool, command, examiner_override=analyst_override)
        audit.log(tool="record_action", params={"description": description}, result_summary=result)
        return result

    @server.tool()
    def record_finding(finding: dict, analyst_override: str = "") -> dict:
        """Stage finding as DRAFT. Requires human approval via 'aiir approve'."""
        result = manager.record_finding(finding, examiner_override=analyst_override)
        audit.log(tool="record_finding", params={"finding": finding}, result_summary=result)

        # Enrich with considerations when staging succeeds
        if result.get("status") == "STAGED":
            result["finding_status"] = "DRAFT — requires human approval via aiir approve"
            result["considerations"] = _build_finding_considerations(finding)
            grounding = manager._score_grounding(finding)
            if grounding:
                result["grounding"] = grounding

        # Enrich validation failures with rule citations
        if result.get("status") == "VALIDATION_FAILED":
            result["guidance"] = _build_validation_guidance(result.get("errors", []))

        return result

    @server.tool()
    def record_timeline_event(event: dict, analyst_override: str = "") -> dict:
        """Stage timeline event as DRAFT. Requires human approval via 'aiir approve'.

        Optional fields on the event dict (pass through automatically):
        - related_findings: list of finding IDs this event supports (e.g. ["F-001", "F-003"])
        - event_type: classification hint — "process", "network", "file", "registry",
          "auth", "persistence", "lateral", "execution", or "other"
        - artifact_ref: deduplication hint — unique artifact identifier
          (e.g. "prefetch:EVIL.EXE-{hash}", "evtx:Security:4624:12345")
        """
        result = manager.record_timeline_event(event, examiner_override=analyst_override)
        audit.log(tool="record_timeline_event", params={"event": event}, result_summary=result)
        return result

    @server.tool()
    def get_findings(status: str = "") -> list[dict]:
        """Return findings, optionally filtered by DRAFT/APPROVED/REJECTED."""
        return manager.get_findings(status or None)

    @server.tool()
    def get_timeline(
        status: str = "",
        source: str = "",
        examiner: str = "",
        start_date: str = "",
        end_date: str = "",
        event_type: str = "",
    ) -> list[dict]:
        """Return timeline events with optional filtering.

        Filters (all optional):
        - status: DRAFT, APPROVED, or REJECTED
        - source: substring match against event source
        - examiner: exact examiner slug
        - start_date: ISO date/datetime lower bound on timestamp
        - end_date: ISO date/datetime upper bound on timestamp
        - event_type: process, network, file, registry, auth, persistence, lateral, execution, other
        """
        return manager.get_timeline(
            status=status or None,
            source=source or None,
            examiner=examiner or None,
            start_date=start_date or None,
            end_date=end_date or None,
            event_type=event_type or None,
        )

    @server.tool()
    def get_actions(limit: int = 50) -> list[dict]:
        """Return recent actions from the case actions log."""
        return manager.get_actions(limit)

    @server.tool()
    def log_reasoning(text: str) -> dict:
        """Voluntary: record orchestrator reasoning or analysis notes to audit trail."""
        result = {"status": "logged"}
        audit.log(tool="log_reasoning", params={"text": text}, result_summary=result, source="orchestrator")
        return result

    @server.tool()
    def log_external_action(command: str, output_summary: str, purpose: str) -> dict:
        """Voluntary: record tool execution done outside MCP (e.g., via sift-mcp or raw Bash)."""
        result = {"status": "logged", "note": "orchestrator_voluntary -- not independently verified"}
        audit.log(
            tool="log_external_action",
            params={"command": command, "output_summary": output_summary, "purpose": purpose},
            result_summary=result,
            source="orchestrator_voluntary",
        )
        return result

    # --- TODOs ---

    @server.tool()
    def add_todo(
        description: str,
        assignee: str = "",
        priority: str = "medium",
        related_findings: list[str] | None = None,
        analyst_override: str = "",
    ) -> dict:
        """Create a TODO item for the investigation. Priority: high/medium/low."""
        result = manager.add_todo(description, assignee, priority, related_findings, examiner_override=analyst_override)
        audit.log(tool="add_todo", params={"description": description, "assignee": assignee}, result_summary=result)
        return result

    @server.tool()
    def list_todos(status: str = "open", assignee: str = "") -> list[dict]:
        """List TODO items. Status: open/completed/all."""
        return manager.list_todos(status, assignee)

    @server.tool()
    def update_todo(
        todo_id: str,
        status: str = "",
        note: str = "",
        assignee: str = "",
        priority: str = "",
        analyst_override: str = "",
    ) -> dict:
        """Update a TODO: change status, add note, reassign, reprioritize."""
        result = manager.update_todo(todo_id, status, note, assignee, priority, examiner_override=analyst_override)
        audit.log(tool="update_todo", params={"todo_id": todo_id}, result_summary=result)
        return result

    @server.tool()
    def complete_todo(todo_id: str, analyst_override: str = "") -> dict:
        """Mark a TODO as completed."""
        result = manager.complete_todo(todo_id, examiner_override=analyst_override)
        audit.log(tool="complete_todo", params={"todo_id": todo_id}, result_summary=result)
        return result

    # --- Evidence Management ---

    @server.tool()
    def register_evidence(path: str, description: str = "") -> dict:
        """Register evidence file: hash, set read-only, record in evidence index."""
        result = manager.register_evidence(path, description)
        audit.log(tool="register_evidence", params={"path": path}, result_summary=result)
        return result

    @server.tool()
    def verify_evidence_integrity() -> dict:
        """Re-hash all registered evidence, report any modifications."""
        result = manager.verify_evidence_integrity()
        audit.log(tool="verify_evidence_integrity", params={}, result_summary=result)
        return result

    @server.tool()
    def list_evidence() -> list[dict]:
        """Return evidence index with registration timestamps and integrity status."""
        return manager.list_evidence()

    @server.tool()
    def get_evidence_access_log(path: str = "") -> list[dict]:
        """Return chain-of-custody log for evidence files."""
        return manager.get_evidence_access_log(path or None)

    # --- Audit ---

    @server.tool()
    def get_audit_log(limit: int = 100, mcp: str = "", tool_filter: str = "") -> list[dict]:
        """Return raw MCP tool call entries for the active case."""
        return manager.get_audit_log(limit, mcp or None, tool_filter or None)

    @server.tool()
    def get_audit_summary() -> dict:
        """Statistics: tool call counts, evidence references, unlinked findings."""
        return manager.get_audit_summary()

    # --- Discipline (Forensic Methodology) ---

    @server.tool()
    def get_investigation_framework() -> dict:
        """Return the full investigation framework: principles, HITL checkpoints, workflow, golden rules, self-check."""
        from forensic_mcp.discipline.rules import get_investigation_framework as _get_fw
        result = _get_fw()
        audit.log(tool="get_investigation_framework", params={}, result_summary={"keys": list(result.keys())})
        return result

    @server.tool()
    def get_rules() -> list[dict]:
        """Return all forensic discipline rules as structured data."""
        from forensic_mcp.discipline.rules import get_all_rules
        return get_all_rules()

    @server.tool()
    def get_checkpoint_requirements(action_type: str) -> dict:
        """What's required before a specific action (attribution, root cause, exclusion, etc.)."""
        from forensic_mcp.discipline.rules import get_checkpoint
        return get_checkpoint(action_type)

    @server.tool()
    def validate_finding(finding_json: dict) -> dict:
        """Check a proposed finding against format and methodology standards."""
        from forensic_mcp.discipline.validation import validate
        return validate(finding_json)

    @server.tool()
    def get_evidence_standards() -> dict:
        """Evidence classification levels with definitions."""
        from forensic_mcp.discipline.rules import get_evidence_standards_data
        return get_evidence_standards_data()

    @server.tool()
    def get_confidence_definitions() -> dict:
        """Confidence levels (HIGH/MEDIUM/LOW/SPECULATIVE) with criteria."""
        from forensic_mcp.discipline.rules import get_confidence_definitions_data
        return get_confidence_definitions_data()

    @server.tool()
    def get_anti_patterns() -> list[dict]:
        """Common forensic mistakes to avoid."""
        from forensic_mcp.discipline.rules import get_anti_patterns_data
        return get_anti_patterns_data()

    @server.tool()
    def get_evidence_template() -> dict:
        """Required evidence presentation format."""
        from forensic_mcp.discipline.rules import get_evidence_template_data
        return get_evidence_template_data()

    @server.tool()
    def get_tool_guidance(tool_name: str) -> dict:
        """How to interpret results from a specific forensic tool."""
        from forensic_mcp.discipline.guidance import get_guidance
        return get_guidance(tool_name)

    @server.tool()
    def get_false_positive_context(tool_name: str, finding_type: str) -> dict:
        """Common false positives for a tool/finding combination."""
        from forensic_mcp.discipline.guidance import get_false_positives
        return get_false_positives(tool_name, finding_type)

    @server.tool()
    def get_corroboration_suggestions(finding_type: str) -> list[dict]:
        """Cross-reference suggestions based on finding type."""
        from forensic_mcp.discipline.guidance import get_corroboration
        return get_corroboration(finding_type)

    @server.tool()
    def list_playbooks() -> list[dict]:
        """Available investigation playbooks."""
        from forensic_mcp.discipline.playbooks import list_all
        return list_all()

    @server.tool()
    def get_playbook(name: str) -> dict:
        """Step-by-step procedure for a specific investigation type."""
        from forensic_mcp.discipline.playbooks import get_by_name
        return get_by_name(name)

    @server.tool()
    def get_collection_checklist(artifact_type: str) -> dict:
        """Evidence collection checklist per artifact type."""
        from forensic_mcp.discipline.playbooks import get_checklist
        return get_checklist(artifact_type)

    # --- Report Generation ---

    @server.tool()
    def generate_full_report() -> dict:
        """Generate a complete IR report from all approved findings, timeline, IOCs, and MITRE mapping. Returns data + Markdown stub + Zeltser IR Writing MCP next steps."""
        result = manager.generate_full_report()
        audit.log(tool="generate_full_report", params={}, result_summary={"findings": len(result.get("report_data", {}).get("findings", []))})
        return result

    @server.tool()
    def generate_executive_summary() -> dict:
        """Generate non-technical management briefing from approved data. Returns data + stub + next steps."""
        result = manager.generate_executive_summary()
        audit.log(tool="generate_executive_summary", params={}, result_summary={"findings_count": result.get("report_data", {}).get("findings_count", 0)})
        return result

    @server.tool()
    def generate_timeline_report(start_date: str = "", end_date: str = "") -> dict:
        """Generate approved timeline report, optionally filtered by date range. Returns chronological table + narrative placeholder."""
        result = manager.generate_timeline_report(start_date, end_date)
        audit.log(tool="generate_timeline_report", params={"start_date": start_date, "end_date": end_date}, result_summary={"events": result.get("report_data", {}).get("event_count", 0)})
        return result

    @server.tool()
    def generate_ioc_report() -> dict:
        """Generate IOC + MITRE ATT&CK report for sharing/blocking. Structural output — usable as-is."""
        result = manager.generate_ioc_report()
        audit.log(tool="generate_ioc_report", params={}, result_summary={"total_iocs": result.get("report_data", {}).get("total_iocs", 0)})
        return result

    @server.tool()
    def generate_findings_report(finding_ids: list[str] | None = None) -> dict:
        """Generate detailed report for specific approved findings. Defaults to all approved if no IDs given."""
        result = manager.generate_findings_report(finding_ids)
        audit.log(tool="generate_findings_report", params={"finding_ids": finding_ids}, result_summary={"count": result.get("report_data", {}).get("findings_count", 0)})
        return result

    @server.tool()
    def generate_status_brief() -> dict:
        """Generate quick status overview for standups/handoffs: counts, key findings, open TODOs."""
        result = manager.generate_status_brief()
        audit.log(tool="generate_status_brief", params={}, result_summary=result.get("report_data", {}).get("counts", {}))
        return result

    @server.tool()
    def save_report(filename: str, content: str, report_type: str = "") -> dict:
        """Persist a report to {case_dir}/reports/. Sanitizes filename, writes atomically."""
        result = manager.save_report(filename, content, report_type)
        audit.log(tool="save_report", params={"filename": filename, "report_type": report_type}, result_summary=result)
        return result

    # --- Multi-Examiner Sync ---

    @server.tool()
    def export_contributions(since: str = "") -> dict:
        """Export this examiner's work as a JSON contribution bundle for sharing with team members."""
        result = manager.export_contributions(since)
        audit.log(tool="export_contributions", params={"since": since}, result_summary={"examiner": result.get("examiner"), "findings": len(result.get("findings", []))})
        return result

    @server.tool()
    def import_contributions(bundle: dict) -> dict:
        """Import a contribution bundle from another examiner. Writes to examiners/{examiner}/."""
        result = manager.import_contributions(bundle)
        audit.log(tool="import_contributions", params={"examiner": bundle.get("examiner", "?")}, result_summary=result)
        return result

    @server.tool()
    def ingest_remote_audit(source: str, mcp_name: str, since: str = "") -> dict:
        """Pull audit entries from a remote MCP file into the local case audit trail."""
        result = manager.ingest_remote_audit(source, mcp_name, since)
        audit.log(tool="ingest_remote_audit", params={"source": source, "mcp_name": mcp_name}, result_summary=result)
        return result

    @server.tool()
    def get_team_status() -> dict:
        """Per-examiner summary: findings, timeline events, TODOs across all team members."""
        return manager.get_team_status()

    return server
