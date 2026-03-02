"""MCP server for forensic investigation management."""

from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import FORENSIC_MCP as _INSTRUCTIONS

from forensic_mcp.audit import AuditWriter
from forensic_mcp.case.manager import CaseManager

logger = logging.getLogger(__name__)

_MAX_TITLE = 500
_MAX_TEXT = 10_000
_MAX_SHORT = 200


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len or containing null bytes."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")


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
            guidance.append(
                "FD-001: Every claim must reference at least one evidence_id from an actual tool call"
            )
        if "confidence_justification" in err.lower():
            guidance.append(
                "FD-005: Confidence must be justified — cite specific evidence for your confidence level"
            )
        if "attribution" in err.lower() and "3" in err:
            guidance.append(
                "FD-003: Attribution requires multiple corroborating TTPs, not just a single IOC match"
            )
    return guidance


def create_server(reference_mode: str = "resources") -> FastMCP:
    """Create and configure the forensic MCP server.

    Args:
        reference_mode: How to expose discipline reference data.
            "resources" (default) — MCP resources, not counted as tools.
            "tools" — MCP tools, for clients without resource support.
    """
    server = FastMCP("forensic-mcp", instructions=_INSTRUCTIONS)
    manager = CaseManager()
    audit = AuditWriter(mcp_name="forensic-mcp")

    # Expose for testing and CLI integration
    server._manager = manager
    server._audit = audit

    # --- Case Lifecycle ---

    @server.tool()
    def get_case_status(case_id: str = "") -> dict:
        """Get investigation summary: findings by status, evidence count, timeline span."""
        try:
            return manager.get_case_status(case_id or None)
        except Exception as e:
            logger.error("get_case_status failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def list_cases() -> list[dict]:
        """List all cases with status."""
        try:
            return manager.list_cases()
        except Exception as e:
            logger.error("list_cases failed: %s", e)
            return [{"error": str(e)}]

    # --- Investigation Records ---

    @server.tool()
    def record_finding(
        finding: dict,
        analyst_override: str = "",
        supporting_commands: list[dict] | None = None,
        artifacts: list[dict] | None = None,
    ) -> dict:
        """Stage finding as DRAFT for human review.

        Every finding needs an evidence trail (provenance). There are three ways:

        1. MCP evidence: Pass evidence_ids from MCP tool responses (the evidence_id
           field in tool results). This is the strongest provenance.
        2. Shell evidence: Pass supporting_commands as a SEPARATE PARAMETER (not
           inside the finding dict) with the Bash commands you ran. Each command
           generates an audited evidence ID automatically.
        3. Analytical: For hypotheses without tool evidence (SPECULATIVE/LOW), pass
           a supporting_commands entry with command="analytical reasoning",
           output_excerpt describing what you observed, and purpose explaining your
           reasoning chain.

        Findings with no evidence trail and no supporting_commands are rejected.

        Required fields in finding dict:
        - title (str): brief summary (max 500 chars)
        - observation (str): factual evidence — what was seen (max 10000 chars)
        - interpretation (str): analytical meaning — what it implies (max 10000 chars)
        - confidence: SPECULATIVE, LOW, MEDIUM, or HIGH
        - confidence_justification (str): why this confidence level — REQUIRED, not optional (max 10000 chars)
        - type: finding, conclusion, attribution, or exclusion
        - evidence_ids (list[str]): IDs from MCP tool responses (format: prefix-examiner-YYYYMMDD-NNN).
          Use [] for SPECULATIVE/LOW findings without MCP evidence, but then you MUST provide
          supporting_commands.

        Optional fields in finding dict:
        - mitre_ids (list[str]): ATT&CK technique IDs (e.g. ["T1055", "T1053.005"])
        - iocs (list[str]): indicators of compromise
        - event_type (str): process, network, file, registry, auth, persistence, lateral, execution, or other
        - artifact_ref, related_findings

        supporting_commands (SEPARATE PARAMETER, not inside finding dict):
        List of dicts, each with:
        - command (str, required): the command that was run, or "analytical reasoning" for hypotheses
        - purpose (str, required): why this command was run / what reasoning was applied
        - output_excerpt (str, optional): relevant output snippet (max 2000 chars)
        Max 5 commands. Each generates an audited shell evidence ID.

        artifacts (SEPARATE PARAMETER, not inside finding dict):
        Raw evidence the examiner reviewed. List of dicts, each with:
        - source (str, required): file path of the artifact
        - extraction (str, required): full command used to extract it
        - content (str, required): the literal raw data — NOT a summary. Use the field name 'content', not 'raw_data'.
        - content_type (str, optional): csv_row, log_entry, registry_key, process_tree, network_capture, file_metadata, raw_text
        - purpose (str, optional): why this extraction was performed
        Max 10 artifacts, content truncated to 5000 chars.

        Requires human approval via 'aiir approve'."""
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        if isinstance(finding, dict):
            _validate_str_length(finding.get("title"), "title", _MAX_TITLE)
            _validate_str_length(finding.get("observation"), "observation", _MAX_TEXT)
            _validate_str_length(
                finding.get("interpretation"), "interpretation", _MAX_TEXT
            )
            _validate_str_length(
                finding.get("confidence_justification"),
                "confidence_justification",
                _MAX_TEXT,
            )
        # Coerce JSON string to list (LLMs often serialize list[dict] as a string)
        if isinstance(supporting_commands, str):
            try:
                supporting_commands = json.loads(supporting_commands)
            except (json.JSONDecodeError, TypeError):
                supporting_commands = None
        if not isinstance(supporting_commands, list):
            supporting_commands = None
        if supporting_commands:
            for cmd in supporting_commands[:5]:
                if isinstance(cmd, dict):
                    _validate_str_length(
                        cmd.get("command"), "supporting_commands.command", _MAX_TEXT
                    )
                    _validate_str_length(
                        cmd.get("purpose"), "supporting_commands.purpose", _MAX_TEXT
                    )
        # Coerce artifacts JSON string to list
        if isinstance(artifacts, str):
            try:
                artifacts = json.loads(artifacts)
            except (json.JSONDecodeError, TypeError):
                artifacts = None
        if not isinstance(artifacts, list):
            artifacts = None
        try:
            result = manager.record_finding(
                finding,
                examiner_override=analyst_override,
                supporting_commands=supporting_commands,
                artifacts=artifacts,
                audit=audit,
            )
        except Exception as e:
            logger.error("record_finding failed: %s", e)
            return {"error": str(e)}
        audit.log(
            tool="record_finding", params={"finding": finding}, result_summary=result
        )

        # Enrich with considerations when staging succeeds
        if result.get("status") == "STAGED":
            result["finding_status"] = (
                "DRAFT — requires human approval via aiir approve"
            )
            result["considerations"] = _build_finding_considerations(finding)
            grounding = manager._score_grounding(finding)
            if grounding:
                result["grounding"] = grounding

            # Add provenance classification to response
            provenance = result.pop("provenance_detail", None)
            if provenance:
                result["provenance"] = provenance
                if provenance["summary"] == "SHELL":
                    result["provenance_guidance"] = (
                        "For stronger provenance, re-run analysis through MCP tools."
                    )

        # Enrich validation failures with rule citations
        if result.get("status") == "VALIDATION_FAILED":
            result["guidance"] = _build_validation_guidance(result.get("errors", []))

        return result

    @server.tool()
    def record_timeline_event(event: dict, analyst_override: str = "") -> dict:
        """Stage timeline event as DRAFT. Requires human approval via 'aiir approve'.

        Required fields in event dict:
        - timestamp (str): ISO 8601 datetime (e.g. "2026-03-01T14:32:00Z")
        - description (str): what happened at this time

        Recommended fields:
        - source (str): origin artifact or tool (e.g. "Security.evtx", "Prefetch")

        Optional fields (pass through automatically):
        - related_findings: list of finding IDs this event supports (e.g. ["F-001", "F-003"])
        - event_type: process, network, file, registry, auth, persistence, lateral, execution, or other
        - artifact_ref: deduplication hint (e.g. "prefetch:EVIL.EXE-{hash}", "evtx:Security:4624:12345")
        """
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        if isinstance(event, dict):
            _validate_str_length(event.get("description"), "description", _MAX_TEXT)
            _validate_str_length(event.get("source"), "source", _MAX_TITLE)
        try:
            result = manager.record_timeline_event(
                event, examiner_override=analyst_override
            )
        except Exception as e:
            logger.error("record_timeline_event failed: %s", e)
            return {"error": str(e)}
        audit.log(
            tool="record_timeline_event", params={"event": event}, result_summary=result
        )
        return result

    @server.tool()
    def get_findings(status: str = "") -> list[dict]:
        """Return findings, optionally filtered by DRAFT/APPROVED/REJECTED.

        Each finding dict contains:
        - id, title, observation, interpretation, confidence, confidence_justification, type
        - evidence_ids: list of evidence trail IDs
        - status: DRAFT, APPROVED, or REJECTED
        - provenance: MCP, HOOK, SHELL, or NONE (string — how evidence was obtained)
        - content_hash: SHA-256 for integrity verification
        - artifacts: list of {source, extraction, content, content_type, purpose} (if provided)
        - supporting_commands: list of {command, output_excerpt, purpose} (if provided)
        - Optional: mitre_ids, iocs, event_type, artifact_ref, related_findings
        - Metadata: staged, modified_at, created_by, examiner
        """
        try:
            return manager.get_findings(status or None)
        except Exception as e:
            logger.error("get_findings failed: %s", e)
            return [{"error": str(e)}]

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
        try:
            return manager.get_timeline(
                status=status or None,
                source=source or None,
                examiner=examiner or None,
                start_date=start_date or None,
                end_date=end_date or None,
                event_type=event_type or None,
            )
        except Exception as e:
            logger.error("get_timeline failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_actions(limit: int = 50) -> list[dict]:
        """Return recent actions from the case actions log."""
        try:
            return manager.get_actions(limit)
        except Exception as e:
            logger.error("get_actions failed: %s", e)
            return [{"error": str(e)}]

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
        _validate_str_length(description, "description", _MAX_TEXT)
        _validate_str_length(assignee, "assignee", _MAX_SHORT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        try:
            result = manager.add_todo(
                description,
                assignee,
                priority,
                related_findings,
                examiner_override=analyst_override,
            )
        except Exception as e:
            logger.error("add_todo failed: %s", e)
            return {"error": str(e)}
        audit.log(
            tool="add_todo",
            params={"description": description, "assignee": assignee},
            result_summary=result,
        )
        return result

    @server.tool()
    def list_todos(status: str = "open", assignee: str = "") -> list[dict]:
        """List TODO items. Status: open/completed/all."""
        try:
            return manager.list_todos(status, assignee)
        except Exception as e:
            logger.error("list_todos failed: %s", e)
            return [{"error": str(e)}]

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
        _validate_str_length(note, "note", _MAX_TEXT)
        _validate_str_length(assignee, "assignee", _MAX_SHORT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        try:
            result = manager.update_todo(
                todo_id,
                status,
                note,
                assignee,
                priority,
                examiner_override=analyst_override,
            )
        except Exception as e:
            logger.error("update_todo failed: %s", e)
            return {"error": str(e)}
        audit.log(
            tool="update_todo", params={"todo_id": todo_id}, result_summary=result
        )
        return result

    @server.tool()
    def complete_todo(todo_id: str, analyst_override: str = "") -> dict:
        """Mark a TODO as completed."""
        try:
            result = manager.complete_todo(todo_id, examiner_override=analyst_override)
        except Exception as e:
            logger.error("complete_todo failed: %s", e)
            return {"error": str(e)}
        audit.log(
            tool="complete_todo", params={"todo_id": todo_id}, result_summary=result
        )
        return result

    # --- Evidence ---

    @server.tool()
    def list_evidence() -> list[dict]:
        """Return evidence index with registration timestamps and integrity status."""
        try:
            return manager.list_evidence()
        except Exception as e:
            logger.error("list_evidence failed: %s", e)
            return [{"error": str(e)}]

    # --- Discipline Reference Data ---

    if reference_mode == "resources":
        _register_discipline_resources(server)
    elif reference_mode == "tools":
        _register_discipline_tools(server, audit)
    else:
        raise ValueError(
            f"Invalid reference_mode: {reference_mode!r} (expected 'resources' or 'tools')"
        )

    return server


def _register_discipline_resources(server: FastMCP) -> None:
    """Register discipline reference data as MCP resources.

    Resources are static reference content accessed by URI. They don't count
    as tools in the tool list, reducing cognitive load for the LLM client.
    """

    @server.resource("forensic-mcp://investigation-framework")
    def investigation_framework_resource() -> str:
        """Full investigation framework: principles, HITL checkpoints, workflow, golden rules, self-check."""
        from forensic_mcp.discipline.rules import get_investigation_framework

        return json.dumps(get_investigation_framework())

    @server.resource("forensic-mcp://rules")
    def rules_resource() -> str:
        """All forensic discipline rules as structured data."""
        from forensic_mcp.discipline.rules import get_all_rules

        return json.dumps(get_all_rules())

    @server.resource("forensic-mcp://checkpoint/{action_type}")
    def checkpoint_resource(action_type: str) -> str:
        """Requirements before a specific action (attribution, root_cause, exclusion, clean_declaration)."""
        from forensic_mcp.discipline.rules import get_checkpoint

        return json.dumps(get_checkpoint(action_type))

    @server.resource("forensic-mcp://validation-schema")
    def validation_schema_resource() -> str:
        """Finding validation rules: required fields, confidence levels, evidence count requirements."""
        from forensic_knowledge import loader

        from forensic_mcp.discipline.validation import VALID_TYPES

        confidence_defs = loader.get_confidence_definitions()
        schema = {
            "required_fields": [
                "title",
                "observation",
                "interpretation",
                "confidence",
                "type",
                "evidence_ids",
                "confidence_justification",
            ],
            "valid_types": sorted(VALID_TYPES),
            "confidence_levels": {
                level: {"min_evidence_ids": defs.get("min_evidence_ids", 1)}
                for level, defs in confidence_defs.items()
            },
            "rules": [
                "FD-001: Every claim must reference at least one evidence_id from an actual tool call",
                "FD-003: Attribution requires at least 3 evidence_ids from multiple corroborating TTPs",
                "FD-005: Confidence must be justified with specific evidence citations",
            ],
        }
        return json.dumps(schema)

    @server.resource("forensic-mcp://evidence-standards")
    def evidence_standards_resource() -> str:
        """Evidence classification levels with definitions."""
        from forensic_mcp.discipline.rules import get_evidence_standards_data

        return json.dumps(get_evidence_standards_data())

    @server.resource("forensic-mcp://confidence-definitions")
    def confidence_definitions_resource() -> str:
        """Confidence levels (HIGH/MEDIUM/LOW/SPECULATIVE) with criteria."""
        from forensic_mcp.discipline.rules import get_confidence_definitions_data

        return json.dumps(get_confidence_definitions_data())

    @server.resource("forensic-mcp://anti-patterns")
    def anti_patterns_resource() -> str:
        """Common forensic mistakes to avoid."""
        from forensic_mcp.discipline.rules import get_anti_patterns_data

        return json.dumps(get_anti_patterns_data())

    @server.resource("forensic-mcp://evidence-template")
    def evidence_template_resource() -> str:
        """Required evidence presentation format."""
        from forensic_mcp.discipline.rules import get_evidence_template_data

        return json.dumps(get_evidence_template_data())

    @server.resource("forensic-mcp://tool-guidance/{tool_name}")
    def tool_guidance_resource(tool_name: str) -> str:
        """How to interpret results from a specific forensic tool."""
        from forensic_mcp.discipline.guidance import get_guidance

        return json.dumps(get_guidance(tool_name))

    @server.resource("forensic-mcp://false-positive-context/{tool_name}/{finding_type}")
    def false_positive_context_resource(tool_name: str, finding_type: str) -> str:
        """Common false positives for a tool/finding combination."""
        from forensic_mcp.discipline.guidance import get_false_positives

        return json.dumps(get_false_positives(tool_name, finding_type))

    @server.resource("forensic-mcp://corroboration/{finding_type}")
    def corroboration_resource(finding_type: str) -> str:
        """Cross-reference suggestions based on finding type."""
        from forensic_mcp.discipline.guidance import get_corroboration

        return json.dumps(get_corroboration(finding_type))

    @server.resource("forensic-mcp://playbooks")
    def playbooks_resource() -> str:
        """Available investigation playbooks."""
        from forensic_mcp.discipline.playbooks import list_all

        return json.dumps(list_all())

    @server.resource("forensic-mcp://playbook/{name}")
    def playbook_resource(name: str) -> str:
        """Step-by-step procedure for a specific investigation type."""
        from forensic_mcp.discipline.playbooks import get_by_name

        return json.dumps(get_by_name(name))

    @server.resource("forensic-mcp://collection-checklist/{artifact_type}")
    def collection_checklist_resource(artifact_type: str) -> str:
        """Evidence collection checklist per artifact type."""
        from forensic_mcp.discipline.playbooks import get_checklist

        return json.dumps(get_checklist(artifact_type))


def _register_discipline_tools(server: FastMCP, audit: AuditWriter) -> None:
    """Register discipline reference data as MCP tools.

    Used when the client doesn't support MCP resources. All 14 functions
    appear in the tool list alongside the 15 active tools.
    """

    @server.tool()
    def get_investigation_framework() -> dict:
        """Return the full investigation framework: principles, HITL checkpoints, workflow, golden rules, self-check."""
        try:
            from forensic_mcp.discipline.rules import (
                get_investigation_framework as _get_fw,
            )

            result = _get_fw()
            audit.log(
                tool="get_investigation_framework",
                params={},
                result_summary={"keys": list(result.keys())},
            )
            return result
        except Exception as e:
            logger.error("get_investigation_framework failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_rules() -> list[dict]:
        """Return all forensic discipline rules as structured data."""
        try:
            from forensic_mcp.discipline.rules import get_all_rules

            return get_all_rules()
        except Exception as e:
            logger.error("get_rules failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_checkpoint_requirements(action_type: str) -> dict:
        """What's required before a specific action (attribution, root cause, exclusion, etc.)."""
        try:
            from forensic_mcp.discipline.rules import get_checkpoint

            return get_checkpoint(action_type)
        except Exception as e:
            logger.error("get_checkpoint_requirements failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def validate_finding(finding_json: dict) -> dict:
        """Check a proposed finding against format and methodology standards."""
        try:
            from forensic_mcp.discipline.validation import validate

            return validate(finding_json)
        except Exception as e:
            logger.error("validate_finding failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_evidence_standards() -> dict:
        """Evidence classification levels with definitions."""
        try:
            from forensic_mcp.discipline.rules import get_evidence_standards_data

            return get_evidence_standards_data()
        except Exception as e:
            logger.error("get_evidence_standards failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_confidence_definitions() -> dict:
        """Confidence levels (HIGH/MEDIUM/LOW/SPECULATIVE) with criteria."""
        try:
            from forensic_mcp.discipline.rules import get_confidence_definitions_data

            return get_confidence_definitions_data()
        except Exception as e:
            logger.error("get_confidence_definitions failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_anti_patterns() -> list[dict]:
        """Common forensic mistakes to avoid."""
        try:
            from forensic_mcp.discipline.rules import get_anti_patterns_data

            return get_anti_patterns_data()
        except Exception as e:
            logger.error("get_anti_patterns failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_evidence_template() -> dict:
        """Required evidence presentation format."""
        try:
            from forensic_mcp.discipline.rules import get_evidence_template_data

            return get_evidence_template_data()
        except Exception as e:
            logger.error("get_evidence_template failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_tool_guidance(tool_name: str) -> dict:
        """How to interpret results from a specific forensic tool."""
        try:
            from forensic_mcp.discipline.guidance import get_guidance

            return get_guidance(tool_name)
        except Exception as e:
            logger.error("get_tool_guidance failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_false_positive_context(tool_name: str, finding_type: str) -> dict:
        """Common false positives for a tool/finding combination."""
        try:
            from forensic_mcp.discipline.guidance import get_false_positives

            return get_false_positives(tool_name, finding_type)
        except Exception as e:
            logger.error("get_false_positive_context failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_corroboration_suggestions(finding_type: str) -> list[dict]:
        """Cross-reference suggestions based on finding type."""
        try:
            from forensic_mcp.discipline.guidance import get_corroboration

            return get_corroboration(finding_type)
        except Exception as e:
            logger.error("get_corroboration_suggestions failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def list_playbooks() -> list[dict]:
        """Available investigation playbooks."""
        try:
            from forensic_mcp.discipline.playbooks import list_all

            return list_all()
        except Exception as e:
            logger.error("list_playbooks failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_playbook(name: str) -> dict:
        """Step-by-step procedure for a specific investigation type."""
        try:
            from forensic_mcp.discipline.playbooks import get_by_name

            return get_by_name(name)
        except Exception as e:
            logger.error("get_playbook failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_collection_checklist(artifact_type: str) -> dict:
        """Evidence collection checklist per artifact type."""
        try:
            from forensic_mcp.discipline.playbooks import get_checklist

            return get_checklist(artifact_type)
        except Exception as e:
            logger.error("get_collection_checklist failed: %s", e)
            return {"error": str(e)}
