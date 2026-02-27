"""Case manager: investigation records, TODOs, evidence listing, grounding.

Local-first: each examiner owns a flat case directory. Case lifecycle
(init, close, activate) is handled by case-mcp and the aiir CLI.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from forensic_mcp.audit import resolve_examiner
from forensic_mcp.discipline.validation import validate as validate_finding_data

logger = logging.getLogger(__name__)


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename to prevent data loss on crash."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _protected_write(path: Path, content: str) -> None:
    """Write to a chmod-444-protected case data file.

    Unlocks (0o644) before write, locks (0o444) after. This is a speed bump
    — the LLM process can chmod — but combined with deny rules and the
    PreToolUse hook it adds defense-in-depth.
    """
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass  # May already be writable or on non-POSIX fs
    _atomic_write(path, content)
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass  # Non-POSIX filesystem


CASES_DIR_ENV = "AIIR_CASES_DIR"
DEFAULT_CASES_DIR = "cases"

# Evidence ID format: prefix-examiner-YYYYMMDD-NNN (all lowercase alphanumeric + hyphens)
_EVIDENCE_ID_PATTERN = re.compile(r"^[a-z]+-[a-z0-9]+-[0-9]{8}-[0-9]{3,}\Z")

# Allowlist: only these fields pass through from user-supplied finding data
_ALLOWED_FINDING_FIELDS = {
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "type",
    "evidence_ids",
    "mitre_ids",
    "iocs",
    "supporting_commands",
    "event_type",
    "artifact_ref",
    "related_findings",
}
_PROTECTED_EVENT_FIELDS = {
    "id",
    "status",
    "staged",
    "modified_at",
    "created_by",
    "examiner",
}

# Keys excluded from content hash — volatile/derived fields
_HASH_EXCLUDE_KEYS = {
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "examiner_notes",
    "examiner_modifications",
    "content_hash",
    "verification",
    "modified_at",
    "provenance",
}


def _compute_content_hash(item: dict) -> str:
    """SHA-256 of canonical JSON excluding volatile fields.

    Duplicated from aiir-cli case_io.py — forensic-mcp does NOT depend on
    aiir-cli. Kept in sync manually.
    """
    hashable = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _next_seq(items: list[dict], id_field: str, prefix: str, examiner: str) -> int:
    """Find max sequence number for IDs matching {prefix}-{examiner}-NNN."""
    pattern = f"{prefix}-{examiner}-"
    max_num = 0
    for item in items:
        item_id = item.get(id_field, "")
        if item_id.startswith(pattern):
            try:
                num = int(item_id[len(pattern) :])
                max_num = max(max_num, num)
            except ValueError:
                pass
    return max_num + 1


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id or not case_id.strip():
        raise ValueError("Case ID cannot be empty")
    if "\x00" in case_id:
        raise ValueError("Case ID contains null byte")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    """Validate examiner slug: lowercase alphanumeric + hyphens, max 20 chars."""
    if not examiner:
        raise ValueError("Examiner identity cannot be empty")
    if not re.match(r"^[a-z0-9][a-z0-9-]{0,19}$", examiner):
        raise ValueError(
            f"Invalid examiner '{examiner}': must be lowercase alphanumeric + hyphens, max 20 chars"
        )


class CaseManager:
    """Manages forensic investigation cases."""

    def __init__(self) -> None:
        self._active_case_id: str | None = None
        self._active_case_path: Path | None = None
        # Read from environment if set by installer/gateway
        env_case = os.environ.get("AIIR_ACTIVE_CASE")
        if env_case:
            try:
                _validate_case_id(env_case)
                case_dir = self.cases_dir / env_case
                if case_dir.is_dir():
                    self._active_case_id = env_case
                    self._active_case_path = case_dir
                    os.environ["AIIR_CASE_DIR"] = str(case_dir)
                    logger.info("Activated case from environment: %s", env_case)
            except ValueError:
                logger.warning(
                    "AIIR_ACTIVE_CASE contains invalid case ID: %s", env_case
                )

    @property
    def cases_dir(self) -> Path:
        return Path(os.environ.get(CASES_DIR_ENV, DEFAULT_CASES_DIR))

    @property
    def active_case_dir(self) -> Path | None:
        if self._active_case_path:
            return self._active_case_path
        if not self._active_case_id:
            return None
        return self.cases_dir / self._active_case_id

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _require_active_case(self) -> Path:
        if self._active_case_id is None:
            active_file = Path.home() / ".aiir" / "active_case"
            if active_file.exists():
                content = active_file.read_text().strip()
                if os.path.isabs(content):
                    # Absolute path — use directly
                    case_dir = Path(content)
                    if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                        self._active_case_id = case_dir.name
                        self._active_case_path = case_dir
                        os.environ["AIIR_CASE_DIR"] = str(case_dir)
                        os.environ["AIIR_ACTIVE_CASE"] = case_dir.name
                else:
                    # Legacy: bare case ID
                    _validate_case_id(content)
                    case_dir = self.cases_dir / content
                    if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                        self._active_case_id = content
                        self._active_case_path = case_dir
                        os.environ["AIIR_CASE_DIR"] = str(case_dir)
                        os.environ["AIIR_ACTIVE_CASE"] = content
        d = self.active_case_dir
        if d is None or not d.exists():
            raise ValueError("No active case. Run 'aiir case activate <id>' first.")
        # Safety belt: refuse closed cases
        meta_file = d / "CASE.yaml"
        if meta_file.exists():
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
                if meta.get("status") == "closed":
                    raise ValueError(
                        f"Case {self._active_case_id} is closed. "
                        f"Run 'aiir case reopen {self._active_case_id}' or "
                        f"'aiir case activate <id>' to work on a different case."
                    )
            except yaml.YAMLError:
                pass
        return d

    def _effective_examiner(self, override: str = "") -> str:
        """Return override if non-empty, otherwise self.examiner.

        Used by gateway to propagate per-request examiner identity.
        """
        return (
            override.strip().lower() if override and override.strip() else self.examiner
        )

    def get_case_status(self, case_id: str | None = None) -> dict:
        """Get investigation summary."""
        case_dir = self._resolve_case_dir(case_id)
        meta = self._load_case_meta(case_dir)
        findings = self._load_findings(case_dir)
        timeline = self._load_timeline(case_dir)
        evidence = self._load_evidence_registry(case_dir)
        todos = self._load_todos(case_dir)

        return {
            "case_id": meta["case_id"],
            "name": meta.get("name", ""),
            "status": meta.get("status", "unknown"),
            "examiner": meta.get("examiner", ""),
            "findings": {
                "total": len(findings),
                "draft": sum(1 for f in findings if f.get("status") == "DRAFT"),
                "approved": sum(1 for f in findings if f.get("status") == "APPROVED"),
                "rejected": sum(1 for f in findings if f.get("status") == "REJECTED"),
            },
            "timeline_events": len(timeline),
            "evidence_files": len(evidence.get("files", [])),
            "todos": {
                "total": len(todos),
                "open": sum(1 for t in todos if t.get("status") == "open"),
                "completed": sum(1 for t in todos if t.get("status") == "completed"),
            },
        }

    def list_cases(self) -> list[dict]:
        """List all cases."""
        if not self.cases_dir.exists():
            return []
        results = []
        for case_dir in sorted(self.cases_dir.iterdir()):
            if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                meta = self._load_case_meta(case_dir)
                results.append(
                    {
                        "case_id": meta["case_id"],
                        "name": meta.get("name", ""),
                        "status": meta.get("status", "unknown"),
                        "created": meta.get("created", ""),
                        "examiner": meta.get("examiner", ""),
                    }
                )
        return results

    # --- Investigation Records ---

    def record_action(
        self,
        description: str,
        tool: str = "",
        command: str = "",
        examiner_override: str = "",
    ) -> dict:
        """Append action to actions.jsonl."""
        case_dir = self._require_active_case()
        ts = datetime.now(timezone.utc).isoformat()
        exam = self._effective_examiner(examiner_override)

        entry: dict[str, Any] = {
            "ts": ts,
            "description": description,
            "examiner": exam,
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
            logger.warning("Failed to write action log: %s", e)
            return {"status": "write_failed", "timestamp": ts, "error": str(e)}

        return {"status": "recorded", "timestamp": ts}

    def record_finding(
        self,
        finding: dict,
        examiner_override: str = "",
        supporting_commands: list[dict] | None = None,
        audit: Any | None = None,
    ) -> dict:
        """Validate and stage finding as DRAFT.

        Args:
            finding: Finding data dict.
            examiner_override: Override examiner identity.
            supporting_commands: List of shell commands that produced evidence.
                Each dict must have command, output_excerpt, purpose.
            audit: AuditWriter instance (needed for shell evidence ID generation).
        """
        case_dir = self._require_active_case()

        # Validate via discipline module
        validation = validate_finding_data(finding)
        if not validation.get("valid", False):
            return {
                "status": "VALIDATION_FAILED",
                "errors": validation.get("errors", []),
            }

        exam = self._effective_examiner(examiner_override)
        findings = self._load_findings(case_dir)
        seq = _next_seq(findings, "id", "F", exam)
        finding_id = f"F-{exam}-{seq:03d}"
        now = datetime.now(timezone.utc).isoformat()
        today = datetime.now(timezone.utc).strftime("%Y%m%d")

        # Allowlist: only accepted fields pass through from user input
        sanitized = {k: v for k, v in finding.items() if k in _ALLOWED_FINDING_FIELDS}

        # Process supporting_commands — generate shell evidence IDs
        shell_evidence_ids: list[str] = []
        validated_commands: list[dict] = []
        if supporting_commands:
            for _i, cmd in enumerate(supporting_commands[:5]):
                if not isinstance(cmd, dict):
                    continue
                command = cmd.get("command", "")
                output_excerpt = cmd.get("output_excerpt", "")
                purpose = cmd.get("purpose", "")
                if not command or not purpose:
                    continue
                # Truncate output_excerpt
                if len(output_excerpt) > 2000:
                    output_excerpt = output_excerpt[:2000]
                shell_seq = self._next_shell_seq(case_dir, exam, today)
                shell_eid = f"shell-{exam}-{today}-{shell_seq:03d}"
                shell_evidence_ids.append(shell_eid)
                validated_cmd = {
                    "command": command,
                    "output_excerpt": output_excerpt,
                    "purpose": purpose,
                }
                validated_commands.append(validated_cmd)
                # Write audit entry for this shell command
                if audit:
                    audit.log(
                        tool="supporting_command",
                        params={"command": command, "purpose": purpose},
                        result_summary={"output_excerpt": output_excerpt[:200]},
                        source="shell_self_report",
                        evidence_id=shell_eid,
                    )

        # Extend evidence_ids with shell evidence IDs
        evidence_ids = list(sanitized.get("evidence_ids", []))
        evidence_ids.extend(shell_evidence_ids)
        sanitized["evidence_ids"] = evidence_ids

        # Classify provenance
        provenance = self._classify_provenance(evidence_ids, case_dir)

        # Hard gate: reject if all NONE and no supporting_commands
        if provenance["summary"] == "NONE" and not validated_commands:
            return {
                "status": "REJECTED",
                "error": (
                    "Finding rejected: no provenance. Provide supporting_commands "
                    "with the Bash commands used, or re-run analysis through MCP "
                    "tools to create an audited evidence trail."
                ),
            }

        finding_record = {
            **sanitized,
            "id": finding_id,
            "status": "DRAFT",
            "staged": now,
            "modified_at": now,
            "created_by": exam,
            "examiner": exam,
            "provenance": provenance["summary"],
        }

        # Store supporting_commands if provided
        if validated_commands:
            finding_record["supporting_commands"] = validated_commands

        # Compute content hash at staging
        finding_record["content_hash"] = _compute_content_hash(finding_record)

        findings.append(finding_record)
        self._save_findings(case_dir, findings)

        return {
            "status": "STAGED",
            "finding_id": finding_id,
            "provenance_detail": provenance,
        }

    def _next_shell_seq(self, case_dir: Path, examiner: str, today: str) -> int:
        """Find next sequence number for shell-{examiner}-{today}-NNN evidence IDs."""
        audit_dir = case_dir / "audit"
        prefix = f"shell-{examiner}-{today}-"
        max_num = 0
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                eid = entry.get("evidence_id", "")
                                if eid.startswith(prefix):
                                    try:
                                        num = int(eid[len(prefix) :])
                                        max_num = max(max_num, num)
                                    except ValueError:
                                        pass
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    continue
        return max_num + 1

    def record_timeline_event(self, event: dict, examiner_override: str = "") -> dict:
        """Validate and stage timeline event as DRAFT."""
        case_dir = self._require_active_case()

        # Basic validation
        required = ["timestamp", "description"]
        missing = [k for k in required if not event.get(k)]
        if missing:
            return {
                "status": "VALIDATION_FAILED",
                "errors": [f"Missing required fields: {missing}"],
            }

        exam = self._effective_examiner(examiner_override)
        timeline = self._load_timeline(case_dir)
        seq = _next_seq(timeline, "id", "T", exam)
        event_id = f"T-{exam}-{seq:03d}"
        now = datetime.now(timezone.utc).isoformat()

        # Strip protected fields from user input for defense-in-depth
        sanitized = {k: v for k, v in event.items() if k not in _PROTECTED_EVENT_FIELDS}
        event_record = {
            **sanitized,
            "id": event_id,
            "status": "DRAFT",
            "staged": now,
            "modified_at": now,
            "created_by": exam,
            "examiner": exam,
        }
        timeline.append(event_record)
        self._save_timeline(case_dir, timeline)

        return {"status": "STAGED", "event_id": event_id}

    def get_findings(self, status: str | None = None) -> list[dict]:
        """Return local findings."""
        case_dir = self._require_active_case()
        findings = self._load_findings(case_dir)
        if status:
            findings = [f for f in findings if f.get("status") == status.upper()]
        return findings

    def get_timeline(
        self,
        status: str | None = None,
        source: str | None = None,
        examiner: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        event_type: str | None = None,
    ) -> list[dict]:
        """Return local timeline, sorted chronologically.

        Optional filters narrow the result set:
        - status: DRAFT, APPROVED, REJECTED
        - source: substring match against event source field
        - examiner: exact match against examiner field
        - start_date: ISO date/datetime lower bound on timestamp
        - end_date: ISO date/datetime upper bound on timestamp
        - event_type: exact match against event_type field
        """
        case_dir = self._require_active_case()
        events = self._load_timeline(case_dir)
        events.sort(key=lambda t: t.get("timestamp", ""))
        if status:
            events = [e for e in events if e.get("status") == status.upper()]
        if source:
            events = [
                e for e in events if source.lower() in e.get("source", "").lower()
            ]
        if examiner:
            events = [e for e in events if e.get("examiner") == examiner]
        if start_date:
            events = [e for e in events if e.get("timestamp", "") >= start_date]
        if end_date:
            events = [e for e in events if e.get("timestamp", "") <= end_date]
        if event_type:
            events = [e for e in events if e.get("event_type", "") == event_type]
        return events

    def get_actions(self, limit: int = 50) -> list[dict]:
        """Return recent actions from actions.jsonl."""
        case_dir = self._require_active_case()
        entries = []
        actions_file = case_dir / "actions.jsonl"
        if actions_file.exists():
            try:
                with open(actions_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                logger.warning("Corrupt JSONL line in %s", actions_file)
            except OSError as e:
                logger.warning("Failed to read actions file %s: %s", actions_file, e)
        entries.sort(key=lambda e: e.get("ts", ""))
        return entries[-limit:]

    # --- TODOs ---

    def add_todo(
        self,
        description: str,
        assignee: str = "",
        priority: str = "medium",
        related_findings: list[str] | None = None,
        examiner_override: str = "",
    ) -> dict:
        """Create a new TODO item."""
        case_dir = self._require_active_case()
        exam = self._effective_examiner(examiner_override)
        todos = self._load_todos(case_dir)
        seq = _next_seq(todos, "todo_id", "TODO", exam)
        todo_id = f"TODO-{exam}-{seq:03d}"

        todo = {
            "todo_id": todo_id,
            "description": description,
            "status": "open",
            "priority": priority if priority in ("high", "medium", "low") else "medium",
            "assignee": assignee,
            "related_findings": related_findings or [],
            "created_by": exam,
            "examiner": exam,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [],
            "completed_at": None,
        }
        todos.append(todo)
        self._save_todos(case_dir, todos)

        return {"status": "created", "todo_id": todo_id}

    def list_todos(self, status: str = "open", assignee: str = "") -> list[dict]:
        """List local TODOs, filtered by status and/or assignee."""
        case_dir = self._require_active_case()
        todos = self._load_todos(case_dir)

        if status != "all":
            todos = [t for t in todos if t.get("status") == status]
        if assignee:
            todos = [t for t in todos if t.get("assignee") == assignee]

        return todos

    def update_todo(
        self,
        todo_id: str,
        status: str = "",
        note: str = "",
        assignee: str = "",
        priority: str = "",
        examiner_override: str = "",
    ) -> dict:
        """Update a TODO item."""
        case_dir = self._require_active_case()
        todos = self._load_todos(case_dir)
        exam = self._effective_examiner(examiner_override)

        for todo in todos:
            if todo["todo_id"] == todo_id:
                if status and status in ("open", "completed"):
                    todo["status"] = status
                    if status == "completed":
                        todo["completed_at"] = datetime.now(timezone.utc).isoformat()
                if assignee:
                    todo["assignee"] = assignee
                if priority and priority in ("high", "medium", "low"):
                    todo["priority"] = priority
                if note:
                    todo["notes"].append(
                        {
                            "note": note,
                            "by": exam,
                            "at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                self._save_todos(case_dir, todos)
                return {"status": "updated", "todo_id": todo_id}

        return {"status": "not_found", "todo_id": todo_id}

    def complete_todo(self, todo_id: str, examiner_override: str = "") -> dict:
        """Mark a TODO as completed."""
        return self.update_todo(
            todo_id, status="completed", examiner_override=examiner_override
        )

    # --- Evidence ---

    def list_evidence(self) -> list[dict]:
        case_dir = self._require_active_case()
        return self._load_evidence_registry(case_dir).get("files", [])

    # --- Grounding Score ---

    # MCP audit files that count as grounding sources
    _GROUNDING_MCPS = ("forensic-rag-mcp", "windows-triage-mcp", "opencti-mcp")

    def _score_grounding(self, finding: dict) -> dict:
        """Score how well a finding is grounded by external reference MCPs.

        Scans the case audit directory for evidence of forensic-rag-mcp,
        windows-triage-mcp, and opencti-mcp usage. Returns WEAK/PARTIAL/STRONG
        with suggestions for unconsulted sources.

        Returns empty dict when STRONG (2+ sources consulted).
        """
        case_dir = self.active_case_dir
        if case_dir is None or not case_dir.exists():
            return {}

        audit_dir = case_dir / "audit"
        if not audit_dir.is_dir():
            return self._grounding_result([], finding)

        consulted = []
        for mcp_name in self._GROUNDING_MCPS:
            audit_file = audit_dir / f"{mcp_name}.jsonl"
            if audit_file.exists() and audit_file.stat().st_size > 0:
                consulted.append(mcp_name)

        return self._grounding_result(consulted, finding)

    def _grounding_result(self, consulted: list[str], finding: dict) -> dict:
        """Build grounding score result from consulted sources list."""
        if len(consulted) >= 2:
            return {}  # STRONG — don't clutter

        missing = [m for m in self._GROUNDING_MCPS if m not in consulted]
        level = "PARTIAL" if len(consulted) == 1 else "WEAK"

        # Load corroboration suggestions from FK for unconsulted sources
        suggestions = []
        finding_type = finding.get("type", "")
        if finding_type:
            try:
                from forensic_knowledge import loader

                checks = loader.get_corroboration(finding_type)
                if checks:
                    for check in checks:
                        check_text = check.get("check", "")
                        # Only suggest checks from missing MCPs
                        for mcp in missing:
                            short_name = mcp.replace("-mcp", "")
                            if short_name in check_text.lower():
                                reason = check.get("reason", "")
                                suggestions.append(
                                    f"{check_text} — {reason}" if reason else check_text
                                )
            except Exception:
                pass  # FK not available — skip suggestions

        result: dict[str, Any] = {
            "level": level,
            "sources_consulted": consulted,
            "sources_missing": missing,
        }
        if suggestions:
            result["suggestions"] = suggestions

        return result

    # --- Provenance Classification ---

    # Provenance tier priority: MCP > HOOK > SHELL
    _PROVENANCE_TIERS = ("MCP", "HOOK", "SHELL")

    def _classify_provenance(self, evidence_ids: list[str], case_dir: Path) -> dict:
        """Classify evidence IDs by provenance tier.

        Scans audit/*.jsonl to determine where each evidence_id came from:
        - MCP: found in any audit file except claude-code.jsonl
        - HOOK: found in claude-code.jsonl
        - NONE: not found in any audit file or malformed ID

        Evidence IDs must match the format: prefix-examiner-YYYYMMDD-NNN.
        Malformed IDs (path traversal, unicode, injection) are classified as NONE.

        Returns {"summary": tier, "mcp": [...], "hook": [...], "shell": [...], "none": [...]}.
        """
        audit_dir = case_dir / "audit"

        # Build evidence_id -> source lookup from audit files
        eid_source: dict[str, str] = {}
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                source = "HOOK" if jsonl_file.name == "claude-code.jsonl" else "MCP"
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                eid = entry.get("evidence_id", "")
                                if not eid:
                                    continue
                                existing = eid_source.get(eid)
                                if existing is None:
                                    eid_source[eid] = source
                                elif source == "MCP":
                                    # MCP > HOOK priority
                                    eid_source[eid] = "MCP"
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    continue

        # Classify each evidence_id
        result: dict[str, list[str]] = {
            "mcp": [],
            "hook": [],
            "shell": [],
            "none": [],
        }
        for eid in evidence_ids:
            # Reject malformed evidence IDs (path traversal, homoglyphs, injection)
            if not _EVIDENCE_ID_PATTERN.match(eid):
                result["none"].append(eid)
                continue
            source = eid_source.get(eid)
            if source:
                result[source.lower()].append(eid)
            else:
                result["none"].append(eid)

        # Compute summary tier
        tiers_present = set()
        if result["mcp"]:
            tiers_present.add("MCP")
        if result["hook"]:
            tiers_present.add("HOOK")
        if result["shell"]:
            tiers_present.add("SHELL")
        has_none = bool(result["none"])

        if not tiers_present:
            summary = "NONE"
        elif len(tiers_present) == 1 and not has_none:
            summary = next(iter(tiers_present))
        else:
            # Mixed tiers or any NONE with other tiers
            summary = "MIXED"

        result["summary"] = summary  # type: ignore[assignment]
        return result

    # --- Internal helpers ---

    def _resolve_case_dir(self, case_id: str | None) -> Path:
        if case_id:
            _validate_case_id(case_id)
            d = self.cases_dir / case_id
            if not d.exists():
                raise ValueError(f"Case not found: {case_id}")
            return d
        return self._require_active_case()

    def _load_case_meta(self, case_dir: Path) -> dict:
        try:
            with open(case_dir / "CASE.yaml") as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError) as e:
            logger.warning("Failed to load CASE.yaml from %s: %s", case_dir, e)
            return {}

    # --- Data I/O (case root) ---

    def _load_findings(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "findings.json", [])

    def _save_findings(self, case_dir: Path, findings: list[dict]) -> None:
        _protected_write(
            case_dir / "findings.json", json.dumps(findings, indent=2, default=str)
        )

    def _load_timeline(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "timeline.json", [])

    def _save_timeline(self, case_dir: Path, timeline: list[dict]) -> None:
        _protected_write(
            case_dir / "timeline.json", json.dumps(timeline, indent=2, default=str)
        )

    def _load_todos(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "todos.json", [])

    def _save_todos(self, case_dir: Path, todos: list[dict]) -> None:
        _atomic_write(case_dir / "todos.json", json.dumps(todos, indent=2, default=str))

    def _load_evidence_registry(self, case_dir: Path) -> dict:
        return self._load_json_file(case_dir / "evidence.json", {"files": []})

    # --- Generic helpers ---

    def _load_json_file(self, path: Path, default: Any) -> Any:
        """Load a JSON file, returning default on missing or corrupt."""
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            logger.error("Corrupt JSON file: %s", path)
            return default
        except OSError as e:
            logger.error("Failed to read JSON file %s: %s", path, e)
            return default
