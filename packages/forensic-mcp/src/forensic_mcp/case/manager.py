"""Case manager: lifecycle, records, evidence, execution, audit aggregation.

Multi-examiner aware: each examiner's work is stored in examiners/{slug}/,
reads merge all examiners/*/ for full team visibility.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
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
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


CASES_DIR_ENV = "AIIR_CASES_DIR"
DEFAULT_CASES_DIR = "cases"

# Protected fields that cannot be overridden by user-supplied data
_PROTECTED_FINDING_FIELDS = {"id", "status", "staged", "created_by", "examiner"}
_PROTECTED_EVENT_FIELDS = {"id", "status", "staged", "created_by", "examiner"}

# Contribution bundle schema version
_BUNDLE_SCHEMA_VERSION = 1


def _safe_id_num(id_str: str) -> int:
    """Extract the numeric suffix from an ID like 'F-001' or 'TODO-003'.

    Returns 0 if the ID cannot be parsed.
    """
    try:
        return int(id_str.split("-")[-1])
    except (ValueError, IndexError):
        return 0


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id:
        raise ValueError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    """Validate examiner slug: lowercase alphanumeric + hyphens, max 20 chars."""
    if not examiner:
        raise ValueError("Examiner identity cannot be empty")
    if not re.match(r'^[a-z0-9][a-z0-9-]{0,19}$', examiner):
        raise ValueError(
            f"Invalid examiner '{examiner}': must be lowercase alphanumeric + hyphens, max 20 chars"
        )


class CaseManager:
    """Manages forensic investigation cases."""

    def __init__(self) -> None:
        self._active_case_id: str | None = None

    @property
    def cases_dir(self) -> Path:
        return Path(os.environ.get(CASES_DIR_ENV, DEFAULT_CASES_DIR))

    @property
    def active_case_dir(self) -> Path | None:
        if not self._active_case_id:
            return None
        return self.cases_dir / self._active_case_id

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _require_active_case(self) -> Path:
        d = self.active_case_dir
        if d is None or not d.exists():
            raise ValueError("No active case. Call set_active_case() or init_case() first.")
        return d

    def _effective_examiner(self, override: str = "") -> str:
        """Return override if non-empty, otherwise self.examiner.

        Used by gateway to propagate per-request examiner identity.
        """
        return override.strip().lower() if override and override.strip() else self.examiner

    def _examiner_dir(self, case_dir: Path, examiner_override: str = "") -> Path:
        """Return the examiners/{slug}/ directory for this examiner's work."""
        return case_dir / "examiners" / self._effective_examiner(examiner_override)

    # --- Case Lifecycle ---

    def init_case(self, name: str, description: str = "", examiner: str = "", collaborative: bool = False) -> dict:
        """Create case directory with initialized docs."""
        ts = datetime.now(timezone.utc)
        case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
        case_dir = self.cases_dir / case_id

        if case_dir.exists():
            raise ValueError(f"Case directory already exists: {case_dir}")

        # Resolve examiner identity
        exam = examiner or self.examiner
        _validate_examiner(exam)

        case_dir.mkdir(parents=True)
        (case_dir / "evidence").mkdir()
        (case_dir / "extracted").mkdir()
        (case_dir / "reports").mkdir()

        # examiners/{slug}/ structure (this examiner's work)
        exam_dir = self._examiner_dir(case_dir)
        exam_dir.mkdir(parents=True)
        (exam_dir / "audit").mkdir()

        mode = "collaborative" if collaborative else "solo"

        # CASE.yaml with examiner, team, and mode
        case_meta = {
            "case_id": case_id,
            "name": name,
            "description": description,
            "mode": mode,
            "status": "open",
            "examiner": exam,
            "team": [exam],
            "created": ts.isoformat(),
            "created_by": exam,
        }
        _atomic_write(case_dir / "CASE.yaml", yaml.dump(case_meta, default_flow_style=False))

        # Initialize local stores
        _atomic_write(exam_dir / "findings.json", json.dumps([]))
        _atomic_write(exam_dir / "timeline.json", json.dumps([]))
        _atomic_write(exam_dir / "todos.json", json.dumps([]))
        _atomic_write(exam_dir / "evidence.json", json.dumps({"files": []}))

        self._active_case_id = case_id
        os.environ["AIIR_CASE_DIR"] = str(case_dir)
        os.environ["AIIR_ACTIVE_CASE"] = case_id
        os.environ["AIIR_EXAMINER"] = exam

        logger.info("Case initialized: %s (%s) examiner=%s mode=%s", case_id, name, exam, mode)
        result: dict[str, Any] = {"case_id": case_id, "path": str(case_dir), "status": "open", "examiner": exam, "mode": mode}

        if collaborative:
            result["collaboration_setup"] = {
                "mode": "collaborative",
                "case_path": str(case_dir),
                "share_instructions": {
                    "linux_nfs": f"Export via /etc/exports: {case_dir} *(rw,sync,no_subtree_check)",
                    "linux_smb": f"Add Samba share for {case_dir} in /etc/samba/smb.conf",
                    "windows_smb": f"Right-click {case_dir} > Properties > Sharing > Share...",
                },
                "examiner_setup": "Each examiner sets AIIR_EXAMINER=<slug> before connecting",
                "join_info": "Other examiners call set_active_case() or `aiir case join` to join",
            }

        return result

    def close_case(self, case_id: str, summary: str = "") -> dict:
        """Close a case. Warns if unapproved findings exist."""
        _validate_case_id(case_id)
        case_dir = self.cases_dir / case_id
        if not case_dir.exists():
            raise ValueError(f"Case not found: {case_id}")

        meta = self._load_case_meta(case_dir)
        if meta.get("status") == "closed":
            return {"case_id": case_id, "status": "already_closed"}

        # Check for unapproved findings (merged from all examiners)
        findings = self._load_all_findings(case_dir)
        drafts = [f for f in findings if f.get("status") == "DRAFT"]

        meta["status"] = "closed"
        meta["closed"] = datetime.now(timezone.utc).isoformat()
        meta["close_summary"] = summary
        _atomic_write(case_dir / "CASE.yaml", yaml.dump(meta, default_flow_style=False))

        result: dict[str, Any] = {"case_id": case_id, "status": "closed"}
        warnings = []
        if drafts:
            warnings.append(f"{len(drafts)} unapproved finding(s) remain as DRAFT")
            result["draft_ids"] = [d["id"] for d in drafts]

        # Check for open TODOs (merged)
        todos = self._load_all_todos(case_dir)
        open_todos = [t for t in todos if t.get("status") == "open"]
        if open_todos:
            warnings.append(f"{len(open_todos)} open TODO(s) remain")
            result["open_todo_ids"] = [t["todo_id"] for t in open_todos]

        if warnings:
            result["warning"] = "; ".join(warnings)
        return result

    def get_case_status(self, case_id: str | None = None) -> dict:
        """Get investigation summary with per-examiner breakdown."""
        case_dir = self._resolve_case_dir(case_id)
        meta = self._load_case_meta(case_dir)
        findings = self._load_all_findings(case_dir)
        timeline = self._load_all_timeline(case_dir)
        evidence = self._load_evidence_registry(case_dir)
        todos = self._load_all_todos(case_dir)

        result = {
            "case_id": meta["case_id"],
            "name": meta.get("name", ""),
            "status": meta.get("status", "unknown"),
            "examiner": meta.get("examiner", ""),
            "team": meta.get("team", []),
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

        # Per-examiner breakdown
        examiners: dict[str, dict] = {}
        for f in findings:
            ex = f.get("examiner", meta.get("examiner", "local"))
            examiners.setdefault(ex, {"findings": 0, "timeline": 0, "todos_open": 0})
            examiners[ex]["findings"] += 1
        for t in timeline:
            ex = t.get("examiner", meta.get("examiner", "local"))
            examiners.setdefault(ex, {"findings": 0, "timeline": 0, "todos_open": 0})
            examiners[ex]["timeline"] += 1
        for t in todos:
            if t.get("status") == "open":
                ex = t.get("created_by", meta.get("examiner", "local"))
                examiners.setdefault(ex, {"findings": 0, "timeline": 0, "todos_open": 0})
                examiners[ex]["todos_open"] += 1
        if examiners:
            result["by_examiner"] = examiners

        return result

    def list_cases(self) -> list[dict]:
        """List all cases."""
        if not self.cases_dir.exists():
            return []
        results = []
        for case_dir in sorted(self.cases_dir.iterdir()):
            if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                meta = self._load_case_meta(case_dir)
                results.append({
                    "case_id": meta["case_id"],
                    "name": meta.get("name", ""),
                    "status": meta.get("status", "unknown"),
                    "created": meta.get("created", ""),
                    "examiner": meta.get("examiner", ""),
                })
        return results

    def set_active_case(self, case_id: str) -> dict:
        """Set active case for session. Auto-joins by creating examiner dir if needed."""
        _validate_case_id(case_id)
        case_dir = self.cases_dir / case_id
        if not case_dir.exists():
            raise ValueError(f"Case not found: {case_id}")

        meta = self._load_case_meta(case_dir)
        exam = self.examiner

        # Auto-join: create examiner dir with empty initial files if not exists
        exam_dir = case_dir / "examiners" / exam
        joined = False
        if not exam_dir.exists():
            _validate_examiner(exam)
            exam_dir.mkdir(parents=True)
            (exam_dir / "audit").mkdir()
            _atomic_write(exam_dir / "findings.json", json.dumps([]))
            _atomic_write(exam_dir / "timeline.json", json.dumps([]))
            _atomic_write(exam_dir / "todos.json", json.dumps([]))
            _atomic_write(exam_dir / "evidence.json", json.dumps({"files": []}))
            joined = True

            # Add examiner to CASE.yaml team list
            if exam not in meta.get("team", []):
                meta.setdefault("team", []).append(exam)
                _atomic_write(case_dir / "CASE.yaml", yaml.dump(meta, default_flow_style=False))

        self._active_case_id = case_id
        os.environ["AIIR_CASE_DIR"] = str(case_dir)
        os.environ["AIIR_ACTIVE_CASE"] = case_id
        os.environ["AIIR_EXAMINER"] = exam

        result: dict[str, Any] = {"active_case": case_id, "examiner": exam}
        if joined:
            result["joined"] = True
            result["message"] = f"Auto-joined case as examiner '{exam}'"
        return result

    # --- Investigation Records ---

    def record_action(self, description: str, tool: str = "", command: str = "", examiner_override: str = "") -> dict:
        """Append action to examiners/{slug}/actions.jsonl."""
        case_dir = self._require_active_case()
        ts = datetime.now(timezone.utc).isoformat()
        exam = self._effective_examiner(examiner_override)

        entry = {
            "ts": ts,
            "description": description,
            "examiner": exam,
        }
        if tool:
            entry["tool"] = tool
        if command:
            entry["command"] = command

        exam_dir = self._examiner_dir(case_dir, examiner_override)
        exam_dir.mkdir(parents=True, exist_ok=True)
        with open(exam_dir / "actions.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return {"status": "recorded", "timestamp": ts}

    def record_finding(self, finding: dict, examiner_override: str = "") -> dict:
        """Validate and stage finding as DRAFT."""
        case_dir = self._require_active_case()

        # Validate via discipline module
        validation = validate_finding_data(finding)
        if not validation.get("valid", False):
            return {"status": "VALIDATION_FAILED", "errors": validation.get("errors", [])}

        # Assign finding ID using max existing local ID
        findings = self._load_findings(case_dir)
        max_num = max((_safe_id_num(f["id"]) for f in findings if "id" in f), default=0)
        finding_id = f"F-{max_num + 1:03d}"

        exam = self._effective_examiner(examiner_override)

        # Strip protected fields from user input for defense-in-depth
        sanitized = {k: v for k, v in finding.items() if k not in _PROTECTED_FINDING_FIELDS}
        finding_record = {
            **sanitized,
            "id": finding_id,
            "status": "DRAFT",
            "staged": datetime.now(timezone.utc).isoformat(),
            "created_by": exam,
            "examiner": exam,
        }
        findings.append(finding_record)
        self._save_findings(case_dir, findings)

        return {"status": "STAGED", "finding_id": finding_id}

    def record_timeline_event(self, event: dict, examiner_override: str = "") -> dict:
        """Validate and stage timeline event as DRAFT."""
        case_dir = self._require_active_case()

        # Basic validation
        required = ["timestamp", "description"]
        missing = [k for k in required if not event.get(k)]
        if missing:
            return {"status": "VALIDATION_FAILED", "errors": [f"Missing required fields: {missing}"]}

        timeline = self._load_timeline(case_dir)
        max_num = max((_safe_id_num(t["id"]) for t in timeline if "id" in t), default=0)
        event_id = f"T-{max_num + 1:03d}"

        exam = self._effective_examiner(examiner_override)

        # Strip protected fields from user input for defense-in-depth
        sanitized = {k: v for k, v in event.items() if k not in _PROTECTED_EVENT_FIELDS}
        event_record = {
            **sanitized,
            "id": event_id,
            "status": "DRAFT",
            "staged": datetime.now(timezone.utc).isoformat(),
            "created_by": exam,
            "examiner": exam,
        }
        timeline.append(event_record)
        self._save_timeline(case_dir, timeline)

        return {"status": "STAGED", "event_id": event_id}

    def get_findings(self, status: str | None = None) -> list[dict]:
        """Return merged findings from all examiners."""
        case_dir = self._require_active_case()
        findings = self._load_all_findings(case_dir)
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
        """Return merged timeline from all examiners, sorted chronologically.

        Optional filters narrow the result set:
        - status: DRAFT, APPROVED, REJECTED
        - source: substring match against event source field
        - examiner: exact match against examiner field
        - start_date: ISO date/datetime lower bound on timestamp
        - end_date: ISO date/datetime upper bound on timestamp
        - event_type: exact match against event_type field
        """
        case_dir = self._require_active_case()
        events = self._load_all_timeline(case_dir)
        if status:
            events = [e for e in events if e.get("status") == status.upper()]
        if source:
            events = [e for e in events if source.lower() in e.get("source", "").lower()]
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
        """Return recent actions from all examiners/*/actions.jsonl."""
        case_dir = self._require_active_case()
        entries = []

        examiners_root = case_dir / "examiners"
        if examiners_root.is_dir():
            for ex_dir in sorted(examiners_root.iterdir()):
                if not ex_dir.is_dir() or ex_dir.name.startswith("."):
                    continue
                actions_file = ex_dir / "actions.jsonl"
                if actions_file.exists():
                    for line in actions_file.read_text().strip().split("\n"):
                        if line:
                            try:
                                entry = json.loads(line)
                            except json.JSONDecodeError:
                                logger.warning("Corrupt JSONL line in %s", actions_file)
                                continue
                            entry.setdefault("examiner", ex_dir.name)
                            entries.append(entry)

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
        todos = self._load_todos(case_dir)
        exam = self._effective_examiner(examiner_override)

        max_num = max(
            (_safe_id_num(t["todo_id"]) for t in todos if "todo_id" in t),
            default=0,
        )
        todo_id = f"TODO-{max_num + 1:03d}"

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
        """List TODOs from all examiners, filtered by status and/or assignee."""
        case_dir = self._require_active_case()
        todos = self._load_all_todos(case_dir)

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
        """Update a TODO item (local only)."""
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
                    todo["notes"].append({
                        "note": note,
                        "by": exam,
                        "at": datetime.now(timezone.utc).isoformat(),
                    })
                self._save_todos(case_dir, todos)
                return {"status": "updated", "todo_id": todo_id}

        return {"status": "not_found", "todo_id": todo_id}

    def complete_todo(self, todo_id: str, examiner_override: str = "") -> dict:
        """Mark a TODO as completed."""
        return self.update_todo(todo_id, status="completed", examiner_override=examiner_override)

    # --- Evidence Management ---

    def register_evidence(self, path: str, description: str = "") -> dict:
        """Register evidence file: hash, chmod 444, record."""
        case_dir = self._require_active_case()
        evidence_path = Path(path).resolve()

        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        # Ensure path is within the case directory
        try:
            evidence_path.relative_to(case_dir.resolve())
        except ValueError:
            raise ValueError(
                f"Evidence path must be within case directory: {case_dir}"
            )

        # Compute hash
        sha256 = hashlib.sha256()
        with open(evidence_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        # Set read-only
        evidence_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444

        # Record in registry
        registry = self._load_evidence_registry(case_dir)
        entry = {
            "path": str(evidence_path),
            "sha256": file_hash,
            "description": description,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "registered_by": self.examiner,
            "examiner": self.examiner,
        }
        registry["files"].append(entry)
        self._save_evidence_registry(case_dir, registry)

        # Log to evidence access log
        self._log_evidence_access(case_dir, "register", str(evidence_path), file_hash)

        return {"status": "registered", "sha256": file_hash, "path": str(evidence_path)}

    def verify_evidence_integrity(self) -> dict:
        """Re-hash all registered evidence, report modifications."""
        case_dir = self._require_active_case()
        registry = self._load_evidence_registry(case_dir)
        results = []

        for entry in registry.get("files", []):
            path = Path(entry["path"])
            expected = entry["sha256"]

            if not path.exists():
                results.append({"path": str(path), "status": "MISSING", "expected": expected})
                continue

            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            actual = sha256.hexdigest()

            status = "OK" if actual == expected else "MODIFIED"
            results.append({
                "path": str(path),
                "status": status,
                "expected": expected,
                "actual": actual,
            })

        self._log_evidence_access(case_dir, "verify_integrity", "*", json.dumps({"results": len(results)}))
        return {"files": results, "total": len(results), "ok": sum(1 for r in results if r["status"] == "OK")}

    def list_evidence(self) -> list[dict]:
        case_dir = self._require_active_case()
        return self._load_evidence_registry(case_dir).get("files", [])

    def get_evidence_access_log(self, path: str | None = None) -> list[dict]:
        """Return chain-of-custody log."""
        case_dir = self._require_active_case()
        log_file = self._examiner_dir(case_dir) / "evidence_access.jsonl"
        if not log_file.exists():
            return []
        entries = []
        for line in log_file.read_text().strip().split("\n"):
            if line:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Corrupt JSONL line in %s", log_file)
                    continue
                if path is None or entry.get("path") == path:
                    entries.append(entry)
        return entries

    # --- Audit Aggregation ---

    def get_audit_log(self, limit: int = 100, mcp: str | None = None, tool_filter: str | None = None) -> list[dict]:
        """Read and merge audit JSONL from all examiners/*/audit/."""
        case_dir = self._require_active_case()
        entries = []

        examiners_root = case_dir / "examiners"
        if examiners_root.is_dir():
            for ex_dir in sorted(examiners_root.iterdir()):
                if not ex_dir.is_dir() or ex_dir.name.startswith("."):
                    continue
                audit_dir = ex_dir / "audit"
                entries.extend(self._read_audit_dir(audit_dir, mcp, tool_filter))

        entries.sort(key=lambda e: e.get("ts", ""))
        return entries[-limit:]

    def get_audit_summary(self) -> dict:
        """Statistics across all audit files."""
        entries = self.get_audit_log(limit=10000)
        tool_counts: dict[str, int] = {}
        mcp_counts: dict[str, int] = {}
        examiner_counts: dict[str, int] = {}
        evidence_ids: set[str] = set()

        for e in entries:
            tool_counts[e.get("tool", "?")] = tool_counts.get(e.get("tool", "?"), 0) + 1
            mcp_counts[e.get("mcp", "?")] = mcp_counts.get(e.get("mcp", "?"), 0) + 1
            ex = e.get("examiner", "?")
            examiner_counts[ex] = examiner_counts.get(ex, 0) + 1
            if e.get("evidence_id"):
                evidence_ids.add(e["evidence_id"])

        return {
            "total_entries": len(entries),
            "by_tool": tool_counts,
            "by_mcp": mcp_counts,
            "by_examiner": examiner_counts,
            "unique_evidence_ids": len(evidence_ids),
        }

    # --- Multi-Examiner Sync ---

    def export_contributions(self, since: str = "") -> dict:
        """Export this examiner's work as a contribution bundle."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        exam = self.examiner
        local = self._examiner_dir(case_dir)

        bundle: dict[str, Any] = {
            "schema_version": _BUNDLE_SCHEMA_VERSION,
            "case_id": meta["case_id"],
            "examiner": exam,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "since": since or None,
        }

        # Findings
        findings = self._load_findings(case_dir)
        for f in findings:
            f.setdefault("examiner", exam)
        bundle["findings"] = findings

        # Timeline
        timeline = self._load_timeline(case_dir)
        for t in timeline:
            t.setdefault("examiner", exam)
        bundle["timeline"] = timeline

        # TODOs
        todos = self._load_todos(case_dir)
        bundle["todos"] = todos

        # Actions (JSONL)
        actions_file = local / "actions.jsonl"
        bundle["actions_jsonl"] = actions_file.read_text() if actions_file.exists() else ""
        # Legacy fallback for old bundles
        legacy_actions = local / "actions.md"
        bundle["actions_md"] = legacy_actions.read_text() if legacy_actions.exists() else ""

        # Approvals
        approvals_file = local / "approvals.jsonl"
        approvals = []
        if approvals_file.exists():
            for line in approvals_file.read_text().strip().split("\n"):
                if line:
                    try:
                        approvals.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning("Corrupt JSONL line in %s", approvals_file)
        bundle["approvals"] = approvals

        # Audit entries (all MCP audit files)
        audit_dir = local / "audit"
        audit: dict[str, list] = {}
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                mcp_name = jsonl_file.stem
                entries = []
                for line in jsonl_file.read_text().strip().split("\n"):
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning("Corrupt JSONL line in %s", jsonl_file)
                audit[mcp_name] = entries
        bundle["audit"] = audit

        # Evidence manifest (hashes + descriptions, not files)
        registry = self._load_evidence_registry(case_dir)
        manifest = []
        for entry in registry.get("files", []):
            manifest.append({
                "sha256": entry["sha256"],
                "description": entry.get("description", ""),
                "registered_at": entry.get("registered_at", ""),
                "examiner": exam,
            })
        bundle["evidence_manifest"] = manifest

        # Filter by since timestamp if provided
        if since:
            bundle["findings"] = [f for f in bundle["findings"] if f.get("staged", "") >= since]
            bundle["timeline"] = [t for t in bundle["timeline"] if t.get("staged", "") >= since]
            bundle["approvals"] = [a for a in bundle["approvals"] if a.get("ts", "") >= since]
            for mcp_name in bundle["audit"]:
                bundle["audit"][mcp_name] = [
                    e for e in bundle["audit"][mcp_name] if e.get("ts", "") >= since
                ]

        return bundle

    def import_contributions(self, bundle: dict) -> dict:
        """Import a contribution bundle from another examiner."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)

        # Validate bundle
        if bundle.get("schema_version") != _BUNDLE_SCHEMA_VERSION:
            return {"status": "error", "message": f"Unsupported schema version: {bundle.get('schema_version')}"}

        bundle_examiner = bundle.get("examiner", "")
        if not bundle_examiner:
            return {"status": "error", "message": "Bundle missing examiner field"}

        if bundle_examiner == meta.get("examiner"):
            return {"status": "error", "message": "Cannot import your own contributions"}

        bundle_case = bundle.get("case_id", "")
        if bundle_case != meta["case_id"]:
            return {"status": "error", "message": f"Case ID mismatch: bundle={bundle_case}, local={meta['case_id']}"}

        _validate_examiner(bundle_examiner)

        # Validate content types
        for field in ("findings", "timeline", "todos"):
            if field in bundle and not isinstance(bundle[field], list):
                return {"status": "error", "message": f"Bundle '{field}' must be a list, got {type(bundle[field]).__name__}"}

        # Validate audit entries have required fields
        if "audit" in bundle:
            if not isinstance(bundle["audit"], dict):
                return {"status": "error", "message": "Bundle 'audit' must be a dict"}
            for mcp_name, entries in bundle["audit"].items():
                if not isinstance(entries, list):
                    return {"status": "error", "message": f"Audit entries for '{mcp_name}' must be a list"}
                for entry in entries:
                    if not isinstance(entry, dict) or "ts" not in entry or "tool" not in entry:
                        return {"status": "error", "message": f"Audit entry in '{mcp_name}' missing required 'ts' or 'tool' fields"}

        # Write to examiners/{examiner}/
        import_dir = case_dir / "examiners" / bundle_examiner
        import_dir.mkdir(parents=True, exist_ok=True)
        (import_dir / "audit").mkdir(exist_ok=True)

        # Write findings
        if "findings" in bundle:
            _atomic_write(import_dir / "findings.json", json.dumps(bundle["findings"], indent=2, default=str))

        # Write timeline
        if "timeline" in bundle:
            _atomic_write(import_dir / "timeline.json", json.dumps(bundle["timeline"], indent=2, default=str))

        # Write TODOs
        if "todos" in bundle:
            _atomic_write(import_dir / "todos.json", json.dumps(bundle["todos"], indent=2, default=str))

        # Write actions
        if bundle.get("actions_jsonl"):
            _atomic_write(import_dir / "actions.jsonl", bundle["actions_jsonl"])
        elif bundle.get("actions_md"):
            _atomic_write(import_dir / "actions.md", bundle["actions_md"])

        # Write approvals
        if "approvals" in bundle:
            lines = [json.dumps(entry, default=str) + "\n" for entry in bundle["approvals"]]
            _atomic_write(import_dir / "approvals.jsonl", "".join(lines))

        # Write audit entries
        if "audit" in bundle:
            for mcp_name, entries in bundle["audit"].items():
                # Validate mcp_name to prevent path traversal
                if not mcp_name or ".." in mcp_name or "/" in mcp_name or "\\" in mcp_name:
                    continue
                lines = [json.dumps(entry, default=str) + "\n" for entry in entries]
                _atomic_write(import_dir / "audit" / f"{mcp_name}.jsonl", "".join(lines))

        # Write evidence manifest
        if "evidence_manifest" in bundle:
            _atomic_write(import_dir / "evidence_manifest.json", json.dumps(bundle["evidence_manifest"], indent=2, default=str))

        # Update team list in CASE.yaml
        if bundle_examiner not in meta.get("team", []):
            meta.setdefault("team", []).append(bundle_examiner)
            _atomic_write(case_dir / "CASE.yaml", yaml.dump(meta, default_flow_style=False))

        return {
            "status": "imported",
            "examiner": bundle_examiner,
            "findings": len(bundle.get("findings", [])),
            "timeline": len(bundle.get("timeline", [])),
            "todos": len(bundle.get("todos", [])),
            "approvals": len(bundle.get("approvals", [])),
        }

    def ingest_remote_audit(self, source: str, mcp_name: str, since: str = "") -> dict:
        """Pull audit entries from a remote MCP into local audit.

        Args:
            source: File path to a JSONL file.
            mcp_name: MCP name for the audit file (e.g., 'wintools-mcp').
            since: ISO timestamp — only ingest entries after this time.
        """
        case_dir = self._require_active_case()

        # Validate mcp_name — no path traversal
        if not mcp_name or ".." in mcp_name or "/" in mcp_name or "\\" in mcp_name:
            return {"status": "error", "message": f"Invalid mcp_name: {mcp_name!r}"}

        # Read entries from file source
        source_path = Path(source).resolve()
        if not source_path.exists():
            return {"status": "error", "message": f"Source not found: {source}"}

        # Validate source is within case directory
        try:
            source_path.relative_to(case_dir.resolve())
        except ValueError:
            return {"status": "error", "message": "Source path must be within case directory"}

        entries = []
        for line in source_path.read_text().strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Corrupt JSONL line in %s", source_path)
                continue

            # Filter by since
            if since and entry.get("ts", "") <= since:
                continue

            # Validate required fields
            required = {"ts", "tool"}
            if not required.issubset(entry.keys()):
                continue

            entries.append(entry)

        if not entries:
            return {"status": "ok", "ingested": 0}

        # Append to examiners/{self}/audit/{mcp_name}.jsonl
        audit_dir = self._examiner_dir(case_dir) / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_file = audit_dir / f"{mcp_name}.jsonl"

        # Read existing entries to deduplicate
        existing_ts = set()
        if audit_file.exists():
            for line in audit_file.read_text().strip().split("\n"):
                if line:
                    try:
                        existing_ts.add(json.loads(line).get("ts", ""))
                    except json.JSONDecodeError:
                        logger.warning("Corrupt JSONL line in %s", audit_file)

        new_entries = [e for e in entries if e.get("ts", "") not in existing_ts]

        with open(audit_file, "a", encoding="utf-8") as f:
            for entry in new_entries:
                f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return {"status": "ok", "ingested": len(new_entries), "skipped_duplicates": len(entries) - len(new_entries)}

    def get_team_status(self) -> dict:
        """Per-examiner summary of contributions."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        exam = self.examiner

        result: dict[str, Any] = {
            "case_id": meta["case_id"],
            "local_examiner": exam,
            "examiners": {},
        }

        examiners_root = case_dir / "examiners"
        if examiners_root.is_dir():
            for ex_dir in sorted(examiners_root.iterdir()):
                if not ex_dir.is_dir() or ex_dir.name.startswith("."):
                    continue
                ex_name = ex_dir.name
                findings = self._load_json_file(ex_dir / "findings.json", [])
                timeline = self._load_json_file(ex_dir / "timeline.json", [])
                todos = self._load_json_file(ex_dir / "todos.json", [])
                result["examiners"][ex_name] = {
                    "source": "local" if ex_name == exam else "team",
                    "findings": len(findings),
                    "timeline": len(timeline),
                    "todos_open": sum(1 for t in todos if t.get("status") == "open"),
                }

        return result

    # --- Report Generation ---

    def _extract_iocs(self, findings: list[dict]) -> dict[str, list[str]]:
        """Aggregate IOCs from approved findings into {type: [values]}."""
        iocs: dict[str, list[str]] = {}
        for f in findings:
            for ioc in f.get("iocs", []):
                ioc_type = ioc.get("type", "unknown")
                ioc_value = ioc.get("value", "")
                if ioc_value:
                    iocs.setdefault(ioc_type, [])
                    if ioc_value not in iocs[ioc_type]:
                        iocs[ioc_type].append(ioc_value)
        return iocs

    def _build_mitre_mapping(self, findings: list[dict]) -> list[dict]:
        """Aggregate MITRE techniques with finding cross-refs."""
        techniques: dict[str, dict] = {}
        for f in findings:
            for tech in f.get("mitre_techniques", []):
                tid = tech.get("id", tech) if isinstance(tech, dict) else tech
                name = tech.get("name", "") if isinstance(tech, dict) else ""
                if tid not in techniques:
                    techniques[tid] = {"id": tid, "name": name, "finding_refs": []}
                techniques[tid]["finding_refs"].append(f["id"])
        return list(techniques.values())

    def _report_envelope(self, report_data: dict, report_stub: str, report_type: str) -> dict:
        """Wrap report with Zeltser guidance and next steps."""
        zeltser_map = {
            "full": ["ir_get_template", "ir_get_guidelines", "ir_load_context", "ir_review_report"],
            "executive_summary": ["ir_get_guidelines", "ir_load_context", "ir_review_report"],
            "timeline": ["ir_get_guidelines"],
            "ioc": [],
            "findings": ["ir_get_guidelines", "ir_review_report"],
            "status_brief": ["ir_get_guidelines"],
        }
        zeltser_tools = zeltser_map.get(report_type, [])

        next_steps = []
        if zeltser_tools:
            next_steps.append("Use the Zeltser IR Writing MCP to refine this report:")
            for tool in zeltser_tools:
                if tool == "ir_get_template":
                    next_steps.append(f"  1. Call {tool}() to get the IR report template structure")
                elif tool == "ir_get_guidelines":
                    next_steps.append(f"  2. Call {tool}() for writing style and content guidelines")
                elif tool == "ir_load_context":
                    next_steps.append(f"  3. Call {tool}() with the report_data to load case context")
                elif tool == "ir_review_report":
                    next_steps.append(f"  4. After writing narrative sections, call {tool}() for quality review")
            next_steps.append("  5. Call save_report() to persist the final report")
        else:
            next_steps.append("This is a structural report — ready for save_report() or direct use")

        result = {
            "report_type": report_type,
            "report_data": report_data,
            "report_stub": report_stub,
            "next_steps": next_steps,
        }
        if zeltser_tools:
            result["zeltser_tools_needed"] = zeltser_tools
        return result

    def generate_full_report(self) -> dict:
        """Complete IR report from all approved data."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        findings = [f for f in self._load_all_findings(case_dir) if f.get("status") == "APPROVED"]
        timeline = [t for t in self._load_all_timeline(case_dir) if t.get("status") == "APPROVED"]
        evidence = self._load_evidence_registry(case_dir)
        todos = self._load_all_todos(case_dir)
        iocs = self._extract_iocs(findings)
        mitre = self._build_mitre_mapping(findings)

        # Load actions from this examiner
        exam_dir = self._examiner_dir(case_dir)
        actions = []
        actions_file = exam_dir / "actions.jsonl"
        if actions_file.exists():
            for line in actions_file.read_text().strip().split("\n"):
                if line:
                    try:
                        actions.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning("Corrupt JSONL line in %s", actions_file)

        report_data = {
            "case": {
                "case_id": meta.get("case_id", ""),
                "name": meta.get("name", ""),
                "status": meta.get("status", ""),
                "examiner": meta.get("examiner", ""),
                "team": meta.get("team", []),
                "created": meta.get("created", ""),
            },
            "findings": findings,
            "timeline": timeline,
            "iocs": iocs,
            "mitre_mapping": mitre,
            "evidence": evidence.get("files", []),
            "actions": actions,
            "todos": [t for t in todos if t.get("status") == "open"],
        }

        # Build stub
        stub_lines = [
            f"# Incident Response Report — {meta.get('case_id', '')}",
            f"**Case:** {meta.get('name', '')}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            f"**Examiner(s):** {', '.join(meta.get('team', []))}",
            "",
            "## Executive Summary",
            "",
            "[PLACEHOLDER: Write a non-technical summary of the incident, key findings, and recommendations]",
            "",
            "## Timeline of Events",
            "",
            "| Timestamp | Event | Source | Evidence | Confidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for t in timeline:
            evidence_str = ", ".join(t.get("evidence_ids", []))
            stub_lines.append(
                f"| {t.get('timestamp', '')} | {t.get('description', '')} | "
                f"{t.get('source', '')} | {evidence_str} | {t.get('confidence', '')} |"
            )
        stub_lines.extend([
            "",
            "## Findings",
            "",
        ])
        for f in findings:
            evidence_str = ", ".join(f.get("evidence_ids", []))
            stub_lines.extend([
                f"### {f['id']}: {f.get('title', 'Untitled')}",
                f"**Confidence:** {f.get('confidence', '')} — {f.get('confidence_justification', '')}",
                f"**Evidence:** {evidence_str}",
                f"**Observation:** {f.get('observation', '')}",
                f"**Interpretation:** {f.get('interpretation', '')}",
                "",
            ])
        if iocs:
            stub_lines.extend(["## Indicators of Compromise", ""])
            stub_lines.append("| Type | Value | Finding |")
            stub_lines.append("| --- | --- | --- |")
            for ioc_type, values in iocs.items():
                for v in values:
                    stub_lines.append(f"| {ioc_type} | {v} | |")
            stub_lines.append("")
        if mitre:
            stub_lines.extend(["## MITRE ATT&CK Mapping", ""])
            stub_lines.append("| Technique | Name | Findings |")
            stub_lines.append("| --- | --- | --- |")
            for m in mitre:
                refs = ", ".join(m["finding_refs"])
                stub_lines.append(f"| {m['id']} | {m['name']} | {refs} |")
            stub_lines.append("")
        stub_lines.extend([
            "## Recommendations",
            "",
            "[PLACEHOLDER: Remediation steps, containment actions, lessons learned]",
            "",
        ])

        return self._report_envelope(report_data, "\n".join(stub_lines), "full")

    def generate_executive_summary(self) -> dict:
        """Non-technical management briefing from approved data."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        all_findings = self._load_all_findings(case_dir)
        approved = [f for f in all_findings if f.get("status") == "APPROVED"]
        timeline = [t for t in self._load_all_timeline(case_dir) if t.get("status") == "APPROVED"]
        iocs = self._extract_iocs(approved)

        confidence_breakdown = {}
        for f in approved:
            conf = f.get("confidence", "UNSPECIFIED")
            confidence_breakdown[conf] = confidence_breakdown.get(conf, 0) + 1

        timeline_range = {}
        if timeline:
            timestamps = [t.get("timestamp", "") for t in timeline if t.get("timestamp")]
            if timestamps:
                timeline_range = {"earliest": min(timestamps), "latest": max(timestamps)}

        report_data = {
            "case": {
                "case_id": meta.get("case_id", ""),
                "name": meta.get("name", ""),
                "status": meta.get("status", ""),
            },
            "findings_count": len(approved),
            "confidence_breakdown": confidence_breakdown,
            "timeline_range": timeline_range,
            "timeline_event_count": len(timeline),
            "ioc_summary": {k: len(v) for k, v in iocs.items()},
            "total_iocs": sum(len(v) for v in iocs.values()),
            "key_findings": [{"id": f["id"], "title": f.get("title", ""), "confidence": f.get("confidence", "")} for f in approved],
        }

        stub_lines = [
            f"# Executive Summary — {meta.get('case_id', '')}",
            f"**Case:** {meta.get('name', '')}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "",
            "## Incident Overview",
            "",
            f"[PLACEHOLDER: Non-technical summary. {len(approved)} approved finding(s), "
            f"{len(timeline)} timeline event(s)",
        ]
        if timeline_range:
            stub_lines[-1] += f", spanning {timeline_range.get('earliest', '?')} to {timeline_range.get('latest', '?')}"
        ioc_total = sum(len(v) for v in iocs.values())
        if ioc_total:
            stub_lines[-1] += f", {ioc_total} IOC(s)"
        stub_lines[-1] += "]"
        stub_lines.extend([
            "",
            "## Key Findings",
            "",
        ])
        for f in approved:
            stub_lines.append(f"- **{f['id']}:** {f.get('title', '')} (Confidence: {f.get('confidence', '')})")
        stub_lines.extend([
            "",
            "## Business Impact",
            "",
            "[PLACEHOLDER: Impact assessment, affected systems, data exposure]",
            "",
            "## Recommendations",
            "",
            "[PLACEHOLDER: Priority actions for management decision]",
            "",
        ])

        return self._report_envelope(report_data, "\n".join(stub_lines), "executive_summary")

    def generate_timeline_report(self, start_date: str = "", end_date: str = "") -> dict:
        """Filtered or complete approved timeline report."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        timeline = [t for t in self._load_all_timeline(case_dir) if t.get("status") == "APPROVED"]

        if start_date:
            timeline = [t for t in timeline if t.get("timestamp", "") >= start_date]
        if end_date:
            timeline = [t for t in timeline if t.get("timestamp", "") <= end_date]

        report_data = {
            "case_id": meta.get("case_id", ""),
            "start_date": start_date or (timeline[0]["timestamp"] if timeline else ""),
            "end_date": end_date or (timeline[-1]["timestamp"] if timeline else ""),
            "event_count": len(timeline),
            "events": timeline,
        }

        date_header = ""
        if start_date or end_date:
            date_header = f" ({start_date or 'start'} to {end_date or 'end'})"

        stub_lines = [
            f"# Timeline Report — {meta.get('case_id', '')}{date_header}",
            "",
            "| Timestamp | Event | Source | Evidence | Confidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for t in timeline:
            evidence_str = ", ".join(t.get("evidence_ids", []))
            stub_lines.append(
                f"| {t.get('timestamp', '')} | {t.get('description', '')} | "
                f"{t.get('source', '')} | {evidence_str} | {t.get('confidence', '')} |"
            )
        stub_lines.extend([
            "",
            "## Timeline Narrative",
            "",
            "[PLACEHOLDER: Narrative analysis of the event sequence]",
            "",
        ])

        return self._report_envelope(report_data, "\n".join(stub_lines), "timeline")

    def generate_ioc_report(self) -> dict:
        """IOCs + MITRE for sharing/blocking. Structural output."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        findings = [f for f in self._load_all_findings(case_dir) if f.get("status") == "APPROVED"]
        iocs = self._extract_iocs(findings)
        mitre = self._build_mitre_mapping(findings)

        # Build IOC list with finding context
        ioc_list = []
        for f in findings:
            for ioc in f.get("iocs", []):
                ioc_list.append({
                    "type": ioc.get("type", ""),
                    "value": ioc.get("value", ""),
                    "finding_id": f["id"],
                    "finding_title": f.get("title", ""),
                })

        report_data = {
            "case_id": meta.get("case_id", ""),
            "iocs_by_type": iocs,
            "ioc_list": ioc_list,
            "total_iocs": sum(len(v) for v in iocs.values()),
            "mitre_mapping": mitre,
        }

        stub_lines = [
            f"# IOC Report — {meta.get('case_id', '')}",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Indicators of Compromise",
            "",
            "| Type | Value | Finding | Context |",
            "| --- | --- | --- | --- |",
        ]
        for item in ioc_list:
            stub_lines.append(f"| {item['type']} | {item['value']} | {item['finding_id']} | {item['finding_title']} |")
        if mitre:
            stub_lines.extend([
                "",
                "## MITRE ATT&CK Mapping",
                "",
                "| Technique | Name | Findings |",
                "| --- | --- | --- |",
            ])
            for m in mitre:
                refs = ", ".join(m["finding_refs"])
                stub_lines.append(f"| {m['id']} | {m['name']} | {refs} |")
        stub_lines.extend([
            "",
            "## Sharing Notes",
            "",
            "[PLACEHOLDER: TLP classification, sharing restrictions, recommended actions]",
            "",
        ])

        return self._report_envelope(report_data, "\n".join(stub_lines), "ioc")

    def generate_findings_report(self, finding_ids: list[str] | None = None) -> dict:
        """Specific findings in detail. Defaults to all approved."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        all_findings = [f for f in self._load_all_findings(case_dir) if f.get("status") == "APPROVED"]

        if finding_ids:
            findings = [f for f in all_findings if f["id"] in finding_ids or f["id"].split("/")[-1] in finding_ids]
        else:
            findings = all_findings

        report_data = {
            "case_id": meta.get("case_id", ""),
            "findings_count": len(findings),
            "findings": findings,
        }

        stub_lines = [
            f"# Findings Report — {meta.get('case_id', '')}",
            f"**Findings:** {len(findings)}",
            "",
        ]
        for f in findings:
            evidence_str = ", ".join(f.get("evidence_ids", []))
            iocs = f.get("iocs", [])
            mitre = f.get("mitre_techniques", [])
            stub_lines.extend([
                f"## {f['id']}: {f.get('title', 'Untitled')}",
                "",
                f"**Type:** {f.get('type', '')}",
                f"**Confidence:** {f.get('confidence', '')}",
                f"**Confidence Justification:** {f.get('confidence_justification', '')}",
                f"**Evidence:** {evidence_str}",
                f"**Examiner:** {f.get('examiner', '')}",
                f"**Approved by:** {f.get('approved_by', '')} at {f.get('approved_at', '')}",
                "",
                "### Observation",
                f"{f.get('observation', '')}",
                "",
                "### Interpretation",
                f"{f.get('interpretation', '')}",
                "",
            ])
            if iocs:
                stub_lines.append("### IOCs")
                for ioc in iocs:
                    stub_lines.append(f"- {ioc.get('type', '')}: {ioc.get('value', '')}")
                stub_lines.append("")
            if mitre:
                stub_lines.append("### MITRE Techniques")
                for t in mitre:
                    if isinstance(t, dict):
                        stub_lines.append(f"- {t.get('id', '')}: {t.get('name', '')}")
                    else:
                        stub_lines.append(f"- {t}")
                stub_lines.append("")
            stub_lines.append("---")
            stub_lines.append("")

        return self._report_envelope(report_data, "\n".join(stub_lines), "findings")

    def generate_status_brief(self) -> dict:
        """Quick overview for standups/handoffs."""
        case_dir = self._require_active_case()
        meta = self._load_case_meta(case_dir)
        findings = self._load_all_findings(case_dir)
        timeline = self._load_all_timeline(case_dir)
        todos = self._load_all_todos(case_dir)
        evidence = self._load_evidence_registry(case_dir)

        approved_findings = [f for f in findings if f.get("status") == "APPROVED"]
        open_todos = [t for t in todos if t.get("status") == "open"]

        report_data = {
            "case": {
                "case_id": meta.get("case_id", ""),
                "name": meta.get("name", ""),
                "status": meta.get("status", ""),
                "team": meta.get("team", []),
            },
            "counts": {
                "findings_total": len(findings),
                "findings_draft": sum(1 for f in findings if f.get("status") == "DRAFT"),
                "findings_approved": len(approved_findings),
                "findings_rejected": sum(1 for f in findings if f.get("status") == "REJECTED"),
                "timeline_events": len(timeline),
                "evidence_files": len(evidence.get("files", [])),
                "todos_open": len(open_todos),
                "todos_total": len(todos),
            },
            "key_findings": [{"id": f["id"], "title": f.get("title", "")} for f in approved_findings[:10]],
            "open_todos": [{"id": t["todo_id"], "description": t["description"], "priority": t.get("priority", "")} for t in open_todos],
        }

        stub_lines = [
            f"# Status Brief — {meta.get('case_id', '')}",
            f"**Case:** {meta.get('name', '')}",
            f"**Status:** {meta.get('status', '')}",
            f"**Team:** {', '.join(meta.get('team', []))}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Counts",
            f"- Findings: {len(findings)} total ({len(approved_findings)} approved, "
            f"{sum(1 for f in findings if f.get('status') == 'DRAFT')} draft)",
            f"- Timeline events: {len(timeline)}",
            f"- Evidence files: {len(evidence.get('files', []))}",
            f"- TODOs: {len(open_todos)} open / {len(todos)} total",
            "",
        ]
        if approved_findings:
            stub_lines.append("## Key Findings")
            for f in approved_findings[:10]:
                stub_lines.append(f"- {f['id']}: {f.get('title', '')}")
            stub_lines.append("")
        if open_todos:
            stub_lines.append("## Open TODOs")
            for t in open_todos:
                stub_lines.append(f"- [{t.get('priority', 'medium')}] {t['description']}")
            stub_lines.append("")
        stub_lines.extend([
            "## Next Steps",
            "",
            "[PLACEHOLDER: Priorities for next working period]",
            "",
        ])

        return self._report_envelope(report_data, "\n".join(stub_lines), "status_brief")

    def save_report(self, filename: str, content: str, report_type: str = "") -> dict:
        """Persist report to {case_dir}/reports/ via atomic write."""
        case_dir = self._require_active_case()

        # Sanitize filename — alphanumeric, hyphens, underscores, dots only
        sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        if not sanitized:
            raise ValueError("Invalid filename")
        # Block path traversal
        if ".." in sanitized or "/" in sanitized or "\\" in sanitized:
            raise ValueError("Path traversal not allowed in filename")

        reports_dir = case_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / sanitized

        _atomic_write(report_path, content)

        # Log to evidence access
        self._log_evidence_access(case_dir, "save_report", str(report_path), report_type)

        return {
            "status": "saved",
            "path": str(report_path),
            "filename": sanitized,
            "report_type": report_type,
            "characters": len(content),
        }

    # --- Grounding Score ---

    # MCP audit files that count as grounding sources
    _GROUNDING_MCPS = ("forensic-rag-mcp", "windows-triage-mcp", "opencti-mcp")

    def _score_grounding(self, finding: dict) -> dict:
        """Score how well a finding is grounded by external reference MCPs.

        Scans this examiner's audit directory for evidence of forensic-rag-mcp,
        windows-triage-mcp, and opencti-mcp usage. Returns WEAK/PARTIAL/STRONG
        with suggestions for unconsulted sources.

        Returns empty dict when STRONG (2+ sources consulted).
        """
        case_dir = self.active_case_dir
        if case_dir is None or not case_dir.exists():
            return {}

        audit_dir = self._examiner_dir(case_dir) / "audit"
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
                                suggestions.append(f"{check_text} — {reason}" if reason else check_text)
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
        with open(case_dir / "CASE.yaml") as f:
            return yaml.safe_load(f) or {}

    # --- Local store I/O (this examiner only) ---

    def _load_findings(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(self._examiner_dir(case_dir) / "findings.json", [])

    def _save_findings(self, case_dir: Path, findings: list[dict]) -> None:
        exam_dir = self._examiner_dir(case_dir)
        exam_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(exam_dir / "findings.json", json.dumps(findings, indent=2, default=str))

    def _load_timeline(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(self._examiner_dir(case_dir) / "timeline.json", [])

    def _save_timeline(self, case_dir: Path, timeline: list[dict]) -> None:
        exam_dir = self._examiner_dir(case_dir)
        exam_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(exam_dir / "timeline.json", json.dumps(timeline, indent=2, default=str))

    def _load_todos(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(self._examiner_dir(case_dir) / "todos.json", [])

    def _save_todos(self, case_dir: Path, todos: list[dict]) -> None:
        exam_dir = self._examiner_dir(case_dir)
        exam_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(exam_dir / "todos.json", json.dumps(todos, indent=2, default=str))

    def _load_evidence_registry(self, case_dir: Path) -> dict:
        return self._load_json_file(self._examiner_dir(case_dir) / "evidence.json", {"files": []})

    def _save_evidence_registry(self, case_dir: Path, registry: dict) -> None:
        exam_dir = self._examiner_dir(case_dir)
        exam_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(exam_dir / "evidence.json", json.dumps(registry, indent=2, default=str))

    def _log_evidence_access(self, case_dir: Path, action: str, path: str, detail: str = "") -> None:
        exam_dir = self._examiner_dir(case_dir)
        exam_dir.mkdir(parents=True, exist_ok=True)
        log_file = exam_dir / "evidence_access.jsonl"
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "path": path,
            "detail": detail,
            "examiner": self.examiner,
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    # --- Merged reads (all examiners) ---

    def _load_all_findings(self, case_dir: Path) -> list[dict]:
        """Load findings from all examiners/*/, with scoped IDs."""
        findings = []
        examiners_root = case_dir / "examiners"
        if not examiners_root.is_dir():
            return findings
        for ex_dir in sorted(examiners_root.iterdir()):
            if not ex_dir.is_dir() or ex_dir.name.startswith("."):
                continue
            exam = ex_dir.name
            ex_findings = self._load_json_file(ex_dir / "findings.json", [])
            for f in ex_findings:
                f.setdefault("examiner", exam)
                if "/" not in f.get("id", ""):
                    f["id"] = f"{exam}/{f['id']}"
            findings.extend(ex_findings)
        return findings

    def _load_all_timeline(self, case_dir: Path) -> list[dict]:
        """Load timeline from all examiners/*/, sorted chronologically."""
        timeline = []
        examiners_root = case_dir / "examiners"
        if not examiners_root.is_dir():
            return timeline
        for ex_dir in sorted(examiners_root.iterdir()):
            if not ex_dir.is_dir() or ex_dir.name.startswith("."):
                continue
            exam = ex_dir.name
            ex_timeline = self._load_json_file(ex_dir / "timeline.json", [])
            for t in ex_timeline:
                t.setdefault("examiner", exam)
                if "/" not in t.get("id", ""):
                    t["id"] = f"{exam}/{t['id']}"
            timeline.extend(ex_timeline)
        timeline.sort(key=lambda t: t.get("timestamp", ""))
        return timeline

    def _load_all_todos(self, case_dir: Path) -> list[dict]:
        """Load TODOs from all examiners/*/."""
        todos = []
        examiners_root = case_dir / "examiners"
        if not examiners_root.is_dir():
            return todos
        for ex_dir in sorted(examiners_root.iterdir()):
            if not ex_dir.is_dir() or ex_dir.name.startswith("."):
                continue
            exam = ex_dir.name
            ex_todos = self._load_json_file(ex_dir / "todos.json", [])
            for t in ex_todos:
                t.setdefault("examiner", exam)
                if "/" not in t.get("todo_id", ""):
                    t["todo_id"] = f"{exam}/{t['todo_id']}"
            todos.extend(ex_todos)
        return todos

    # --- Audit helpers ---

    def _read_audit_dir(self, audit_dir: Path, mcp: str | None, tool_filter: str | None) -> list[dict]:
        """Read JSONL files from an audit directory."""
        entries = []
        if not audit_dir.is_dir():
            return entries
        for jsonl_file in audit_dir.glob("*.jsonl"):
            for line in jsonl_file.read_text().strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Corrupt JSONL line in %s", jsonl_file)
                    continue
                if mcp and entry.get("mcp") != mcp:
                    continue
                if tool_filter and entry.get("tool") != tool_filter:
                    continue
                entries.append(entry)
        return entries

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
