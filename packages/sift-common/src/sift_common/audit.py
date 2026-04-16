"""Audit trail writer for Valhuntir MCP servers.

Each MCP writes to its own JSONL file in the case audit directory.
Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _sanitize_slug(raw: str) -> str:
    """Sanitize a raw string into a valid examiner slug.

    Lowercases, replaces invalid characters with hyphens, strips leading/trailing
    hyphens, and truncates to 20 characters.
    """
    slug = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")
    if len(slug) > 20:
        logger.warning(
            "Examiner slug truncated from %d to 20 chars: %s", len(slug), slug[:20]
        )
        slug = slug[:20]
    if not slug:
        return "unknown"
    slug = slug.lstrip("-")
    return slug if slug else "unknown"


def resolve_examiner() -> str:
    """Resolve examiner identity: VHIR_EXAMINER > VHIR_ANALYST > OS username.

    The result is validated against the slug pattern ^[a-z0-9][a-z0-9-]{0,19}$.
    """
    examiner = os.environ.get("VHIR_EXAMINER") or os.environ.get("VHIR_ANALYST")
    if not examiner:
        try:
            examiner = getpass.getuser()
        except Exception:
            examiner = "unknown"
    return _sanitize_slug(examiner)


class AuditWriter:
    """Writes audit entries to a per-MCP JSONL file.

    Thread-safe: sequence counter protected by lock,
    file writes wrapped in try/except with fsync for durability.
    """

    def __init__(self, mcp_name: str, audit_dir: str | None = None) -> None:
        self.mcp_name = mcp_name
        self._explicit_audit_dir = audit_dir
        self._sequence = 0
        self._date_str = ""
        self._lock = threading.Lock()
        self._cached_case_id: str = ""

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_audit_dir(self) -> Path | None:
        """Get the audit directory.

        Priority: explicit audit_dir > VHIR_AUDIT_DIR > VHIR_CASE_DIR/audit/.
        """
        if self._explicit_audit_dir:
            audit_dir = Path(self._explicit_audit_dir)
        elif os.environ.get("VHIR_AUDIT_DIR"):
            audit_dir = Path(os.environ["VHIR_AUDIT_DIR"])
        else:
            case_dir = os.environ.get("VHIR_CASE_DIR", "").strip()
            # Validate: must be a directory with CASE.yaml
            if case_dir:
                path = Path(case_dir)
                if path.is_dir() and (path / "CASE.yaml").exists():
                    audit_dir = path / "audit"
                else:
                    case_dir = ""  # set-but-wrong, try active_case
            if not case_dir:
                # Fallback: read active case pointer file
                try:
                    case_dir = (
                        (Path.home() / ".vhir" / "active_case").read_text().strip()
                    )
                except OSError:
                    return None
                if not case_dir:
                    return None
                path = Path(case_dir)
                if not path.is_dir() or not (path / "CASE.yaml").exists():
                    logger.warning(
                        "VHIR_CASE_DIR=%s is not a case directory, skipping audit",
                        case_dir,
                    )
                    return None
                audit_dir = path / "audit"
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Cannot create audit directory %s: %s", audit_dir, e)
            return None
        return audit_dir

    def _next_audit_id(self) -> str:
        """Generate next audit ID: {prefix}-{examiner}-{date}-{seq}."""
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        with self._lock:
            if today != self._date_str:
                self._date_str = today
                self._sequence = self._resume_sequence(today)
            self._sequence += 1
            seq = self._sequence
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        return f"{prefix}-{self.examiner}-{today}-{seq:03d}"

    def _resume_sequence(self, date_str: str) -> int:
        """Resume sequence from sidecar file, falling back to JSONL scan.

        Prevents duplicate audit IDs after server restart.
        Must be called under self._lock.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return 0

        # Try sidecar first (O(1) read)
        seq_file = audit_dir / f"{self.mcp_name}.seq"
        try:
            if seq_file.exists():
                data = json.loads(seq_file.read_text())
                if data.get("date") == date_str:
                    return data.get("seq", 0)
        except (json.JSONDecodeError, OSError):
            pass

        # Fallback: scan JSONL (O(n) — only on first startup or date change)
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_file.exists():
            return 0
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        pattern = f"{prefix}-{self.examiner}-{date_str}-"
        max_seq = 0
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or date_str not in line:
                        continue
                    try:
                        entry = json.loads(line)
                        eid = entry.get("audit_id", "")
                        if eid.startswith(pattern):
                            try:
                                seq = int(eid[len(pattern) :])
                                max_seq = max(max_seq, seq)
                            except ValueError:
                                pass
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            logger.warning(
                "Failed to read audit log %s for sequence resume: %s", log_file, e
            )
        return max_seq

    def _write_seq_sidecar(self) -> None:
        """Write current sequence to sidecar for fast resume."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return
        seq_file = audit_dir / f"{self.mcp_name}.seq"
        try:
            seq_file.write_text(
                json.dumps({"date": self._date_str, "seq": self._sequence})
            )
        except OSError:
            pass

    def _read_active_case_id(self) -> str:
        """Read case_id from ~/.vhir/active_case file, cached."""
        if self._cached_case_id:
            return self._cached_case_id
        try:
            raw = (Path.home() / ".vhir" / "active_case").read_text().strip()
            if raw:
                self._cached_case_id = Path(raw).name
        except OSError:
            pass
        return self._cached_case_id

    def log(
        self,
        tool: str,
        params: dict[str, Any],
        result_summary: Any,
        source: str = "mcp_server",
        audit_id: str | None = None,
        case_id: str | None = None,
        elapsed_ms: float | None = None,
        input_files: list[str] | None = None,
        input_sha256s: list[str] | None = None,
        input_detection_method: str = "",
        source_evidence: str = "",
        extra: dict[str, Any] | None = None,
    ) -> str | None:
        """Write an audit entry. Returns the audit_id, or None when no case is active."""
        if not self._get_audit_dir():
            return None
        if audit_id is None:
            audit_id = self._next_audit_id()

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "mcp": self.mcp_name,
            "tool": tool,
            "audit_id": audit_id,
            "examiner": self.examiner,
            "case_id": case_id
            or os.environ.get("VHIR_ACTIVE_CASE", "")
            or self._read_active_case_id(),
            "source": source,
            "params": params,
            "result_summary": _summarize(result_summary),
        }
        if elapsed_ms is not None:
            entry["elapsed_ms"] = round(elapsed_ms, 1)
        if input_files:
            entry["input_files"] = input_files
            entry["input_sha256s"] = input_sha256s or []
        if input_detection_method:
            entry["input_detection_method"] = input_detection_method
        if source_evidence:
            entry["source_evidence"] = source_evidence
        if extra:
            entry.update(extra)

        if not self._write_entry(entry):
            logger.warning(
                "Audit write failed for audit_id=%s — returning None",
                audit_id,
            )
            return None
        self._write_seq_sidecar()
        return audit_id

    def _write_entry(self, entry: dict) -> bool:
        """Write a single audit entry to the JSONL file with fsync.

        Returns True if the entry was written or no case is active (normal skip).
        Returns False only on actual write errors.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            logger.debug(
                "No active case, audit entry not written: %s/%s",
                self.mcp_name,
                entry.get("tool"),
            )
            return True
        try:
            log_file = audit_dir / f"{self.mcp_name}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return True
        except OSError as e:
            logger.warning(
                "Failed to write audit entry for audit_id=%s tool=%s: %s "
                "(this audit_id was NOT recorded to the audit trail)",
                entry.get("audit_id"),
                entry.get("tool"),
                e,
            )
            return False

    def get_entries(
        self, since: str | None = None, case_id: str | None = None
    ) -> list[dict]:
        """Read back audit entries, optionally filtered."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return []
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_file.exists():
            return []
        entries = []
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Corrupt JSONL line in %s", log_file)
                        continue
                    if since and entry.get("ts", "") < since:
                        continue
                    if case_id and entry.get("case_id", "") != case_id:
                        continue
                    entries.append(entry)
        except OSError as e:
            logger.warning("Failed to read audit entries from %s: %s", log_file, e)
        return entries

    def reset_counter(self) -> None:
        """Reset the audit ID counter. For testing only."""
        with self._lock:
            self._sequence = 0
            self._date_str = ""
        # Remove sidecar so _resume_sequence starts fresh
        audit_dir = self._get_audit_dir()
        if audit_dir:
            seq_file = audit_dir / f"{self.mcp_name}.seq"
            seq_file.unlink(missing_ok=True)


def _summarize(result: Any) -> Any:
    """Truncate large results for audit log."""
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
