"""Audit trail writer for AIIR MCP servers.

Each MCP writes to its own JSONL file in the case audit directory.
Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def resolve_examiner() -> str:
    """Resolve examiner identity: AIIR_EXAMINER > AIIR_ANALYST > OS username."""
    examiner = os.environ.get("AIIR_EXAMINER") or os.environ.get("AIIR_ANALYST")
    if not examiner:
        try:
            examiner = getpass.getuser()
        except Exception:
            examiner = "unknown"
    return examiner.lower()


class AuditWriter:
    """Writes audit entries to a per-MCP JSONL file.

    Thread-safe: sequence counter protected by lock,
    file writes wrapped in try/except with fsync for durability.
    """

    def __init__(self, mcp_name: str) -> None:
        self.mcp_name = mcp_name
        self._sequence = 0
        self._date_str = ""
        self._lock = threading.Lock()

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_audit_dir(self) -> Path | None:
        """Get the audit directory from AIIR_CASE_DIR env var."""
        case_dir = os.environ.get("AIIR_CASE_DIR")
        if not case_dir:
            return None
        path = Path(case_dir)
        if not path.is_dir():
            logger.warning("AIIR_CASE_DIR=%s is not a directory, skipping audit", case_dir)
            return None
        audit_dir = path / "examiners" / self.examiner / "audit"
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Cannot create audit directory %s: %s", audit_dir, e)
            return None
        return audit_dir

    def _next_evidence_id(self) -> str:
        """Generate next evidence ID: {prefix}-{examiner}-{date}-{seq}."""
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
        """Scan existing audit JSONL for highest sequence on this date.

        Prevents duplicate evidence IDs after server restart.
        Must be called under self._lock.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return 0
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_file.exists():
            return 0
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        pattern = f"{prefix}-{self.examiner}-{date_str}-"
        max_seq = 0
        try:
            for line in log_file.read_text().strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    eid = entry.get("evidence_id", "")
                    if eid.startswith(pattern):
                        try:
                            seq = int(eid[len(pattern):])
                            max_seq = max(max_seq, seq)
                        except ValueError:
                            pass
                except json.JSONDecodeError:
                    continue
        except OSError as e:
            logger.warning("Failed to read audit log %s for sequence resume: %s", log_file, e)
        return max_seq

    def log(
        self,
        tool: str,
        params: dict[str, Any],
        result_summary: Any,
        source: str = "mcp_server",
        evidence_id: str | None = None,
        case_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> str:
        """Write an audit entry. Returns the evidence_id."""
        if evidence_id is None:
            evidence_id = self._next_evidence_id()

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "mcp": self.mcp_name,
            "tool": tool,
            "evidence_id": evidence_id,
            "examiner": self.examiner,
            "case_id": case_id or os.environ.get("AIIR_ACTIVE_CASE", ""),
            "source": source,
            "params": params,
            "result_summary": _summarize(result_summary),
        }
        if elapsed_ms is not None:
            entry["elapsed_ms"] = round(elapsed_ms, 1)

        self._write_entry(entry)
        return evidence_id

    def _write_entry(self, entry: dict) -> bool:
        """Write a single audit entry to the JSONL file with fsync.

        Returns True if the entry was written successfully, False otherwise.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            logger.debug(
                "No AIIR_CASE_DIR set, audit entry not written: %s/%s",
                self.mcp_name,
                entry.get("tool"),
            )
            return False
        try:
            log_file = audit_dir / f"{self.mcp_name}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return True
        except OSError as e:
            logger.warning(
                "Failed to write audit entry for evidence_id=%s tool=%s: %s "
                "(this evidence_id was NOT recorded to the audit trail)",
                entry.get("evidence_id"), entry.get("tool"), e,
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
            with open(log_file, "r", encoding="utf-8") as f:
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
        """Reset the evidence ID counter. For testing only."""
        with self._lock:
            self._sequence = 0
            self._date_str = ""


def _summarize(result: Any) -> Any:
    """Truncate large results for audit log."""
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
