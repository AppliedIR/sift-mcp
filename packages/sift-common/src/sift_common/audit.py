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
import time
from collections.abc import Callable
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

    Ids need no counter or lock: each ends in a ULID. File writes are wrapped
    in try/except with fsync for durability.
    """

    def __init__(
        self,
        mcp_name: str,
        audit_dir: str | None = None,
        case_dir_resolver: Callable[[], Path | str | None] | None = None,
    ) -> None:
        self.mcp_name = mcp_name
        self._explicit_audit_dir = audit_dir
        # A server that resolves its own case passes that resolver, so its
        # audit goes to the case its tools act on. It must have no side effects.
        self._case_dir_resolver = case_dir_resolver

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_audit_dir(self, case_dir: str | Path | None = None) -> Path | None:
        """Get the audit directory.

        Priority: explicit audit_dir > VHIR_AUDIT_DIR > `case_dir` (a case the
        caller resolved already; "" for none; nothing when it's no longer a
        case) > the server's own case
        resolver > VHIR_CASE_DIR/audit/ > the active case pointer.
        """
        if self._explicit_audit_dir:
            audit_dir = Path(self._explicit_audit_dir)
        elif os.environ.get("VHIR_AUDIT_DIR"):
            audit_dir = Path(os.environ["VHIR_AUDIT_DIR"])
        elif case_dir is not None:
            # none, or moved away since it was resolved: never recreated
            if not case_dir or not (Path(case_dir) / "CASE.yaml").is_file():
                return None
            audit_dir = Path(case_dir) / "audit"
        elif self._case_dir_resolver and (resolved := self._case_dir_resolver()):
            audit_dir = Path(resolved) / "audit"
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

    def _next_audit_id(self, audit_dir: Path | None = None) -> str:
        """Generate the next audit ID: {prefix}-{examiner}-{date}-{ulid}.

        The ULID (48-bit milliseconds, 80 random bits) makes the id unique
        without a counter, across processes, cases and installations.
        `audit_dir` is accepted for callers that pass it.
        """
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        return f"{prefix}-{self.examiner}-{today}-{new_ulid()}"

    def _read_active_case_id(self) -> str:
        """Read case_id from ~/.vhir/active_case file.

        Re-reads on every call to handle mid-session case switches.
        The file is ~50 bytes and OS page-cached, so effectively free.
        """
        try:
            raw = (Path.home() / ".vhir" / "active_case").read_text().strip()
            if raw:
                return Path(raw).name
        except OSError:
            pass
        return ""

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
        case_dir: str | Path | None = None,
    ) -> str | None:
        """Write an audit entry. Returns the audit_id, or None when no case is active.

        The directory is resolved once: the id is minted for it (when not
        given) and the entry is written to it, so a case switch can't put one
        case's id into another. `case_dir` is the case the caller resolved
        when its operation started ("" for none): the entry goes there, with
        that case's id.
        """
        audit_dir = self._get_audit_dir(case_dir)
        if not audit_dir:
            return None
        if not case_id and case_dir:
            case_id = _case_id_of(case_dir)
        if audit_id is None:
            audit_id = self._next_audit_id(audit_dir)

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

        if not self._write_entry(entry, audit_dir):
            logger.warning(
                "Audit write failed for audit_id=%s — returning None",
                audit_id,
            )
            return None
        return audit_id

    def _write_entry(self, entry: dict, audit_dir: Path | None = None) -> bool:
        """Write a single audit entry to the JSONL file with fsync.

        Returns True if the entry was written or no case is active (normal skip).
        Returns False only on actual write errors.
        """
        if audit_dir is None:
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
        """Kept for callers' tests: ids no longer use a counter."""


_ULID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"  # Crockford base32, lowercase


def new_ulid() -> str:
    """A 26-character lowercase ULID: 48-bit milliseconds, 80 random bits."""
    n = (time.time_ns() // 1_000_000) << 80 | int.from_bytes(os.urandom(10), "big")
    return "".join(_ULID_ALPHABET[(n >> s) & 31] for s in range(125, -1, -5))


def _case_id_of(case_dir: str | Path) -> str:
    """A case's id: its CASE.yaml case_id, else its folder's name."""
    import yaml

    try:
        meta = yaml.safe_load((Path(case_dir) / "CASE.yaml").read_text())
        if isinstance(meta, dict) and isinstance(meta.get("case_id"), str):
            if meta["case_id"].strip():
                return meta["case_id"].strip()
    except (OSError, ValueError, yaml.YAMLError) as e:
        logger.debug("No case_id in %s/CASE.yaml: %s", case_dir, e)
    return Path(case_dir).name


def _summarize(result: Any) -> Any:
    """Truncate large results for audit log."""
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
