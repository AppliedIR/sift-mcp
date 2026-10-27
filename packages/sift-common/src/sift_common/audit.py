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
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
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


# Why a call's entry was not recorded, as its reply says it (one copy)
_UNRECORDED = {
    "no_case": "not recorded: no case was active for this call",
    "case_gone": "not recorded: {} is no longer a case (no CASE.yaml). "
    "The call itself ran; calling it again repeats it.",
    "write_failed": "Audit write failed — not recorded: {}. "
    "The call itself ran; calling it again repeats it.",
}


@dataclass(frozen=True)
class CaseResolution:
    """Where a call's entries go, taken once: "case" or "audit_dir" (with its
    path), "no_case", "case_gone" (the path) or "write_failed" (the reason)."""

    outcome: str
    path: str = ""
    reason: str = ""


@dataclass(frozen=True)
class AuditOutcome:
    """What became of one entry: "recorded" (its id), "no_case", "case_gone"
    or "write_failed" (detail: the path or the reason)."""

    kind: str = "recorded"
    audit_id: str | None = None
    detail: str = ""

    def note(self, reply: dict) -> dict:
        """Say in `reply` why its call was not recorded: no case under
        `audit`, otherwise after any `warning` it has, joined by " | "."""
        if self.kind == "recorded":
            return reply
        text = _UNRECORDED[self.kind].format(self.detail)
        warning = reply.get("warning") or ""
        if self.kind == "no_case":
            reply["audit"] = text
        elif text not in warning:
            reply["warning"] = f"{warning} | {text}" if warning else text
        return reply


def is_case(path: str | Path) -> bool:
    return (Path(path) / "CASE.yaml").exists()


def _as_case(path: str) -> CaseResolution:
    return CaseResolution("case" if is_case(path) else "case_gone", path)


def resolve_active_case() -> CaseResolution:
    """The active case: VHIR_CASE_DIR when it names a case, else the pointer.
    An unreadable or undecodable pointer is a failed write, never an error."""
    case_dir = os.environ.get("VHIR_CASE_DIR", "").strip()
    if case_dir and is_case(case_dir):
        return CaseResolution("case", case_dir)
    pointer = Path.home() / ".vhir" / "active_case"
    try:
        if pointer.is_fifo() or pointer.is_char_device():  # its read could block
            raise OSError(f"{pointer} is not a regular file")
        case_dir = pointer.read_text().strip()
    except FileNotFoundError:
        return CaseResolution("no_case")
    except (OSError, UnicodeDecodeError) as e:
        return CaseResolution("write_failed", reason=str(e))
    if case_dir and not is_case(case_dir):
        logger.warning("%s is not a case directory, skipping audit", case_dir)
    return _as_case(case_dir) if case_dir else CaseResolution("no_case")


def mkdir_in_case(root: str | Path, *parts: str) -> Path:
    """Create `parts` below a case root one level at a time, never the root:
    a case moved away is not recreated (FileNotFoundError)."""
    path = Path(root)
    for part in parts:
        path = path / part
        path.mkdir(exist_ok=True)
    return path


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

    def resolve(
        self, case_dir: str | Path | CaseResolution | None = None
    ) -> CaseResolution:
        """Where this call's entries go, taken once (a caller may take it at
        the start and pass it back): explicit audit_dir > VHIR_AUDIT_DIR >
        `case_dir` ("" for none) > the server's own case resolver >
        VHIR_CASE_DIR > the active case pointer."""
        if folder := self._explicit_audit_dir or os.environ.get("VHIR_AUDIT_DIR"):
            return CaseResolution("audit_dir", folder)
        if isinstance(case_dir, CaseResolution):
            return case_dir
        if case_dir is None and self._case_dir_resolver:
            case_dir = self._case_dir_resolver() or None
        if case_dir is None:
            return resolve_active_case()
        return _as_case(str(case_dir)) if case_dir else CaseResolution("no_case")

    def _make_audit_dir(self, res: CaseResolution) -> Path | AuditOutcome:
        """The resolution's audit folder, created now only inside a case that
        is one at this moment (or under an explicit audit folder's parent)."""
        if res.outcome not in ("case", "audit_dir"):
            return AuditOutcome(res.outcome, detail=res.path or res.reason)
        path = Path(res.path)
        root, name = (
            (path, "audit") if res.outcome == "case" else (path.parent, path.name)
        )
        try:
            if res.outcome == "audit_dir" and not self._explicit_audit_dir:
                path.mkdir(parents=True, exist_ok=True)  # VHIR_AUDIT_DIR: not a case
                return path
            if res.outcome == "case" and not is_case(path):
                return AuditOutcome("case_gone", detail=res.path)
            return mkdir_in_case(root, name)
        except FileNotFoundError:
            return AuditOutcome("case_gone", detail=str(root))
        except OSError as e:
            logger.warning("Cannot create audit directory %s: %s", path, e)
            return AuditOutcome("write_failed", detail=str(e))

    def _get_audit_dir(self, case_dir: str | Path | None = None) -> Path | None:
        """The audit directory (see `resolve`), or None when nothing is recorded."""
        audit_dir = self._make_audit_dir(self.resolve(case_dir))
        return None if isinstance(audit_dir, AuditOutcome) else audit_dir

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
        except (OSError, UnicodeDecodeError):
            pass
        return ""

    def record(
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
        case_dir: str | Path | CaseResolution | None = None,
    ) -> AuditOutcome:
        """Write an audit entry and say what became of it: recorded (its id),
        no case, case gone or write failed. The folder is resolved once: the id
        is minted for it (when not given) and the entry is written to it.
        `case_dir` is the case the caller resolved when its operation started
        ("" for none): the entry goes there, with that case's id.
        """
        res = self.resolve(case_dir)
        audit_dir = self._make_audit_dir(res)
        if isinstance(audit_dir, AuditOutcome):
            return audit_dir
        if not case_id and case_dir and res.outcome == "case":
            case_id = _case_id_of(res.path)
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

        if (error := self._append(entry, audit_dir)) is None:
            return AuditOutcome(audit_id=audit_id)
        if res.outcome == "case" and not is_case(res.path):
            return AuditOutcome("case_gone", detail=res.path)
        return AuditOutcome("write_failed", detail=str(error))

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
        case_dir: str | Path | CaseResolution | None = None,
    ) -> str | None:
        """Write an audit entry (as `record`). Returns the audit_id, or None
        when it was not recorded."""
        args = {k: v for k, v in locals().items() if k != "self"}
        return self.record(**args).audit_id

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
        return self._append(entry, audit_dir) is None

    def _append(self, entry: dict, audit_dir: Path) -> OSError | None:
        """Append one entry, fsynced; the error when it was not written."""
        try:
            log_file = audit_dir / f"{self.mcp_name}.jsonl"
            # Non-blocking, and only into a regular file: a FIFO there would
            # wait for a reader, or hand the entry to one
            fd = os.open(
                log_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK, 0o666
            )
            try:  # the descriptor is closed on any failure before fdopen owns it
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError(f"{log_file} is not a regular file")
                f = os.fdopen(fd, "a", encoding="utf-8")
            except BaseException:
                os.close(fd)
                raise
            with f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return None
        except OSError as e:
            logger.warning(
                "Failed to write audit entry for audit_id=%s tool=%s: %s "
                "(this audit_id was NOT recorded to the audit trail)",
                entry.get("audit_id"),
                entry.get("tool"),
                e,
            )
            return e

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
