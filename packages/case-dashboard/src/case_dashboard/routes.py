"""Case dashboard routes — Starlette sub-app for finding review."""

import getpass
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import re
import secrets
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

# Max delta file size (1 MB)
_MAX_DELTA_SIZE = 1_048_576

# Fields excluded from content hash (must match case_io.py _HASH_EXCLUDE_KEYS)
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

_VALID_DELTA_KEYS = {
    "id",
    "type",
    "action",
    "content_hash_at_review",
    "modifications",
    "rejection_reason",
    "note",
    "todo_description",
    "todo_priority",
}

_REQUIRED_DELTA_KEYS = {"id", "type", "action"}

# Editable fields for modifications (must match approve.py:681-695 exactly)
_DELTA_EDITABLE_FIELDS = {
    # Finding fields
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "mitre_ids",
    "iocs",
    "context",
    # Timeline event fields
    "timestamp",
    "description",
    "source",
}

# In-memory challenge store (gateway is single-process uvicorn)
_challenges: dict[str, dict] = {}  # challenge_id → {nonce, examiner, created_at}
_CHALLENGE_TTL = 60  # seconds
_MAX_COMMIT_ATTEMPTS = 3
_COMMIT_LOCKOUT_SECONDS = 900


def _resolve_case_dir() -> Path | None:
    """Resolve case directory per-request.

    Priority: AIIR_CASE_DIR env var > ~/.aiir/active_case file.
    Returns None if no case is active or directory lacks CASE.yaml.
    """
    from sift_common import resolve_case_dir

    d = resolve_case_dir()
    if not d:
        return None
    p = Path(d)
    return p if p.is_dir() and (p / "CASE.yaml").exists() else None


def _no_case_response() -> JSONResponse:
    return JSONResponse(
        {"error": "No active case. Run `aiir case activate` first."},
        status_code=404,
    )


def _compute_content_hash(item: dict) -> str:
    """SHA-256 of canonical JSON excluding volatile fields."""
    hashable = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _load_json(path: Path) -> list | dict | None:
    """Load a JSON file, return None on missing/corrupt."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file. Returns None if missing. Raises ValueError on corrupt/unreadable."""
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Corrupt YAML: {path}: {e}") from e
    except OSError as e:
        raise ValueError(f"Cannot read YAML: {path}: {e}") from e


def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file, skipping corrupt lines."""
    if not path.exists():
        return []
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return entries


def _verify_items(case_dir: Path, items: list[dict]) -> list[dict]:
    """Add computed verification field to each item (finding or timeline event).

    Reimplements content-hash comparison from case_io.py.
    Five states: confirmed, tampered, unverified, no approval record, draft.
    """
    approvals = _load_jsonl(case_dir / "approvals.jsonl")

    # Build lookup: item_id -> last approval record
    last_approval: dict[str, dict] = {}
    for record in approvals:
        item_id = record.get("item_id")
        if item_id:
            last_approval[item_id] = record

    results = []
    for f in items:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f.get("id", "")
        record = last_approval.get(fid)

        if status == "DRAFT":
            result["verification"] = "draft"
        elif record:
            if record.get("action") == status:
                recomputed = _compute_content_hash(f)
                finding_hash = f.get("content_hash")
                approval_hash = record.get("content_hash")
                if (finding_hash and recomputed != finding_hash) or (
                    approval_hash and recomputed != approval_hash
                ):
                    result["verification"] = "tampered"
                elif finding_hash or approval_hash:
                    result["verification"] = "confirmed"
                else:
                    result["verification"] = "unverified"
            else:
                result["verification"] = "no approval record"
        else:
            result["verification"] = "no approval record"
        results.append(result)
    return results


# --- Commit helpers ---


_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _resolve_examiner(request: Request) -> str | None:
    """Get examiner from auth middleware, fall back to env var."""
    examiner = getattr(request.state, "examiner", None)
    if examiner and examiner != "anonymous":
        if not _EXAMINER_RE.match(examiner):
            return None
        return examiner
    # Single-user fallback
    env_examiner = os.environ.get("AIIR_EXAMINER")
    if env_examiner and not _EXAMINER_RE.match(env_examiner):
        return None
    return env_examiner


def _load_password_entry(examiner: str) -> dict | None:
    """Read password entry from /var/lib/aiir/passwords/{examiner}.json."""
    if ".." in examiner or "/" in examiner or "\\" in examiner:
        return None
    path = Path("/var/lib/aiir/passwords") / f"{examiner}.json"
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "hash" in data and "salt" in data:
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _check_commit_lockout(examiner: str) -> str | None:
    """Returns error message if locked out, None if OK."""
    lockout_file = Path.home() / ".aiir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    failures = data.get(examiner, [])
    now = time.time()
    recent = sum(1 for t in failures if now - t < _COMMIT_LOCKOUT_SECONDS)
    if recent >= _MAX_COMMIT_ATTEMPTS:
        oldest = min(t for t in failures if now - t < _COMMIT_LOCKOUT_SECONDS)
        remaining = int(_COMMIT_LOCKOUT_SECONDS - (now - oldest))
        return f"Too many failed attempts. Try again in {max(remaining, 1)}s."
    return None


def _record_commit_failure(examiner: str) -> None:
    """Record a failed commit attempt to shared lockout file."""
    lockout_file = Path.home() / ".aiir" / ".password_lockout"
    lockout_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    data.setdefault(examiner, []).append(time.time())
    fd, tmp = tempfile.mkstemp(dir=str(lockout_file.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, str(lockout_file))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _clear_commit_failures(examiner: str) -> None:
    """Clear failure count on successful commit."""
    lockout_file = Path.home() / ".aiir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return
    if examiner in data:
        del data[examiner]
        fd, tmp = tempfile.mkstemp(dir=str(lockout_file.parent), suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            os.replace(tmp, str(lockout_file))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _commit_failure_count(examiner: str) -> int:
    """Count recent failures for examiner."""
    lockout_file = Path.home() / ".aiir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return 0
    now = time.time()
    return sum(1 for t in data.get(examiner, []) if now - t < _COMMIT_LOCKOUT_SECONDS)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply_note(item: dict, note: str, identity: dict) -> None:
    """Apply an examiner note to an item (mirrors CLI approve.py:602-610)."""
    item.setdefault("examiner_notes", []).append(
        {
            "note": note,
            "by": identity["examiner"],
            "at": _iso_now(),
        }
    )


def _write_approval_log_entry(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    now: str,
    **kwargs: object,
) -> None:
    """Append to approvals.jsonl. Schema matches case_io.py:write_approval_log."""
    log_path = case_dir / "approvals.jsonl"
    entry = {
        "ts": now,
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "examiner": identity["examiner"],
        "examiner_source": identity.get("examiner_source", ""),
        "mode": "dashboard",
    }
    if kwargs.get("reason"):
        entry["reason"] = kwargs["reason"]
    if kwargs.get("content_hash"):
        entry["content_hash"] = kwargs["content_hash"]
    if kwargs.get("stale_at_approval"):
        entry["stale_at_approval"] = True

    # Match CLI: chmod 644 → append → chmod 444
    try:
        if log_path.exists():
            os.chmod(str(log_path), 0o644)
    except OSError:
        pass
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        logger.warning("Failed to write approval log: %s", log_path)
    try:
        os.chmod(str(log_path), 0o444)
    except OSError:
        pass


def _write_hmac_entries(
    case_dir: Path,
    case_id: str,
    items: list[dict],
    examiner: str,
    derived_key: bytes,
    now: str,
) -> list[str]:
    """Write HMAC verification ledger entries. Returns list of failed item IDs.

    Matches CLI pattern: per-item try/except, failures are non-fatal.
    Entry format matches CLI exactly (approve.py:447-456).
    """
    verification_dir = Path("/var/lib/aiir/verification")
    verification_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ledger_path = verification_dir / f"{case_id}.jsonl"
    failures: list[str] = []

    for item in items:
        item_id = item.get("id", "")
        item_type = "timeline" if item_id.startswith("T-") else "finding"
        # Same formula as case_io.hmac_text()
        hashable = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
        description = json.dumps(hashable, sort_keys=True, default=str)
        mac = hmac_mod.new(derived_key, description.encode(), "sha256").hexdigest()
        entry = {
            "finding_id": item_id,
            "type": item_type,
            "hmac": mac,
            "hmac_version": 2,
            "content_snapshot": description,
            "approved_by": examiner,
            "approved_at": now,
            "case_id": case_id,
            "mode": "dashboard",
        }
        try:
            with open(ledger_path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(str(ledger_path), 0o600)
        except OSError:
            logger.warning("HMAC write failed for %s", item_id)
            failures.append(item_id)

    return failures


def _save_protected(path: Path, data: object) -> None:
    """Write JSON with chmod 444 protection. Matches CLI case_io._protected_write."""
    try:
        os.chmod(str(path), 0o644)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
        os.chmod(str(path), 0o444)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _apply_delta(case_dir: Path, examiner: str, derived_key: bytes) -> dict:
    """Apply pending delta. Returns summary dict.

    derived_key is the stored PBKDF2 hash bytes — same as derive_hmac_key()
    would produce from the raw password + salt.

    This is a faithful port of _review_mode (approve.py:806-1159).
    Every field name, key, and schema detail matches the CLI.

    Write ordering matches CLI exactly (approve.py:1066-1113):
    Step 1 (critical): Save findings.json + timeline.json
    Step 2 (best-effort): Write approval log entries
    Step 3 (best-effort): Write HMAC ledger entries
    """
    delta_path = case_dir / "pending-reviews.json"
    processing_path = case_dir / "pending-reviews.processing"

    # Crash recovery (mirrors CLI approve.py:811-826)
    if processing_path.exists():
        if delta_path.exists():
            processing_path.unlink()
        else:
            os.rename(str(processing_path), str(delta_path))

    if not delta_path.exists():
        raise ValueError("No pending reviews to commit")

    # Atomic lock: rename to .processing
    try:
        os.rename(str(delta_path), str(processing_path))
    except OSError as exc:
        raise ValueError("Another commit is in progress") from exc

    try:
        delta = json.loads(processing_path.read_text())
        items_list = delta.get("items", [])
        if not items_list:
            raise ValueError("No items in delta")

        # Resolve case_id from CASE.yaml (matches approve.py:428-440)
        case_id = ""
        meta_file = case_dir / "CASE.yaml"
        if meta_file.exists():
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
                case_id = meta.get("case_id", "")
            except Exception:
                pass
        if not case_id:
            case_id = case_dir.name

        # Case ID validation (mirrors CLI approve.py:856-872)
        delta_case_id = delta.get("case_id", "")
        if delta_case_id and case_id and delta_case_id != case_id:
            raise ValueError(
                f"Delta case_id ({delta_case_id}) does not match "
                f"active case ({case_id})"
            )

        # Load current state
        findings = _load_json(case_dir / "findings.json") or []
        timeline = _load_json(case_dir / "timeline.json") or []
        all_items = findings + timeline
        item_by_id = {item["id"]: item for item in all_items}

        identity = {
            "examiner": examiner,
            "examiner_source": "dashboard",
            "os_user": getpass.getuser(),
        }
        now = _iso_now()

        approved_count = 0
        rejected_count = 0
        edited_count = 0
        skipped: list[tuple[str, str]] = []
        errors: list[str] = []
        approved_items: list[dict] = []
        log_entries: list[tuple[str, str, dict]] = []

        # Categorize by action (mirrors CLI approve.py:919-930)
        approvals = [
            de for de in items_list if de.get("action", "").lower() == "approve"
        ]
        rejections = [
            de for de in items_list if de.get("action", "").lower() == "reject"
        ]
        edits = [de for de in items_list if de.get("action", "").lower() == "edit"]

        # --- Process approvals (mirrors approve.py:953-1003) ---
        for entry in approvals:
            item_id = entry.get("id", "")
            item = item_by_id.get(item_id)
            if item is None:
                skipped.append((item_id, "not found"))
                continue

            modifications = entry.get("modifications", {})
            pre_mod_hash = item.get("content_hash", "")

            # C5: Verify modification originals match current values
            mod_conflict = False
            for field, mod in modifications.items():
                current_val = item.get(field)
                original_val = mod.get("original")
                if current_val != original_val:
                    skipped.append((item_id, f"field '{field}' changed since review"))
                    mod_conflict = True
                    break
            if mod_conflict:
                continue

            # Apply modifications (only editable fields)
            if modifications:
                for field, mod in modifications.items():
                    if field not in _DELTA_EDITABLE_FIELDS:
                        continue
                    item[field] = mod.get("modified")
                    item.setdefault("examiner_modifications", {})[field] = {
                        "original": mod.get("original"),
                        "modified": mod.get("modified"),
                        "modified_by": examiner,
                        "modified_at": now,
                    }

            # Apply note
            note = entry.get("note")
            if note:
                _apply_note(item, note, identity)

            # Compute content hash AFTER modifications
            new_hash = _compute_content_hash(item)
            item["content_hash"] = new_hash
            item["status"] = "APPROVED"
            item["approved_at"] = now
            item["approved_by"] = examiner
            item["modified_at"] = now
            approved_count += 1
            approved_items.append(item)

            ch_at_review = entry.get("content_hash_at_review")
            stale = bool(ch_at_review and ch_at_review != pre_mod_hash)

            log_entries.append(
                (
                    item_id,
                    "APPROVED",
                    {
                        "content_hash": new_hash,
                        "stale_at_approval": stale,
                    },
                )
            )

        # --- Process edits (mirrors approve.py:1005-1046) ---
        for entry in edits:
            item_id = entry.get("id", "")
            item = item_by_id.get(item_id)
            if item is None:
                skipped.append((item_id, "not found"))
                continue

            modifications = entry.get("modifications", {})
            if not modifications:
                continue

            # C5: Verify originals match
            mod_conflict = False
            for field, mod in modifications.items():
                current_val = item.get(field)
                original_val = mod.get("original")
                if current_val != original_val:
                    skipped.append((item_id, f"field '{field}' changed since review"))
                    mod_conflict = True
                    break
            if mod_conflict:
                continue

            for field, mod in modifications.items():
                if field not in _DELTA_EDITABLE_FIELDS:
                    continue
                item[field] = mod.get("modified")
                item.setdefault("examiner_modifications", {})[field] = {
                    "original": mod.get("original"),
                    "modified": mod.get("modified"),
                    "modified_by": examiner,
                    "modified_at": now,
                }

            new_hash = _compute_content_hash(item)
            item["content_hash"] = new_hash
            item["modified_at"] = now
            edited_count += 1

            log_entries.append((item_id, "EDITED", {"content_hash": new_hash}))

        # --- Process rejections (mirrors approve.py:1048-1064) ---
        for entry in rejections:
            item_id = entry.get("id", "")
            item = item_by_id.get(item_id)
            if item is None:
                skipped.append((item_id, "not found"))
                continue

            reason = entry.get("rejection_reason", "") or entry.get("reason", "")
            item["status"] = "REJECTED"
            item["rejected_at"] = now
            item["rejected_by"] = examiner
            if reason:
                item["rejection_reason"] = reason
            item["modified_at"] = now
            rejected_count += 1

            log_entries.append((item_id, "REJECTED", {"reason": reason}))

        # ============================================================
        # Disk writes — CLI ordering (approve.py:1066-1113):
        # Step 1 (critical): Save primary data FIRST
        # Step 2 (best-effort): Approval log
        # Step 3 (best-effort): HMAC ledger
        # ============================================================

        # Step 1: Save findings + timeline
        _save_protected(case_dir / "findings.json", findings)
        _save_protected(case_dir / "timeline.json", timeline)

        # Step 2: Write approval log entries (best-effort)
        for item_id, action, kwargs in log_entries:
            _write_approval_log_entry(
                case_dir, item_id, action, identity, now, **kwargs
            )

        # Step 3: Write HMAC ledger entries (best-effort)
        hmac_failures: list[str] = []
        if approved_items:
            hmac_failures = _write_hmac_entries(
                case_dir, case_id, approved_items, examiner, derived_key, now
            )

        # Delete processing file
        processing_path.unlink(missing_ok=True)

        return {
            "approved": approved_count,
            "rejected": rejected_count,
            "edited": edited_count,
            "skipped": [{"id": s[0], "reason": s[1]} for s in skipped],
            "errors": errors,
            "hmac_failures": hmac_failures,
        }
    except BaseException:
        # Restore delta file on failure
        try:
            if processing_path.exists() and not delta_path.exists():
                os.rename(str(processing_path), str(delta_path))
        except OSError:
            pass
        raise


# --- Endpoints ---


async def get_findings(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_items(case_dir, findings)
    return JSONResponse(verified)


async def get_finding_by_id(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["id"]
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_items(case_dir, findings)
    for f in verified:
        if f.get("id") == finding_id:
            return JSONResponse(f)
    return JSONResponse({"error": f"Finding {finding_id} not found"}, status_code=404)


async def get_timeline(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    timeline = _load_json(case_dir / "timeline.json") or []
    verified = _verify_items(case_dir, timeline)
    return JSONResponse(verified)


async def get_evidence(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    raw = _load_json(case_dir / "evidence.json")
    evidence = raw.get("files", []) if isinstance(raw, dict) else (raw or [])

    # Build referenced_by reverse index from findings
    findings = _load_json(case_dir / "findings.json") or []
    ref_index: dict[str, list[str]] = {}
    for f in findings:
        for eid in f.get("evidence_ids", []):
            ref_index.setdefault(eid, []).append(f.get("id", ""))

    # Enrich evidence items
    for item in evidence:
        eid = item.get("evidence_id", item.get("id", ""))
        item["referenced_by"] = ref_index.get(eid, [])

    return JSONResponse(evidence)


async def get_audit_for_finding(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["finding_id"]

    # Get the finding's evidence_ids
    findings = _load_json(case_dir / "findings.json") or []
    evidence_ids: set[str] = set()
    for f in findings:
        if f.get("id") == finding_id:
            evidence_ids = set(f.get("evidence_ids", []))
            break

    if not evidence_ids:
        return JSONResponse([])

    # Scan audit/*.jsonl for matching evidence_ids
    audit_dir = case_dir / "audit"
    if not audit_dir.is_dir():
        return JSONResponse([])

    matches = []
    for audit_file in sorted(audit_dir.glob("*.jsonl")):
        backend = audit_file.stem
        for entry in _load_jsonl(audit_file):
            entry_eid = entry.get("evidence_id", "")
            if entry_eid in evidence_ids:
                entry["_backend"] = backend
                matches.append(entry)

    return JSONResponse(matches)


async def get_delta(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    delta = _load_json(case_dir / "pending-reviews.json")
    if delta is None:
        return JSONResponse({"items": []})
    return JSONResponse(delta)


async def get_case(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    try:
        meta = _load_yaml(case_dir / "CASE.yaml")
    except ValueError as e:
        logger.error("Corrupt CASE.yaml: %s", e)
        return JSONResponse({"error": str(e)}, status_code=500)
    if meta is None:
        return JSONResponse({})
    return JSONResponse(meta)


async def get_todos(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    todos = _load_json(case_dir / "todos.json") or []
    return JSONResponse(todos)


async def get_summary(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    findings = _load_json(case_dir / "findings.json") or []
    timeline = _load_json(case_dir / "timeline.json") or []
    raw_ev = _load_json(case_dir / "evidence.json")
    evidence = raw_ev.get("files", []) if isinstance(raw_ev, dict) else (raw_ev or [])
    todos = _load_json(case_dir / "todos.json") or []

    status_counts = {}
    for f in findings:
        s = f.get("status", "DRAFT")
        status_counts[s] = status_counts.get(s, 0) + 1

    timeline_counts = {}
    for t in timeline:
        s = t.get("status", "DRAFT")
        timeline_counts[s] = timeline_counts.get(s, 0) + 1

    open_todos = sum(1 for t in todos if t.get("status", "open") == "open")

    return JSONResponse(
        {
            "findings": {"total": len(findings), "by_status": status_counts},
            "timeline": {"total": len(timeline), "by_status": timeline_counts},
            "evidence": {"total": len(evidence)},
            "todos": {"total": len(todos), "open": open_todos},
        }
    )


async def post_delta(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    # Size check
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > _MAX_DELTA_SIZE:
            return JSONResponse(
                {"error": "Request body too large (max 1 MB)"},
                status_code=413,
            )
    except ValueError:
        pass

    body = await request.body()
    if len(body) > _MAX_DELTA_SIZE:
        return JSONResponse(
            {"error": "Request body too large (max 1 MB)"},
            status_code=413,
        )

    # Validate JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(data, dict):
        return JSONResponse({"error": "Expected JSON object"}, status_code=400)
    items = data.get("items")
    if items is not None and not isinstance(items, list):
        return JSONResponse({"error": "'items' must be a list"}, status_code=400)

    if items:
        for item in items:
            if not isinstance(item, dict):
                return JSONResponse(
                    {"error": "Each item must be a dict"}, status_code=400
                )
            unknown = set(item.keys()) - _VALID_DELTA_KEYS
            if unknown:
                return JSONResponse(
                    {
                        "error": f"Unknown fields in delta item: {', '.join(sorted(unknown))}"
                    },
                    status_code=400,
                )
            missing = _REQUIRED_DELTA_KEYS - set(item.keys())
            if missing:
                return JSONResponse(
                    {
                        "error": f"Missing required fields in delta item: {', '.join(sorted(missing))}"
                    },
                    status_code=400,
                )

    delta_path = case_dir / "pending-reviews.json"

    # Symlink protection
    if delta_path.exists() and os.path.islink(delta_path):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )

    try:
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(case_dir), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(delta_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("Failed to write delta file: %s", e)
        return JSONResponse({"error": "Write failed"}, status_code=500)

    return JSONResponse({"status": "ok"})


async def delete_delta_item(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    item_id = request.path_params["id"]
    delta_path = case_dir / "pending-reviews.json"

    # Symlink protection
    if delta_path.exists() and os.path.islink(delta_path):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )

    delta = _load_json(delta_path)

    if delta is None or not isinstance(delta, dict):
        return JSONResponse({"error": "No delta file"}, status_code=404)

    items = delta.get("items", [])
    new_items = [i for i in items if i.get("id") != item_id]

    if len(new_items) == len(items):
        return JSONResponse(
            {"error": f"Item {item_id} not found in delta"},
            status_code=404,
        )

    delta["items"] = new_items
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(case_dir), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(delta, f, indent=2)
            os.replace(tmp_path, str(delta_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("Failed to write delta file: %s", e)
        return JSONResponse({"error": "Write failed"}, status_code=500)

    return JSONResponse({"status": "ok", "remaining": len(new_items)})


async def verify_evidence(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    rel_path = request.path_params["path"]

    # Path traversal protection
    if ".." in rel_path or rel_path.startswith("/"):
        return JSONResponse(
            {"error": "Invalid path"},
            status_code=400,
        )

    evidence_dir = case_dir / "evidence"
    target = (evidence_dir / rel_path).resolve()

    # Ensure resolved path is under evidence directory
    try:
        target.relative_to(evidence_dir.resolve())
    except ValueError:
        return JSONResponse(
            {"error": "Path traversal rejected"},
            status_code=400,
        )

    if not target.is_file():
        return JSONResponse(
            {"error": f"File not found: {rel_path}"},
            status_code=404,
        )

    # Hash the file
    h = hashlib.sha256()
    try:
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        logger.error("Cannot read evidence file %s: %s", target, e)
        return JSONResponse(
            {"error": "Cannot read file"},
            status_code=500,
        )
    computed_hash = h.hexdigest()

    # Compare against evidence registry
    raw_ev = _load_json(case_dir / "evidence.json")
    evidence = raw_ev.get("files", []) if isinstance(raw_ev, dict) else (raw_ev or [])
    stored_hash = None
    for item in evidence:
        if item.get("path") == rel_path:
            stored_hash = item.get("sha256")
            break

    if stored_hash is None:
        return JSONResponse(
            {
                "path": rel_path,
                "computed_sha256": computed_hash,
                "status": "not_registered",
            }
        )

    match = computed_hash == stored_hash
    return JSONResponse(
        {
            "path": rel_path,
            "computed_sha256": computed_hash,
            "stored_sha256": stored_hash,
            "status": "verified" if match else "failed",
        }
    )


async def get_commit_challenge(request: Request) -> JSONResponse:
    """Issue a challenge nonce + salt for password verification."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    entry = _load_password_entry(examiner)
    if not entry:
        return JSONResponse(
            {"error": "No password configured. Run: aiir config --setup-password"},
            status_code=403,
        )

    # Purge expired challenges
    now = time.time()
    expired = [
        k for k, v in _challenges.items() if now - v["created_at"] > _CHALLENGE_TTL
    ]
    for k in expired:
        del _challenges[k]

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_hex(32)
    _challenges[challenge_id] = {
        "nonce": nonce,
        "examiner": examiner,
        "created_at": now,
    }

    return JSONResponse(
        {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "salt": entry["salt"],
            "iterations": 600000,
            "hash_algorithm": "SHA-256",
        }
    )


async def post_commit(request: Request) -> JSONResponse:
    """Apply delta with challenge-response authentication."""
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = body.get("challenge_id")
    response_hmac = body.get("response")

    if not challenge_id or not response_hmac:
        return JSONResponse(
            {"error": "Missing challenge_id or response"}, status_code=400
        )

    # Validate challenge
    challenge = _challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    now = time.time()
    if now - challenge["created_at"] > _CHALLENGE_TTL:
        return JSONResponse({"error": "Challenge expired"}, status_code=401)

    if challenge["examiner"] != examiner:
        return JSONResponse({"error": "Challenge/examiner mismatch"}, status_code=401)

    # Verify response: HMAC-SHA256(stored_pbkdf2_hash, nonce)
    entry = _load_password_entry(examiner)
    if not entry:
        return JSONResponse({"error": "No password configured"}, status_code=403)

    stored_hash = bytes.fromhex(entry["hash"])
    expected = hmac_mod.new(
        stored_hash, challenge["nonce"].encode(), "sha256"
    ).hexdigest()

    if not hmac_mod.compare_digest(expected, response_hmac):
        _record_commit_failure(examiner)
        remaining = _MAX_COMMIT_ATTEMPTS - _commit_failure_count(examiner)
        if remaining <= 0:
            msg = f"Too many failed attempts. Locked for {_COMMIT_LOCKOUT_SECONDS}s."
        else:
            msg = f"Incorrect password. {remaining} attempt(s) remaining."
        return JSONResponse({"error": msg}, status_code=401)

    _clear_commit_failures(examiner)

    # Apply delta (mirrors _review_mode)
    try:
        result = _apply_delta(case_dir, examiner, stored_hash)
    except Exception as e:
        logger.exception("Commit failed")
        return JSONResponse({"error": str(e)}, status_code=500)

    return JSONResponse(result)


async def serve_index(request: Request) -> Response:
    index_path = _STATIC_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse(
            {"error": "Dashboard not built yet"},
            status_code=404,
        )
    return FileResponse(index_path, media_type="text/html")


_V2_STATIC_DIR = _STATIC_DIR / "v2"


async def serve_v2_index(request: Request) -> Response:
    index_path = _V2_STATIC_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse(
            {"error": "Dashboard v2 not built yet"},
            status_code=404,
        )
    return FileResponse(index_path, media_type="text/html")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; "
            "img-src 'self'; "
            "connect-src 'self'"
        )
        return response


def _dashboard_api_routes() -> list[Route]:
    """API routes shared by v1 and v2 dashboard apps."""
    return [
        Route("/api/findings", get_findings, methods=["GET"]),
        Route("/api/findings/{id}", get_finding_by_id, methods=["GET"]),
        Route("/api/timeline", get_timeline, methods=["GET"]),
        Route("/api/evidence", get_evidence, methods=["GET"]),
        Route("/api/audit/{finding_id}", get_audit_for_finding, methods=["GET"]),
        Route("/api/delta", get_delta, methods=["GET"]),
        Route("/api/delta", post_delta, methods=["POST"]),
        Route("/api/delta/{id}", delete_delta_item, methods=["DELETE"]),
        Route("/api/case", get_case, methods=["GET"]),
        Route("/api/todos", get_todos, methods=["GET"]),
        Route("/api/summary", get_summary, methods=["GET"]),
        Route("/api/evidence/{path:path}/verify", verify_evidence, methods=["POST"]),
        Route("/api/commit/challenge", get_commit_challenge, methods=["GET"]),
        Route("/api/commit", post_commit, methods=["POST"]),
    ]


def create_dashboard_app() -> Starlette:
    """Create the v1 dashboard sub-app for mounting on the gateway."""
    routes = _dashboard_api_routes()
    routes.append(Route("/", serve_index, methods=["GET"]))
    return Starlette(routes=routes, middleware=[Middleware(SecurityHeadersMiddleware)])


def create_dashboard_v2_app() -> Starlette:
    """Create the v2 dashboard sub-app for mounting on the gateway."""
    routes = _dashboard_api_routes()
    routes.append(Route("/", serve_v2_index, methods=["GET"]))
    return Starlette(routes=routes, middleware=[Middleware(SecurityHeadersMiddleware)])
