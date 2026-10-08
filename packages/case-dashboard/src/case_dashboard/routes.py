"""Case dashboard routes — Starlette sub-app for finding review."""

import hashlib
import json
import logging
import os
from pathlib import Path

import anyio
import yaml
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from case_dashboard import hosts, signing

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

# Max delta file size (1 MB)
_MAX_DELTA_SIZE = 1_048_576

_ITEM_FILES = (
    ("findings", "findings.json"),
    ("timeline", "timeline.json"),
    ("iocs", "iocs.json"),
)


def _resolve_case_dir() -> Path | None:
    """Resolve case directory per-request.

    Priority: VHIR_CASE_DIR env var > ~/.vhir/active_case file.
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
        {"error": "No active case. Run `vhir case activate` first."},
        status_code=404,
    )


def _load_json(path: Path) -> list | dict | None:
    """Load a JSON file, return None on missing/corrupt."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("Corrupt JSON file: %s", path)
        return None
    except OSError as e:
        logger.warning("Failed to read %s: %s", path, e)
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
    return _read_jsonl(path)[0]


def _read_jsonl(path: Path) -> tuple[list[dict], int]:
    """A JSONL file's entries, skipping corrupt lines, and how many lines
    weren't UTF-8 (skipped too)."""
    entries: list[dict] = []
    not_utf8 = 0
    try:
        with open(path, "rb") as f:
            for raw in f:
                try:
                    line = raw.decode("utf-8").strip()
                except UnicodeDecodeError:
                    not_utf8 += 1
                    continue
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return entries, not_utf8


def _withdrawals(case_dir: Path) -> tuple[list[dict], int]:
    """Candidate findings withdrawn after challenge, oldest first.

    Each is a record_finding audit entry whose result is WITHDRAWN. An entry
    repeated in the trail counts once, by audit id and time together, so two
    withdrawals never collapse into one.
    """
    audit_dir = case_dir / "audit"
    if not audit_dir.is_dir():
        return [], 0
    seen: set[tuple] = set()
    withdrawals = []
    not_utf8 = 0
    for audit_file in sorted(audit_dir.glob("*.jsonl")):
        entries, skipped = _read_jsonl(audit_file)
        not_utf8 += skipped
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("tool") != "record_finding":
                continue
            result = entry.get("result_summary")
            if not isinstance(result, dict) or result.get("status") != "WITHDRAWN":
                continue
            key = (entry.get("audit_id"), entry.get("ts"))
            if key in seen:
                continue
            seen.add(key)
            withdrawals.append(
                {
                    "audit_id": entry.get("audit_id", ""),
                    "ts": entry.get("ts", ""),
                    "examiner": entry.get("examiner", ""),
                    "title": result.get("title", ""),
                    "observation": result.get("observation", ""),
                    "contradiction": result.get("contradiction", ""),
                    "skeptic_audit_ids": result.get("skeptic_audit_ids", []),
                }
            )
    return sorted(withdrawals, key=lambda w: str(w["ts"])), not_utf8


def _resolve_examiner(request: Request) -> str | None:
    """Get examiner from auth middleware, fall back to env var."""
    from vhir_cli.identity import valid_name

    examiner = getattr(request.state, "examiner", None)
    if examiner and examiner != "anonymous":
        return examiner if valid_name(examiner) else None
    # Single-user fallback
    env_examiner = os.environ.get("VHIR_EXAMINER")
    if env_examiner and not valid_name(env_examiner):
        return None
    return env_examiner


# --- Verdicts -------------------------------------------------------------------
# Every badge comes from vhir's verify_case, the one verdict source. The view
# is cached on the files it reads (their mtimes and sizes), and the items the
# portal serves are the records verify judged, so a badge never describes a
# different copy of an item. A served item gains only keys the signed view
# leaves out (`verification`, `content_hash`), so the page can compare a
# signed snapshot with it field by field; the badge's longer text is in the
# case summary, by id.

VALID_NOTE = (
    "Valid (not anchored): compare the fingerprint with a copy kept off this machine."
)
LEGACY_NOTE = "Approved under 0.6, before signing: no signature covers it."
_view_cache: dict = {"key": None, "value": None}


def _view_key(case_dir: Path) -> tuple:
    from vhir_cli import keys, ledger
    from vhir_cli.case_io import case_id_of

    try:
        case_id = case_id_of(case_dir)
        paths = [ledger.chain_path(case_id), ledger.legacy_path(case_id)]
    except Exception:  # noqa: BLE001 - an unusable case id is judged by verify
        paths = []
    paths += [case_dir / name for _, name in _ITEM_FILES]
    paths += [case_dir / "CASE.yaml", case_dir / "verification.jsonl"]
    paths += sorted((case_dir / "ledger").rglob("*"))
    paths += sorted(Path(keys.KEYS_DIR).glob("*.json"))
    out = []
    for p in paths:
        try:
            st = p.stat()
            out.append((str(p), st.st_mtime_ns, st.st_size))
        except OSError:
            out.append((str(p), None, None))
    return (str(case_dir), tuple(out))


def _failure_note(status: str) -> str:
    """What the portal shows for an item that fails: the recovery line verify
    prints for its status (or the status itself, when verify prints none)."""
    from vhir_cli.ledger_verify import RECOVERY

    recovery = RECOVERY.get(status)
    return f"{status}. Recovery: {recovery}" if recovery else status


def _judged(case_dir: Path) -> dict:
    """{"records": {file key: [served item]}, "summary": {...}}, from one
    verify_case read."""
    from vhir_cli.case_io import compute_content_hash
    from vhir_cli.ledger_verify import approved_view, verification_json

    view = approved_view(case_dir)
    result = view["result"]
    shown = {
        id(i): view["labels"].get(i.get("id"), "")
        for key in ("findings", "timeline", "iocs")
        for i in view[key]
    }
    failed = {n["id"]: n["status"] for n in view["not_verified"]}
    kinds = {"findings": "finding", "timeline": "timeline", "iocs": "ioc"}
    records: dict[str, list[dict]] = {"findings": [], "timeline": [], "iocs": []}
    notes: dict[str, str] = {}
    for key, rec in result.records:
        if not isinstance(rec, dict):
            continue
        item = dict(rec)
        # the hash a review records, recomputed (the stored one is a cache)
        item["content_hash"] = compute_content_hash(rec)
        rid = str(rec.get("id"))
        status = rec.get("status", "DRAFT")
        verdict = result.verdict(rid)
        if verdict is not None and verdict.item_type != kinds[key]:
            verdict = None
        if id(rec) in shown:
            label = shown[id(rec)]
            if label == "approved under 0.6 (before signing)":
                item["verification"] = label
                notes[rid] = LEGACY_NOTE
            else:
                item["verification"] = "valid (not anchored)"
                # the key of this item's own signing line (an examiner can have several)
                notes[rid] = (
                    VALID_NOTE
                    + (
                        f" Key: {verdict.examiner} {verdict.fingerprint}."
                        if verdict and verdict.fingerprint
                        else ""
                    )
                    + (f" {label}." if label else "")
                )
        elif status == "APPROVED":
            item["verification"] = failed.get(rec.get("id"), "NO_SIGNED_LINE")
            notes[rid] = _failure_note(item["verification"])
        elif verdict is not None and verdict.status not in (
            "VALID",
            "APPROVED_UNDER_0_6",
        ):
            item["verification"] = verdict.status
            notes[rid] = _failure_note(verdict.status)
        elif verdict is not None:
            item["verification"] = "valid (not anchored)"
            notes[rid] = VALID_NOTE
        else:
            item["verification"] = status.lower()
        records[key].append(item)
    summary = verification_json(view)
    summary["notices"] = list(result.notices)
    summary["badge_notes"] = notes
    return {"records": records, "summary": summary}


def _verdicts(case_dir: Path) -> dict:
    key = _view_key(case_dir)
    if _view_cache["key"] == key:
        return _view_cache["value"]
    try:
        value = _judged(case_dir)
    except Exception as e:  # noqa: BLE001 - shown, never a blank portal
        logger.exception("verify_case failed")
        value = {
            "records": {
                k: [{**i, "verification": "unverified (verify failed)"}
                    for i in (_load_json(case_dir / name) or []) if isinstance(i, dict)]
                for k, name in _ITEM_FILES
            },
            "summary": {"error": f"verify failed: {e}"},
        }  # fmt: skip
        return value
    if _view_key(case_dir) == key:  # nothing changed while it was read
        _view_cache.update(key=key, value=value)
    return value


async def _served(case_dir: Path, file_key: str) -> list[dict]:
    return (await anyio.to_thread.run_sync(_verdicts, case_dir))["records"][file_key]


# --- Endpoints ---


async def get_findings(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    return JSONResponse(await _served(case_dir, "findings"))


async def get_finding_by_id(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["id"]
    for f in await _served(case_dir, "findings"):
        if f.get("id") == finding_id:
            return JSONResponse(f)
    return JSONResponse({"error": f"Finding {finding_id} not found"}, status_code=404)


async def get_timeline(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    return JSONResponse(await _served(case_dir, "timeline"))


async def get_evidence(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    raw = _load_json(case_dir / "evidence.json")
    evidence = raw.get("files", []) if isinstance(raw, dict) else (raw or [])

    # Build referenced_by reverse index: evidence path → finding IDs
    findings = _load_json(case_dir / "findings.json") or []
    ref_index: dict[str, list[str]] = {}
    for f in findings:
        fid = f.get("id", "")
        if not fid:
            continue
        # Link via artifact source paths
        for art in f.get("artifacts", []):
            src = art.get("source", "")
            if src:
                ref_index.setdefault(src, []).append(fid)

    # Enrich evidence items
    for item in evidence:
        path = item.get("path", "")
        item["referenced_by"] = ref_index.get(path, [])

    return JSONResponse(evidence)


async def get_audit_for_finding(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["finding_id"]

    # Get the finding's audit_ids
    findings = _load_json(case_dir / "findings.json") or []
    audit_ids: set[str] = set()
    for f in findings:
        if f.get("id") == finding_id:
            audit_ids = set(f.get("audit_ids", []))
            # Include provenance chain audit_ids for enriched rendering
            for art in f.get("artifacts", []):
                for step in art.get("provenance_chain", []):
                    if step.get("audit_id"):
                        audit_ids.add(step["audit_id"])
            break

    if not audit_ids:
        return JSONResponse([])

    # Scan audit/*.jsonl for matching audit_ids
    audit_dir = case_dir / "audit"
    if not audit_dir.is_dir():
        return JSONResponse([])

    matches = []
    for audit_file in sorted(audit_dir.glob("*.jsonl")):
        backend = audit_file.stem
        for entry in _load_jsonl(audit_file):
            entry_eid = entry.get("audit_id", "")
            if entry_eid in audit_ids:
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
    out = dict(meta) if isinstance(meta, dict) else {}
    # who signs here, the active key's fingerprint, and the case's keys and heads
    out["signing"] = signing.signing_state(
        getattr(request.state, "examiner", None), case_dir
    )
    out["you"] = _resolve_examiner(request)  # whose staged entries this page edits
    out["verification"] = (await anyio.to_thread.run_sync(_verdicts, case_dir))[
        "summary"
    ]
    return JSONResponse(out)


async def get_todos(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    todos = _load_json(case_dir / "todos.json") or []
    return JSONResponse(todos)


async def get_iocs(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    return JSONResponse(await _served(case_dir, "iocs"))


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
    withdrawals, not_utf8 = _withdrawals(case_dir)
    withdrawn: dict = {"total": len(withdrawals), "items": withdrawals}
    if not_utf8:
        withdrawn["unreadable_lines"] = not_utf8
        withdrawn["note"] = (
            f"Audit lines skipped because they aren't UTF-8: {not_utf8}. "
            "A withdrawal recorded on them isn't listed."
        )

    return JSONResponse(
        {
            "findings": {"total": len(findings), "by_status": status_counts},
            "timeline": {"total": len(timeline), "by_status": timeline_counts},
            "evidence": {"total": len(evidence)},
            "todos": {"total": len(todos), "open": open_todos},
            "withdrawn": withdrawn,
        }
    )


async def post_delta(request: Request) -> JSONResponse:
    """Save the poster's staged entries, merged under the case lock: their own
    entries are replaced by the posted ones, and everyone else's are kept.
    The server stamps `staged_by`; a client's value is never stored."""
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
    for item in items or []:
        problem = signing.entry_problem(item)
        if problem:
            return JSONResponse({"error": problem}, status_code=400)

    poster = _resolve_examiner(request)
    if not poster:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    # Symlink protection
    if signing.is_symlink(case_dir):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )

    dropped, refusal = await signing.locked(
        signing._post_locked, case_dir, items or [], poster
    )
    if refusal:
        return refusal
    return JSONResponse({"status": "ok", "dropped": dropped})


async def delete_delta_item(request: Request) -> JSONResponse:
    """Remove the caller's own staged entry for the id (or one with no
    `staged_by`), under the case lock. Others' entries are never touched."""
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    item_id = request.path_params["id"]
    caller = _resolve_examiner(request)
    if not caller:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    # Symlink protection
    if signing.is_symlink(case_dir):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )
    if not (case_dir / "pending-reviews.json").exists():
        return JSONResponse({"error": "No delta file"}, status_code=404)

    remaining, refusal = await signing.locked(
        signing._delete_locked, case_dir, item_id, caller
    )
    if refusal:
        return refusal
    if remaining is None:
        return JSONResponse(
            {"error": f"Item {item_id} not found in delta"},
            status_code=404,
        )
    return JSONResponse({"status": "ok", "remaining": remaining})


async def verify_evidence(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    req_path = request.path_params["path"]

    # Look up in evidence registry — the registry is the source of truth
    raw_ev = _load_json(case_dir / "evidence.json")
    evidence = raw_ev.get("files", []) if isinstance(raw_ev, dict) else (raw_ev or [])
    entry = None
    for item in evidence:
        if item.get("path") == req_path:
            entry = item
            break

    if entry is None:
        return JSONResponse(
            {"error": f"Not in evidence registry: {req_path}"},
            status_code=404,
        )

    stored_hash = entry.get("sha256", "")
    file_path = Path(entry["path"])

    # Path traversal protection on the registered path
    if ".." in str(file_path):
        return JSONResponse({"error": "Invalid path"}, status_code=400)

    if not file_path.is_file():
        return JSONResponse(
            {"error": f"File not found: {entry['path']}"},
            status_code=404,
        )

    # Hash the file
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        logger.error("Cannot read evidence file %s: %s", file_path, e)
        return JSONResponse(
            {"error": "Cannot read file"},
            status_code=500,
        )
    computed_hash = h.hexdigest()

    match = computed_hash == stored_hash
    return JSONResponse(
        {
            "path": entry["path"],
            "computed_sha256": computed_hash,
            "stored_sha256": stored_hash,
            "status": "verified" if match else "failed",
        }
    )


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
        Route("/api/iocs", get_iocs, methods=["GET"]),
        Route("/api/summary", get_summary, methods=["GET"]),
        Route("/api/evidence/{path:path}/verify", verify_evidence, methods=["POST"]),
        Route("/api/commit/plan", signing.post_commit_plan, methods=["POST"]),
        Route("/api/commit/key", signing.post_commit_key, methods=["POST"]),
        Route("/api/commit", signing.post_commit, methods=["POST"]),
        Route("/api/hosts", hosts.get_hosts, methods=["GET"]),
        Route("/api/hosts/decisions", hosts.post_host_decision, methods=["POST"]),
        Route("/api/hosts/runs", hosts.get_runs, methods=["GET"]),
        Route("/api/hosts/ops", hosts.get_ops, methods=["GET"]),
        Route("/api/hosts/ops", hosts.post_op, methods=["POST"]),
        Route("/api/hosts/{m16}", hosts.get_host, methods=["GET"]),
    ]


def create_dashboard_app() -> Starlette:
    """Create the v1 dashboard sub-app for mounting on the gateway."""
    routes = _dashboard_api_routes()
    routes.append(Route("/", serve_index, methods=["GET"]))
    return Starlette(routes=routes, middleware=[Middleware(SecurityHeadersMiddleware)])


async def serve_v2_static(request: Request) -> Response:
    """Serve static files from the v2 directory (images, icons, etc.)."""
    filename = request.path_params.get("filename", "")
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        return JSONResponse({"error": "not found"}, status_code=404)
    allowed_ext = {".png", ".jpg", ".svg", ".ico", ".css", ".js"}
    if Path(filename).suffix.lower() not in allowed_ext:
        return JSONResponse({"error": "not found"}, status_code=404)
    file_path = _V2_STATIC_DIR / filename
    if not file_path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".css": "text/css",
        ".js": "application/javascript",
    }
    return FileResponse(
        file_path,
        media_type=media_types.get(
            Path(filename).suffix.lower(), "application/octet-stream"
        ),
    )


def create_dashboard_v2_app() -> Starlette:
    """Create the v2 dashboard sub-app for mounting on the gateway."""
    routes = _dashboard_api_routes()
    routes.append(Route("/{filename}", serve_v2_static, methods=["GET"]))
    routes.append(Route("/", serve_v2_index, methods=["GET"]))
    return Starlette(routes=routes, middleware=[Middleware(SecurityHeadersMiddleware)])
