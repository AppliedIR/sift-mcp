"""Case dashboard routes — Starlette sub-app for finding review."""

import hashlib
import json
import logging
import os
from pathlib import Path

import yaml
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
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


def _resolve_case_dir() -> Path | None:
    """Resolve case directory per-request.

    Priority: AIIR_CASE_DIR env var > ~/.aiir/active_case file.
    Returns None if no case is active.
    """
    env_dir = os.environ.get("AIIR_CASE_DIR", "").strip()
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            return p
        return None

    active_case_file = Path.home() / ".aiir" / "active_case"
    if active_case_file.exists():
        case_path = active_case_file.read_text().strip()
        if case_path:
            p = Path(case_path)
            if p.is_dir():
                return p
    return None


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
    """Load a YAML file, return None on missing/corrupt."""
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return None


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


def _verify_findings(case_dir: Path, findings: list[dict]) -> list[dict]:
    """Add computed verification field to each finding.

    Reimplements content-hash comparison from case_io.py.
    Four states: confirmed, tampered, no approval record, draft.
    """
    approvals = _load_jsonl(case_dir / "approvals.jsonl")

    # Build lookup: item_id -> last approval record
    last_approval: dict[str, dict] = {}
    for record in approvals:
        item_id = record.get("item_id")
        if item_id:
            last_approval[item_id] = record

    results = []
    for f in findings:
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
                if finding_hash and recomputed != finding_hash:
                    result["verification"] = "tampered"
                elif approval_hash and recomputed != approval_hash:
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


# --- Endpoints ---


async def get_findings(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_findings(case_dir, findings)
    return JSONResponse(verified)


async def get_finding_by_id(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["id"]
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_findings(case_dir, findings)
    for f in verified:
        if f.get("id") == finding_id:
            return JSONResponse(f)
    return JSONResponse({"error": f"Finding {finding_id} not found"}, status_code=404)


async def get_timeline(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    timeline = _load_json(case_dir / "timeline.json") or []
    return JSONResponse(timeline)


async def get_evidence(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    evidence = _load_json(case_dir / "evidence.json") or []

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
    meta = _load_yaml(case_dir / "CASE.yaml")
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
    evidence = _load_json(case_dir / "evidence.json") or []
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

    return JSONResponse({
        "findings": {"total": len(findings), "by_status": status_counts},
        "timeline": {"total": len(timeline), "by_status": timeline_counts},
        "evidence": {"total": len(evidence)},
        "todos": {"total": len(todos), "open": open_todos},
    })


async def post_delta(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    # Size check
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_DELTA_SIZE:
        return JSONResponse(
            {"error": "Request body too large (max 1 MB)"},
            status_code=413,
        )

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

    delta_path = case_dir / "pending-reviews.json"

    # Symlink protection
    if delta_path.exists() and os.path.islink(delta_path):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )

    try:
        delta_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
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
        delta_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
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
        return JSONResponse(
            {"error": f"Cannot read file: {e}"},
            status_code=500,
        )
    computed_hash = h.hexdigest()

    # Compare against evidence registry
    evidence = _load_json(case_dir / "evidence.json") or []
    stored_hash = None
    for item in evidence:
        if item.get("path") == rel_path:
            stored_hash = item.get("sha256")
            break

    if stored_hash is None:
        return JSONResponse({
            "path": rel_path,
            "computed_sha256": computed_hash,
            "status": "not_registered",
        })

    match = computed_hash == stored_hash
    return JSONResponse({
        "path": rel_path,
        "computed_sha256": computed_hash,
        "stored_sha256": stored_hash,
        "status": "verified" if match else "failed",
    })


async def serve_index(request: Request) -> FileResponse:
    index_path = _STATIC_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse(
            {"error": "Dashboard not built yet"},
            status_code=404,
        )
    return FileResponse(index_path, media_type="text/html")


def create_dashboard_app() -> Starlette:
    """Create the dashboard sub-app for mounting on the gateway."""
    routes = [
        Route("/api/findings", get_findings),
        Route("/api/findings/{id}", get_finding_by_id),
        Route("/api/timeline", get_timeline),
        Route("/api/evidence", get_evidence),
        Route("/api/audit/{finding_id}", get_audit_for_finding),
        Route("/api/delta", get_delta, methods=["GET"]),
        Route("/api/delta", post_delta, methods=["POST"]),
        Route("/api/delta/{id}", delete_delta_item, methods=["DELETE"]),
        Route("/api/case", get_case),
        Route("/api/todos", get_todos),
        Route("/api/summary", get_summary),
        Route("/api/evidence/{path:path}/verify", verify_evidence, methods=["POST"]),
        Route("/", serve_index),
    ]
    return Starlette(routes=routes)
