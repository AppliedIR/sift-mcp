"""File identity: the SHA-256 of a regular file, with no size cap.

Every place that records what a file is hashes it here, so a hash in one
entry can be compared with a hash in another.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

INLINE_LIMIT = 1_000_000_000  # bytes a tool call may hash before it answers
_CHUNK = 1 << 20
_jobs: dict[tuple, str] = {}  # (real path, size, mtime_ns) -> job id, while it runs
_jobs_lock = threading.Lock()


class NotRegularFile(ValueError):
    """Only a regular file has an identity hash: a FIFO, device, socket or
    directory is refused without being read."""


@dataclass(frozen=True)
class HashResult:
    path: str
    sha256: str
    size: int
    st_dev: int
    st_ino: int
    mtime_ns: int


@dataclass(frozen=True)
class Pending:
    """A hash still running: `job_id` names the `hash_complete` (or
    `hash_failed`) entry that will close it in the case's file-identity log."""

    path: str
    job_id: str


def hash_file(path) -> HashResult:
    """The SHA-256 of the whole file, however large. The file is opened
    non-blocking and checked before any read, so a FIFO never blocks."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise NotRegularFile(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        h = hashlib.sha256()
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return HashResult(
        str(path), h.hexdigest(), st.st_size, st.st_dev, st.st_ino, st.st_mtime_ns
    )


def registered_hash(case_dir, path) -> str | None:
    """The registry's hash when `path` is a registered file (compared by its
    real path), else None. The file itself is never read: a registered input
    links to the registry by its path."""
    try:
        registry = json.loads((Path(case_dir) / "evidence.json").read_text())
    except (OSError, ValueError):
        return None
    files = registry.get("files") if isinstance(registry, dict) else registry
    real = os.path.realpath(path)
    for entry in files if isinstance(files, list) else []:
        if (
            isinstance(entry, dict)
            and entry.get("path") == real
            and entry.get("sha256")
        ):
            return entry["sha256"]
    return None


def hash_for_call(
    path, *, case_dir, requested_by: str = "", inline_limit: int = INLINE_LIMIT
) -> HashResult | Pending | None:
    """A hash for a tool call that must answer in time: a file of up to
    `inline_limit` bytes is hashed in the call; a larger one by a thread of
    this process, whose result goes to the case's `audit/file-identity.jsonl`.
    Callers asking for the same file while its thread runs share its job.
    Without a case there's nowhere to record that result: None, and nothing
    starts."""
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise NotRegularFile(f"{path} is not a regular file")
    if st.st_size <= inline_limit:
        return hash_file(path)
    if not case_dir:
        return None
    key = (os.path.realpath(path), st.st_size, st.st_mtime_ns)
    with _jobs_lock:
        if key in _jobs:
            return Pending(str(path), _jobs[key])
        job_id = _jobs[key] = f"hash-{uuid.uuid4().hex[:16]}"
    threading.Thread(
        target=_hash_job,
        args=(key, job_id, str(path), str(case_dir), requested_by),
        name=f"file-identity-{job_id}",
        daemon=True,
    ).start()
    return Pending(str(path), job_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_job(key, job_id: str, path: str, case_dir: str, requested_by: str) -> None:
    """Hash one file and close its pending hash, either way."""
    from sift_common.audit import AuditWriter

    started = _now()
    try:
        r = hash_file(path)
        tool = "hash_complete"
        result = {"sha256": r.sha256, "size": r.size, "st_ino": r.st_ino,
                  "mtime_ns": r.mtime_ns}  # fmt: skip
    except Exception as e:  # noqa: BLE001 -- a pending hash must always close
        tool, result = "hash_failed", {"error": f"{type(e).__name__}: {e}"}
    finally:
        with _jobs_lock:
            _jobs.pop(key, None)
    logged = AuditWriter("file-identity", audit_dir=str(Path(case_dir) / "audit")).log(
        tool=tool,
        params={"path": path},
        result_summary=result,
        extra={
            "job_id": job_id,
            "path": path,
            "requested_by": requested_by,
            "started": started,
            "finished": _now(),
            **result,
        },
    )
    if logged is None:
        logger.warning("%s for %s (%s) was not recorded", tool, path, job_id)
