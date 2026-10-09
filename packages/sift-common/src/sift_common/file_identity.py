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
# (the case, a file's key: real path, size, mtime_ns; or a list's: the tuple of
# its files' keys) -> the id of the job hashing it, while that job runs. Per
# case: a job's closing entry goes to the case that asked.
_jobs: dict[tuple, str] = {}
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
    ctime_ns: int = 0


@dataclass(frozen=True)
class Pending:
    """A hash still running: `job_id` names the `hash_complete` (or
    `hash_failed`) entry that will close it in the case's file-identity log."""

    path: str
    job_id: str


@dataclass(frozen=True)
class Batch:
    """A list of files: `done` hashed in the call, `pending` in job `job_id`
    ("" with no case: unhashed), `not_regular` refused unread."""

    done: dict[str, HashResult]
    job_id: str
    pending: list[str]
    not_regular: list[str]


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
    return HashResult(str(path), h.hexdigest(), st.st_size, st.st_dev, st.st_ino,
                      st.st_mtime_ns, st.st_ctime_ns)  # fmt: skip


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
    return Pending(str(path), _start(key, str(path), str(case_dir), requested_by))


def hash_files_for_call(
    paths, *, case_dir, requested_by: str = "", inline_limit: int = INLINE_LIMIT
) -> Batch:
    """The hashes of a list of files (a folder's manifest) for a tool call that
    must answer in time: regular files are hashed in the call while their
    summed sizes stay within `inline_limit`, and every other one in a single
    background job, as `hash_for_call` does for one file. A FIFO, device or
    directory is listed in `not_regular`, unread. Without a case the rest
    stay unhashed."""
    done: dict[str, HashResult] = {}
    rest: list[str] = []
    not_regular: list[str] = []
    budget = inline_limit
    for p in map(str, paths):
        try:
            st = os.stat(p)
        except OSError:
            rest.append(p)  # its job records why it can't be read
            continue
        if not stat.S_ISREG(st.st_mode):
            not_regular.append(p)
        elif st.st_size <= budget:
            try:
                done[p] = hash_file(p)
                budget -= st.st_size
            except (OSError, NotRegularFile):
                rest.append(p)
        else:
            rest.append(p)
    if not rest or not case_dir:
        return Batch(done, "", rest, not_regular)
    key = tuple(_file_key(p) for p in rest)
    return Batch(
        done, _start(key, rest, str(case_dir), requested_by), rest, not_regular
    )


def _file_key(path: str) -> tuple:
    try:
        st = os.stat(path)
        return (os.path.realpath(path), st.st_size, st.st_mtime_ns)
    except OSError:
        return (os.path.realpath(path), -1, -1)


def _start(key: tuple, paths, case_dir: str, requested_by: str) -> str:
    """The id of the job hashing `paths` (one path, or a list) for this case in
    this process: the running one for the same key, else a new daemon thread."""
    key = (os.path.realpath(case_dir), key)
    with _jobs_lock:
        if key in _jobs:
            return _jobs[key]
        job_id = _jobs[key] = f"hash-{uuid.uuid4().hex[:16]}"
    threading.Thread(
        target=_job,
        args=(key, job_id, paths, case_dir, requested_by),
        name=f"file-identity-{job_id}",
        daemon=True,
    ).start()
    return job_id


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _one(path: str) -> dict:
    try:
        r = hash_file(path)
        return {"path": path, "sha256": r.sha256, "size": r.size, "st_dev": r.st_dev,
                "st_ino": r.st_ino, "mtime_ns": r.mtime_ns, "ctime_ns": r.ctime_ns}  # fmt: skip
    except Exception as e:  # noqa: BLE001 -- a pending hash must always close
        return {"path": path, "error": f"{type(e).__name__}: {e}"}


def _job(key, job_id: str, paths, case_dir: str, requested_by: str) -> None:
    """Hash the job's files and close its pending hashes, either way: one
    `hash_complete` entry (a one-file job's fields at the top level, a list
    job's in `files[]`), or `hash_failed` when nothing could be read."""
    from sift_common.audit import AuditWriter

    started = _now()
    try:
        if isinstance(paths, str):
            result = _one(paths)
            files = [result]
        else:
            files = [_one(p) for p in paths]
            result = {"files": files}
    finally:
        with _jobs_lock:
            _jobs.pop(key, None)
    tool = "hash_complete" if any("sha256" in f for f in files) else "hash_failed"
    logged = AuditWriter("file-identity", audit_dir=str(Path(case_dir) / "audit")).log(
        tool=tool,
        params={"path": paths} if isinstance(paths, str) else {"files": len(paths)},
        result_summary=result,
        extra={
            "job_id": job_id,
            "requested_by": requested_by,
            "started": started,
            "finished": _now(),
            **result,
        },
    )
    if logged is None:
        logger.warning("%s (%s) was not recorded", tool, job_id)


_STAT_KEY = ("st_dev", "st_ino", "size", "mtime_ns", "ctime_ns")


def completed_hash(case_dir, path) -> str | None:
    """The hash a completed background job recorded for `path` in this case,
    taken only while the file is unchanged: the same device, inode, size,
    mtime and ctime as when it was hashed (ctime can't be set back, so a
    rewrite with its mtime set back isn't taken). Else None."""
    log = Path(case_dir) / "audit" / "file-identity.jsonl"
    try:
        st = os.stat(path)
        lines = log.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    real = os.path.realpath(path)
    now = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    found = None
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or entry.get("tool") != "hash_complete":
            continue
        for row in entry.get("files") or [entry]:
            if (
                isinstance(row, dict)
                and row.get("sha256")
                and isinstance(row.get("path"), str)
                and os.path.realpath(row["path"]) == real
                and tuple(row.get(k) for k in _STAT_KEY) == now
            ):
                found = row["sha256"]
    return found
