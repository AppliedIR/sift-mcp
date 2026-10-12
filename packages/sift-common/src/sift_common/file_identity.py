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
# (the case, a file's key: real path, st_dev, st_ino, size, mtime_ns, ctime_ns;
# or a list's: the tuple of its files' keys) -> the id of the job hashing it,
# while that job runs. Per case: a job's closing entry goes to the case that asked.
_jobs: dict[tuple, str] = {}
_jobs_lock = threading.Lock()


class NotRegularFile(ValueError):
    """Only a regular file has an identity hash: a FIFO, device, socket or
    directory is refused without being read."""


_STAT_KEY = ("st_dev", "st_ino", "size", "mtime_ns", "ctime_ns")


def _stat_key(st) -> tuple:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class FileChanged(OSError):
    """The file changed while it was hashed (its `fields`), so no hash names
    its bytes. An OSError: callers that handle a read error handle this."""

    def __init__(self, path, fields):
        self.fields = fields
        super().__init__(f"{path} changed while it was hashed: {', '.join(fields)}")


def _changed(before: tuple, after: tuple) -> list[str]:
    return [k for k, a, b in zip(_STAT_KEY, before, after, strict=True) if a != b]


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


def open_regular(path):
    """`path` open for reading as bytes, only if it is a regular file. It is
    opened non-blocking and its descriptor checked before any read, so a
    FIFO or device is refused (NotRegularFile) without waiting or reading.
    A link is followed, and its target checked."""
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NONBLOCK)
    try:  # the descriptor is closed on any failure before fdopen owns it
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile(f"{path} is not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_regular(path) -> bytes:
    """The bytes of `path`, a regular file (see `open_regular`)."""
    with open_regular(path) as f:
        return f.read()


LINE_CAP = 16 << 20  # the longest line a case log may hold
DOC_CAP = 16 << 20  # the largest case document read whole


class CaseFileTooBig(ValueError):
    """A case log line over LINE_CAP, or a case document over DOC_CAP: refused
    by name, never held whole. Like NotRegularFile, never an OSError: a reader
    that passes over an unreadable file (`except OSError`) must not pass over
    this one. `line`: the line's number, None for a document."""

    def __init__(self, text: str, line: int | None = None):
        super().__init__(text)
        self.line = line


_HOLDS = {  # what a case file holds, for the text that refuses it (vhir's case_io.holds)
    "approvals.jsonl": "approval records", "findings.json": "findings",
    "timeline.json": "timeline events", "iocs.json": "IOCs",
    "keys.json": "signing-key records", "verification.jsonl": "0.6 approval records",
    # sift's own files
    "evidence.json": "evidence records", "todos.json": "TODOs",
    "pending-reviews.json": "staged reviews", "CASE.yaml": "case details",
    "actions.jsonl": "action records", "host-ops.json": "host-operation records",
    "host-observations.jsonl": "host observations", "host-decisions.jsonl": "host decisions",
}  # fmt: skip


def _holds(path) -> str:
    p = Path(path)
    if p.name in _HOLDS:
        return _HOLDS[p.name]
    return "audit entries" if p.parent.name == "audit" else "case records"


def _keep_a_copy(path) -> str:
    return (f"It holds the case's {_holds(path)}: keep a copy of it before you move it "
            "out of the case, then try again.")  # fmt: skip


def _case_fd(path, follow: bool = True) -> int:
    """`path` opened non-blocking and checked on the descriptor: a FIFO,
    device, socket or directory raises NotRegularFile, unread."""
    flags = os.O_RDONLY | os.O_NONBLOCK | (0 if follow else os.O_NOFOLLOW)
    fd = os.open(os.fspath(path), flags)
    try:
        mode = os.fstat(fd).st_mode
        if stat.S_ISDIR(mode):
            raise NotRegularFile(f"{path} is a folder, not a file. Put the case's "
                                 "own file back, then try again.")  # fmt: skip
        if not stat.S_ISREG(mode):
            raise NotRegularFile(
                f"{path} isn't a regular file (a named pipe, socket or device). "
                "Put the case's own file back, then try again."
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


def capped_lines(path, follow: bool = True):
    """Each line of a regular case log, as bytes with its newline; the file is
    opened and checked now. A line over LINE_CAP raises CaseFileTooBig naming
    it: no more than LINE_CAP + 2 bytes of it are read, and it is never split."""
    return _capped(os.fdopen(_case_fd(path, follow), "rb"), path)


def _capped(f, path):
    with f:
        n = 0
        while raw := f.readline(LINE_CAP + 2):
            n += 1
            # the cap counts a line's content, not its \n or \r\n
            end = 2 if raw.endswith(b"\r\n") else 1 if raw.endswith(b"\n") else 0
            if len(raw) - end > LINE_CAP:
                raise CaseFileTooBig(
                    f"{path} line {n} is longer than {LINE_CAP >> 20} MiB, so the "
                    f"file wasn't read past it. {_keep_a_copy(path)}",
                    n,
                )
            yield raw


def read_document(path, follow: bool = True) -> bytes:
    """A regular case document's bytes, read whole only when its size is at
    most DOC_CAP (checked on the descriptor before any read)."""
    with os.fdopen(_case_fd(path, follow), "rb") as f:
        size = os.fstat(f.fileno()).st_size
        data = f.read(DOC_CAP + 1) if size <= DOC_CAP else b""
    if size > DOC_CAP or len(data) > DOC_CAP:  # grown since fstat: refused too
        raise CaseFileTooBig(
            f"{path} is larger than {DOC_CAP >> 20} MiB, so it wasn't read. "
            f"{_keep_a_copy(path)}"
        )
    return data


def hash_file(path) -> HashResult:
    """The SHA-256 of the whole file, however large. The file is opened
    non-blocking and checked before any read, so a FIFO never blocks."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise NotRegularFile(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        h, read = hashlib.sha256(), 0
        while chunk := f.read(_CHUNK):
            h.update(chunk)
            read += len(chunk)
        # the bytes hashed are the file's only if nothing changed while they were read
        fields = _changed(_stat_key(st), _stat_key(os.fstat(f.fileno())))
    if fields or read != st.st_size:
        raise FileChanged(path, fields or ["size"])
    return HashResult(str(path), h.hexdigest(), st.st_size, st.st_dev, st.st_ino,
                      st.st_mtime_ns, st.st_ctime_ns)  # fmt: skip


def registered_hash(case_dir, path) -> str | None:
    """The registry's hash when `path` is a registered file (compared by its
    real path), else None. The file itself is never read: a registered input
    links to the registry by its path."""
    try:
        # a registry that isn't a regular file reads as none, and never blocks
        registry = json.loads(read_regular(Path(case_dir) / "evidence.json").decode())
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
    # the job hashes the file only while it is still as it is now
    key = (os.path.realpath(path), *_stat_key(st))
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
        return (os.path.realpath(path), *_stat_key(os.stat(path)))
    except OSError:
        return (os.path.realpath(path), -1, -1, -1, -1, -1)


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


def _one(path: str, called: tuple = ()) -> dict:
    """`called`: the file's stat key when the call asked (its job key's entry)."""
    try:
        r = hash_file(path)
        now = (r.st_dev, r.st_ino, r.size, r.mtime_ns, r.ctime_ns)
        if called and (fields := _changed(called, now)):
            raise FileChanged(path, fields)
        return {"path": path, "sha256": r.sha256, "size": r.size, "st_dev": r.st_dev,
                "st_ino": r.st_ino, "mtime_ns": r.mtime_ns, "ctime_ns": r.ctime_ns}  # fmt: skip
    except Exception as e:  # noqa: BLE001 -- a pending hash must always close
        row = {"path": path, "error": f"changed since the call: {', '.join(e.fields)}"
               if isinstance(e, FileChanged) else f"{type(e).__name__}: {e}"}  # fmt: skip
        try:  # the file as it was, so the failure is taken only while it's unchanged
            st = os.stat(path)
            row.update(size=st.st_size, st_dev=st.st_dev, st_ino=st.st_ino,
                       mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns,
                       st_mode=st.st_mode)  # fmt: skip
        except OSError:
            pass
        return row


def _called(key: tuple, paths) -> list[tuple]:
    """Each file's stat key when the call asked, from its job key (`_start`'s
    `(case, a file's key or a list's)`); () where none is known: no check."""
    fk = key[1] if len(key) > 1 else ()
    keys = [fk] if isinstance(paths, str) else list(fk)
    got = [k[1:] if isinstance(k, tuple) and len(k) == 6 and k[1] != -1 else ()
           for k in keys]  # fmt: skip
    n = 1 if isinstance(paths, str) else len(paths)
    return got if len(got) == n else [()] * n


def _job(key, job_id: str, paths, case_dir: str, requested_by: str) -> None:
    """Hash the job's files and close its pending hashes, either way: one
    `hash_complete` entry (a one-file job's fields at the top level, a list
    job's in `files[]`), or `hash_failed` when nothing could be read."""
    from sift_common.audit import AuditWriter

    started = _now()
    try:
        called = _called(key, paths)
        if isinstance(paths, str):
            result = _one(paths, called[0])
            files = [result]
        else:
            files = [_one(p, c) for p, c in zip(paths, called, strict=True)]
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


def _completed_rows(case_dir) -> dict[str, dict]:
    """Each file's last recorded background result in this case (a hash or an
    error), by real path, read from the log once."""
    try:
        raw = read_regular(Path(case_dir) / "audit" / "file-identity.jsonl")
    except (OSError, NotRegularFile):
        return {}
    lines = raw.decode("utf-8").splitlines()
    rows: dict[str, dict] = {}
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or entry.get("tool") not in (
            "hash_complete", "hash_failed",
        ):  # fmt: skip
            continue
        for row in entry.get("files") or [entry]:
            if isinstance(row, dict) and isinstance(row.get("path"), str):
                rows[os.path.realpath(row["path"])] = {
                    **row, "job_id": entry.get("job_id", "")}  # fmt: skip
    return rows


# Recorded failures already taken in this process, by (job id, real path)
_taken: set[tuple[str, str]] = set()


def completed_hashes(case_dir, paths) -> dict[str, dict]:
    """What completed background jobs recorded for these files in this case,
    `{path: {"sha256": …} or {"error": …}}`, taken only while a file is
    unchanged: the same device, inode, size, mtime and ctime as then (ctime
    can't be set back, so a rewrite with its mtime set back isn't taken; a
    file fixed after a failure has a new ctime, so it's hashed again; a
    failure also needs the same permissions, as a coarse ctime may not tick
    when they're fixed). A failure is taken once, by the call that follows its job, which stops the
    automatic retry (see `take_failures`); after that it's left out, so the
    next request hashes the file again. Files with nothing recorded are left
    out."""
    rows = _completed_rows(case_dir)
    found: dict[str, dict] = {}
    for path in map(str, paths):
        row = rows.get(os.path.realpath(path))
        try:
            st = os.stat(path)
        except OSError:
            continue
        now = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if row is None or tuple(row.get(k) for k in _STAT_KEY) != now:
            continue
        if row.get("sha256"):
            found[path] = {"sha256": row["sha256"]}
        elif row.get("error") and row.get("st_mode") == st.st_mode:
            with _jobs_lock:
                if (str(row.get("job_id", "")), os.path.realpath(path)) in _taken:
                    continue
            found[path] = {"error": row["error"], "job_id": str(row.get("job_id", ""))}
    return found


def take_failures(found: dict) -> None:
    """Mark the failures in `completed_hashes`' result as taken, so the next
    request hashes those files again. Call it only once they're used: on a
    call that starts no job of its own."""
    with _jobs_lock:
        for path, r in found.items():
            if "error" in r:
                _taken.add((r.get("job_id", ""), os.path.realpath(path)))


def completed_hash(case_dir, path) -> str | None:
    """The hash a completed background job recorded for `path` while it's
    unchanged (see `completed_hashes`), else None."""
    return completed_hashes(case_dir, [path]).get(str(path), {}).get("sha256")
