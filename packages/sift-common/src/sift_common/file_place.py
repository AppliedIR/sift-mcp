"""Where a file a tool call reads or writes is, and its record in the call's
audit entry.

The records follow the field contract the audit's readers share:
- ``inputs[]``: each read as ``{path, realpath, st_dev, mnt_id}``, with its
  ``sha256`` when it isn't registered evidence (``pending:<job_id>`` while a
  large file is hashed in the background; none for a folder);
- ``input_registered[]``: a registered evidence file, by its registered path
  and the registry's SHA-256, never read again;
- ``outputs[]``: each written file as ``{path, realpath, st_dev, mnt_id,
  sha256, size, st_ino, mtime_ns}``.
``input_files``/``input_sha256s`` stay for today's readers (``listed``).
"""

from __future__ import annotations

import os
from pathlib import Path

from sift_common import file_identity as fi

MOUNTINFO = "/proc/self/mountinfo"


def _unescape(field: str) -> str:
    return (
        field.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def mounts() -> list[tuple[int, str, str]]:
    """This process's mounts, in order: (mount id, mount point, source)."""
    try:
        lines = Path(MOUNTINFO).read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or "-" not in parts:
            continue
        rest = parts[parts.index("-") + 1 :]
        try:
            out.append(
                (
                    int(parts[0]),
                    _unescape(parts[4]),
                    _unescape(rest[1]) if len(rest) > 1 else "",
                )
            )
        except ValueError:
            continue
    return out


def mnt_id(realpath: str) -> int | None:
    """The mount id of the mount holding ``realpath`` (the last one mounted
    at the longest matching point)."""
    best, best_len = None, -1
    for mid, point, _ in mounts():
        inside = realpath == point or realpath.startswith(point.rstrip("/") + "/")
        if inside and len(point) >= best_len:
            best, best_len = mid, len(point)
    return best


def place(path) -> dict:
    """The path as given, its realpath, ``st_dev`` and mount id; a path that
    can't be resolved keeps only what could be read."""
    out: dict = {"path": str(path)}
    try:
        real = os.path.realpath(path)
        out["realpath"] = real
        out["st_dev"] = os.stat(real).st_dev
        out["mnt_id"] = mnt_id(real)
    except OSError:
        pass
    return out


def _hash(path: str, case_dir, requested_by: str):
    """The call's hash (``file_identity.hash_for_call``): a HashResult,
    ``pending:<job_id>``, or None (a large file with no case to record its
    job, or one that can't be read)."""
    try:
        r = fi.hash_for_call(
            path,
            case_dir=case_dir or "",
            requested_by=requested_by,
            inline_limit=fi.INLINE_LIMIT,  # read now: the limit in force
        )
    except (OSError, fi.NotRegularFile):
        return None
    return f"pending:{r.job_id}" if isinstance(r, fi.Pending) else r


def input_record(case_dir, path, requested_by: str = "") -> tuple[dict, dict | None]:
    """``(input, registered)`` for a file or folder a call reads: registered
    evidence links by its path to the registry's hash and isn't read; a
    folder isn't hashed; any other file is hashed for the call."""
    rec = place(path)
    real = rec.get("realpath")
    if "st_dev" not in rec:
        return rec, None  # gone, or never there
    reg = fi.registered_hash(case_dir, real) if case_dir else None
    if reg:
        return rec, {"path": real, "sha256": reg}
    if not os.path.isdir(real):
        h = _hash(real, case_dir, requested_by)
        if h is not None:
            rec["sha256"] = h if isinstance(h, str) else h.sha256
    return rec, None


def output_records(case_dir, paths, requested_by: str = "") -> list[dict]:
    """The files a call wrote, each hashed with its size, inode and mtime:
    in the call while their summed sizes stay within the inline limit, the
    rest in one background job (``pending:<job_id>``)."""
    paths = [str(p) for p in paths]
    batch = fi.hash_files_for_call(
        [p for p in paths if os.path.isfile(p)],  # a missing one: nothing to hash
        case_dir=case_dir or "",
        requested_by=requested_by,
        inline_limit=fi.INLINE_LIMIT,  # read now: the limit in force
    )
    recs = []
    for p in paths:
        rec = place(p)
        h = batch.done.get(p)
        if h is not None:
            rec.update(
                sha256=h.sha256, size=h.size, st_ino=h.st_ino, mtime_ns=h.mtime_ns
            )
        else:
            if batch.job_id and p in batch.pending:
                rec["sha256"] = f"pending:{batch.job_id}"
            try:
                st = os.stat(p)
                rec.update(size=st.st_size, st_ino=st.st_ino, mtime_ns=st.st_mtime_ns)
            except OSError:
                pass
        recs.append(rec)
    return recs


def output_record(case_dir, path, requested_by: str = "") -> dict:
    """One file a call wrote (see ``output_records``)."""
    return output_records(case_dir, [path], requested_by)[0]


def listed(inputs: list[dict], registered: list[dict]) -> tuple[list[str], list[str]]:
    """``input_files`` and ``input_sha256s`` for today's readers: each input's
    resolved path with its hash (the registry's for registered evidence; ""
    for a folder)."""
    reg = {r["path"]: r["sha256"] for r in registered}
    files = [i.get("realpath") or i["path"] for i in inputs]
    shas = [i.get("sha256") or reg.get(i.get("realpath", ""), "") for i in inputs]
    return files, shas
