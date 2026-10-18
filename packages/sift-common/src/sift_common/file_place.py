"""Where a file a tool call reads or writes is, and its record in the call's
audit entry.

The records follow the field contract the audit's readers share:
- ``inputs[]``: each read as ``{path, realpath, st_dev, mnt_id}``, with its
  ``sha256`` when it isn't registered evidence (``pending:<job_id>`` while a
  large file is hashed in the background; none for a folder, which a
  run_command records with its ``folder: {files, bytes, sha256}`` digest when
  it's eligible, see ``folder_record``);
- ``input_registered[]``: a registered evidence file, by its registered path
  and the registry's SHA-256, never read again;
- ``outputs[]``: each written file as ``{path, realpath, st_dev, mnt_id,
  sha256, size, st_ino, mtime_ns}``.
``input_files``/``input_sha256s`` stay for today's readers (``listed``).
"""

from __future__ import annotations

import json
import os
import stat
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


def _folder_roots(case_dir) -> list[str]:
    """The registered folder roots' realpaths."""
    try:
        registry = json.loads(
            fi.read_regular(Path(case_dir) / "evidence.json").decode()
        )
    except (OSError, ValueError):
        return []
    files = registry.get("files") if isinstance(registry, dict) else registry
    return [os.path.realpath(e["path"]) for e in files if isinstance(e, dict)
            and e.get("kind") == "folder" and isinstance(e.get("path"), str)
            ] if isinstance(files, list) else []  # fmt: skip


def folder_record(case_dir, rec: dict, known=None) -> dict | None:
    """``{files, bytes, sha256}``: each member hashed now for its content (never
    from the registry), and their folder digest. None unless it isn't a folder
    root, is in the case on its mount or in a folder root, crosses no mount,
    holds 1 to FOLDER_FILES files of FOLDER_BYTES or less, and holds no symlink
    (a directory's too: the tool follows it) or special file, with no walk
    error and no member changed while hashed. ``known`` (realpath -> SHA-256:
    files the caller itself wrote and hashed in this run, never the registry)
    gives every member's hash when it holds them all: nothing is hashed, so
    neither the place nor the size bounds apply."""
    real, roots = rec["realpath"], _folder_roots(case_dir)
    case_real = os.path.realpath(case_dir)
    in_case = real.startswith(case_real + os.sep) and rec.get("mnt_id") == mnt_id(
        case_real
    )
    placed = in_case or any(real.startswith(r + os.sep) for r in roots)
    if real in roots or not (placed or known):
        return None
    members, size, errors, all_known = [], 0, [], bool(known)
    try:
        for top, dirs, names in os.walk(real, onerror=errors.append):
            for d in dirs:
                st = os.lstat(os.path.join(top, d))
                if not stat.S_ISDIR(st.st_mode) or st.st_dev != rec["st_dev"]:
                    return None  # a directory symlink, or another filesystem
            for n in names:
                st = os.lstat(os.path.join(top, n))
                if not stat.S_ISREG(st.st_mode):
                    return None  # a symlink or a special file
                members.append(os.path.join(top, n))
                size += st.st_size
                if all_known and members[-1] not in known:
                    if not placed:
                        return None  # not known, and not where a walk may hash
                    all_known = False
        if errors or not members:
            return None
        if all_known:
            pairs = [(p[len(real) + 1 :], known[p]) for p in members]
            return {
                "files": len(pairs),
                "bytes": size,
                "sha256": fi.folder_digest(pairs),
            }
        if len(members) > fi.FOLDER_FILES or size > fi.FOLDER_BYTES:
            return None
        hashed = [fi.hash_file(p) for p in members]  # FileChanged is an OSError
    except (OSError, fi.NotRegularFile):
        return None
    pairs = [
        (p[len(real) + 1 :], h.sha256) for p, h in zip(members, hashed, strict=True)
    ]
    return {"files": len(pairs), "bytes": sum(h.size for h in hashed),
            "sha256": fi.folder_digest(pairs)}  # fmt: skip


def input_record(
    case_dir, path, requested_by: str = "", folder: bool = False, known=None
) -> tuple[dict, dict | None]:
    """``(input, registered)`` for a file or folder a call reads: registered
    evidence links by its path to the registry's hash and isn't read; a
    folder isn't hashed, but with ``folder`` an eligible one gets its digest
    (``folder_record``, with ``known``); any other file is hashed for the call."""
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
    elif folder and case_dir and (digest := folder_record(case_dir, rec, known)):
        rec["folder"] = digest
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
