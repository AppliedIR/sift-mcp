"""Provenance: trace a file, or a recorded operation, to the registered evidence
it came from, through links the case recorded and nothing else.

A link is one of: the file is a registered root (by its path); it's listed in
a registered folder's manifest; it's an earlier operation's recorded output at
the same path with the same SHA-256; it was read through a recorded mount; an
operation's recorded inputs. A path alone, a name, an order or a host never
links. A trace is graded FULL (every link recorded, to its roots: an
operation reading several registered files lists each), DECLARED (a link the
AI asserted), AMBIGUOUS (one file with more than one recorded origin, all
named) or BROKEN (with the kind of break, what's missing and how to fix it).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

NO_ORIGIN = "no recorded origin: made outside recorded tools"
_FIX_ORIGIN = (
    "register the original evidence and make this file with a recorded tool "
    "(run_command), or declare how it was made with log_external_action"
)


def entry_sha256(line: bytes) -> str:
    """The SHA-256 of an audit entry's line, as written (without its newline)."""
    return hashlib.sha256(line).hexdigest()


@dataclass
class Case:
    dir: Path
    roots: list[dict]  # the registry's entries: files, and folders with a manifest
    by_id: dict[str, list[tuple[dict, bytes]]]  # audit id -> (entry, its line)
    # id(entry) -> (ts, log, line): when; the trail's own order breaks a tie
    order: dict[int, tuple] = field(default_factory=dict)


@dataclass
class Trace:
    grade: str  # FULL, DECLARED, AMBIGUOUS or BROKEN
    root: dict | None = None  # {path, sha256, label}: the first root
    roots: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)  # root first
    candidates: list[dict] = field(default_factory=list)
    break_: dict | None = None  # {kind, detail, fix}
    reason: str = ""  # one line, for every grade but FULL

    def as_dict(self) -> dict:
        return {"grade": self.grade, "root": self.root, "roots": self.roots,
                "links": self.links, "candidates": self.candidates,
                "break": self.break_, "reason": self.reason}  # fmt: skip


def load_case(case_dir) -> Case:
    """The registry's roots and every audit entry with its line bytes, read once."""
    d = Path(case_dir)
    try:
        registry = json.loads((d / "evidence.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        registry = {}
    files = registry.get("files") if isinstance(registry, dict) else registry
    roots = [e for e in files or [] if isinstance(e, dict) and e.get("path")]
    by_id: dict[str, list[tuple[dict, bytes]]] = defaultdict(list)
    order: dict[int, tuple] = {}
    for n_log, log in enumerate(sorted((d / "audit").glob("*.jsonl"))):
        try:
            data = log.read_bytes()
        except OSError:
            continue
        for n, line in enumerate(data.splitlines()):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("audit_id"), str):
                by_id[entry["audit_id"]].append((entry, line))
                order[id(entry)] = (str(entry.get("ts", "")), n_log, n)
    return Case(d, roots, dict(by_id), order)


def _when(case: Case, entry: dict) -> tuple:
    return case.order.get(id(entry), (str(entry.get("ts", "")), 0, 0))


def _broken(kind: str, detail: str, fix: str = "", reason: str = "", links=()) -> Trace:
    return Trace("BROKEN", links=list(links), reason=reason or detail,
                 break_={"kind": kind, "detail": detail, "fix": fix})  # fmt: skip


def _link(method: str, frm: dict, to: dict, entry=None, line=b"") -> dict:
    return {"method": method, "audit_id": (entry or {}).get("audit_id", ""),
            "entry_sha256": entry_sha256(line) if line else "", "from": frm, "to": to}  # fmt: skip


def _manifest_rows(case: Case, folder: dict) -> list[dict]:
    """A folder root's manifest rows; none when it's missing or no longer has
    the hash recorded at registration."""
    try:
        data = (case.dir / folder["manifest_path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != folder.get("manifest_sha256"):
            return []
        rows = json.loads(data)["files"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    return [r for r in rows if isinstance(r, dict)]


def _label(root: dict) -> str:
    """Who registered a root: an acquisition, the AI, or the examiner."""
    if root.get("acquired_by"):
        return f"acquired by {root['acquired_by']}"
    return (
        "AI-registered"
        if root.get("registered_via") == "mcp"
        else "examiner-registered"
    )


def _registered(case: Case, real: str, sha256: str) -> Trace | None:
    """FULL when the path is a registered root (a file, with the registry's
    hash, unread; or a folder, with its manifest's hash), or a file listed in a
    registered folder's manifest."""
    frm = {"path": real, "sha256": sha256}
    for r in case.roots:
        if r["path"] == real:  # a file, or a folder root's own path
            sha = r.get(
                "manifest_sha256" if r.get("kind") == "folder" else "sha256", ""
            )
            root = {"path": real, "sha256": sha, "label": _label(r)}
            to = {"path": real, "sha256": root["sha256"]}
            return Trace("FULL", root, [root], [_link("registered-path", frm, to)])
    rel = os.path.relpath(real, case.dir.resolve())
    for r in case.roots:
        if r.get("kind") == "folder" and real.startswith(r["path"] + os.sep):
            row = next(
                (x for x in _manifest_rows(case, r) if x.get("path") == rel), None
            )
            if row:
                root = {
                    "path": real,
                    "sha256": row.get("sha256", ""),
                    "folder": r["path"],
                    "label": _label(r),
                }
                to = {"path": real, "sha256": root["sha256"]}
                return Trace("FULL", root, [root], [_link("manifest", frm, to)])
    return None


def _where(case: Case, record: dict):
    """A record's path on this box: wintools records its SIFT path relative to
    the case ('/' separators), never compared by its Windows path."""
    rel = record.get("sift_path")
    return str(case.dir.joinpath(*rel.split("/"))) if isinstance(rel, str) and rel else (
        record.get("path"))  # fmt: skip


def _outputs(case: Case, entry: dict) -> list[tuple[str, str]]:
    """An entry's recorded outputs (path, SHA-256): one record each
    (`outputs[]`), its output files, and its saved stdout."""
    out = [(_where(case, o), o.get("sha256")) for o in entry.get("outputs") or []
           if isinstance(o, dict)]  # fmt: skip
    rs = entry.get("result_summary")
    if not isinstance(rs, dict):
        rs = {}
    files, shas = rs.get("output_files") or [], rs.get("output_sha256s") or []
    out += list(zip(files, shas, strict=False))
    if rs.get("output_file"):
        out.append((rs["output_file"], rs.get("output_sha256", "")))
    return [(p, h) for p, h in out if isinstance(p, str) and isinstance(h, str) and h]


def _job(case: Case, real: str, job_id: str) -> tuple[str, Trace | dict]:
    """What background hash job `job_id` recorded for the file: its hash and
    the `recorded-id` link to the entry that closed the job; or a named break,
    "hash pending" while nothing has closed it, "hash failed" with its reason."""
    for items in case.by_id.values():
        for e, line in items:
            if e.get("tool") not in ("hash_complete", "hash_failed"):
                continue
            if e.get("job_id") != job_id:
                continue
            for row in e.get("files") or [e]:
                if not isinstance(row, dict):
                    continue
                if os.path.realpath(str(row.get("path", ""))) != real:
                    continue
                if row.get("sha256"):
                    frm = {"path": real, "sha256": f"pending:{job_id}"}
                    to = {"path": real, "sha256": row["sha256"]}
                    return row["sha256"], _link("recorded-id", frm, to, e, line)
                why = f"hash of {real} failed (job {job_id}): {row.get('error', '')}"
                return "", _broken("hash-failed", why, "run the step again so the "
                                   "file is hashed")  # fmt: skip
    return "", _broken("hash-pending", f"hash pending (job {job_id}): {real}",
                       "wait for the job to finish, then trace again")  # fmt: skip


def _mount_link(case, real, sha, st_dev, mnt_id, at, seen) -> Trace | None:
    """A file under a recorded mount point links only by that mount: the same
    filesystem (st_dev, and the mount id where both record one), read inside
    the mount's recorded life, which ends at the first `umount` entry naming
    that point's realpath and mount id. None when no recorded mount holds the
    path."""
    entries = [(e, line) for items in case.by_id.values() for e, line in items]
    under = [
        (e, line, p)
        for e, line in entries
        if isinstance(e.get("mount"), dict)
        for p in e["mount"].get("points") or []
        if isinstance(p, dict)
        and isinstance(p.get("realpath"), str)
        and (real + os.sep).startswith(p["realpath"].rstrip(os.sep) + os.sep)
    ]
    if not under:
        return None
    for e, line, p in under:
        start = _when(case, e)
        end = min((_when(case, u) for u, _ in entries if isinstance(u.get("umount"), dict)
                   and u["umount"].get("realpath") == p["realpath"]
                   and u["umount"].get("mnt_id") == p.get("mnt_id")
                   and _when(case, u) >= start), default=None)  # fmt: skip
        if (st_dev is not None and p.get("st_dev") == st_dev
                and (mnt_id is None or p.get("mnt_id") is None or mnt_id == p["mnt_id"])
                and (at is None or (start <= at and (end is None or at <= end)))):  # fmt: skip
            to = {"path": p["realpath"], "sha256": ""}
            trace = _trace_entry(case, e, line, seen, to)
            return _extend(trace, _link("recorded-mount", {"path": real, "sha256": sha}, to,
                                        e, line))  # fmt: skip
    return _broken("mount-mismatch", f"{real} is under a recorded mount point, but not "
                   "read from that mount's filesystem during its recorded life",
                   "read it through the recorded mount, or record the mount it was "
                   "read from")  # fmt: skip


def trace_file(
    case: Case, path, sha256: str | None = None, *, realpath=None, st_dev=None, mnt_id=None,
    _at=None, _seen=frozenset(),
) -> Trace:  # fmt: skip
    """The registered evidence a file came from: the file is a registered root,
    or in a registered folder's manifest; or it was read through a recorded
    mount of a registered image (its st_dev matching, inside the mount's life);
    or it's an earlier operation's recorded output at this path with this
    SHA-256, traced on through that operation's inputs ("earlier": before the
    reading entry, in time, then in the trail's order). A hash at another path
    never links.

    An ingest accepts an input whose trace is FULL, and refuses any other with
    the trace's `break_["fix"]`, or its `reason` when it has no break."""
    real = realpath or os.path.realpath(path)
    sha = sha256 or ""
    found = _registered(case, real, sha) or _mount_link(
        case, real, sha, st_dev, mnt_id, _at, _seen
    )
    if found:
        return found
    via = []  # the job link, when the file's own hash was recorded pending
    if sha.startswith("pending:"):
        sha, got = _job(case, real, sha.split(":", 1)[1])
        if not sha:
            return got
        via = [got]
    # each recorded output at this path; one recorded pending is taken through
    # its job, and while no job gives it a hash, that's the named break
    producers, waiting = [], None
    for items in case.by_id.values():
        for e, line in items:
            if _at is not None and _when(case, e) >= _at:
                continue  # only an earlier operation can be its origin
            for out, out_sha in _outputs(case, e):
                if os.path.realpath(out) != real:
                    continue
                job_link = None
                if out_sha.startswith("pending:"):
                    out_sha, got = _job(case, real, out_sha.split(":", 1)[1])
                    if not out_sha:
                        waiting = waiting or got
                        continue
                    job_link = got
                if sha and out_sha == sha:
                    producers.append((e, line, out_sha, job_link))
    if len(producers) > 1:  # never the last writer: each is named
        named = [{"audit_id": e["audit_id"], "entry_sha256": entry_sha256(line),
                  "path": real, "sha256": h} for e, line, h, _j in producers]  # fmt: skip
        return Trace("AMBIGUOUS", candidates=named, reason=f"{real} is a recorded "
                     f"output of {len(named)} operations: " + ", ".join(
                         x["audit_id"] for x in named))  # fmt: skip
    if producers:
        e, line, out_sha, job_link = producers[0]
        frm, to = {"path": real, "sha256": sha}, {"path": real, "sha256": out_sha}
        t = _trace_entry(case, e, line, _seen, to)
        for link in ([job_link] if job_link else []) + via:  # the jobs' hashes
            t = _extend(t, link)
        return _extend(t, _link("hash+place", frm, to, e, line))
    if waiting is not None:
        return waiting
    return _broken("no-recorded-origin", f"{real} (SHA-256 {sha or 'not recorded'}) "
                   "has no recorded origin", _FIX_ORIGIN, NO_ORIGIN)  # fmt: skip


def trace_op(case: Case, audit_id: str) -> Trace:
    """The registered evidence a recorded operation's inputs came from."""
    items = case.by_id.get(audit_id)
    if not items:
        return _broken("no-entry", f"no audit entry records {audit_id}")
    if len(items) > 1:  # until ids are unique: never the last copy
        named = [{"audit_id": audit_id, "entry_sha256": entry_sha256(line),
                  "tool": e.get("tool", "")} for e, line in items]  # fmt: skip
        return Trace("AMBIGUOUS", candidates=named,
                     reason=f"{audit_id} is on {len(items)} audit entries")  # fmt: skip
    return _trace_entry(case, *items[0], frozenset())


_WORST = ("BROKEN", "AMBIGUOUS", "DECLARED", "FULL")


def _extend(t: Trace, link: dict) -> Trace:
    t.links.append(link)
    return t


def _inputs(case: Case, e: dict) -> list[dict]:
    """An entry's inputs: one record each (`inputs[]`), else the parallel lists.
    An input the AI declared is marked: `found: declared` or `declared: true`
    on its record, or, in the lists, one the AI listed (`llm`) that isn't in
    the command."""
    if isinstance(e.get("inputs"), list):
        return [{"path": _where(case, i), "sha256": i.get("sha256") or "",
                 "realpath": i.get("realpath"), "st_dev": i.get("st_dev"),
                 "mnt_id": i.get("mnt_id"),
                 "declared": i.get("found") == "declared" or i.get("declared") is True}
                for i in e["inputs"] if isinstance(i, dict) and isinstance(_where(case, i), str)]  # fmt: skip
    files = e.get("input_files") or []
    shas = e.get("input_sha256s") or []
    reals = e.get("input_realpaths") or []
    devs = e.get("input_st_devs") or []
    mnts = e.get("input_mnt_ids") or []
    command = (e.get("params") or {}).get("command")
    said = {str(t) for t in command} if isinstance(command, list) else set()
    said |= {os.path.realpath(t) for t in said}
    llm = e.get("input_detection_method") == "llm"
    return [{"path": f, "sha256": shas[n] if n < len(shas) else "",
             "realpath": reals[n] if n < len(reals) else None,
             "st_dev": devs[n] if n < len(devs) else None,
             "mnt_id": mnts[n] if n < len(mnts) else None,
             "declared": llm and f not in said and os.path.realpath(f) not in said}
            for n, f in enumerate(files) if isinstance(f, str)]  # fmt: skip


def _trace_entry(
    case: Case, e: dict, line: bytes, seen: frozenset, output: dict | None = None
) -> Trace:
    """An operation's trace: each recorded input's, then the operation, to the
    output being followed (else its saved stdout)."""
    aid = e["audit_id"]
    if aid in seen:
        return _broken("cycle", f"{aid} is recorded as its own origin")
    inputs = _inputs(case, e)
    if not inputs:
        return _broken("no-inputs", f"{aid} recorded no inputs")
    traces = []
    for i in inputs:
        t = trace_file(case, i["path"], i["sha256"], realpath=i["realpath"],
                       st_dev=i["st_dev"], mnt_id=i["mnt_id"], _at=_when(case, e),
                       _seen=seen | {aid})  # fmt: skip
        if i["declared"] and t.grade == "FULL":  # an input only the AI named
            f = {
                "path": i["realpath"] or os.path.realpath(i["path"]),
                "sha256": i["sha256"],
            }
            t = Trace("DECLARED", t.root, t.roots, t.links + [_link("declared", f, f, e, line)],
                      reason=f"declared by the AI: {f['path']}, an input of {aid}")  # fmt: skip
        traces.append(t)
    rs = e.get("result_summary") if isinstance(e.get("result_summary"), dict) else {}
    first = inputs[0]
    frm = {"path": first["realpath"] or os.path.realpath(first["path"]),
           "sha256": first["sha256"]}  # fmt: skip
    to = output or {
        "path": rs.get("output_file", ""),
        "sha256": rs.get("output_sha256", ""),
    }
    # an entry the AI declared (log_external_action) links as declared
    declared = e.get("declared") is True or e.get("tool") == "log_external_action"
    links = [link for t in traces for link in t.links]
    links.append(_link("declared" if declared else "recorded-id", frm, to, e, line))
    worst = min(traces, key=lambda t: _WORST.index(t.grade))
    roots = list({r["path"]: r for t in traces for r in t.roots}.values())
    if worst.grade in ("BROKEN", "AMBIGUOUS"):
        return Trace(worst.grade, worst.root, roots, links, worst.candidates,
                     worst.break_, worst.reason)  # fmt: skip
    if declared:
        reason = f"declared by the AI: {aid} ({e.get('tool', '')})"
        return Trace("DECLARED", roots[0], roots, links, reason=reason)
    if worst.grade != "FULL":
        return Trace(worst.grade, worst.root, roots, links, worst.candidates,
                     worst.break_, worst.reason)  # fmt: skip
    return Trace("FULL", roots[0], roots, links)
