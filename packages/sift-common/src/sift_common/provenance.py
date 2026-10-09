"""Provenance: trace a file, or a recorded operation, to the registered evidence
it came from, through links the case recorded and nothing else.

A link is one of: the file is a registered root (by its path); it's listed in
a registered folder's manifest; it's an earlier operation's recorded output at
the same path with the same SHA-256; it was read through a recorded mount; an
operation's recorded inputs. A path alone, a name, an order or a host never
links. A trace is graded FULL (every link recorded, to a root), DECLARED (a
link the AI asserted), AMBIGUOUS (more than one origin or root, all named) or
BROKEN (with the kind of break, what's missing and how to fix it).
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
    for log in sorted((d / "audit").glob("*.jsonl")):
        try:
            data = log.read_bytes()
        except OSError:
            continue
        for line in data.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("audit_id"), str):
                by_id[entry["audit_id"]].append((entry, line))
    return Case(d, roots, dict(by_id))


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
            root = {"path": real, "sha256": sha}
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
                }
                to = {"path": real, "sha256": root["sha256"]}
                return Trace("FULL", root, [root], [_link("manifest", frm, to)])
    return None


def _outputs(entry: dict) -> list[tuple[str, str]]:
    """An entry's recorded outputs (path, SHA-256): its output files, and its
    saved stdout."""
    rs = entry.get("result_summary")
    if not isinstance(rs, dict):
        return []
    files, shas = rs.get("output_files") or [], rs.get("output_sha256s") or []
    out = list(zip(files, shas, strict=False))
    if rs.get("output_file"):
        out.append((rs["output_file"], rs.get("output_sha256", "")))
    return [(p, h) for p, h in out if isinstance(p, str) and isinstance(h, str) and h]


def _job_hash(case: Case, real: str, job_id: str) -> str | None:
    """The hash a completed background job recorded for the file."""
    for items in case.by_id.values():
        for e, _ in items:
            if e.get("tool") == "hash_complete" and e.get("job_id") == job_id:
                for row in e.get("files") or [e]:
                    if os.path.realpath(row.get("path", "")) == real and row.get(
                        "sha256"
                    ):
                        return row["sha256"]
    return None


def trace_file(
    case: Case, path, sha256: str | None = None, *, realpath=None, _seen=frozenset()
) -> Trace:
    """The registered evidence a file came from: the file is a registered root,
    or in a registered folder's manifest; or it's an earlier operation's
    recorded output at this path with this SHA-256, traced on through that
    operation's inputs. A hash at another path never links."""
    real = realpath or os.path.realpath(path)
    sha = sha256 or ""
    found = _registered(case, real, sha)
    if found:
        return found
    if sha.startswith("pending:"):
        job = sha.split(":", 1)[1]
        sha = _job_hash(case, real, job) or ""
        if not sha:
            return _broken("hash-pending", f"{real}: hash job {job} never completed",
                           "run the step again so the file is hashed")  # fmt: skip
    producers = [
        (e, line, out_sha)
        for items in case.by_id.values()
        for e, line in items
        for out, out_sha in _outputs(e)
        if sha and out_sha == sha and os.path.realpath(out) == real
    ]
    if len(producers) == 1:
        e, line, out_sha = producers[0]
        frm, to = {"path": real, "sha256": sha}, {"path": real, "sha256": out_sha}
        return _extend(
            _trace_entry(case, e, line, _seen, to),
            _link("hash+place", frm, to, e, line),
        )
    return _broken("no-recorded-origin", f"{real} (SHA-256 {sha or 'not recorded'}) "
                   "has no recorded origin", _FIX_ORIGIN, NO_ORIGIN)  # fmt: skip


def trace_op(case: Case, audit_id: str) -> Trace:
    """The registered evidence a recorded operation's inputs came from."""
    items = case.by_id.get(audit_id)
    if not items:
        return _broken("no-entry", f"no audit entry records {audit_id}")
    return _trace_entry(case, *items[0], frozenset())


_WORST = ("BROKEN", "AMBIGUOUS", "DECLARED", "FULL")


def _extend(t: Trace, link: dict) -> Trace:
    t.links.append(link)
    return t


def _trace_entry(
    case: Case, e: dict, line: bytes, seen: frozenset, output: dict | None = None
) -> Trace:
    """An operation's trace: each recorded input's, then the operation, to the
    output being followed (else its saved stdout)."""
    aid = e["audit_id"]
    if aid in seen:
        return _broken("cycle", f"{aid} is recorded as its own origin")
    files = [f for f in e.get("input_files") or [] if isinstance(f, str)]
    if not files:
        return _broken("no-inputs", f"{aid} recorded no inputs")
    shas = e.get("input_sha256s") or []
    reals = e.get("input_realpaths") or []
    traces = [
        trace_file(case, f, shas[n] if n < len(shas) else "",
                   realpath=reals[n] if n < len(reals) else None, _seen=seen | {aid})
        for n, f in enumerate(files)
    ]  # fmt: skip
    rs = e.get("result_summary") if isinstance(e.get("result_summary"), dict) else {}
    frm = {"path": os.path.realpath(files[0]), "sha256": shas[0] if shas else ""}
    to = output or {
        "path": rs.get("output_file", ""),
        "sha256": rs.get("output_sha256", ""),
    }
    links = [link for t in traces for link in t.links]
    links.append(_link("recorded-id", frm, to, e, line))
    worst = min(traces, key=lambda t: _WORST.index(t.grade))
    roots = list({r["path"]: r for t in traces for r in t.roots}.values())
    if worst.grade != "FULL":
        return Trace(worst.grade, worst.root, roots, links, worst.candidates,
                     worst.break_, worst.reason)  # fmt: skip
    return Trace("FULL", roots[0], roots, links)
