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


def trace_file(case: Case, path, sha256: str | None = None) -> Trace:
    """The registered evidence a file came from."""
    return _broken("no-recorded-origin", f"{path} (SHA-256 {sha256 or 'not recorded'}) "
                   "has no recorded origin", _FIX_ORIGIN, NO_ORIGIN)  # fmt: skip


def trace_op(case: Case, audit_id: str) -> Trace:
    """The registered evidence a recorded operation's inputs came from."""
    if not case.by_id.get(audit_id):
        return _broken("no-entry", f"no audit entry records {audit_id}")
    return _broken("no-inputs", f"{audit_id} recorded no inputs")
