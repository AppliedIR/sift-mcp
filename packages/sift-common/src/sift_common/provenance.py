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

import codecs
import hashlib
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

NO_ORIGIN = "no recorded origin: made outside recorded tools"
_FIX_ORIGIN = (
    "register the original evidence and make this file with a recorded tool "
    "(run_command), or declare how it was made with log_external_action"
)


_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


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
    # indexes built once, on first use: folders' manifest rows, recorded
    # outputs by real path, hash jobs, mounts and unmounts
    cache: dict = field(default_factory=dict, repr=False)


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


def _before(case: Case, entry: dict, at: tuple) -> bool:
    """Whether `entry` came before `at`: earlier in time, or at the same time
    and earlier in the same log. A tie across logs is neither before nor after."""
    ts, log, n = _when(case, entry)
    return ts < at[0] or (ts == at[0] and log == at[1] and n < at[2])


def _after(case: Case, entry: dict, at: tuple) -> bool:
    ts, log, n = _when(case, entry)
    return ts > at[0] or (ts == at[0] and log == at[1] and n > at[2])


def _not_before(case: Case, entry: dict, at: tuple) -> bool:
    """Whether `entry` came at or after `at`: later in time, or at the same time
    and not earlier in the same log. Logs have no order between them."""
    ts, log, n = _when(case, entry)
    return ts > at[0] or (ts == at[0] and log == at[1] and n >= at[2])


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


def _other_hash(real: str, recorded: str, registered: str) -> Trace | None:
    """A break when the operation recorded a hash for a registered file and it
    isn't the registered one: those weren't the registered bytes."""
    if (
        recorded
        and not recorded.startswith("pending:")
        and registered
        and (recorded != registered)
    ):
        return _broken("hash-mismatch", f"{real} was recorded with SHA-256 {recorded}, "
                       f"but is registered with {registered}", "verify the evidence "
                       "(vhir evidence verify), then run the step again")  # fmt: skip
    return None


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
            if r.get("kind") != "folder" and (bad := _other_hash(real, sha256, sha)):
                return bad
            root = {"path": real, "sha256": sha, "label": _label(r)}
            to = {"path": real, "sha256": root["sha256"]}
            return Trace("FULL", root, [root], [_link("registered-path", frm, to)])
    rel = os.path.relpath(real, case.dir.resolve())
    for r in case.roots:
        if r.get("kind") == "folder" and real.startswith(r["path"] + os.sep):
            key = ("rows", r["path"])
            if key not in case.cache:
                case.cache[key] = {x.get("path"): x for x in _manifest_rows(case, r)}
            row = case.cache[key].get(rel)
            if row and (bad := _other_hash(real, sha256, row.get("sha256", ""))):
                return bad
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


def _index(case: Case, name: str, build) -> dict:
    """An index of the trail, built once per case: `build(entry, line)` gives
    the (key, value) pairs each entry adds."""
    if name not in case.cache:
        index: dict = defaultdict(list)
        for items in case.by_id.values():
            for e, line in items:
                for key, value in build(e, line):
                    index[key].append(value)
        case.cache[name] = index
    return case.cache[name]


def _job(case: Case, real: str, job_id: str) -> tuple[str, Trace | dict]:
    """What background hash job `job_id` recorded for the file: its hash and
    the `recorded-id` link to the entry that closed the job; or a named break,
    "hash pending" while nothing has closed it, "hash failed" with its reason.
    AMBIGUOUS, each named, when the closing entry's id is on several entries
    or two closing entries disagree."""
    closes = _index(case, "jobs", lambda e, line: [
        ((e.get("job_id"), os.path.realpath(str(row.get("path", "")))), (e, line, row))
        for row in (e.get("files") or [e]) if isinstance(row, dict)]
        if e.get("tool") in ("hash_complete", "hash_failed") else []).get((job_id, real), [])  # fmt: skip
    if not closes:
        return "", _broken("hash-pending", f"hash pending (job {job_id}): {real}",
                           "wait for the job to finish, then trace again")  # fmt: skip
    if len({(r.get("sha256"), r.get("error")) for _e, _l, r in closes}) > 1:
        named = [{"audit_id": e.get("audit_id", ""), "entry_sha256": entry_sha256(line),
                  "path": real, "sha256": r.get("sha256", "")} for e, line, r in closes]  # fmt: skip
        return "", Trace("AMBIGUOUS", candidates=named, reason=f"job {job_id} was closed "
                         f"{len(named)} times for {real}, with different results")  # fmt: skip
    e, line, row = closes[0]
    if (twice := _one_entry(case, e.get("audit_id", ""))) is not None:
        return "", twice
    if row.get("sha256"):
        frm = {"path": real, "sha256": f"pending:{job_id}"}
        to = {"path": real, "sha256": row["sha256"]}
        return row["sha256"], _link("recorded-id", frm, to, e, line)
    why = f"hash of {real} failed (job {job_id}): {row.get('error', '')}"
    return "", _broken("hash-failed", why, "run the step again so the file is hashed")


def _mount_link(case, real, sha, st_dev, mnt_id, at, seen) -> Trace | None:
    """A file under a recorded mount point links only by that mount: the same
    filesystem (st_dev, and the mount id where both record one), read inside
    the mount's recorded life, which ends at the first `umount` entry naming
    that point's realpath and mount id; with no read time, only while the
    mount is still live. None when no recorded mount holds the path."""
    points = _index(case, "mounts", lambda e, line: [
        ("point", (e, line, p)) for p in (e["mount"].get("points") or [])
        if isinstance(p, dict) and isinstance(p.get("realpath"), str)]
        if isinstance(e.get("mount"), dict) else []).get("point", [])  # fmt: skip
    entries = _index(case, "umounts", lambda e, line: [("umount", (e, line))]
                     if isinstance(e.get("umount"), dict) else []).get("umount", [])  # fmt: skip
    under = [(e, line, p) for e, line, p in points
             if (real + os.sep).startswith(p["realpath"].rstrip(os.sep) + os.sep)]  # fmt: skip
    if not under:
        return None
    matches = []
    for e, line, p in under:
        start = _when(case, e)
        # this mount's unmounts: its point's realpath and mount id, not before it
        ends = [u for u, _ in entries if u["umount"].get("realpath") == p["realpath"]
                and u["umount"].get("mnt_id") == p.get("mnt_id")
                and not _before(case, u, start)]  # fmt: skip
        # live at the read: mounted not after it, and no unmount before it (a tie
        # across logs counts as neither); with no read time, only if never unmounted
        live = (not ends if at is None else not _after(case, e, at)
                and not any(_before(case, u, at) for u in ends))  # fmt: skip
        if (st_dev is not None and p.get("st_dev") == st_dev
                and (mnt_id is None or p.get("mnt_id") is None or mnt_id == p["mnt_id"])
                and live):  # fmt: skip
            matches.append((e, line, p))
    if (
        len(matches) > 1
    ):  # more than one mount could have served the read: never the first
        named = [{"audit_id": e.get("audit_id", ""), "entry_sha256": entry_sha256(line),
                  "path": p["realpath"], "image": e["mount"].get("image", "")}
                 for e, line, p in matches]  # fmt: skip
        return Trace("AMBIGUOUS", candidates=named, reason=f"{real} could have been read "
                     f"through {len(named)} recorded mounts: " + ", ".join(
                         x["audit_id"] for x in named))  # fmt: skip
    if matches:
        e, line, p = matches[0]
        to = {"path": p["realpath"], "sha256": ""}
        trace = _trace_entry(case, e, line, seen, to)
        return _extend(trace, _link("recorded-mount", {"path": real, "sha256": sha}, to,
                                    e, line))  # fmt: skip
    why = (" (no read time recorded, so only a mount still live counts)"
           if at is None else "")  # fmt: skip
    return _broken("mount-mismatch", f"{real} is under a recorded mount point, but not "
                   f"read from that mount's filesystem during its recorded life{why}",
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
    outputs = _index(case, "outputs", lambda e, line: [
        (os.path.realpath(out), (e, line, h)) for out, h in _outputs(case, e)])  # fmt: skip
    for e, line, out_sha in outputs.get(real, []):
        if _at is not None and _not_before(case, e, _at):
            continue  # only an earlier operation can be its origin
        job_link = None
        if out_sha.startswith("pending:"):
            out_sha, got = _job(case, real, out_sha.split(":", 1)[1])
            if not out_sha:
                if waiting is None or got.grade == "AMBIGUOUS":  # never lost to order
                    waiting = got
                continue
            job_link = got
        if sha and sha != _EMPTY_SHA256 and out_sha == sha:  # empty: no origin
            producers.append((e, line, out_sha, job_link))
    if waiting is not None and waiting.grade == "AMBIGUOUS":
        return waiting  # an origin that can't be named isn't passed over for another
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
    return _trace_entry(case, *items[0], frozenset())


def _one_entry(case: Case, audit_id: str) -> Trace | None:
    """AMBIGUOUS, naming each, when one audit id is on several entries, however
    the trace reached it: never the last copy (until ids are unique)."""
    items = case.by_id.get(audit_id) or []
    if len(items) < 2:
        return None
    named = [{"audit_id": audit_id, "entry_sha256": entry_sha256(line),
              "tool": e.get("tool", "")} for e, line in items]  # fmt: skip
    return Trace("AMBIGUOUS", candidates=named,
                 reason=f"{audit_id} is on {len(items)} audit entries")  # fmt: skip


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
    if (twice := _one_entry(case, aid)) is not None:
        return twice
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


# --- Artifacts: what a finding cites, checked against what it quotes ---------

ARTIFACT_GRADES = ("CITED-UNVERIFIED", "BROKEN", "AMBIGUOUS", "DECLARED", "FULL")
_ENRICHMENT = ("triage", "threat_intel")  # fields written by enrichment, not evidence
# opensearch-mcp's queries; from 0.6.4 each records the ingests its results came from
_QUERIES = frozenset({"idx_search", "idx_count", "idx_aggregate", "idx_get_event",
                      "idx_timeline", "idx_field_values", "idx_case_summary",
                      "idx_list_detections", "idx_host_inventory"})  # fmt: skip
BEFORE_064 = "recorded before 0.6.4"


def _norm(text: str) -> str:
    return " ".join(text.split())


def quotable(content) -> bool:
    """Whether a quote has any text to check (a letter or digit), not only
    whitespace, ellipses or punctuation."""
    return any(ch.isalnum() for ch in str(content or ""))


def _quote_lines(content: str) -> list[str]:
    """A quote's lines, normalized; blank lines and elisions ("...") skipped."""
    lines = [_norm(line) for line in str(content).splitlines()]
    return [line for line in lines if line and line not in ("...", "…")]


_QUOTE_FILE_CAP = 64 << 20  # a recorded output file larger than this isn't read
_CHUNK = 1 << 20


def _found_in(path, sha256, lines: list[str], cap: int | None) -> tuple[set, str]:
    """Which quoted lines a saved file holds, read in bounded chunks with an
    overlap (whitespace normalized across them), the file counted only when it
    still has its recorded SHA-256. Returns (found, why skipped): a file over
    `cap` isn't read at all, and says so."""
    try:
        size = os.path.getsize(path)
    except (OSError, TypeError):
        return set(), ""
    if cap is not None and size > cap:
        return set(), f"output too large to check ({path})"
    if not sha256:
        return set(), ""
    digest = hashlib.sha256()
    decode = codecs.getincrementaldecoder("utf-8")(errors="replace").decode
    keep = max((len(q) for q in lines), default=0)
    found, carry = set(), ""
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK), b""):
                digest.update(chunk)
                text = re.sub(r"\s+", " ", decode(chunk))
                if carry.endswith(" ") and text.startswith(" "):
                    text = text[1:]
                window = carry + text
                found |= {q for q in lines if q in window}
                carry = window[-keep:] if keep else ""
    except OSError:
        return set(), ""
    return (found if digest.hexdigest() == sha256 else set()), ""


def _saved_values(path, sha256) -> list[str] | None:
    """A saved response's values as returned: the JSON decoded, every value
    normalized; the text itself when it isn't JSON. None when it's missing or
    no longer has its recorded SHA-256. Never the JSON-escaped text."""
    try:
        if os.path.getsize(path) > _QUOTE_FILE_CAP:
            return None
        data = Path(path).read_bytes()
    except (OSError, TypeError):
        return None
    if not sha256 or hashlib.sha256(data).hexdigest() != sha256:
        return None
    text = data.decode("utf-8", errors="replace")
    try:
        decoded = json.loads(text)
    except ValueError:
        return [_norm(text)]
    return [v for _f, v in _flat(decoded)]


def _in_values(quote: list[str], values: list[str]) -> bool:
    return all(any(q in v for v in values) for q in quote)


def _unverified(why: str, links=()) -> Trace:
    return Trace("CITED-UNVERIFIED", links=list(links), reason=why,
                 break_={"kind": "cited-unverified", "detail": why,
                         "fix": "quote the output the cited operation produced"})  # fmt: skip


def _run_missing(case: Case, e: dict, quote: list[str]) -> tuple[list[str], list[str]]:
    """The quoted lines a run's saved output and recorded output files don't
    hold, each file only while it has its recorded hash; and the files too
    large to check. The saved stdout is searched first, then each output file
    (up to the size cap) only while lines are still missing."""
    rs = e.get("result_summary") if isinstance(e.get("result_summary"), dict) else {}
    missing, skipped = list(quote), []
    sources = [(rs.get("output_file"), rs.get("output_sha256"), None)]
    sources += [(p, h, _QUOTE_FILE_CAP) for p, h in _outputs(case, e)]
    for path, sha256, cap in sources:
        if not missing:
            break
        if not path:
            continue
        if isinstance(sha256, str) and sha256.startswith("pending:"):
            sha256, got = _job(case, os.path.realpath(path), sha256.split(":", 1)[1])
            if not sha256:  # the job is still running or failed: not checkable yet
                skipped.append(got.reason)
                continue
        found, why = _found_in(path, sha256, missing, cap)
        if why:
            skipped.append(why)
        missing = [q for q in missing if q not in found]
    return missing, skipped


def _flat(record, prefix: str = "") -> list[tuple[str, str]]:
    """(dotted field, normalized value) for every scalar in a returned record."""
    if isinstance(record, dict):
        return [x for k, v in record.items() for x in _flat(v, f"{prefix}{k}.")]
    if isinstance(record, list):
        return [x for v in record for x in _flat(v, prefix)]
    # a string as returned; any other scalar as JSON spells it (true, null, 3)
    text = record if isinstance(record, str) else json.dumps(record)
    return [(prefix.rstrip("."), _norm(text))]


def _reference_link(e: dict, line: bytes) -> dict:
    """The link to the operation that looked reference data up."""
    ref = e.get("reference") if isinstance(e.get("reference"), dict) else {}
    resp = ref.get("response") if isinstance(ref.get("response"), dict) else {}
    link = _link("reference", {"path": "", "sha256": ""},
                 {"path": resp.get("path", ""), "sha256": resp.get("sha256", "")}, e, line)  # fmt: skip
    link["reference"] = {"source": ref.get("source", ""),
                         "source_version": ref.get("source_version", "")}  # fmt: skip
    return link


def _reference(case: Case, e: dict, line: bytes) -> Trace:
    """Reference data (threat intel, a triage baseline) links to the operation
    that looked it up; it never stands in for evidence."""
    link = _reference_link(e, line)
    ref = e.get("reference") if isinstance(e.get("reference"), dict) else {}
    why = f"reference data from {ref.get('source') or e.get('tool', '')}, not evidence"
    return Trace("BROKEN", links=[link], reason=why,
                 break_={"kind": "reference", "detail": why, "fix": ""})  # fmt: skip


def trace_artifact(case: Case, audit_id: str, content: str) -> Trace:
    """A finding artifact: its quoted content checked against what the cited
    operation produced, then its chain to registered evidence.

    - A run: each quoted line must be in its saved output, or in one of its
      recorded output files, unchanged since; then the run's trace.
    - A query: the saved response must be unchanged; each line must be in a
      returned record (a document query, then only the matched records are
      followed through their ingests) or in the response (a summary, then
      every ingest it counted is followed).
    - Reference data (a lookup) links to the operation that looked it up,
      graded BROKEN "reference". A line found only in a record's enrichment
      fields links to the operation that wrote them, and the record is
      followed to its evidence as usual.
    - A query logged before 0.6.4 recorded nothing to follow: BROKEN, "recorded
      before 0.6.4".
    A quote the operation didn't produce is CITED-UNVERIFIED."""
    items = case.by_id.get(audit_id) or []
    if len(items) != 1:
        return trace_op(case, audit_id)  # no entry, or one id on several
    e, line = items[0]
    quote = _quote_lines(content)
    if not quote or not quotable(content):  # a placeholder: nothing to check
        return _unverified(f"nothing quotable was given for {audit_id}: quote the "
                           "output it produced")  # fmt: skip
    if isinstance(e.get("reference"), dict):
        resp = e["reference"].get("response") or {}
        values = _saved_values(resp.get("path"), resp.get("sha256")) if resp else None
        if resp and (values is None or not _in_values(quote, values)):
            return _unverified(f"the quote isn't in {audit_id}'s saved response")
        return _reference(case, e, line)
    params = e.get("params") if isinstance(e.get("params"), dict) else {}
    if "result_docs" in params or "result_ingests" in params or "response" in e:
        return _trace_query(case, e, line, params, quote)
    if e.get("tool") in _QUERIES:  # neither results nor a response: an older query
        return _broken("recorded-before-0.6.4", f"{audit_id} was {BEFORE_064}: it "
                       "records no results to follow", "run the query again and cite that",
                       reason=f"{BEFORE_064}: {audit_id} records no results to follow")  # fmt: skip
    missing, skipped = _run_missing(case, e, quote)
    if missing:
        return _unverified(f"{missing[0]!r} isn't in {audit_id}'s saved output or its "
                           "recorded output files, as they were recorded"
                           + "".join(f"; {why}" for why in skipped))  # fmt: skip
    return trace_op(case, audit_id)


def _trace_query(
    case: Case, e: dict, line: bytes, params: dict, quote: list[str]
) -> Trace:
    aid = e["audit_id"]
    docs = [d for d in params.get("result_docs") or [] if isinstance(d, dict)]
    ingests = [i for i in params.get("result_ingests") or [] if isinstance(i, str)]
    if not docs and not ingests:
        return _broken("no-results-recorded", f"{aid} recorded no results to follow",
                       "run the query again and cite that")  # fmt: skip
    resp = e.get("response") if isinstance(e.get("response"), dict) else {}
    values = _saved_values(resp.get("path"), resp.get("sha256"))
    if values is None:
        return _unverified(
            f"{aid}'s saved response is missing or changed since the query"
        )
    if not _in_values(quote, values):
        return _unverified(f"the quote isn't in what {aid} returned")
    if docs and e.get("tool") != "idx_list_detections":
        return _match_back(case, e, line, docs, quote)
    # a summary (or detections) counts records it can't trace: never FULL
    missing = _count(params.get("result_ingests_missing"))
    overflow = _count(params.get("result_ingests_overflow"))
    if missing:
        return _broken("ingests-unrecorded", f"{aid} counted {missing} documents with "
                       "no recorded ingest", "query only records an ingest wrote, and "
                       "cite that")  # fmt: skip
    if overflow:
        return _broken("ingests-unrecorded", f"{aid}: ingests not fully listed "
                       f"({overflow})", "narrow the query so every ingest it counts "
                       "is listed, and cite that")  # fmt: skip
    follow = [(d.get("ingest_audit_id", ""), d) for d in docs] or [
        (i, None) for i in ingests
    ]
    return _follow(case, e, line, follow)


def _count(value) -> int:
    return value if isinstance(value, int) and value > 0 else 0


def _match_back(
    case: Case, e: dict, line: bytes, docs: list[dict], quote: list[str]
) -> Trace:
    """Each quoted line in a returned record; only those records are followed.
    A line found only in a record's enrichment fields also links to the
    operation that wrote them: reference data, annotated, never the grade."""
    try:
        returned = json.loads(Path(e["response"]["path"]).read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError):
        returned = {}
    records = (
        returned.get("results")
        if isinstance(returned.get("results"), list)
        else [returned]
    )
    by_key = {(d.get("_index"), d.get("_id")): d for d in docs}
    followed, enriched = {}, {}  # enriched: record -> the groups its lines matched
    for q in quote:
        hits = [
            (r, f)
            for r in records
            if isinstance(r, dict)
            for f, v in _flat(r)
            if q in v
        ]
        ev = [r for r, f in hits if f.split(".")[0] not in _ENRICHMENT]
        if not hits:
            return _unverified(f"{q!r} is in no record {e['audit_id']} returned")
        for r in ev or [r for r, _f in hits]:
            d = by_key.get((r.get("_index"), r.get("_id")))
            if d is None:
                return _broken("no-results-recorded", f"{e['audit_id']} didn't record the "
                               f"record {r.get('_id')} it returned")  # fmt: skip
            key = (d.get("_index"), d.get("_id"))
            followed[key] = d
            if not ev:
                enriched.setdefault(key, set()).update(
                    f.split(".")[0] for hit, f in hits if hit is r
                )
    t = _follow(
        case, e, line, [(d.get("ingest_audit_id", ""), d) for d in followed.values()]
    )
    notes = []
    for key, groups in enriched.items():  # each record's own steps, per group matched
        d = followed[key]
        for group in sorted(groups):
            ops = _group_ops(d.get("enrichment"), group)
            if not ops:
                return _broken("reference-not-recorded", f"{e['audit_id']}: record "
                               f"{d.get('_id')}'s {group} data names no step that wrote it",
                               links=t.links)  # fmt: skip
            for op in ops:
                found = case.by_id.get(op) or []
                if not found:
                    return _broken("reference-not-recorded", f"{e['audit_id']}: record "
                                   f"{d.get('_id')}'s {group} data is from {op}, which "
                                   "isn't recorded", "enrich again, then query and cite that",
                                   links=t.links)  # fmt: skip
                if (twice := _one_entry(case, op)) is not None:
                    # the worse grade stands, with the evidence's links
                    if _WORST.index(t.grade) < _WORST.index("AMBIGUOUS"):
                        t.candidates += twice.candidates
                        return t
                    return Trace("AMBIGUOUS", t.root, t.roots, t.links,
                                 t.candidates + twice.candidates, None, twice.reason)  # fmt: skip
                link = _reference_link(*found[0])
                t.links.append(link)
                ref = link["reference"]
                notes.append(f"reference: {ref['source'] or found[0][0].get('tool', '')}, "
                             f"{ref['source_version'] or 'version not recorded'}, op {op}")  # fmt: skip
    if notes:
        t.reason = "; ".join([t.reason, *notes] if t.reason else notes)
    return t


def _group_ops(groups, group: str) -> list[str]:
    """The step ids a returned record names for one enrichment group."""
    v = groups.get(group) if isinstance(groups, dict) else None
    return [v] if isinstance(v, str) else [x for x in v or [] if isinstance(x, str)]


def _follow(case: Case, e: dict, line: bytes, follow: list) -> Trace:
    """Each followed record's ingest traced to its roots, its recorded original
    compared with them; then the query's own link per record."""
    if not follow:
        return _broken("no-results-recorded", f"{e['audit_id']}: no returned record "
                       "was followed")  # fmt: skip
    traces, links = [], []
    for ingest, doc in follow:
        t = trace_op(case, ingest) if ingest else _broken(
            "no-results-recorded", f"{e['audit_id']} returned a record with no ingest")  # fmt: skip
        if doc is not None and t.grade in ("FULL", "DECLARED"):
            original = doc.get("original_sha256")
            stamped = {original} if isinstance(original, str) else set(original or [])
            reached = {r.get("sha256") for r in t.roots}
            if stamped - {""} and stamped != reached:
                t = _broken("stamp-mismatch", f"record {doc.get('_id')} is stamped as from "
                            f"{sorted(stamped)}, but its chain reaches {sorted(reached)}",
                            links=t.links)  # fmt: skip
        traces.append(t)
        links += t.links
        link = _link(
            "recorded-id",
            {"path": "", "sha256": ""},
            {"path": "", "sha256": ""},
            e,
            line,
        )
        if doc is not None:
            link["document"] = {"_index": doc.get("_index", ""), "_id": doc.get("_id", ""),
                                "content_hash": doc.get("content_hash", "")}  # fmt: skip
        links.append(link)
    worst = min(traces, key=lambda t: _WORST.index(t.grade))
    roots = list({r["path"]: r for t in traces for r in t.roots}.values())
    if worst.grade != "FULL":
        return Trace(worst.grade, worst.root, roots, links, worst.candidates,
                     worst.break_, worst.reason)  # fmt: skip
    return Trace("FULL", roots[0], roots, links)


def finding_grade(artifacts: list[Trace]) -> str:
    """A finding's grade: the worst of its evidence artifacts. Reference
    artifacts (threat intel, baselines, enrichment) are left out when there's
    evidence; a finding with no artifacts is DECLARED. Never PARTIAL."""
    evidence = [t for t in artifacts if (t.break_ or {}).get("kind") != "reference"]
    graded = evidence or artifacts
    if not graded:
        return "DECLARED"
    return min((t.grade for t in graded), key=ARTIFACT_GRADES.index)
