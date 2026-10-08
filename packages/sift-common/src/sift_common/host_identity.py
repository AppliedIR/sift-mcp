"""Host identity for a case: the host logs, the case lock, and the fold.

Three files at the case root hold every host decision:

- ``host-observations.jsonl``: evidence sources (units), the host names seen
  in them, names bound while ingesting, host-list uploads and the case's
  identity header. Written by the scan, ingest workers and the list upload.
- ``host-decisions.jsonl``: the examiner's decisions, and completed host
  operations (rename, merge, split). Each line carries the observation-log
  offset the examiner saw.
- ``host-ops.json``: the host-operation journal.

Both logs are append-only. Appends open with ``O_NOFOLLOW|O_APPEND``, refuse
anything but a regular file with one link, and run under one ``flock`` held
on the observation log. ``fold()`` turns the two logs into machines and
bindings; it is a pure function of their bytes.

Terms: a *unit* is one evidence source, keyed by ``u16`` (the first 16 hex
digits of the sha256 of its locator). A *raw name* is a host name as found
in the evidence. A *machine* is one host identity: one or more machine keys
(``m16``, random, never changed) and a canonical name. A *binding* maps
``(unit, raw name)`` to the machine key its records are stored under.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import stat
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

OBSERVATIONS = "host-observations.jsonl"
DECISIONS = "host-decisions.jsonl"
OPS = "host-ops.json"
CASE_LOCK = "case.lock"
HOST_FILES = (OBSERVATIONS, DECISIONS, OPS)

CONFIRMED = "confirmed"
STARTED_NOW = "started-now"
NEW = "new"

# Where a name came from. Only names read from evidence the examiner put in
# the case can confirm a machine or join one while ingesting.
ARTIFACT = "artifact"
FOLDER = "folder"
AI_ORIGINS = frozenset({"argument", "file-name", "unregistered", "ai"})

FLAG_MATCHED_DURING_INGEST = "matched during ingest"
FLAG_AI_ORIGIN = "named only by the AI or an unregistered file"
FLAG_CANONICAL_CLASH = "renamed to keep host names unique"
FLAG_V1_MERGED = "merged automatically by an earlier version: confirm or split"
FLAG_NOT_A_HOST = "not a host"


class HostLogError(RuntimeError):
    """A host log could not be written safely, or a decision was refused."""


class CaseLockBusy(RuntimeError):
    """The case lock is held in a conflicting mode."""


# --------------------------------------------------------------------------
# Names and keys


def spelling(name: str | None) -> str:
    """Compare form of a host name: NFC, case-folded, trimmed, no trailing dot."""
    if not name:
        return ""
    s = unicodedata.normalize("NFC", str(name)).strip().casefold()
    while s.endswith("."):
        s = s[:-1]
    return s


def split_name(name: str | None) -> tuple[str, str]:
    """(short name, domain) of a host name in compare form."""
    s = spelling(name)
    short, _, domain = s.partition(".")
    return short, domain


def unit_locator(
    path: str | os.PathLike,
    case_dir: str | os.PathLike | None = None,
    member: str = "",
    offset: int | None = None,
) -> str:
    """The locator of an evidence source: its case-root-relative path, or its
    resolved path outside the case root, plus any archive member (after
    `!`) or volume offset (after `@`). `%`, `!` and `@` in the path and the
    member are percent-escaped, so a file named `a.zip!b` is never the
    member `b` of `a.zip`."""
    p = Path(path).resolve()
    text = str(p)
    if case_dir:
        root = Path(case_dir).resolve()
        with contextlib.suppress(ValueError):
            text = p.relative_to(root).as_posix() or "."
    text = _escape(text)
    if member:
        text += "!" + _escape(member)
    if offset is not None:
        text += "@" + str(int(offset))
    return text


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("!", "%21").replace("@", "%40")


def unit_key(locator: str) -> str:
    """``u16`` of a unit locator."""
    return hashlib.sha256(locator.encode("utf-8")).hexdigest()[:16]


def new_machine_key() -> str:
    """A fresh ``m16``."""
    return secrets.token_hex(8)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --------------------------------------------------------------------------
# Files


def ensure_host_files(case_dir: str | os.PathLike) -> None:
    """Create the host logs, the journal and the case lock file where missing.

    Never truncates and never replaces an existing path. Run at case init, at
    the identity mint and on every open, before anything else can write into
    the case.
    """
    root = Path(case_dir)
    for name in (*HOST_FILES, CASE_LOCK):
        mode = 0o666 if name == CASE_LOCK else 0o644
        try:
            fd = os.open(
                root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
            )
        except FileExistsError:
            continue
        try:
            if name == CASE_LOCK:
                # A root-run ingest may create it; the examiner's processes
                # must still be able to open it.
                with contextlib.suppress(OSError):
                    os.fchmod(fd, mode)
        finally:
            os.close(fd)


def _open_checked(path: Path, flags: int) -> int:
    """Open without following a link; refuse anything but a regular file
    with exactly one link."""
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW)
    except OSError as e:
        raise HostLogError(f"{path.name}: refused to open ({e.strerror or e})") from e
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise HostLogError(
            f"{path.name}: not a regular file with a single link; refused"
        )
    return fd


@contextlib.contextmanager
def _log_lock(case_dir: Path):
    """Exclusive lock for appends to either host log."""
    ensure_host_files(case_dir)
    fd = _open_checked(case_dir / OBSERVATIONS, os.O_RDONLY)
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _encode(record: dict) -> bytes:
    line = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return (line + "\n").encode("utf-8")


def _append_locked(path: Path, record: dict) -> int:
    """Append one line; caller holds the log lock. Returns the new size.
    A torn last line (a write that stopped short) is ended first, so this
    record never joins it and is lost with it."""
    fd = _open_checked(path, os.O_RDWR | os.O_APPEND)
    try:
        data = _encode(record)
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            data = b"\n" + data
        written = os.write(fd, data)
        if written != len(data):
            # Cut the part that landed: a later newline must not revive it
            os.ftruncate(fd, size)
            raise HostLogError(
                f"{path.name}: short write ({written} of {len(data)} bytes)"
            )
        return os.fstat(fd).st_size
    finally:
        os.close(fd)


def append_observations(case_dir: str | os.PathLike, records: list[dict]) -> int:
    """Append observation lines. Returns the observation log's size after."""
    root = Path(case_dir)
    size = 0
    with _log_lock(root):
        for rec in records:
            size = _append_locked(root / OBSERVATIONS, {"t": _now(), **rec})
    return size


def append_decision(
    case_dir: str | os.PathLike, record: dict, seen_offset: int, door: str = "portal"
) -> int:
    """Append one decision line that was made on a view of the observation log
    up to ``seen_offset``: all of it, or none (refused when that offset is
    past the log's end, or when any item breaks the invariants that
    host_guard checks). ``door`` is who asks: the portal, Start now, R."""
    return _append_decision(Path(case_dir), record, seen_offset, door, partial=False)[
        "size"
    ]


def append_decision_items(
    case_dir: str | os.PathLike, record: dict, seen_offset: int, door: str = "portal"
) -> dict:
    """As append_decision, for a request of many items (confirm-all, Start
    now): the items the invariants refuse are left out and reported, the
    rest appended. Returns {"size", "appended", "refused": [{index, reason}]}."""
    return _append_decision(Path(case_dir), record, seen_offset, door, partial=True)


def _append_decision(
    root: Path, record: dict, seen_offset, door: str, partial: bool
) -> dict:
    from sift_common import host_guard

    with _log_lock(root):
        size = os.stat(root / OBSERVATIONS).st_size
        if not isinstance(seen_offset, int) or seen_offset < 0 or seen_offset > size:
            raise HostLogError(
                f"decision refused: it refers to observation-log offset {seen_offset}, "
                f"past the log's end ({size} bytes)"
            )
        state = load(root)
        if record.get("action") not in (
            "confirm",
            "start_now",
        ):  # (items: per item, below)
            clash = _canonical_clash(state, record)
            if clash:
                raise HostLogError(clash)
        refused = host_guard.check_decision(state, record, door)
        whole = [why for i, why in refused if i is None]
        if whole or (refused and not partial):
            i, why = refused[0]
            where = "" if i is None else f"item {i + 1}: "
            raise host_guard.Refused(f"decision refused: {where}{why}")
        out_record = record
        if refused:
            drop = {i for i, _ in refused}
            args = dict(record.get("args") or {})
            args["machines"] = [
                m for i, m in enumerate(args.get("machines") or ()) if i not in drop
            ]
            out_record = {**record, "args": args}
        appended = len((out_record.get("args") or {}).get("machines") or ()) or 1
        if partial and refused and not (out_record.get("args") or {}).get("machines"):
            new_size, appended = os.stat(root / DECISIONS).st_size, 0
        else:
            # Replayed at the log's size now, after every observation that came
            # in since the examiner's view: one of them never overrides it
            new_size = _append_locked(
                root / DECISIONS,
                {"t": _now(), **out_record, "offset": seen_offset, "at": size},
            )
    return {
        "size": new_size,
        "appended": appended,
        "refused": [{"index": i, "reason": why} for i, why in refused],
    }


def _canonical_clash(state: HostState, record: dict) -> str:
    """Why an examiner-entered canonical in ``record`` is refused, or "".

    Two machines never share a canonical. A name the examiner types that is
    already another machine's is refused, and offered as a merge; automatic
    proposals are made unique by the fold instead.
    """
    action = record.get("action")
    args = record.get("args") if isinstance(record.get("args"), dict) else {}
    wanted: list[tuple[str, set[str]]] = []
    if action == "confirm":
        for item in args.get("machines") or ():
            if not isinstance(item, dict) or not item.get("canonical"):
                continue
            own = set()
            m = state.machine_of_key(str(item.get("key") or ""))
            if m is not None:
                own.add(m.id)
            for p in item.get("pairs") or ():
                bound = state.machine_of_pair(*p) if _pair(p) else None
                if bound is not None:
                    own.add(bound.id)
            wanted.append((str(item["canonical"]), own))
    elif action in ("rename", "split") and args.get("canonical"):
        m = state.machine_of_key(str(args.get("machine") or ""))
        own = {m.id} if m is not None and action == "rename" else set()
        wanted.append((str(args["canonical"]), own))
    for name, own in wanted:
        owner = state.canonical_owner(name)
        if owner is not None and owner.id not in own:
            return (
                f"host name {name!r} is already used by another machine "
                f"({owner.canonical}); merge the two machines instead"
            )
    return ""


def write_case_header(
    case_dir: str | os.PathLike, c12: str, reason: str, case_uuid: str = ""
) -> None:
    """Record the case identity the logs belong to. The latest header wins."""
    rec = {"kind": "case", "c12": c12, "reason": reason}
    if case_uuid:
        rec["case_uuid"] = case_uuid
    append_observations(case_dir, [rec])


def _case_uuid_of(meta: dict) -> str:
    raw = str(meta.get("case_uuid") or "").strip().lower()
    hexed = raw.replace("-", "")
    return (
        raw if len(hexed) == 32 and all(c in "0123456789abcdef" for c in hexed) else ""
    )


def write_case_yaml(path: Path, meta: dict) -> None:
    """Replace CASE.yaml with ``meta``, keeping its mode; the caller holds the
    log lock.

    The temp file is created fresh, never followed or reused: a file or link
    already at its name is refused.
    """
    import yaml

    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise HostLogError(f"{tmp}: already exists; refused") from None
    try:
        with contextlib.suppress(OSError):
            os.fchmod(fd, path.stat().st_mode & 0o777)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(yaml.safe_dump(meta, sort_keys=False))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def ensure_case_uuid(
    case_dir: str | os.PathLike, naming_version: int = 1
) -> tuple[str, int]:
    """(c12, naming_version) of a case, minting its identity if it has none.

    The one place a case gets its `case_uuid`. Under the log lock, a case
    whose CASE.yaml has none gets a UUID4 (its other keys kept, and
    `naming_version` set when absent), and the host logs record it. A case
    whose logs already record an identity that CASE.yaml has lost is
    refused, naming the UUID to restore: minting again would orphan every
    record stored under the old one.
    """
    import uuid

    import yaml

    root = Path(case_dir)
    ensure_host_files(root)
    path = root / "CASE.yaml"
    with _log_lock(root):
        try:
            meta = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            raise FileNotFoundError(f"no CASE.yaml in {root}") from None
        if not isinstance(meta, dict):
            raise HostLogError(f"{path}: not a mapping")
        state = load(root)
        current = _case_uuid_of(meta)
        if current:
            c12 = current.replace("-", "")[:12]
            if state.c12 and state.c12 != c12:
                restore = state.case_uuid or f"(a UUID beginning {state.c12})"
                raise HostLogError(
                    f"{path} has case_uuid {current}, but this case's records are "
                    f"stored under {state.c12}: restore case_uuid: {restore} in CASE.yaml"
                )
            if state.c12 is None:  # minted elsewhere: the logs learn it
                _append_locked(root / OBSERVATIONS, {"t": _now(), "kind": "case", "c12": c12,
                               "case_uuid": current, "reason": "case identity recorded"})  # fmt: skip
            return c12, int(meta.get("naming_version") or 1)
        if state.c12:
            restore = state.case_uuid or f"(a UUID beginning {state.c12})"
            raise HostLogError(
                f"{path} has no case_uuid, but this case's records are stored under "
                f"{state.c12}: restore case_uuid: {restore} in CASE.yaml"
            )
        new = str(uuid.uuid4())
        meta["case_uuid"] = new
        meta.setdefault("naming_version", naming_version)
        write_case_yaml(path, meta)
        c12 = new.replace("-", "")[:12]
        _append_locked(root / OBSERVATIONS, {"t": _now(), "kind": "case", "c12": c12,
                       "case_uuid": new, "reason": "case identity minted"})  # fmt: skip
        return c12, int(meta["naming_version"])


def recorded_c12(case_dir: str | os.PathLike) -> str | None:
    """The case identity the host logs last recorded, or None."""
    return load(case_dir).c12


def update_case_meta(case_dir: str | os.PathLike, changes: dict) -> dict:
    """Set keys in a case's CASE.yaml, keeping every other key; returns it.

    The load-modify-write runs under the same lock as the identity mint, so
    neither can write over the other's change.
    """
    import yaml

    root = Path(case_dir)
    path = root / "CASE.yaml"
    with _log_lock(root):
        try:
            meta = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            raise FileNotFoundError(f"no CASE.yaml in {root}") from None
        if not isinstance(meta, dict):
            raise HostLogError(f"{path}: not a mapping")
        meta.update(changes)
        data = yaml.safe_dump(meta, sort_keys=False).encode("utf-8")
        tmp = path.with_name(f".{path.name}.{os.getpid()}.meta.tmp")
        # Created fresh: a file or link planted at the name is refused, never
        # written through
        try:
            fd = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            raise HostLogError(f"{tmp}: already exists; refused") from None
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            with contextlib.suppress(OSError):
                os.chmod(tmp, path.stat().st_mode & 0o777)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        return meta


# --------------------------------------------------------------------------
# The fold


@dataclass
class Machine:
    id: str
    canonical: str
    state: str
    keys: list[str] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)
    former: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "canonical": self.canonical,
            "state": self.state,
            "keys": list(self.keys),
            "pairs": [list(p) for p in self.pairs],
            "former": list(self.former),
            "flags": list(self.flags),
        }


@dataclass
class HostState:
    c12: str | None = None
    case_uuid: str | None = None
    units: dict[str, dict] = field(default_factory=dict)
    names: dict[tuple[str, str], dict] = field(default_factory=dict)
    machines: dict[str, Machine] = field(default_factory=dict)
    key_machine: dict[str, str] = field(default_factory=dict)
    bindings: dict[tuple[str, str], str] = field(default_factory=dict)
    pair_flags: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    host_list: dict | None = None
    suggestions: list[dict] = field(default_factory=list)
    hints: list[dict] = field(
        default_factory=list
    )  # near spellings, found once per new name
    v1_imported: bool = False
    obs_offset: int = 0
    dec_offset: int = 0
    unreadable_lines: int = 0
    canon: dict[str, str] = field(default_factory=dict)  # compare form -> machine id
    waits: dict[str, list[str]] = field(default_factory=dict)  # run id -> its units
    cancelled: set[str] = field(default_factory=set)  # runs the examiner cancelled

    def machine_of_key(self, key: str) -> Machine | None:
        mid = self.key_machine.get(key)
        return self.machines.get(mid) if mid else None

    def machine_of_pair(self, unit: str, raw: str) -> Machine | None:
        key = self.bindings.get((unit, raw))
        return self.machine_of_key(key) if key else None

    def canonical_owner(self, canonical: str) -> Machine | None:
        """The machine whose canonical equals ``canonical`` in compare form."""
        mid = self.canon.get(spelling(canonical))
        return self.machines.get(mid) if mid else None

    def canonical_taken(
        self, canonical: str, *, except_machine: str | None = None
    ) -> bool:
        owner = self.canonical_owner(canonical)
        return owner is not None and owner.id != except_machine

    def unique_canonical(
        self, canonical: str, *, except_machine: str | None = None
    ) -> str:
        """``canonical``, or ``canonical (n)`` with the smallest n that is free."""
        if not self.canonical_taken(canonical, except_machine=except_machine):
            return canonical
        n = 2
        while self.canonical_taken(f"{canonical} ({n})", except_machine=except_machine):
            n += 1
        return f"{canonical} ({n})"

    def pending_pairs(self, unit: str | None = None) -> list[tuple[str, str]]:
        """Names seen in evidence that are bound to no machine yet."""
        return [
            p
            for p in self.names
            if p not in self.bindings and (unit is None or p[0] == unit)
        ]


def _lines(data: bytes):
    """Complete lines of a log; an unterminated last line is skipped."""
    end = data.rfind(b"\n")
    if end < 0:
        return 0, []
    return end + 1, data[: end + 1].splitlines()


def _parse(raw: bytes):
    try:
        rec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return rec if isinstance(rec, dict) else None


def _pair(value) -> tuple[str, str] | None:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        u, r = value
        if isinstance(u, str) and isinstance(r, str):
            return u, r
    return None


def _add_flag(flags: list[str], flag: str) -> None:
    if flag and flag not in flags:
        flags.append(flag)


class _Folder:
    def __init__(self) -> None:
        self.s = HostState()

    # -- machines

    def _new_machine(self, key: str, canonical: str, state: str, flags=()) -> Machine:
        s = self.s
        name = canonical or key
        unique = s.unique_canonical(name)
        m = Machine(id=key, canonical=unique, state=state, keys=[key])
        s.canon[spelling(unique)] = key
        for f in flags:
            _add_flag(m.flags, f)
        if unique != name:
            _add_flag(m.flags, FLAG_CANONICAL_CLASH)
        s.machines[key] = m
        s.key_machine[key] = key
        return m

    def _set_canonical(self, m: Machine, canonical: str) -> None:
        if not canonical or canonical == m.canonical:
            return
        unique = self.s.unique_canonical(canonical, except_machine=m.id)
        if unique != canonical:
            _add_flag(m.flags, FLAG_CANONICAL_CLASH)
        if m.canonical not in m.former:
            m.former.append(m.canonical)
        if self.s.canon.get(spelling(m.canonical)) == m.id:
            del self.s.canon[spelling(m.canonical)]
        m.canonical = unique
        self.s.canon[spelling(unique)] = m.id

    def _bind(self, pair: tuple[str, str], key: str) -> None:
        s = self.s
        old = s.bindings.get(pair)
        if old == key:
            return
        if old is not None:
            om = s.machine_of_key(old)
            if om is not None and pair in om.pairs:
                om.pairs.remove(pair)
        s.bindings[pair] = key
        m = s.machine_of_key(key)
        if m is not None and pair not in m.pairs:
            m.pairs.append(pair)

    def _absorb(self, into: Machine, other: Machine) -> None:
        """Relabel: every key and pair of ``other`` joins ``into``."""
        s = self.s
        if other.id == into.id:
            return
        for k in other.keys:
            if k not in into.keys:
                into.keys.append(k)
            s.key_machine[k] = into.id
        for p in other.pairs:
            if p not in into.pairs:
                into.pairs.append(p)
        for name in (*other.former, other.canonical):
            if name not in into.former and name != into.canonical:
                into.former.append(name)
        for f in other.flags:
            if f != FLAG_CANONICAL_CLASH:
                _add_flag(into.flags, f)
        if s.canon.get(spelling(other.canonical)) == other.id:
            del s.canon[spelling(other.canonical)]
        del s.machines[other.id]

    def _machine_for(self, key: str, canonical: str, state: str, flags=()) -> Machine:
        m = self.s.machine_of_key(key)
        if m is None:
            m = self._new_machine(key, canonical, state, flags)
        return m

    # -- observations

    def observation(self, rec: dict) -> None:
        s = self.s
        kind = rec.get("kind")
        if kind == "case":
            if isinstance(rec.get("c12"), str):
                s.c12 = rec["c12"]
                s.case_uuid = (
                    rec.get("case_uuid")
                    if isinstance(rec.get("case_uuid"), str)
                    else None
                )
        elif kind == "unit":
            u = rec.get("unit")
            if isinstance(u, str):  # what the scan found out about it, latest wins
                entry = s.units.setdefault(u, {})
                entry.update(
                    {k: v for k, v in rec.items() if k not in ("kind", "t", "unit")}
                )
        elif kind == "name":
            p = _pair((rec.get("unit"), rec.get("raw")))
            if p is None:
                return
            entry = s.names.setdefault(p, {"evidence": [], "origins": []})
            ev = rec.get("evidence")
            if ev and ev not in entry["evidence"]:
                entry["evidence"].append(ev)
            origin = rec.get("origin")
            if origin and origin not in entry["origins"]:
                entry["origins"].append(origin)
        elif kind == "bind":
            p = _pair((rec.get("unit"), rec.get("raw")))
            key = rec.get("key")
            if p is None or not isinstance(key, str):
                return
            s.names.setdefault(p, {"evidence": [], "origins": []})
            m = self._machine_for(
                key,
                str(rec.get("canonical") or p[1]),
                str(rec.get("state") or NEW),
                rec.get("machine_flags") or (),
            )
            self._bind(p, key)
            for f in rec.get("flags") or ():
                _add_flag(s.pair_flags.setdefault(p, []), f)
            if m.state != CONFIRMED and rec.get("state") == CONFIRMED:
                m.state = CONFIRMED
        elif kind == "list":
            s.host_list = {
                k: rec.get(k) for k in ("entries", "sha256", "examiner", "t")
            }
        elif kind == "suggestion":
            s.suggestions.append({k: v for k, v in rec.items() if k != "kind"})
        elif kind == "hint":
            s.hints.append({k: v for k, v in rec.items() if k not in ("kind", "t")})
        elif kind == "v1-import":
            s.v1_imported = True
        elif kind == "run_wait":
            run, units = rec.get("run_id"), rec.get("units")
            if isinstance(run, str) and isinstance(units, list):
                s.waits[run] = [u for u in units if isinstance(u, str)]

    # -- decisions

    def decision(self, rec: dict) -> None:
        s = self.s
        action = rec.get("action")
        args = rec.get("args") if isinstance(rec.get("args"), dict) else {}
        if action in ("confirm", "start_now"):
            state = CONFIRMED if action == "confirm" else STARTED_NOW
            for item in args.get("machines") or ():
                if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                    continue
                key = item["key"]
                canonical = str(item.get("canonical") or "")
                pairs = [p for p in (_pair(x) for x in item.get("pairs") or ()) if p]
                m = s.machine_of_key(key)
                owner = next(
                    (
                        b
                        for b in (s.machine_of_pair(*p) for p in pairs)
                        if b is not None
                    ),
                    None,
                )
                if m is None and owner is not None:
                    # Pairs already bound: their machine takes the key, so the
                    # confirmed name isn't taken by the machine it replaces
                    owner.keys.append(key)
                    s.key_machine[key] = owner.id
                    m = owner
                if m is None:
                    m = self._new_machine(
                        key, canonical or (pairs[0][1] if pairs else key), state
                    )
                elif state == CONFIRMED or m.state == NEW:
                    m.state = state
                for p in pairs:
                    bound = s.machine_of_pair(*p)
                    if bound is not None and bound.id != m.id:
                        self._absorb(m, bound)
                    elif bound is None:
                        self._bind(p, key)
                # after absorbing: the name it gives is free of the machines it took in
                self._set_canonical(m, canonical)
        elif action == "cancel_run":
            run = args.get("run_id")
            if isinstance(run, str):
                s.cancelled.add(run)
        elif action == "not_a_host":
            for item in args.get("pairs") or ():
                p = _pair(item)
                if p is None:
                    continue
                _add_flag(s.pair_flags.setdefault(p, []), FLAG_NOT_A_HOST)
                key = args.get("key")
                if isinstance(key, str) and p not in s.bindings:
                    self._machine_for(key, f"unattributed:{p[0]}", CONFIRMED)
                    self._bind(p, key)
        elif action == "rename":
            m = s.machine_of_key(str(args.get("machine") or ""))
            if m is not None:
                self._set_canonical(m, str(args.get("canonical") or ""))
                m.state = CONFIRMED
        elif action == "merge":
            into = s.machine_of_key(str(args.get("into") or ""))
            if into is None:
                return
            for other_id in args.get("from") or ():
                other = s.machine_of_key(str(other_id))
                if other is not None:
                    self._absorb(into, other)
            into.state = CONFIRMED
        elif action == "split":
            src = s.machine_of_key(str(args.get("machine") or ""))
            keys = [k for k in args.get("keys") or () if isinstance(k, str)]
            if src is None or not keys or not set(keys) < set(src.keys):
                return
            new_id = keys[0]
            moved = [p for p in src.pairs if s.bindings.get(p) in keys]
            src.keys = [k for k in src.keys if k not in keys]
            if src.id in keys:
                # The machine keeps its identity through its remaining keys.
                s.machines.pop(src.id)
                src.id = src.keys[0]
                s.machines[src.id] = src
                s.canon[spelling(src.canonical)] = src.id
                for k in src.keys:
                    s.key_machine[k] = src.id
            src.pairs = [p for p in src.pairs if p not in moved]
            m = Machine(
                id=new_id, canonical="", state=CONFIRMED, keys=list(keys), pairs=moved
            )
            s.machines[new_id] = m
            for k in keys:
                s.key_machine[k] = new_id
            m.canonical = s.unique_canonical(
                str(args.get("canonical") or new_id), except_machine=new_id
            )
            s.canon[spelling(m.canonical)] = new_id


def fold(observations: bytes, decisions: bytes) -> HostState:
    """Machines, bindings and names from the two host logs.

    Deterministic: the same bytes give the same state. Each decision line is
    applied after the observation lines that were in the log when it was
    appended, so an observation that came in between the examiner's view and
    the decision is folded first, and never overrides it.
    """
    folder = _Folder()
    obs_end, obs_lines = _lines(observations)
    dec_end, dec_lines = _lines(decisions)
    folder.s.obs_offset = obs_end
    folder.s.dec_offset = dec_end

    obs_records = []
    pos = 0
    for raw in obs_lines:
        pos += len(raw) + 1
        rec = _parse(raw)
        if rec is None:
            folder.s.unreadable_lines += 1
            continue
        obs_records.append((pos, rec))
    dec_records = []
    for raw in dec_lines:
        rec = _parse(raw)
        if rec is None:
            folder.s.unreadable_lines += 1
            continue
        dec_records.append(rec)

    i = 0
    for dec in dec_records:
        at = dec.get("at", dec.get("offset"))
        limit = at if isinstance(at, int) else obs_end
        while i < len(obs_records) and obs_records[i][0] <= limit:
            folder.observation(obs_records[i][1])
            i += 1
        folder.decision(dec)
    for _, rec in obs_records[i:]:
        folder.observation(rec)
    return folder.s


_cache: dict[str, tuple[tuple, HostState]] = {}
_cache_lock = threading.Lock()


def _read(path: Path) -> tuple[tuple, bytes]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return (None, 0), b""
    except OSError as e:
        raise HostLogError(f"{path.name}: unreadable ({e.strerror or e})") from e
    try:
        st = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        return (st.st_ino, len(data)), data
    finally:
        os.close(fd)


def load(case_dir: str | os.PathLike) -> HostState:
    """The fold of a case's host logs, cached by the logs' identities and sizes."""
    root = Path(case_dir)
    obs_id, obs = _read(root / OBSERVATIONS)
    dec_id, dec = _read(root / DECISIONS)
    key = (obs_id, dec_id)
    cache_key = str(root.resolve())
    with _cache_lock:
        hit = _cache.get(cache_key)
        if hit is not None and hit[0] == key:
            return hit[1]
    state = fold(obs, dec)
    with _cache_lock:
        _cache[cache_key] = (key, state)
    return state


# --------------------------------------------------------------------------
# Get-or-mint while ingesting


def _match_confirmed(state: HostState, raw: str) -> Machine | None:
    """The one machine the examiner settled (confirmed, or started now) whose
    name equals ``raw`` after spelling normalization; None when there is none
    or more than one."""
    target = spelling(raw)
    if not target:
        return None
    found = []
    for m in state.machines.values():
        if m.state not in (CONFIRMED, STARTED_NOW):
            continue
        names = {spelling(m.canonical)}  # a name marked not a host never matches
        names |= {spelling(p[1]) for p in m.pairs
                  if FLAG_NOT_A_HOST not in state.pair_flags.get(p, [])}  # fmt: skip
        names |= {spelling(n) for n in m.former}
        if target in names:  # the exact name: its domain is the machine's own
            found.append(m)
    return found[0] if len(found) == 1 else None


def short_name_holders(state: HostState, raw: str, but_unit: str = "") -> set:
    """The machines (any state) and the units with names not yet bound that
    hold ``raw``'s short name, across the whole case (``but_unit``'s own
    names aside)."""
    short = split_name(raw)[0]
    holders: set[tuple[str, str]] = set()
    for m in state.machines.values():
        names = [m.canonical, *m.former]
        names += [
            p[1] for p in m.pairs if FLAG_NOT_A_HOST not in state.pair_flags.get(p, [])
        ]
        if any(split_name(n)[0] == short for n in names):
            holders.add(("machine", m.id))
    for p in state.names:
        if p in state.bindings or FLAG_NOT_A_HOST in state.pair_flags.get(p, []):
            continue
        if split_name(p[1])[0] == short and p[0] != but_unit:
            holders.add(("unit", p[0]))
    return holders


def _late_list_binding(state: HostState, unit: str, raw: str):
    """(key, canonical) of the one host-list entry a late name confirms to,
    under the list's one rule (host_proposal.late_list_binding), or None."""
    from sift_common import host_proposal

    return host_proposal.late_list_binding(state, unit, raw)


def get_or_mint(
    case_dir: str | os.PathLike,
    unit: str,
    raw: str,
    *,
    origin: str = ARTIFACT,
    evidence: str = "",
    canonical: str = "",
) -> tuple[str, str]:
    """The machine key and canonical for ``(unit, raw)``, binding it if it is
    new. Runs under the log lock, so one pair is bound once however many
    workers meet it.

    A pair already bound keeps its machine. A name read from evidence that
    equals exactly one confirmed machine's name joins that machine, flagged
    "matched during ingest". Anything else becomes its own machine in state
    ``new``; a name with only AI-origin support is flagged as such.
    """
    root = Path(case_dir)
    pair = (unit, raw)
    state = load(root)
    key = state.bindings.get(pair)
    if key is not None:
        m = state.machine_of_key(key)
        return key, m.canonical if m else raw
    with _log_lock(root):
        state = load(root)
        key = state.bindings.get(pair)
        if key is not None:
            m = state.machine_of_key(key)
            return key, m.canonical if m else raw
        records: list[dict] = []
        if (unit, raw) not in state.names:
            records.append(
                {
                    "kind": "name",
                    "unit": unit,
                    "raw": raw,
                    "evidence": evidence,
                    "origin": origin,
                }
            )
        from sift_common import host_guard

        def mint(wanted: str) -> tuple[dict, str, str]:
            k = new_machine_key()
            name = state.unique_canonical(wanted)
            flags = [FLAG_AI_ORIGIN] if origin in AI_ORIGINS else []
            if name != wanted:
                flags.append(FLAG_CANONICAL_CLASH)
            return ({"kind": "bind", "unit": unit, "raw": raw, "key": k, "canonical": name,
                     "state": NEW, "machine_flags": flags}, k, name)  # fmt: skip

        from sift_common.host_proposal import is_address

        if is_address(raw):  # never a machine's name: the unit's placeholder
            from sift_common.host_gate import placeholder_name

            own = host_guard.placeholder_of(state, unit)
            m = next((x for x in state.machines.values() if x.canonical in own), None)
            if m is not None:
                bind, key, result = (
                    {"kind": "bind", "unit": unit, "raw": raw, "key": m.keys[0]},
                    m.keys[0],
                    m.canonical,
                )
            else:
                locator = str((state.units.get(unit) or {}).get("locator") or unit)
                bind, key, result = mint(placeholder_name(locator))
        elif FLAG_NOT_A_HOST in state.pair_flags.get(pair, []):
            # not a host: with its unit's own machine, or the unit's placeholder
            own = {}
            placeholders = host_guard.placeholder_of(state, unit)
            for p, k in state.bindings.items():
                if p[0] != unit or p == pair:
                    continue
                m = state.machine_of_key(k)
                if m is None:
                    continue
                if host_guard._own(state, p) or m.canonical in placeholders:
                    own.setdefault(m.id, [m, 0])[1] += 1  # (its placeholder is its own)
            if own:
                m = sorted(own.values(), key=lambda x: (-x[1], x[0].id))[0][0]
                bind, key, result = (
                    {"kind": "bind", "unit": unit, "raw": raw, "key": m.keys[0]},
                    m.keys[0],
                    m.canonical,
                )
            else:
                from sift_common.host_gate import placeholder_name

                locator = str((state.units.get(unit) or {}).get("locator") or unit)
                bind, key, result = mint(placeholder_name(locator))
        else:
            # Only a name the scan never held, read from the evidence, joins a
            # machine by itself: a held one waits for the examiner at the gate.
            late = (unit, raw) not in state.names and origin == ARTIFACT
            if late and not split_name(raw)[1]:
                # a name without a domain joins only what nothing else in the
                # case could also be: one machine or unit holds its short name
                late = len(short_name_holders(state, raw)) == 1
            match = _match_confirmed(state, raw) if late else None
            domain = split_name(raw)[1]
            if (
                match is not None
                and domain
                and {
                    split_name(n)[1]
                    for n in (
                        match.canonical,
                        *(
                            p[1]
                            for p in match.pairs  # a not-a-host name counts for nothing
                            if FLAG_NOT_A_HOST not in state.pair_flags.get(p, [])
                        ),
                    )  # fmt: skip
                }
                - {"", domain}
            ):
                match = None  # a machine holding a name in another domain: not this one
            listed = (
                _late_list_binding(state, unit, raw) if late and match is None else None
            )
            if listed is not None:  # a host-list entry the name matches
                key, result = listed
                bind = {"kind": "bind", "unit": unit, "raw": raw, "key": key,
                        "canonical": result, "state": CONFIRMED,
                        "flags": [FLAG_MATCHED_DURING_INGEST]}  # fmt: skip
            elif match is not None:
                key, result = match.keys[0], match.canonical
                bind = {"kind": "bind", "unit": unit, "raw": raw, "key": key,
                        "flags": [FLAG_MATCHED_DURING_INGEST]}  # fmt: skip
            else:
                bind, key, result = mint(canonical or raw)
            # judged with this name's own record in place (its evidence counts)
            if host_guard.check_binds(state, [*records, bind], "late"):
                bind, key, result = mint(canonical or raw)  # its own machine, then
        records.append(bind)
        for rec in records:
            _append_locked(root / OBSERVATIONS, {"t": _now(), **rec})
    return key, result


# --------------------------------------------------------------------------
# Pre-0.7 cases


def import_v1(
    case_dir: str | os.PathLike,
    dictionary_hosts: dict,
    pairs: list[tuple[str, str, str]],
) -> bool:
    """Seed the logs of a pre-0.7 case once.

    ``dictionary_hosts`` is the v1 ``host-dictionary.yaml`` ``hosts`` map;
    ``pairs`` is ``(index, host.name, host.id)`` from the case's pre-0.7
    indices. Each v1 machine becomes a confirmed machine whose canonical is
    the ``host.id`` its records carry, so pre-0.7 and new records agree; a v1
    machine that joined differently spelled names was merged automatically
    and is flagged for the examiner. Returns False when already imported.
    """
    root = Path(case_dir)
    with _log_lock(root):
        if load(root).v1_imported:
            return False
        alias_of: dict[str, str] = {}
        auto_merged: set[str] = set()
        for canonical, entry in (dictionary_hosts or {}).items():
            if not isinstance(canonical, str):
                continue
            aliases = [
                a for a in ((entry or {}).get("aliases") or []) if isinstance(a, str)
            ]
            alias_of[spelling(canonical)] = canonical
            for a in aliases:
                alias_of.setdefault(spelling(a), canonical)
            if {spelling(a) for a in aliases} - {spelling(canonical)}:
                auto_merged.add(canonical)

        # host.id the records carry, per v1 machine.
        stamped: dict[str, dict[str, int]] = {}
        groups: dict[str, list[tuple[str, str]]] = {}
        for index, host_name, host_id in pairs:
            if not isinstance(index, str):
                continue
            name = (
                host_name
                if isinstance(host_name, str) and host_name
                else (host_id or "")
            )
            if not name:
                continue
            v1 = (
                alias_of.get(spelling(name))
                or alias_of.get(spelling(host_id or ""))
                or (host_id or name)
            )
            groups.setdefault(v1, []).append((index, name))
            if isinstance(host_id, str) and host_id:
                counts = stamped.setdefault(v1, {})
                counts[host_id] = counts.get(host_id, 0) + 1

        records: list[dict] = []
        taken: set[str] = set()
        for v1 in sorted(groups):
            counts = stamped.get(v1) or {}
            canonical = max(sorted(counts), key=lambda h: counts[h]) if counts else v1
            if spelling(canonical) in taken:
                canonical = v1
            taken.add(spelling(canonical))
            key = new_machine_key()
            flags = [FLAG_V1_MERGED] if v1 in auto_merged else []
            seen_units: set[str] = set()
            for index, name in sorted(set(groups[v1])):
                locator = f"pre-0.7 index {index}"
                u = unit_key(locator)
                if u not in seen_units:
                    records.append(
                        {
                            "kind": "unit",
                            "unit": u,
                            "locator": locator,
                            "source": "pre-0.7 index",
                        }
                    )
                    seen_units.add(u)
                records.append(
                    {
                        "kind": "name",
                        "unit": u,
                        "raw": name,
                        "evidence": f"host.name in {index}",
                        "origin": ARTIFACT,
                    }
                )
                records.append(
                    {
                        "kind": "bind",
                        "unit": u,
                        "raw": name,
                        "key": key,
                        "canonical": canonical,
                        "state": CONFIRMED,
                        "machine_flags": flags,
                    }
                )
        records.append({"kind": "v1-import", "machines": len(groups)})
        for rec in records:
            _append_locked(root / OBSERVATIONS, {"t": _now(), **rec})
    return True


# --------------------------------------------------------------------------
# The case lock


_inproc_lock = threading.Lock()
_inproc: dict[str, list[int]] = {}  # path -> [shared holders, exclusive holders]


@contextlib.contextmanager
def case_lock(case_dir: str | os.PathLike, *, shared: bool, blocking: bool = False):
    """Hold the case lock: shared for ingest, enrichment and backup;
    exclusive for host operations.

    ``fcntl.flock`` on a fresh descriptor per holder, on a lock file inside
    the case directory that is never removed. Holders in this process are
    also counted, so an exclusive request from the server conflicts with its
    own in-process shared holders. Raises CaseLockBusy when the lock is held
    in a conflicting mode and ``blocking`` is False.
    """
    import fcntl

    root = Path(case_dir)
    path = root / CASE_LOCK
    key = str(path.resolve())
    with _inproc_lock:
        counts = _inproc.setdefault(key, [0, 0])
        if (shared and counts[1]) or (not shared and (counts[0] or counts[1])):
            if not blocking:
                raise CaseLockBusy(
                    "the case lock is held by another task in this process"
                )
        counts[0 if shared else 1] += 1
    fd = -1
    try:
        for _ in range(5):
            ensure_host_files(root)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
                fcntl.flock(fd, mode if blocking else mode | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                fd = -1
                raise CaseLockBusy("a process holds the case lock") from None
            try:
                same = os.fstat(fd).st_ino == os.stat(path).st_ino
            except FileNotFoundError:
                same = False
            if same:
                break
            os.close(fd)
            fd = -1
        else:
            raise CaseLockBusy("the case lock file keeps changing; refused")
        yield
    finally:
        if fd >= 0:
            os.close(fd)
        with _inproc_lock:
            _inproc[key][0 if shared else 1] -= 1


# --------------------------------------------------------------------------
# The host-operation journal


def read_ops(case_dir: str | os.PathLike) -> dict:
    """The host-operation journal: ``{"ops": {op_id: {...}}}``. Empty when
    no operation ever ran."""
    path = Path(case_dir) / OPS
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"ops": {}}
    try:
        data = b""
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if not data.strip():
        return {"ops": {}}
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise HostLogError(f"{OPS}: unreadable ({e})") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("ops"), dict):
        raise HostLogError(f"{OPS}: not a host-operation journal")
    return doc


def unfinished_op(case_dir: str | os.PathLike) -> dict | None:
    """The host operation that is running or incomplete, or None."""
    for op_id, op in sorted(read_ops(case_dir)["ops"].items()):
        if isinstance(op, dict) and op.get("state") in ("running", "incomplete"):
            return {"id": op_id, **op}
    return None
