"""The one check every host-log writer runs, under the log lock, on the fresh
state: the examiner's decisions (portal, Start now, cancel), names bound
while ingesting, and the host list's confirmations. Each item of a request
is checked against the state including the request's earlier items.

- Names stay: a machine in use (one holding names) never changes its name and never
  merges with another, except through a host operation (rename, merge or
  split), which only R appends.
- Not a host: a name marked not a host binds only to its own unit's machine (one
  holding another name of that unit's own) or to the unit's placeholder.
- One machine: an automatic join (the list, a late name, Start now, a confirm-all of
  proposals) never makes a machine hold two machine ids (counted from the
  units whose own names it holds) or one name in two domains. A single
  confirmation of the examiner's may; conflicts are theirs to decide.

A refused item comes back with its reason (HTTP 409 for the portal).
"""

from __future__ import annotations

from sift_common import host_identity as hi

AUTOMATIC_DOORS = frozenset({"start_now", "list", "late", "proposed"})
OPS = frozenset({"rename", "merge", "split"})
IN_USE = "renaming or merging a machine in use is done with a host rename or merge"


class Refused(hi.HostLogError):
    """A decision or bind the invariants refuse (HTTP 409 at the portal)."""

    status = 409


def _foreign(state: hi.HostState, p) -> bool:
    ev = (state.names.get(p) or {}).get("evidence") or []
    return bool(ev) and all(
        e.endswith("host column") or e.lower().startswith("forwardedevents") for e in ev
    )


def _not_a_host(state: hi.HostState, p) -> bool:
    return hi.FLAG_NOT_A_HOST in state.pair_flags.get(p, [])


def _own(state: hi.HostState, p) -> bool:
    """One of its unit's own names: neither a row's nor a forwarded log's,
    nor one the examiner said is not a host."""
    return not _foreign(state, p) and not _not_a_host(state, p)


def placeholder_of(state, unit: str) -> set[str]:
    """The names a unit's own placeholder machine may carry: the unit's
    placeholder, exactly, and the examiner's `unattributed:<unit>`."""
    from sift_common import host_gate

    locator = str((state.units.get(unit) or {}).get("locator") or "")
    names = {f"unattributed:{unit}"}
    if locator:
        names.add(host_gate.placeholder_name(locator))
    return names


def _placeholder(state, unit: str, canonical: str) -> bool:
    return canonical in placeholder_of(state, unit)


def _i2(state: hi.HostState, pairs, canonical: str, added=None) -> str:
    """Why the not-a-host names the step adds (`added`; all of `pairs`, the
    machine's names after it, when None) can't belong to it, or ""."""
    for p in pairs if added is None else added:
        if not _not_a_host(state, p):
            continue
        if _placeholder(state, p[0], canonical):
            continue
        if not any(q[0] == p[0] and q != p and _own(state, q) for q in pairs):
            return (
                f"{p[1]!r} is not a host: it goes only with its own unit's machine "
                "or the unit's placeholder"
            )
    return ""


def _ids_and_domains(state, pairs) -> tuple[set, dict]:
    from sift_common.host_proposal import LIST_UNIT

    units = {p[0] for p in pairs if p[0] != LIST_UNIT and _own(state, p)}
    guids = {
        str((state.units.get(u) or {}).get("machine_guid") or "").lower() for u in units
    } - {""}
    shorts: dict[str, set] = {}
    for p in pairs:
        if _not_a_host(state, p):
            continue
        short, domain = hi.split_name(p[1])
        if domain:
            shorts.setdefault(short, set()).add(domain)
    return guids, shorts


def _i3(state: hi.HostState, pairs, before=()) -> str:
    """Why a machine holding `pairs` (after an automatic join; `before` it)
    would be two machines, or "". What the examiner already confirmed
    together stands: only what the join adds is judged."""
    guids, shorts = _ids_and_domains(state, pairs)
    had, had_shorts = _ids_and_domains(state, list(before))
    if len(guids) > 1 and guids != had:
        return "it would join machines with different machine ids"
    if any(len(d) > 1 and d != had_shorts.get(s) for s, d in shorts.items()):
        return "it would put one name in two domains on one machine"
    return ""


class _Overlay:
    """The fresh state plus what the request's earlier items and records
    would change: names, binds and new machines. Nothing is copied."""

    def __init__(self, state: hi.HostState):
        from collections import ChainMap

        self.s = state
        self.new_names: dict = {}
        self.names = ChainMap(self.new_names, state.names)
        self.pair_flags = state.pair_flags
        self.units = state.units
        self.bind: dict = {}  # pair -> key
        self.key_mid: dict = {}  # key -> machine id
        self.added: dict = {}  # machine id -> pairs
        self.canon: dict = {}  # machine id -> canonical, for machines made here

    def machine_of_key(self, key):
        return self.key_mid.get(key) or self.s.key_machine.get(key)

    def machine_of_pair(self, p):
        key = self.bind.get(p) or self.s.bindings.get(p)
        return self.machine_of_key(key) if key else None

    def canonical(self, mid) -> str:
        m = self.s.machines.get(mid)
        return self.canon.get(mid) or (m.canonical if m else "")

    def pairs(self, mid) -> list:
        m = self.s.machines.get(mid)
        return list(dict.fromkeys([*(m.pairs if m else ()), *self.added.get(mid, ())]))

    def canonical_owner(self, canonical: str):
        for mid, c in self.canon.items():
            if hi.spelling(c) == hi.spelling(canonical):
                return mid
        m = self.s.canonical_owner(canonical)
        return m.id if m else None

    def join(self, mid, key, canonical, pairs) -> None:
        self.key_mid.setdefault(key, mid)
        if mid not in self.s.machines:
            self.canon.setdefault(mid, canonical)
        for p in pairs:
            if self.machine_of_pair(p) is None:
                self.bind[p] = key
                self.added.setdefault(mid, []).append(p)


def _item_reason(
    v: _Overlay, action: str, item: dict, automatic: bool, examiner: bool
) -> str:
    """Why one confirm or Start-now item is refused, or ""."""
    key = str(item.get("key") or "")
    pairs = [p for p in (hi._pair(x) for x in item.get("pairs") or ()) if p]
    kmid = v.machine_of_key(key) if key else None
    canonical = str(item.get("canonical") or "") or (v.canonical(kmid) if kmid else "")
    mids = {m for m in [kmid, *(v.machine_of_pair(p) for p in pairs)] if m}
    in_use = [m for m in mids if v.pairs(m)]
    if examiner and canonical:  # a name the examiner typed that another machine has
        owner = v.canonical_owner(canonical)
        if owner is not None and owner not in mids:
            return (
                f"host name {canonical!r} is already used by another machine "
                f"({v.canonical(owner)}); merge the two machines instead"
            )
    # two machines in use never share a name, so a merge of two is caught here too
    if any(v.canonical(m) != canonical for m in in_use):
        return IN_USE
    target = in_use[0] if in_use else kmid
    had = v.pairs(target) if target else []
    result = list(dict.fromkeys([*had, *pairs]))
    why = _i2(v, result, canonical, [p for p in pairs if p not in had])
    if why:
        return why
    if automatic:
        return _i3(v, result, had)
    return ""


def check_decision(state: hi.HostState, record: dict, door: str) -> list[tuple]:
    """[(item index or None, reason)] for what `record` may not do."""
    action = record.get("action")
    if action in OPS:
        return [] if door == "R" else [(None, "a host operation comes from R only")]
    if action not in ("confirm", "start_now"):
        return []
    args = record.get("args") if isinstance(record.get("args"), dict) else {}
    automatic = action == "start_now" or bool(args.get("proposed"))
    v = _Overlay(state)
    refused = []
    for i, item in enumerate(args.get("machines") or ()):
        if not isinstance(item, dict):
            continue
        why = _item_reason(v, action, item, automatic, examiner=action == "confirm")
        if why:
            refused.append((i, why))
            continue
        key = str(item.get("key") or "")
        pairs = [p for p in (hi._pair(x) for x in item.get("pairs") or ()) if p]
        mid = next(
            (m for m in [v.machine_of_key(key), *(v.machine_of_pair(p) for p in pairs)]
             if m and v.pairs(m)),
            v.machine_of_key(key) or key,
        )  # fmt: skip
        v.join(mid, key, str(item.get("canonical") or ""), pairs)
    return refused


def check_binds(state: hi.HostState, records: list[dict], door: str) -> list[tuple]:
    """[(record index, reason)] for the bind records that may not be
    appended; each is judged with the earlier records (names and binds) in
    place."""
    automatic = door in AUTOMATIC_DOORS
    v = _Overlay(state)
    refused = []
    for i, rec in enumerate(records):
        if rec.get("kind") == "name":  # its evidence counts for the binds after it
            p = hi._pair((rec.get("unit"), rec.get("raw")))
            if p is not None:
                info = v.new_names.setdefault(p, {"evidence": [], "origins": []})
                for k, field in (("evidence", "evidence"), ("origin", "origins")):
                    x = rec.get(k)
                    if x and x not in info[field]:
                        info[field].append(x)
                old = state.names.get(p) or {}
                for field in ("evidence", "origins"):
                    info[field] = list(
                        dict.fromkeys([*(old.get(field) or ()), *info[field]])
                    )
            continue
        if rec.get("kind") != "bind":
            continue
        p = hi._pair((rec.get("unit"), rec.get("raw")))
        key = rec.get("key")
        if p is None or not isinstance(key, str):
            continue
        before = v.bind.get(p) or state.bindings.get(p)
        if before is not None and before != key:
            refused.append((i, "it is bound to another machine already"))
            continue
        mid = v.machine_of_key(key) or key
        canonical = v.canonical(mid) or str(rec.get("canonical") or p[1])
        had = v.pairs(mid)
        pairs = list(dict.fromkeys([*had, p]))
        why = _i2(v, pairs, canonical, [p]) or (_i3(v, pairs, had) if automatic else "")
        if why:
            refused.append((i, why))
            continue
        v.join(mid, key, canonical, [p])
    return refused
