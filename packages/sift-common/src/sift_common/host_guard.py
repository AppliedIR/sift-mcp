"""The one check every host-log writer runs, under the log lock, on the fresh
state: the examiner's decisions (portal, Start now, cancel), names bound
while ingesting, and the host list's confirmations. Each item of a request
is checked against the state including the request's earlier items.

- Names stay: a machine in use (one holding names) never changes its name and never
  merges with another, except through a host operation (rename, merge or
  split), which only R appends.
- Not a host: a name marked not a host binds only to its own unit's machine (one
  holding another name of that unit's own) or to the unit's placeholder.
- No flagged unit by the list: the host list never confirms a unit's own
  names while the unit carries a scan flag (an unusual or non-host name, a
  near spelling, one short name in two domains, a folder name its artifacts
  contradict, thin evidence): the examiner decides those.
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


def _foreign(state: hi.HostState, p, evidence=None) -> bool:
    """A row's or a forwarded log's name. `evidence`: the name's evidence as
    a bind sees it (a name met while ingesting isn't in the state yet)."""
    ev = evidence or (state.names.get(p) or {}).get("evidence") or []
    return bool(ev) and all(
        e.endswith("host column") or e.lower().startswith("forwardedevents") for e in ev
    )


def _not_a_host(state: hi.HostState, p) -> bool:
    return hi.FLAG_NOT_A_HOST in state.pair_flags.get(p, [])


def _own(state: hi.HostState, p) -> bool:
    """One of its unit's own names: neither a row's nor a forwarded log's,
    nor one the examiner said is not a host."""
    return not _foreign(state, p) and not _not_a_host(state, p)


def _its_own_machine(had, unit: str) -> bool:
    """Whether the machine holding `had` is the unit's own: every name it
    holds is the unit's (the examiner decided that machine for the unit)."""
    return all(q[0] == unit for q in had)


def placeholder_of(state, unit: str) -> set[str]:
    """The names a unit's own placeholder machine may carry: the unit's
    placeholder, exactly (named from its locator, or from the unit when it
    has none, as the doors name it), the examiner's `unattributed:<unit>`, and
    the name of the machine the examiner named the unit on (a pair of the unit
    no evidence gave)."""
    from sift_common import host_gate

    locator = str((state.units.get(unit) or {}).get("locator") or unit)
    own = {f"unattributed:{unit}", host_gate.placeholder_name(locator)}
    s = getattr(state, "s", state)  # (a request's overlay: the state under it)
    for p, key in s.bindings.items():
        if p[0] == unit and p not in s.names:
            m = s.machine_of_key(key)
            if m is not None:
                own.add(m.canonical)
    return own


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
    from sift_common.host_proposal import LIST_UNIT, is_address

    units = {p[0] for p in pairs if p[0] != LIST_UNIT and _own(state, p)}
    guids = {
        str((state.units.get(u) or {}).get("machine_guid") or "").lower() for u in units
    } - {""}
    shorts: dict[str, set] = {}
    for p in pairs:
        if _not_a_host(state, p) or is_address(p[1]):  # (an address has no domain)
            continue
        short, domain = hi.split_name(p[1])
        if domain:
            shorts.setdefault(short, set()).add(domain)
    return guids, shorts


def unit_flag(state: hi.HostState, unit: str) -> str:
    """The scan flag a unit's own names carry, or "": read here from the
    state, apart from the list's own judgement of it."""
    from sift_common import host_proposal as hp

    ps, own, _ = hp._sides(state, unit)
    if any(hp.name_flags(p[1]) for p in own if not ps[p].ai_only):
        return "an unusual or non-host name"
    hinted = {(h.get("unit"), h.get("raw")) for h in state.hints}
    if any(p in hinted for p in own):
        return "a near spelling"
    domains: dict[str, set] = {}
    for p in own:
        short, domain = hi.split_name(p[1])
        if domain:
            domains.setdefault(short, set()).add(domain)
    if any(len(d) > 1 for d in domains.values()):
        return hp.FLAG_DOMAINS
    folder = [p for p in own if ps[p].folder]
    artifact = [p for p in own if ps[p].artifact and not hp.name_flags(p[1])]
    if (
        folder
        and artifact
        and not any(hp.close(f[1], a[1]) for f in folder for a in artifact)
    ):
        return hp.FLAG_FOLDER
    if len({e for p in own for e in ps[p].evidence}) <= 1:
        return hp.FLAG_THIN
    return ""


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


def _join_reason(state: hi.HostState, mid, canonical: str, had, added) -> str:
    """Why an automatic join of the names `added` into the existing machine
    `mid` (holding `had`) is refused, or "": a name with a domain never
    joins a machine holding a name in another domain (through its bare names
    too), and a bare name only one no other machine or unit in the case also
    holds. A name with a domain the machine doesn't hold exactly joins
    through its short name, under the same rule. A unit's names on its own
    machine aren't judged here."""
    from sift_common.host_proposal import LIST_UNIT, is_address

    if not had:  # a machine made now: when it links units, its bare names too
        if len({p[0] for p in added if p[0] != LIST_UNIT}) < 2:
            return ""
        for p in added:
            if p[0] == LIST_UNIT or _not_a_host(state, p) or is_address(p[1]):
                continue
            if not hi.split_name(p[1])[1] and _other_holders(state, p, mid, set(added)):
                return f"{p[1]!r} is a bare name another machine or unit in the case also holds"
        return ""
    for p in added:
        if p[0] == LIST_UNIT or _not_a_host(state, p) or is_address(p[1]):
            continue
        if _its_own_machine(had, p[0]):
            continue  # its unit's own machine
        # the machine's names, other than this unit's own
        names = [
            canonical,
            *(q[1] for q in had if q[0] != p[0] and not _not_a_host(state, q)),
        ]
        domains = {hi.split_name(n)[1] for n in names if not is_address(n)} - {""}
        domain = hi.split_name(p[1])[1]
        if domain and domains - {domain}:
            return f"{p[1]!r} would join a machine with a name in another domain"
        # matched through its short name (it has none, or the machine holds it
        # bare only): only when no other machine or unit in the case holds it
        exact = hi.spelling(p[1]) in {hi.spelling(n) for n in names}
        if (not domain or not exact) and _other_holders(state, p, mid, set(had)):
            return (
                f"{p[1]!r} would join through a short name another machine or unit"
                " in the case also holds"
            )
    return ""


def _only_through_not_a_host(state: hi.HostState, canonical: str, had, added) -> str:
    """Why a join of `added` into the machine holding `had` links them only
    through a name the examiner marked not a host, or ""."""
    if not had:
        return ""
    on = [(canonical, False), *((q[1], _not_a_host(state, q)) for q in had)]
    for p in added:
        if _its_own_machine(had, p[0]):
            continue  # its unit's own machine
        mine = [(q[1], _not_a_host(state, q)) for q in state.names if q[0] == p[0]]
        mine.append((p[1], _not_a_host(state, p)))

        def shorts(names, real_only):
            return {hi.split_name(n)[0] for n, nah in names if not (real_only and nah)}

        if (shorts(mine, False) & shorts(on, False)) and not (
            shorts(mine, True) & shorts(on, True)
        ):
            return (
                f"{p[1]!r} would join a machine only through a name marked not a host"
            )
    return ""


def _other_holders(state: hi.HostState, p, mid, on_target: set) -> set:
    """The machines and units other than `mid` (and `p`'s unit) holding
    `p`'s short name; a unit whose such names are all on `mid` already (by
    this request) counts as `mid`."""
    short = hi.split_name(p[1])[0]
    out = set()
    for h in hi.short_name_holders(state, p[1], but_unit=p[0]) - {("machine", mid)}:
        if h[0] == "unit" and all(
            q in on_target
            for q in state.names
            if q[0] == h[1]
            and q not in state.bindings
            and hi.split_name(q[1])[0] == short
        ):
            continue
        out.add(h)
    return out


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
    added = [p for p in pairs if p not in had]
    why = _i2(v, result, canonical, added) or (
        _only_through_not_a_host(v.s, v.canonical(target), had, added) if target else ""
    )
    if why:
        return why
    if action == "confirm" and automatic or (action == "start_now" and had):
        # unflagged, judged now: a confirm-all item, or a Start now join into
        # a machine that exists, never for a unit flagged at this state
        for unit in sorted({p[0] for p in added}):
            if action == "start_now" and _its_own_machine(had, unit):
                continue  # its own machine: Start now is how the examiner unblocks it
            flag = unit_flag(v.s, unit)
            if flag:
                return f"the unit is flagged now ({flag}); the examiner decides"
    if automatic:
        added = [p for p in pairs if p not in had]
        return _i3(v, result, had) or _join_reason(
            v.s, target, v.canonical(target) if target else canonical, had, added
        )
    return ""


ADDRESS = "an IP address never names a machine"
ADDRESS_BIND = "an IP address goes only on its unit's placeholder"


def refuse_while_operating(root, door: str) -> None:
    """Raises HostOpRunning while the examiner's host operation (R) is
    running or incomplete: nothing but R's own door writes host decisions or
    binds then, or R's own decision could be refused and the case stuck.
    Called by every writer under the host-log lock."""
    if door != "R" and hi.unfinished_op(root):
        raise hi.HostOpRunning("a host rename/merge is running; try again when it ends")


def check_decision(state: hi.HostState, record: dict, door: str) -> list[tuple]:
    """[(item index or None, reason)] for what `record` may not do."""
    from sift_common.host_proposal import is_address

    action = record.get("action")
    args = record.get("args") if isinstance(record.get("args"), dict) else {}
    if action in OPS:
        if door != "R":
            return [(None, "a host operation comes from R only")]
        return [(None, ADDRESS)] if is_address(str(args.get("canonical") or "")) else []
    if action not in ("confirm", "start_now"):
        return []
    automatic = action == "start_now" or bool(args.get("proposed"))
    v = _Overlay(state)
    refused = []
    for i, item in enumerate(args.get("machines") or ()):
        if not isinstance(item, dict):
            continue
        why = (
            ADDRESS
            if is_address(str(item.get("canonical") or ""))
            else _item_reason(v, action, item, automatic, examiner=action == "confirm")
        )
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
    from sift_common.host_proposal import LIST_UNIT, is_address

    automatic = door in AUTOMATIC_DOORS
    v = _Overlay(state)
    refused = []
    flagged: dict[str, str] = {}  # unit -> its scan flag, for the list
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
        # an address never names a machine and goes only on its unit's
        # placeholder, whatever the door's own filters let through
        if is_address(canonical):
            refused.append((i, ADDRESS))
            continue
        if is_address(p[1]) and not _placeholder(state, p[0], canonical):
            refused.append((i, ADDRESS_BIND))
            continue
        # the list confirms automatically, at its own door and for a name met
        # while ingesting (a late bind it confirms): never a flagged unit's
        from_list = door == "list" or (
            door == "late" and rec.get("state") == hi.CONFIRMED
        )
        # a name met while ingesting that matches a confirmed machine exactly
        # joins it automatically too (no state: the machine's own)
        matched = door == "late" and hi.FLAG_MATCHED_DURING_INGEST in (
            rec.get("flags") or []
        )
        evidence = (v.new_names.get(p) or {}).get("evidence")
        if (
            (from_list or matched)
            and p[0] != LIST_UNIT
            and not _foreign(state, p, evidence)
            and not _not_a_host(state, p)
        ):
            if p[0] not in flagged:
                # at the late door, a flag the scan gave: a unit with no names
                # of its own yet has none to give (its first name is late)
                scanned = door == "list" or any(
                    q[0] == p[0] and not _foreign(state, q) for q in state.names
                )
                flagged[p[0]] = unit_flag(state, p[0]) if scanned else ""
            if flagged[p[0]] and from_list:
                refused.append((i, f"the list never confirms a unit with a flag "
                                   f"({flagged[p[0]]}); the examiner decides"))  # fmt: skip
                continue
            if flagged[p[0]] and not _its_own_machine(v.pairs(mid), p[0]):
                refused.append((i, f"a name met while ingesting never joins a "
                                   f"confirmed machine for a unit with a flag "
                                   f"({flagged[p[0]]}); the examiner decides"))  # fmt: skip
                continue
        had = v.pairs(mid)
        pairs = list(dict.fromkeys([*had, p]))
        why = (
            _i2(v, pairs, canonical, [p])
            or _only_through_not_a_host(state, canonical, had, [p])
            or (
                _i3(v, pairs, had) or _join_reason(state, mid, canonical, had, [p])
                if automatic
                else ""
            )
        )
        if why:
            refused.append((i, why))
            continue
        v.join(mid, key, canonical, [p])
    return refused
