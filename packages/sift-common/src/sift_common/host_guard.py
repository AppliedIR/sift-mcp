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

import copy

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


def _placeholder(state: hi.HostState, unit: str, canonical: str) -> bool:
    from sift_common import host_gate

    if canonical.startswith("unattributed:"):
        return True
    locator = str((state.units.get(unit) or {}).get("locator") or "")
    return bool(locator) and hi.spelling(canonical).startswith(
        hi.spelling(host_gate.placeholder_name(locator))
    )


def _i2(state: hi.HostState, pairs, canonical: str) -> str:
    """Why the not-a-host names among `pairs` (the machine's names after the
    step) can't belong to it, or ""."""
    for p in pairs:
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


def _i3(state: hi.HostState, pairs) -> str:
    """Why a machine holding `pairs` would be two machines, or ""."""
    from sift_common.host_proposal import LIST_UNIT

    units = {p[0] for p in pairs if p[0] != LIST_UNIT and _own(state, p)}
    guids = {
        str((state.units.get(u) or {}).get("machine_guid") or "").lower() for u in units
    } - {""}
    if len(guids) > 1:
        return "it would join machines with different machine ids"
    shorts: dict[str, set] = {}
    for p in pairs:
        if _not_a_host(state, p):
            continue
        short, domain = hi.split_name(p[1])
        if domain:
            shorts.setdefault(short, set()).add(domain)
    if any(len(d) > 1 for d in shorts.values()):
        return "it would put one name in two domains on one machine"
    return ""


def _item_reason(state: hi.HostState, item: dict, automatic: bool) -> str:
    """Why one confirm or Start-now item is refused on `state`, or ""."""
    key = str(item.get("key") or "")
    pairs = [p for p in (hi._pair(x) for x in item.get("pairs") or ()) if p]
    km = state.machine_of_key(key) if key else None
    canonical = str(item.get("canonical") or "") or (km.canonical if km else "")
    bound = {}
    for p in pairs:
        m = state.machine_of_pair(*p)
        if m is not None:
            bound[m.id] = m
    in_use = [m for m in ([km] if km else []) + list(bound.values()) if m.pairs]
    if any(m.canonical != canonical for m in in_use):
        return IN_USE
    if len({m.id for m in in_use}) > 1:
        return IN_USE
    target = in_use[0] if in_use else km
    result = list(dict.fromkeys([*(target.pairs if target else ()), *pairs]))
    why = _i2(state, result, canonical)
    if why:
        return why
    if automatic:
        return _i3(state, result)
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
    folder = hi._Folder()
    folder.s = copy.deepcopy(state)
    refused = []
    for i, item in enumerate(args.get("machines") or ()):
        if not isinstance(item, dict):
            continue
        why = _item_reason(folder.s, item, automatic)
        if why:
            refused.append((i, why))
            continue
        folder.decision({"action": action, "args": {"machines": [item]}})
    return refused


def check_binds(state: hi.HostState, records: list[dict], door: str) -> list[tuple]:
    """[(record index, reason)] for the bind records that may not be
    appended; each is judged with the earlier records in place."""
    automatic = door in AUTOMATIC_DOORS
    added: dict[str, list] = {}  # key -> pairs bound in this batch
    bound: dict[tuple, str] = {}  # pair -> key, in this batch
    canon: dict[str, str] = {}
    refused = []
    for i, rec in enumerate(records):
        if rec.get("kind") != "bind":
            continue
        p = hi._pair((rec.get("unit"), rec.get("raw")))
        key = rec.get("key")
        if p is None or not isinstance(key, str):
            continue
        before = bound.get(p) or state.bindings.get(p)
        if before is not None and before != key:
            refused.append((i, "it is bound to another machine already"))
            continue
        m = state.machine_of_key(key)
        canonical = (
            m.canonical if m else canon.get(key) or str(rec.get("canonical") or p[1])
        )
        pairs = list(dict.fromkeys([*(m.pairs if m else ()), *added.get(key, ()), p]))
        why = _i2(state, pairs, canonical) or (_i3(state, pairs) if automatic else "")
        if why:
            refused.append((i, why))
            continue
        added.setdefault(key, []).append(p)
        bound[p] = key
        canon.setdefault(key, canonical)
    return refused
