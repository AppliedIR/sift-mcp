"""The ingest gate: a run writes nothing until each of its units' host names
belongs to a machine the examiner confirmed (or started now).

A unit resolves when every host name its evidence gave is bound to a machine
in state ``confirmed`` or ``started-now``: by the examiner's host list (which
confirms at the scan), by an earlier confirmation, or by Start now. Anything
else waits, with its reason, and the worker polls the fold until it resolves
or the run is cancelled. Start now and cancel are the examiner's, from the
Hosts tab; neither is reachable through MCP.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from sift_common import host_identity as hi

AWAITING = "awaiting host confirmation"
CANCELLED = "cancelled"
WAIT_MESSAGE = (
    "ask the examiner to confirm the hosts in the Hosts tab, or to choose Start now"
)
HOST_LIST_HINT = (
    "If you have an inventory of the machines in scope, upload it in the Hosts tab "
    "before ingesting; matching hosts then confirm automatically."
)
# with the list's own confirmation off (host_proposal.LIST_AUTO_CONFIRM)
HOST_LIST_HINT_PROPOSED = (
    "If you have an inventory of the machines in scope, upload it in the Hosts tab "
    "before ingesting; matching hosts are then proposed for you to confirm."
)
REASON_UNCONFIRMED = "not confirmed"
REASON_AI = "named only by the AI or an unregistered file"
REASON_NO_NAME = "no host name found"
REASON_NEEDS_NAME = "needs a name: its only name is not a host"

_RESOLVED = (hi.CONFIRMED, hi.STARTED_NOW)
_FILE_NAME = "file-name"
_AI = hi.AI_ORIGINS | {_FILE_NAME}


class RunCancelled(RuntimeError):
    """The examiner cancelled a run that was waiting for host confirmation."""


def host_list_hint(case_dir: str | os.PathLike) -> str:
    """The host-list encouragement, or "" when the case has a list loaded."""
    from sift_common import host_proposal

    hint = (
        HOST_LIST_HINT if host_proposal.LIST_AUTO_CONFIRM else HOST_LIST_HINT_PROPOSED
    )
    try:
        state = hi.load(case_dir)
    except hi.HostLogError:
        return hint
    return "" if state.host_list else hint


def unresolved(state: hi.HostState, units) -> list[dict]:
    """What keeps ``units`` from writing: one entry per host name not bound to
    a confirmed or started-now machine, and one per unit with no name. A name
    only the file name gave stops holding once a name read from the unit's
    evidence is on a confirmed or started-now machine."""
    out: list[dict] = []
    for unit in dict.fromkeys(units):
        locator = str((state.units.get(unit) or {}).get("locator") or unit)
        # what its evidence names, and what the examiner named it
        pairs = list(
            dict.fromkeys(p for p in (*state.names, *state.bindings) if p[0] == unit)
        )
        if not pairs:
            out.append(
                {"unit": unit, "locator": locator, "raw": "", "reason": REASON_NO_NAME}
            )
            continue
        # a name the examiner marked not a host is resolved, never held
        rest = [p for p in pairs if p in state.bindings or not _not_a_host(state, p)]
        if not rest:
            out.append(
                {
                    "unit": unit,
                    "locator": locator,
                    "raw": "",
                    "reason": REASON_NEEDS_NAME,
                }
            )
            continue
        free = _released(state, rest)
        for p in rest:
            if _resolved(state, p) or p in free:
                continue
            origins = _origins(state, p)
            reason = REASON_AI if origins and origins <= _AI else REASON_UNCONFIRMED
            out.append(
                {"unit": unit, "locator": locator, "raw": p[1], "reason": reason}
            )
    return out


def released(state: hi.HostState) -> set:
    """Every unit's host names that no longer hold it (`_released`)."""
    by_unit: dict[str, list] = {}
    for p in dict.fromkeys((*state.names, *state.bindings)):
        if p in state.bindings or not _not_a_host(state, p):
            by_unit.setdefault(p[0], []).append(p)
    return {p for ps in by_unit.values() for p in _released(state, ps)}


def _released(state: hi.HostState, pairs) -> set:
    """Of one unit's names, those only the file name gave (Kansa's module)
    once a name read from the unit's evidence is on a confirmed or
    started-now machine: that name says what the file name guessed."""
    named = any(
        hi.ARTIFACT in _origins(state, p) and not _not_a_host(state, p)
        and _resolved(state, p)
        for p in pairs
    )  # fmt: skip
    if not named:
        return set()
    return {
        p
        for p in pairs
        if _origins(state, p) == {_FILE_NAME} and not _resolved(state, p)
    }


def _not_a_host(state: hi.HostState, p) -> bool:
    return hi.FLAG_NOT_A_HOST in state.pair_flags.get(p, [])


def _resolved(state: hi.HostState, p) -> bool:
    m = state.machine_of_pair(*p)
    return m is not None and m.state in _RESOLVED


def _origins(state: hi.HostState, p) -> set:
    return set((state.names.get(p) or {}).get("origins") or ())


def placeholder_name(locator: str) -> str:
    """The name Start now gives a unit no name of its evidence can give: as a
    hostless volume is named, `<image>-<digest>`, plus its volume's offset."""
    import hashlib
    import re

    base, _, offset = str(locator).partition("@")
    leaf = re.split(r"[/!]", base)[-1] or "unit"
    stem = leaf.rsplit(".", 1)[0] if "." in leaf.strip(".") else leaf
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-.") or "unit"
    digest = hashlib.sha256(base.encode()).hexdigest()[:8]
    return f"{clean}-{digest}" + (f"-{offset}" if offset else "")


def summary(pending: list[dict]) -> dict:
    """The waiting state as a status or an MCP result carries it."""
    return {
        "status": AWAITING,
        "unresolved": len(pending),
        "hosts": [
            {k: e[k] for k in ("locator", "raw", "reason")} for e in pending[:50]
        ],
        "message": WAIT_MESSAGE,
    }


def record_wait(case_dir: str | os.PathLike, run_id: str, units) -> None:
    """Record that ``run_id`` waits on ``units``, for Start now and the tab."""
    hi.append_observations(
        case_dir, [{"kind": "run_wait", "run_id": run_id, "units": list(units)}]
    )


def _may_join(state: hi.HostState, m: hi.Machine, unit: str, p) -> bool:
    """Whether Start now may put name `p` of `unit` on machine `m`, which
    already exists: its own unit's machine, one it's bound to already, or a
    confirmed machine one of whose names it matches exactly (equal domains
    where both have one), from evidence, not the AI's."""
    from sift_common import host_proposal

    if state.bindings.get(p) in m.keys or all(q[0] == unit for q in m.pairs):
        return True
    if m.state != hi.CONFIRMED:
        return False
    from sift_common import host_guard

    if host_guard.unit_flag(state, unit):
        return False  # a flagged unit gets its own machine; the examiner joins it
    info = state.names.get(p) or {}
    x = host_proposal._Pair(
        unit, p[1], list(info.get("evidence") or []), set(info.get("origins") or [])
    )
    if not x.artifact or x.ai_only:
        return False
    names = [m.canonical, *(q[1] for q in m.pairs if not _not_a_host(state, q))]
    if not any(host_proposal.list_matches(p[1], [{"name": n}]) for n in names):
        return False
    domain = hi.split_name(p[1])[1]  # judged against the machine, bare names and all
    if domain and {hi.split_name(n)[1] for n in names} - {"", domain}:
        return False
    # a name without a domain: only when nothing else in the case holds it
    return bool(hi.split_name(p[1])[1]) or hi.short_name_holders(
        state, p[1], but_unit=unit
    ) == {("machine", m.id)}


def start_now(
    case_dir: str | os.PathLike,
    run_id: str,
    examiner: str,
    seen_offset: int | None = None,
) -> dict:
    """Bind the waiting run's unresolved names to the machines proposed for
    them, in state ``started-now``; a unit no name can name (none found, or
    only names the examiner marked not a host) gets its placeholder machine.
    The examiner's, from the Hosts tab: `seen_offset` is the observation-log
    offset the page showed."""
    from sift_common import host_proposal

    if not examiner:
        raise hi.HostLogError("Start now needs the examiner who chose it")
    root = Path(case_dir)
    state = hi.load(root)
    units = state.waits.get(run_id)
    if units is None:
        raise hi.HostLogError(f"no run {run_id!r} is waiting for host confirmation")
    waiting = unresolved(state, units)
    pending = {(e["unit"], e["raw"]) for e in waiting if e["raw"]}
    machines: list[dict] = []
    taken: set[str] = set()

    def canonical_for(wanted: str) -> str:
        name, n = wanted, 2
        while state.canonical_taken(name) or hi.spelling(name) in taken:
            name, n = f"{wanted} ({n})", n + 1
        taken.add(hi.spelling(name))
        return name

    # Start now names; it never merges. A proposed group's names are split
    # by unit, and a unit's names join a machine that already exists only
    # when it is that unit's own, when they are bound to it already, or when
    # the machine is confirmed and the name is evidence's and matches one of
    # its names exactly. Every other slice is a new machine of its unit alone.
    addresses: dict[str, list] = {}  # never a machine's name: the unit's placeholder
    for g in host_proposal.cached_propose(root, state):
        by_unit: dict[str, list] = {}
        for p in g.pairs:
            if p in pending and host_proposal.is_address(p[1]):
                addresses.setdefault(p[0], []).append(p)
            elif p in pending:
                by_unit.setdefault(p[0], []).append(p)
        m = state.machines.get(g.machine) if g.machine else None
        for unit, pairs in sorted(by_unit.items()):
            if m is not None:
                joins = [p for p in pairs if _may_join(state, m, unit, p)]
                pairs = [p for p in pairs if p not in joins]
                if joins:
                    machines.append({"key": m.keys[0], "canonical": m.canonical,
                                     "pairs": [list(p) for p in joins]})  # fmt: skip
            if pairs:  # a machine of this unit alone, named by its own names
                wanted = host_proposal.own_best_name(state, pairs)
                machines.append({"key": hi.new_machine_key(),
                                 "canonical": canonical_for(wanted),
                                 "pairs": [list(p) for p in pairs]})  # fmt: skip
    for e in waiting:  # nothing to name it by: its placeholder
        if e["raw"]:
            continue
        wanted = placeholder_name(e["locator"])
        rejected = [
            list(p) for p in state.names if p[0] == e["unit"] and _not_a_host(state, p)
        ]
        # (a unit whose placeholder machine exists waits by the names bound to it,
        # so it's proposed above, never here)
        key, name = hi.new_machine_key(), canonical_for(wanted)
        machines.append(
            {"key": key, "canonical": name,
             "pairs": [[e["unit"], name], *rejected,
                       *(list(p) for p in addresses.pop(e["unit"], []))]}
        )  # fmt: skip
    for unit, pairs in sorted(addresses.items()):  # its addresses: its placeholder
        from sift_common import host_guard

        own = host_guard.placeholder_of(state, unit)
        m = next((x for x in state.machines.values() if x.canonical in own), None)
        if m is not None:
            machines.append({"key": m.keys[0], "canonical": m.canonical,
                             "pairs": [list(p) for p in pairs]})  # fmt: skip
            continue
        locator = str((state.units.get(unit) or {}).get("locator") or unit)
        name = canonical_for(placeholder_name(locator))
        machines.append({"key": hi.new_machine_key(), "canonical": name,
                         "pairs": [[unit, name], *(list(p) for p in pairs)]})  # fmt: skip
    record = {
        "action": "start_now",
        "examiner": examiner,
        "args": {"run_id": run_id, "machines": machines},
    }
    out = hi.append_decision_items(
        root,
        record,
        state.obs_offset if seen_offset is None else seen_offset,
        door="start_now",
    )
    refused = {r["index"] for r in out["refused"]}
    return {
        "run_id": run_id,
        "machines": [m for i, m in enumerate(machines) if i not in refused],
        "refused": [{**r, "machine": machines[r["index"]]} for r in out["refused"]],
    }


def cancel(case_dir: str | os.PathLike, run_id: str, examiner: str) -> None:
    """Cancel a run that waits for host confirmation. The examiner's."""
    if not examiner:
        raise hi.HostLogError("a cancel needs the examiner who chose it")
    state = hi.load(case_dir)
    if run_id not in state.waits:
        raise hi.HostLogError(f"no run {run_id!r} is waiting for host confirmation")
    if run_id in state.cancelled:
        raise hi.HostLogError(f"run {run_id!r} is already cancelled")
    hi.append_decision(
        case_dir,
        {"action": "cancel_run", "examiner": examiner, "args": {"run_id": run_id}},
        state.obs_offset,
    )


def wait_for_hosts(
    case_dir: str | os.PathLike,
    run_id: str,
    units,
    on_wait=None,
    poll: float = 2.0,
) -> None:
    """Return once every unit resolves; until then call ``on_wait(summary)``
    on every poll, and poll the fold. No timeout: the examiner confirms,
    starts now or cancels (RunCancelled). Holds no lock between polls.

    The host list's confirmations are applied once no host operation is
    running: a scan made during one skipped them."""
    from sift_common import host_proposal

    root = Path(case_dir)
    units = list(dict.fromkeys(units))
    recorded = listed = False
    while True:
        if not listed:
            try:
                host_proposal.apply_host_list(root, units)
                listed = True
            except hi.HostOpRunning:
                pass  # again on the next poll
        state = hi.load(root)
        if run_id and run_id in state.cancelled:
            raise RunCancelled(f"run {run_id} was cancelled in the Hosts tab")
        pending = unresolved(state, units)
        if not pending:
            return
        if not recorded:
            record_wait(root, run_id, units)
            recorded = True
        if on_wait is not None:
            on_wait(summary(pending))
        time.sleep(poll)
