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
_AI = hi.AI_ORIGINS | {"file-name"}


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
    a confirmed or started-now machine, and one per unit with no name."""
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
        for p in rest:
            m = state.machine_of_pair(*p)
            if m is not None and m.state in _RESOLVED:
                continue
            origins = set((state.names.get(p) or {}).get("origins") or ())
            reason = REASON_AI if origins and origins <= _AI else REASON_UNCONFIRMED
            out.append(
                {"unit": unit, "locator": locator, "raw": p[1], "reason": reason}
            )
    return out


def _not_a_host(state: hi.HostState, p) -> bool:
    return hi.FLAG_NOT_A_HOST in state.pair_flags.get(p, [])


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

    for g in host_proposal.cached_propose(root, state):
        pairs = [p for p in g.pairs if p in pending]
        if not pairs:
            continue
        if g.machine:  # a machine already holds some of them: they join it
            m = state.machines[g.machine]
            key, canonical = m.keys[0], m.canonical
        else:
            key, canonical = hi.new_machine_key(), canonical_for(g.canonical)
        machines.append(
            {"key": key, "canonical": canonical, "pairs": [list(p) for p in pairs]}
        )
    for e in waiting:  # nothing to name it by: its placeholder
        if e["raw"]:
            continue
        name = canonical_for(placeholder_name(e["locator"]))
        rejected = [
            list(p) for p in state.names if p[0] == e["unit"] and _not_a_host(state, p)
        ]
        machines.append(
            {"key": hi.new_machine_key(), "canonical": name,
             "pairs": [[e["unit"], name], *rejected]}
        )  # fmt: skip
    record = {
        "action": "start_now",
        "examiner": examiner,
        "args": {"run_id": run_id, "machines": machines},
    }
    hi.append_decision(
        root, record, state.obs_offset if seen_offset is None else seen_offset
    )
    return {"run_id": run_id, "machines": machines}


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
    when what is pending changes, and poll the fold. No timeout: the examiner
    confirms, starts now or cancels (RunCancelled). Holds no lock."""
    root = Path(case_dir)
    units = list(dict.fromkeys(units))
    recorded = False
    last = None
    while True:
        state = hi.load(root)
        if run_id and run_id in state.cancelled:
            raise RunCancelled(f"run {run_id} was cancelled in the Hosts tab")
        pending = unresolved(state, units)
        if not pending:
            return
        if not recorded:
            record_wait(root, run_id, units)
            recorded = True
        now = summary(pending)
        if on_wait is not None and now != last:
            on_wait(now)
        last = now
        time.sleep(poll)
