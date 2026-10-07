"""The host invariants hold whatever door is used, in whatever order.

A seeded random sequence drives the real doors (names arriving with each
scan's list judgment, list uploads, the examiner's confirmations from stale
pages, confirm-all of proposals, not-a-host, names bound while ingesting,
Start now), and after every step an oracle written apart from the product
checks:

- names stay: a machine holding names keeps its name and is never merged;
- not a host: a not-a-host name is only with its own unit's machine or placeholder;
- one machine: an automatic door never leaves a machine with two machine ids (from
  the units whose own names it holds) or one name in two domains.

The probes that found each breach are fixed rows. Names are synthetic.
"""

from __future__ import annotations

import random

import pytest
from sift_common import host_gate as hg
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

NAMES = ["WKS01", "wks01.corp-a.test", "wks01.corp-b.test", "DC01", "dc01.a.test",
         "dc01.b.test", "WORKGROUP", "SRV", "REMOTE"]  # fmt: skip
EVIDENCE = ["SYSTEM ComputerName", "Security.evtx Computer", "events.csv host column",
            "ForwardedEvents Computer"]  # fmt: skip
LISTS = ["DC01\nWKS01,wks01.corp-a.test\n", "DC01\n", "WKS01\nSRV\nREMOTE\n"]
AUTOMATIC = {"name", "list", "confirm_all", "mint", "start"}


# -- the oracle (independent of host_guard)


def _foreign(state, p) -> bool:
    ev = (state.names.get(p) or {}).get("evidence") or []
    return bool(ev) and all(
        e.endswith("host column") or e.lower().startswith("forwardedevents") for e in ev
    )


def _nah(state, p) -> bool:
    return hi.FLAG_NOT_A_HOST in state.pair_flags.get(p, [])


def violations(P, Q, door) -> list:
    out = []
    seen: dict = {}
    for m in P.machines.values():  # names stay
        if not m.pairs:
            continue
        q = Q.machine_of_key(m.keys[0])
        if q is None:
            continue
        if q.canonical != m.canonical:
            out.append(("renamed in use", door, m.canonical, q.canonical))
        if q.id in seen:
            out.append(("merged in use", door, seen[q.id], m.canonical))
        seen[q.id] = m.canonical
    for p, flags in Q.pair_flags.items():  # not a host
        if hi.FLAG_NOT_A_HOST not in flags or p not in Q.bindings:
            continue
        if P.bindings.get(p) == Q.bindings.get(p):
            continue
        m = Q.machine_of_pair(*p)
        locator = str((Q.units.get(p[0]) or {}).get("locator") or p[0])
        placeholder = m.canonical.startswith("unattributed:") or m.canonical.startswith(
            hg.placeholder_name(locator)
        )
        own = [x for x in m.pairs if x[0] == p[0] and x != p
               and not _foreign(Q, x) and not _nah(Q, x)]  # fmt: skip
        if not own and not placeholder:
            out.append(("not a host elsewhere", door, p[1], m.canonical))
    if door in AUTOMATIC:  # one machine, on the machines this step changed
        for q in Q.machines.values():
            before = P.machine_of_key(q.keys[0])
            if before is not None and sorted(before.pairs) == sorted(q.pairs):
                continue
            units = {u for u, r in q.pairs if u != hp.LIST_UNIT
                     and not _foreign(Q, (u, r)) and not _nah(Q, (u, r))}  # fmt: skip
            guids = {str((Q.units.get(u) or {}).get("machine_guid") or "").lower()
                     for u in units} - {""}  # fmt: skip
            if len(guids) > 1:
                out.append(("two machine ids", door, q.canonical, sorted(guids)))
            shorts: dict = {}
            for p in q.pairs:
                if _nah(Q, p):
                    continue
                s, d = hi.split_name(p[1])
                if d:
                    shorts.setdefault(s, set()).add(d)
            if any(len(d) > 1 for d in shorts.values()):
                out.append(
                    ("two domains", door, q.canonical, sorted(n for _, n in q.pairs))
                )
    return out


# -- the sequence


def _case(tmp_path, seed):
    d = tmp_path / f"s{seed}"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def run(tmp_path, seed: int, steps: int = 60, monkeypatch=None) -> list:
    rng = random.Random(seed)
    monkeypatch.setattr(hi, "new_machine_key", lambda: f"{rng.getrandbits(64):016x}")
    case = _case(tmp_path, seed)
    units = [f"u{i}" for i in range(5)]
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": f"ev/{u}.raw",
         "machine_guid": rng.choice(["A", "B", None]), "client_id": rng.choice(["c1", None])}
        for u in units
    ])  # fmt: skip
    history, found = [], []
    for step in range(steps):
        P = hi.load(case)
        history.append(P)
        door = rng.choice(["name", "name", "list", "confirm", "confirm_all", "nah", "mint",
                           "start"])  # fmt: skip
        before = (case / hi.DECISIONS).read_bytes()
        try:
            if door == "name":
                u, n = rng.choice(units), rng.choice(NAMES)
                hi.append_observations(case, [{"kind": "name", "unit": u, "raw": n,
                    "evidence": rng.choice(EVIDENCE),
                    "origin": rng.choice(["artifact"] * 4 + ["argument"])}])  # fmt: skip
                hp.apply_host_list(case, [u])  # as every scan does
            elif door == "list":
                hp.upload_host_list(case, rng.choice(LISTS), "ex")
            elif door == "confirm":  # one examiner's page, maybe stale
                view = rng.choice(history[-3:])
                if not view.names:
                    continue
                items = []
                for _ in range(rng.randint(1, 3)):  # items may overlap
                    pairs = rng.sample(
                        sorted(view.names), min(len(view.names), rng.randint(1, 2))
                    )
                    item = {"key": hi.new_machine_key(), "canonical": rng.choice(NAMES + ["EDIT"]),
                            "pairs": [list(p) for p in pairs]}  # fmt: skip
                    if view.machines and rng.random() < 0.4:
                        m = rng.choice(
                            sorted(view.machines.values(), key=lambda m: m.id)
                        )
                        item["key"], item["canonical"] = m.keys[0], m.canonical
                    items.append(item)
                hi.append_decision(case, {"action": "confirm", "args": {"machines": items}},
                                   view.obs_offset)  # fmt: skip
            elif door == "confirm_all":  # the proposals as one page showed them
                view = rng.choice(history[-3:])
                items = [{"key": view.machines[g.machine].keys[0] if g.machine
                          else hi.new_machine_key(),
                          "canonical": g.canonical, "pairs": [list(p) for p in g.pairs]}
                         for g in hp.propose(view) if any(p not in view.bindings for p in g.pairs)]  # fmt: skip
                if items:
                    # (a release before per-item decisions: the whole request)
                    getattr(hi, "append_decision_items", hi.append_decision)(
                        case,
                        {
                            "action": "confirm",
                            "args": {"machines": items, "proposed": True},
                        },
                        view.obs_offset,
                    )
            elif door == "nah" and P.names:
                p = rng.choice(sorted(P.names))
                hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [list(p)]}},
                                   P.obs_offset)  # fmt: skip
            elif door == "mint" and P.names:
                p = (
                    rng.choice(sorted(P.names))
                    if rng.random() < 0.6
                    else (rng.choice(units), rng.choice(NAMES))
                )
                hi.get_or_mint(case, p[0], p[1])
            elif door == "start":
                hg.record_wait(case, f"r{step}", rng.sample(units, 2))
                hg.start_now(case, f"r{step}", "ex")
        except hi.HostLogError:
            if door == "confirm":  # all or nothing
                assert (case / hi.DECISIONS).read_bytes() == before
        found += [(seed, step, *v) for v in violations(P, hi.load(case), door)]
    return found


@pytest.mark.parametrize("block", range(10))
def test_the_invariants_hold_through_every_door(tmp_path, monkeypatch, block):
    found = []
    for seed in range(block * 20, block * 20 + 20):
        found += run(tmp_path, seed, monkeypatch=monkeypatch)
    assert found == []


# -- the probes, as fixed rows


@pytest.fixture
def case(tmp_path):
    return _case(tmp_path, "fixed")


def obs(case, *recs):
    hi.append_observations(case, list(recs))


def unit(u, guid=None, client=None):
    return {"kind": "unit", "unit": u, "locator": f"ev/{u}", "machine_guid": guid,
            "client_id": client}  # fmt: skip


def name(u, raw, ev="SYSTEM ComputerName", origin="artifact"):
    return {"kind": "name", "unit": u, "raw": raw, "evidence": ev, "origin": origin}


def test_two_items_of_one_request_naming_one_name_twice_are_refused(case):
    obs(case, unit("u1"), name("u1", "WKS01"), name("u1", "X"))
    P = hi.load(case)
    with pytest.raises(hi.HostLogError, match="in use"):
        hi.append_decision(case, {"action": "confirm", "args": {"machines": [
            {"key": "k1", "canonical": "WKS01", "pairs": [["u1", "WKS01"], ["u1", "X"]]},
            {"key": "k2", "canonical": "RENAMED", "pairs": [["u1", "X"]]}]}},
            P.obs_offset)  # fmt: skip
    assert violations(P, hi.load(case), "confirm") == []


def test_a_not_a_host_name_never_goes_to_a_remote_machine(case, monkeypatch):
    keys = iter(["ffff000000000001", "0000000000000002", "0000000000000003"])
    monkeypatch.setattr(hi, "new_machine_key", lambda: next(keys))
    obs(case, unit("u1"), name("u1", "COLLECTOR"),
        name("u1", "COLLECTOR", "Security.evtx Computer"),
        name("u1", "REMOTE", "events.csv host column"), name("u1", "WORKGROUP"))  # fmt: skip
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": "ffff000000000001", "canonical": "COLLECTOR", "pairs": [["u1", "COLLECTOR"]]},
        {"key": "0000000000000002", "canonical": "REMOTE", "pairs": [["u1", "REMOTE"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [["u1", "WORKGROUP"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    P = hi.load(case)
    key, canonical = hi.get_or_mint(case, "u1", "WORKGROUP")
    assert canonical == "COLLECTOR"  # its unit's own machine, never REMOTE
    assert violations(P, hi.load(case), "mint") == []


def test_a_unit_without_a_machine_id_never_bridges_two(case):
    obs(case, unit("u1", "A", "c1"), unit("u2", None, "c1"), unit("u3", "B", "c1"),
        name("u1", "H1"), name("u2", "H2"), name("u3", "H3"))  # fmt: skip
    hg.record_wait(case, "r1", ["u1", "u2", "u3"])
    P = hi.load(case)
    hg.start_now(case, "r1", "ex")
    assert violations(P, hi.load(case), "start") == []


def test_one_list_entry_never_joins_names_of_two_domains(case):
    obs(case, unit("u1"), name("u1", "WS1"), name("u1", "WS1", "Security.evtx Computer"),
        name("u1", "dc01.a.test", "events.csv host column"),
        name("u1", "dc01.b.test", "events.csv host column"))  # fmt: skip
    P = hi.load(case)
    hp.upload_host_list(case, "DC01\n", "ex")
    assert violations(P, hi.load(case), "list") == []


def test_start_now_never_merges_two_machines_in_use(case):
    obs(
        case,
        unit("u1"),
        name("u1", "WKS01"),
        name("u1", "wks01.corp.test", "Security.evtx Computer"),
    )
    hi.get_or_mint(case, "u1", "WKS01")
    hi.get_or_mint(case, "u1", "wks01.corp.test")
    hg.record_wait(case, "r1", ["u1"])
    P = hi.load(case)
    hg.start_now(case, "r1", "ex")
    assert violations(P, hi.load(case), "start") == []


def test_only_r_appends_a_rename_merge_or_split(case):
    obs(case, unit("u1"), name("u1", "WKS01"), unit("u2"), name("u2", "WKS02"))
    ka, _ = hi.get_or_mint(case, "u1", "WKS01")
    kb, _ = hi.get_or_mint(case, "u2", "WKS02")
    seen = hi.load(case).obs_offset
    for rec in ({"action": "rename", "args": {"machine": ka, "canonical": "WKS09"}},
                {"action": "merge", "args": {"into": ka, "from": [kb]}},
                {"action": "split", "args": {"machine": ka, "keys": [ka]}}):  # fmt: skip
        with pytest.raises(hi.HostLogError, match="from R only"):
            hi.append_decision(case, rec, seen)
    hi.append_decision(case, {"action": "rename", "args": {"machine": ka, "canonical": "WKS09"}},
                       seen, door="R")  # fmt: skip
    assert hi.load(case).machine_of_key(ka).canonical == "WKS09"


def test_a_bind_of_a_not_a_host_name_to_another_units_machine_is_refused(case):
    from sift_common import host_guard

    obs(case, unit("u1"), name("u1", "WKS01"), unit("u2"), name("u2", "WORKGROUP"))
    k, _ = hi.get_or_mint(case, "u1", "WKS01")
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [["u2", "WORKGROUP"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    bind = {"kind": "bind", "unit": "u2", "raw": "WORKGROUP", "key": k}
    (refused,) = host_guard.check_binds(hi.load(case), [bind], "list")
    assert "not a host" in refused[1]


def test_a_name_in_other_units_rows_doesnt_count_their_machine_ids(case):
    obs(case, unit("u1", "A"), unit("u2", "B"),
        name("u1", "WS1"), name("u1", "WS1", "Security.evtx Computer"),
        name("u1", "DC01", "events.csv host column"),
        name("u2", "WS2"), name("u2", "WS2", "Security.evtx Computer"),
        name("u2", "DC01", "ForwardedEvents Computer"))  # fmt: skip
    hp.upload_host_list(case, "DC01\nWS1\nWS2\n", "ex")
    state = hi.load(case)
    one = state.machine_of_pair("u1", "DC01")
    assert one is not None and one is state.machine_of_pair("u2", "DC01")


def test_a_units_only_name_marked_not_a_host_may_go_to_its_placeholder_only(case):
    obs(case, {"kind": "unit", "unit": "u1", "locator": "ev/disk.raw@0"},
        name("u1", "WORKGROUP"))  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [["u1", "WORKGROUP"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    seen = hi.load(case).obs_offset
    with pytest.raises(hi.HostLogError, match="not a host"):
        hi.append_decision(case, {"action": "confirm", "args": {"machines": [
            {"key": "k1", "canonical": "SRV01", "pairs": [["u1", "WORKGROUP"]]}]}}, seen)  # fmt: skip
    placeholder = hg.placeholder_name("ev/disk.raw@0")
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": "k2", "canonical": placeholder, "pairs": [["u1", "WORKGROUP"]]}]}}, seen)  # fmt: skip
    assert hi.load(case).machine_of_pair("u1", "WORKGROUP").canonical == placeholder


def test_a_bind_never_moves_a_name_bound_to_another_machine(case):
    from sift_common import host_guard

    obs(case, unit("u1"), name("u1", "WKS01"))
    hi.get_or_mint(case, "u1", "WKS01")
    bind = {"kind": "bind", "unit": "u1", "raw": "WKS01", "key": "f" * 16}
    (refused,) = host_guard.check_binds(hi.load(case), [bind], "late")
    assert refused[1] == "it is bound to another machine already"
