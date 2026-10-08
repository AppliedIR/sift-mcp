"""The host invariants hold whatever door is used, in whatever order.

A seeded random sequence drives the real doors (names arriving with each
scan's list judgment, list uploads, the examiner's confirmations from stale
pages, confirm-all of proposals, not-a-host, names bound while ingesting,
Start now), and after every step an oracle written apart from the product
checks:

- names stay: a machine holding names keeps its name and is never merged;
- not a host: a not-a-host name is only with its own unit's machine or placeholder;
- one machine: an automatic door never leaves a machine with two machine ids (from
  the units whose own names it holds) or one name in two domains;
- one holder: a late name joins through a short name (its own, or the
  machine's bare one) only when one machine or unit in the case holds it.

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
SETTLED = (hi.CONFIRMED, hi.STARTED_NOW)  # what the examiner decided


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
        placeholder = m.canonical in {
            f"unattributed:{p[0]}",
            hg.placeholder_name(locator),
        }
        own = [x for x in m.pairs if x[0] == p[0] and x != p
               and not _foreign(Q, x) and not _nah(Q, x)]  # fmt: skip
        if not own and not placeholder:
            out.append(("not a host elsewhere", door, p[1], m.canonical))
    if door in ("name", "list", "mint"):  # a join by the list or a late name
        for p, key in Q.bindings.items():
            if P.bindings.get(p) == key or p[0] == hp.LIST_UNIT or _nah(Q, p):
                continue  # (a not-a-host name goes with its unit's machine: checked above)
            before = P.machine_of_key(key)
            if before is None or not before.pairs:
                continue  # a machine made for it
            # the unit is one machine: its own names join together, so some
            # name of the unit's must be one of the machine's (never a not-a-host)
            mine = {hi.split_name(r)[0] for (u, r), k in Q.bindings.items()
                    if u == p[0] and k == key and not _nah(Q, (u, r))}  # fmt: skip
            theirs = {hi.split_name(before.canonical)[0]} | {
                hi.split_name(q[1])[0] for q in before.pairs if not _nah(P, q)}  # fmt: skip
            if not mine & theirs:
                out.append(
                    ("joined through a not-a-host name", door, p[1], before.canonical)
                )
    if door == "mint":  # a late name of one confirmed machine's own goes to it
        from sift_common import host_guard

        for p in set(Q.names) - set(P.names):
            if (Q.names[p].get("origins") or []) != ["artifact"] or _nah(Q, p):
                continue
            # unless its unit is flagged (by the scan: it has names of its own)
            # and the name is the unit's own: then it never joins automatically
            scanned = any(q[0] == p[0] and not _foreign(P, q) for q in P.names)
            if scanned and not _foreign(Q, p) and host_guard.unit_flag(P, p[0]):
                confirmed = {k for x in P.machines.values()
                             if x.state == hi.CONFIRMED for k in x.keys}  # fmt: skip
                if Q.bindings.get(p) in confirmed:
                    out.append(("a flagged unit's late name joined automatically",
                                door, p[1], ""))  # fmt: skip
                continue
            spelled = hi.spelling(p[1])
            homes = [m for m in P.machines.values() if m.state in SETTLED and spelled in {
                hi.spelling(m.canonical), *(hi.spelling(n) for n in m.former),
                *(hi.spelling(q[1]) for q in m.pairs if not _nah(P, q))}]  # fmt: skip
            short, domain = hi.split_name(p[1])
            joined = next((x for x in P.machines.values()  # (not its unit's own)
                           if Q.bindings.get(p) in x.keys and x.pairs
                           and any(q[0] != p[0] for q in x.pairs)), None)  # fmt: skip
            if domain and joined is not None and spelled not in {
                hi.spelling(n) for n in (
                    joined.canonical, *(q[1] for q in joined.pairs if not _nah(P, q)))
            }:  # through its short name: only what one machine or unit holds  # fmt: skip
                held = {
                    ("m", x.id)
                    for x in P.machines.values()
                    if short
                    in {
                        hi.split_name(n)[0]
                        for n in (
                            x.canonical,
                            *x.former,
                            *(q[1] for q in x.pairs if not _nah(P, q)),
                        )
                    }
                }
                held |= {("u", q[0]) for q in P.names if q not in P.bindings
                         and q[0] != p[0] and not _nah(P, q)
                         and hi.split_name(q[1])[0] == short}  # fmt: skip
                if len(held) != 1:
                    out.append(("late name joined through a short name others hold",
                                door, p[1], joined.canonical))  # fmt: skip
            if not domain:  # bare: only what one machine or unit in the case holds
                holders = {
                    ("m", x.id)
                    for x in P.machines.values()
                    if short
                    in {
                        hi.split_name(x.canonical)[0],
                        *(hi.split_name(f)[0] for f in x.former),
                        *(hi.split_name(q[1])[0] for q in x.pairs if not _nah(P, q)),
                    }
                }
                holders |= {
                    ("u", q[0])
                    for q in P.names
                    if q not in P.bindings
                    and not _nah(P, q)
                    and hi.split_name(q[1])[0] == short
                }
                if len(holders) != 1:
                    existing = {k for x in P.machines.values() for k in x.keys}
                    if Q.bindings.get(p) in existing:
                        out.append(("ambiguous bare late name joined", door, p[1], ""))
                    continue  # fmt: skip
            if len(homes) != 1:
                continue
            m = homes[0]
            other = {  # a not-a-host name counts for nothing
                hi.split_name(n)[1]
                for n in (m.canonical, *(q[1] for q in m.pairs if not _nah(P, q)))
            }
            if domain and other - {"", domain}:  # a machine in another domain: never
                if Q.bindings.get(p) in m.keys:
                    out.append(
                        ("joined a machine in another domain", door, p[1], m.canonical)
                    )
                continue

            def ids(pairs):
                us = {u for u, r in pairs if u != hp.LIST_UNIT
                      and not _foreign(Q, (u, r)) and not _nah(Q, (u, r))}  # fmt: skip
                return {str((Q.units.get(u) or {}).get("machine_guid") or "").lower()
                        for u in us} - {""}  # fmt: skip

            def doms(pairs):
                out_: dict = {}
                for q in pairs:
                    if not _nah(Q, q):
                        s_, d = hi.split_name(q[1])
                        if d:
                            out_.setdefault(s_, set()).add(d)
                return out_

            after_ids, after_doms = ids([*m.pairs, p]), doms([*m.pairs, p])
            fine = (len(after_ids) <= 1 or after_ids == ids(m.pairs)) and all(
                len(d) <= 1 or d == doms(m.pairs).get(s_)
                for s_, d in after_doms.items()
            )
            if fine:
                if Q.bindings.get(p) not in m.keys:
                    out.append(("late name not joined", door, p[1], m.canonical))
    if door in (
        "name",
        "list",
    ):  # the list never makes a second machine of a settled name
        for p, key in Q.bindings.items():
            if P.bindings.get(p) == key or p[0] == hp.LIST_UNIT or _nah(Q, p):
                continue
            if P.machine_of_key(key) is not None:
                continue  # it joined a machine that was there
            spelled = hi.spelling(p[1])
            homes = [m for m in P.machines.values() if m.state in SETTLED and spelled in {
                hi.spelling(m.canonical), *(hi.spelling(q[1]) for q in m.pairs if not _nah(P, q))}]  # fmt: skip
            if len(homes) == 1:
                out.append(
                    ("second machine of a settled name", door, p[1], homes[0].canonical)
                )
    for u in {
        p[0] for p in Q.bindings
    }:  # one placeholder machine per unit, never "(2)"
        locator = str((Q.units.get(u) or {}).get("locator") or u)
        mine = hg.placeholder_name(locator)
        names = {
            m.canonical
            for m in Q.machines.values()
            if m.canonical.startswith(mine + " (")
        }
        if names and not any(
            m.canonical.startswith(mine + " (") for m in P.machines.values()
        ):
            out.append(("second placeholder", door, u, sorted(names)))
    if door in AUTOMATIC:  # one machine, on the machines this step changed
        for q in Q.machines.values():
            before = P.machine_of_key(q.keys[0])
            if before is not None and sorted(before.pairs) == sorted(q.pairs):
                continue
            units = {u for u, r in q.pairs if u != hp.LIST_UNIT
                     and not _foreign(Q, (u, r)) and not _nah(Q, (u, r))}  # fmt: skip
            guids = {str((Q.units.get(u) or {}).get("machine_guid") or "").lower()
                     for u in units} - {""}  # fmt: skip
            had = set()
            if before is not None:
                had = {str((Q.units.get(u) or {}).get("machine_guid") or "").lower()
                       for u, r in before.pairs if u != hp.LIST_UNIT
                       and not _foreign(Q, (u, r)) and not _nah(Q, (u, r))} - {""}  # fmt: skip
            if len(guids) > 1 and guids != had:  # what the examiner joined stands
                out.append(("two machine ids", door, q.canonical, sorted(guids)))
            shorts: dict = {}
            for p in q.pairs:
                if _nah(Q, p) or hp.is_address(p[1]):  # (an address has no domain)
                    continue
                s, d = hi.split_name(p[1])
                if d:
                    shorts.setdefault(s, set()).add(d)
            had_shorts: dict = {}
            for p in before.pairs if before is not None else ():
                if _nah(Q, p) or hp.is_address(p[1]):  # (an address has no domain)
                    continue
                s, d = hi.split_name(p[1])
                if d:
                    had_shorts.setdefault(s, set()).add(d)
            if any(len(d) > 1 and d != had_shorts.get(s) for s, d in shorts.items()):
                out.append(
                    ("two domains", door, q.canonical, sorted(n for _, n in q.pairs))
                )
    for m in Q.machines.values():  # an address never names a machine, at any door
        if hp.is_address(m.canonical) and m.canonical not in {
            x.canonical for x in P.machines.values()
        }:
            out.append(("a machine named after an address", door, m.canonical, ""))
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
                hi.get_or_mint(case, p[0], p[1], evidence=rng.choice([*EVIDENCE, ""]))
            elif door == "start":
                hg.record_wait(case, f"r{step}", rng.sample(units, 2))
                hg.start_now(case, f"r{step}", "ex")
        except hi.HostLogError as e:
            if door == "confirm":  # all or nothing
                assert (case / hi.DECISIONS).read_bytes() == before
            if door == "confirm_all":  # skip and report: never the whole request
                found.append((seed, step, "confirm-all refused whole", str(e)))
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


def test_a_list_entry_never_matches_through_a_not_a_host_name(case):
    obs(case, unit("u1"), name("u1", "WKS01"), name("u1", "WKS01", "Security.evtx Computer"),
        name("u1", "BUILD", "events.csv host column"), unit("u2"),
        name("u2", "BUILD"), name("u2", "BUILD", "Security.evtx Computer"))  # fmt: skip
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": "k1", "canonical": "WKS01", "pairs": [["u1", "WKS01"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [["u1", "BUILD"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    hi.get_or_mint(case, "u1", "BUILD")  # with WKS01, as not a host
    P = hi.load(case)
    hp.upload_host_list(case, "BUILD\n", "ex")
    Q = hi.load(case)
    assert Q.machine_of_pair("u2", "BUILD") is not Q.machine_of_key("k1")
    assert violations(P, Q, "list") == []


def test_one_clashing_item_of_a_confirm_all_is_reported_and_the_rest_appended(case):
    obs(case, unit("u1"), name("u1", "WKS01"), unit("u2"), name("u2", "SRV01"),
        name("u2", "SRV01", "Security.evtx Computer"),
        unit("u3"), name("u3", "DC01"), name("u3", "DC01", "Security.evtx Computer"))  # fmt: skip
    hi.get_or_mint(case, "u1", "WKS01")  # a machine called WKS01
    out = hi.append_decision_items(case, {"action": "confirm", "args": {"proposed": True,
        "machines": [{"key": "k2", "canonical": "WKS01", "pairs": [["u2", "SRV01"]]},
                     {"key": "k3", "canonical": "DC01", "pairs": [["u3", "DC01"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    assert [r["index"] for r in out["refused"]] == [0] and out["appended"] == 1
    assert hi.load(case).machine_of_pair("u3", "DC01").canonical == "DC01"


def test_a_forwarded_name_met_while_ingesting_joins_its_machine(case):
    obs(case, unit("u1", "A"), name("u1", "DC01"), name("u1", "DC01", "Security.evtx Computer"),
        unit("u2", "B"), name("u2", "WEC01"))  # fmt: skip
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": "k1", "canonical": "DC01", "pairs": [["u1", "DC01"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    P = hi.load(case)
    key, canonical = hi.get_or_mint(
        case, "u2", "DC01", evidence="ForwardedEvents Computer"
    )
    assert (key, canonical) == ("k1", "DC01")  # never "DC01 (2)"
    assert violations(P, hi.load(case), "mint") == []


def test_a_machine_the_examiner_confirmed_with_two_ids_still_takes_its_late_names(case):
    obs(case, unit("u1", "A"), name("u1", "DC01"), unit("u2", "B"), name("u2", "DC01"),
        unit("u3"), name("u3", "WEC01"))  # fmt: skip
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {
                        "key": "k1",
                        "canonical": "DC01",
                        "pairs": [["u1", "DC01"], ["u2", "DC01"]],
                    }
                ]
            },
        },
        hi.load(case).obs_offset,
    )  # fmt: skip (the examiner's: two machine ids, theirs to keep)
    key, _ = hi.get_or_mint(case, "u3", "DC01", evidence="ForwardedEvents Computer")
    assert key == "k1"  # the join adds no machine id


def test_a_not_a_host_name_is_no_rival_match_for_a_list_entry(case):
    obs(case, unit("u1", "A"), name("u1", "DC01"), name("u1", "DC01", "Security.evtx Computer"),
        unit("u2", "B"), name("u2", "DC01"), name("u2", "DC01", "Security.evtx Computer"))  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [["u2", "DC01"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    hp.upload_host_list(case, "DC01\n", "ex")
    m = hi.load(case).machine_of_pair("u1", "DC01")
    assert m is not None and m.state == hi.CONFIRMED


def test_a_late_name_a_started_machine_holds_joins_it(case):
    obs(case, unit("u1"), name("u1", "WKS01"), name("u1", "WKS01", "Security.evtx Computer"),
        unit("u2"), name("u2", "WEC01"))  # fmt: skip
    hg.record_wait(case, "r1", ["u1"])
    (m,) = hg.start_now(case, "r1", "ex")["machines"]
    P = hi.load(case)
    key, canonical = hi.get_or_mint(
        case, "u2", "WKS01", evidence="ForwardedEvents Computer"
    )
    assert (key, canonical) == (m["key"], "WKS01")  # never "WKS01 (2)"
    assert violations(P, hi.load(case), "mint") == []


def test_the_list_never_makes_a_second_machine_of_a_started_machines_name(case):
    # the started unit sorts after the new one, so the list meets the new one first
    obs(
        case,
        unit("u9"),
        name("u9", "WKS01"),
        name("u9", "WKS01", "Security.evtx Computer"),
    )
    hg.record_wait(case, "r1", ["u9"])
    (m,) = hg.start_now(case, "r1", "ex")["machines"]
    obs(
        case,
        unit("u2"),
        name("u2", "WKS01"),
        name("u2", "WKS01", "Security.evtx Computer"),
    )
    P = hi.load(case)
    hp.upload_host_list(case, "WKS01\n", "ex")
    Q = hi.load(case)
    assert Q.machine_of_pair("u2", "WKS01").id == Q.machine_of_key(m["key"]).id
    assert violations(P, Q, "list") == []


def test_a_not_a_host_name_goes_only_to_its_own_units_exact_placeholder(case):
    from sift_common import host_guard

    obs(case, {"kind": "unit", "unit": "u1", "locator": "ev/a.raw@0"}, name("u1", "WORKGROUP"),
        {"kind": "unit", "unit": "u2", "locator": "ev/b.raw@0"}, name("u2", "OTHER"))  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [["u1", "WORKGROUP"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    state = hi.load(case)
    mine = hg.placeholder_name("ev/a.raw@0")
    for other in (
        hg.placeholder_name("ev/b.raw@0"),
        "unattributed:u2",
        mine + "-x",
        mine + " (2)",
    ):
        bind = {"kind": "bind", "unit": "u1", "raw": "WORKGROUP", "key": "f" * 16,
                "canonical": other}  # fmt: skip
        assert host_guard.check_binds(state, [bind], "late"), other
    ok = {
        "kind": "bind",
        "unit": "u1",
        "raw": "WORKGROUP",
        "key": "e" * 16,
        "canonical": mine,
    }
    assert host_guard.check_binds(state, [ok], "late") == []


def test_a_units_rejected_names_share_its_one_placeholder(case):
    obs(case, {"kind": "unit", "unit": "u1", "locator": "ev/a.raw@0"},
        name("u1", "WORKGROUP"), name("u1", "BUILD"))  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {
        "pairs": [["u1", "WORKGROUP"], ["u1", "BUILD"]]}}, hi.load(case).obs_offset)  # fmt: skip
    P = hi.load(case)
    k1, c1 = hi.get_or_mint(case, "u1", "WORKGROUP")
    k2, c2 = hi.get_or_mint(case, "u1", "BUILD")
    assert (k1, c1) == (k2, c2) == (k1, hg.placeholder_name("ev/a.raw@0"))
    hg.record_wait(case, "r1", ["u1"])
    hg.start_now(case, "r1", "ex")  # reuses it too
    Q = hi.load(case)
    assert {m.canonical for m in Q.machines.values()} == {c1}
    assert violations(P, Q, "mint") == []


# -- cases a generated corpus found, as fixed rows


SYS, EVTX = "SYSTEM ComputerName", "Security.evtx Computer"


def test_an_exports_addresses_never_name_a_machine(case):
    obs(case, unit("u1"), name("u1", "10.100.218.46", "edr.csv host column"),
        name("u1", "10.100.218.47", "edr.csv host column"))  # fmt: skip
    hg.record_wait(case, "r1", ["u1"])
    P = hi.load(case)
    hg.start_now(case, "r1", "ex")
    Q = hi.load(case)
    assert violations(P, Q, "start") == []
    m = Q.machine_of_pair("u1", "10.100.218.46")
    assert m is not None and not hp.is_address(m.canonical)


def test_an_fqdn_never_joins_a_machine_of_another_domain_through_its_bare_name(case):
    obs(case, unit("u1"), name("u1", "DC01", SYS), name("u1", "DC01", EVTX),
        unit("u2"), name("u2", "DC01.acq.example.test", SYS),
        name("u2", "DC01.acq.example.test", EVTX))  # fmt: skip
    hi.append_decision(case, {"action": "confirm", "examiner": "ex", "args": {"machines": [
        {"key": "k1", "canonical": "DC01.eu.corp.example.test", "pairs": [["u1", "DC01"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    hg.record_wait(case, "r1", ["u2"])
    P = hi.load(case)
    hg.start_now(case, "r1", "ex")
    Q = hi.load(case)
    assert violations(P, Q, "start") == []
    assert "k1" not in Q.machine_of_pair("u2", "DC01.acq.example.test").keys
