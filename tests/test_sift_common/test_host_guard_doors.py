"""The guard holds every rule under the log lock, whatever a door decided on
its own earlier load: no machine is named after an address; a name with a
domain never joins a machine holding a name in another domain (through its
bare names too); a bare name joins only what no other machine or unit in the
case also holds; a name marked not a host is never a link; and an automatic
confirmation never takes a unit flagged now. Start now names each unit's
machine by that unit's own names. Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import pytest
from sift_common import host_gate
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

SYS, EVTX = "SYSTEM ComputerName", "Security.evtx Computer"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def unit(case, locator, names, **attrs):
    """names: [(raw, evidence)] of artifact origin, or [(raw, evidence, origin)]"""
    u = hi.unit_key(locator)
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": locator, **attrs}] + [
        {"kind": "name", "unit": u, "raw": n[0], "evidence": n[1],
         "origin": n[2] if len(n) > 2 else "artifact"} for n in names
    ])  # fmt: skip
    return u


def two(name):
    return [(name, SYS), (name, EVTX)]


def confirm(case, u, canonical, *raws) -> str:
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": canonical, "pairs": [[u, r] for r in raws]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return key


def start(case, *units, run="run-1"):
    host_gate.record_wait(case, run, list(units))
    return host_gate.start_now(case, run, "ex1")


def machine(case, u, raw):
    return hi.load(case).machine_of_pair(u, raw)


# -- no machine is named after an address


def test_start_now_puts_a_units_addresses_on_its_placeholder(case):
    """T's EDR export: its host column holds only addresses."""
    x = unit(case, "evidence/edr.csv", [("10.100.218.46", "edr.csv host column"),
                                        ("10.100.218.47", "edr.csv host column")])  # fmt: skip
    start(case, x)
    m1, m2 = machine(case, x, "10.100.218.46"), machine(case, x, "10.100.218.47")
    assert m1 is not None and m1.id == m2.id
    assert not hp.is_address(m1.canonical) and m1.canonical.startswith("edr-")


def test_an_address_met_while_ingesting_goes_to_the_units_placeholder(case):
    x = unit(case, "evidence/edr.csv", two("WKS1"))
    key, canonical = hi.get_or_mint(case, x, "10.1.2.3", evidence="edr.csv host column")
    assert not hp.is_address(canonical) and canonical.startswith("edr-")
    key2, _ = hi.get_or_mint(case, x, "10.1.2.4", evidence="edr.csv host column")
    assert key2 == key


@pytest.mark.parametrize("action", ["confirm", "rename"])
def test_no_door_names_a_machine_after_an_address(case, action):
    u = unit(case, "evidence/a", two("WKS1"))
    if action == "confirm":
        with pytest.raises(hi.HostLogError, match="IP address never names a machine"):
            confirm(case, u, "10.9.9.9", "WKS1")
    else:
        key = confirm(case, u, "WKS1", "WKS1")
        with pytest.raises(hi.HostLogError, match="IP address never names a machine"):
            hi.append_decision(case, {"action": "rename", "examiner": "ex1",
                                      "args": {"machine": key, "canonical": "10.9.9.9"}},
                               hi.load(case).obs_offset, door="R")  # fmt: skip


# -- a domain conflict is judged against the machine


def _eu_dc(case):
    """T's case: the examiner confirmed DC01.eu on the eu export's bare DC01."""
    eu = unit(case, "evidence/eu-ad.csv", two("DC01"))
    return eu, confirm(case, eu, "DC01.eu.corp.example.test", "DC01")


def test_an_fqdn_never_joins_a_machine_of_another_domain_through_its_bare_name(case):
    eu, key = _eu_dc(case)
    acq = unit(case, "evidence/acq", two("DC01.acq.example.test"))
    start(case, acq)
    assert key not in machine(case, acq, "DC01.acq.example.test").keys


def test_a_late_fqdn_never_joins_a_machine_of_another_domain(case):
    eu, key = _eu_dc(case)
    x = unit(case, "evidence/rows", two("WKS9"))
    got, _ = hi.get_or_mint(
        case, x, "DC01.acq.example.test", evidence="rows host column"
    )
    assert got != key


def test_the_guard_refuses_a_join_into_another_domains_machine_at_any_door(case):
    eu, key = _eu_dc(case)
    acq = unit(case, "evidence/acq", two("DC01.acq.example.test"))
    out = hi.append_decision_items(case, {"action": "confirm", "examiner": "ex1", "args": {
        "proposed": True, "machines": [{"key": key, "canonical": "DC01.eu.corp.example.test",
                                        "pairs": [[acq, "DC01.acq.example.test"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    assert out["appended"] == 0 and "another domain" in out["refused"][0]["reason"]


# -- decided under the lock, not on a door's earlier load


def test_a_holder_that_arrives_after_start_now_read_the_case_refuses_the_join(
    case, monkeypatch
):
    """CR's race: DC01.acq lands between Start now's read and its append."""
    a = unit(case, "evidence/dc01", two("DC01"))
    key = confirm(case, a, "DC01", "DC01")
    x = unit(case, "evidence/ad.csv", two("DC01"))
    real = hi.append_decision_items

    def late_holder(case_dir, record, seen, door="portal"):
        unit(case, "evidence/acq", two("DC01.acq.example.test"))
        return real(case_dir, record, seen, door=door)

    monkeypatch.setattr(hi, "append_decision_items", late_holder)
    out = start(case, x)
    assert any("also holds" in r["reason"] for r in out["refused"])
    assert machine(case, x, "DC01") is None or key not in machine(case, x, "DC01").keys


# -- each unit's machine named by its own names


def test_two_units_of_one_machine_id_get_their_own_names(case):
    """CR's OLDNAME/NEWNAME: one proposed group, two units, two machines."""
    old = unit(case, "evidence/old", two("OLDNAME"), machine_guid="g-1")
    new = unit(case, "evidence/new", two("NEWNAME"), machine_guid="g-1")
    start(case, new, old)
    assert machine(case, old, "OLDNAME").canonical == "OLDNAME"
    assert machine(case, new, "NEWNAME").canonical == "NEWNAME"


# -- CR's surviving mutants


def test_a_folder_only_name_never_joins_a_confirmed_machine(case):
    a = unit(case, "evidence/dc01", two("DC01.corp.example.test"))
    key = confirm(case, a, "DC01.corp.example.test", "DC01.corp.example.test")
    f = unit(case, "evidence/DC01.corp.example.test",
             [("DC01.corp.example.test", "folder name", "folder"),
              ("DC01.corp.example.test", "path name", "folder")])  # fmt: skip
    start(case, f)
    assert key not in machine(case, f, "DC01.corp.example.test").keys


def test_a_machines_former_name_counts_as_a_holder(case):
    """B was confirmed as DC01.old, then renamed: only its former name holds
    DC01 now."""
    b = unit(case, "evidence/b", two("OLDDC"))
    key_b = confirm(case, b, "DC01.old.example.test", "OLDDC")
    hi.append_decision(
        case,
        {
            "action": "rename",
            "examiner": "ex1",
            "args": {"machine": key_b, "canonical": "NEWDC"},
        },
        hi.load(case).obs_offset,
        door="R",
    )
    state = hi.load(case)
    m = state.machine_of_key(key_b)
    assert "DC01.old.example.test" in m.former and m.canonical == "NEWDC"
    assert ("machine", m.id) in hi.short_name_holders(state, "DC01")


def test_a_not_a_host_name_holds_no_short_name(case):
    a = unit(case, "evidence/a", two("DC01"))
    key = confirm(case, a, "DC01", "DC01")
    c = unit(case, "evidence/c", [("DC01", "rows host column")])
    hi.append_decision(
        case,
        {"action": "not_a_host", "examiner": "ex1", "args": {"pairs": [[c, "DC01"]]}},
        hi.load(case).obs_offset,
    )
    holders = hi.short_name_holders(hi.load(case), "DC01")
    assert holders == {("machine", hi.load(case).machine_of_key(key).id)}


# -- a not-a-host name is never a link


def _collector(case):
    """CR's probe: COLLECTOR holds BUILD, which the examiner then marked not a
    host; another unit's evidence really is BUILD."""
    c = unit(
        case, "evidence/collector", two("COLLECTOR") + [("BUILD", "rows host column")]
    )
    key = confirm(case, c, "COLLECTOR", "COLLECTOR", "BUILD")
    hi.append_decision(
        case,
        {"action": "not_a_host", "examiner": "ex1", "args": {"pairs": [[c, "BUILD"]]}},
        hi.load(case).obs_offset,
    )
    b = unit(case, "evidence/build", two("BUILD"))
    return key, b


def test_a_not_a_host_name_never_groups_another_unit_with_its_machine(case):
    key, b = _collector(case)
    (g,) = [g for g in hp.propose(hi.load(case)) if (b, "BUILD") in g.pairs]
    assert g.machine is None or key not in hi.load(case).machines[g.machine].keys


def test_start_now_and_confirm_all_never_join_through_a_not_a_host_name(case):
    key, b = _collector(case)
    out = hi.append_decision_items(case, {"action": "confirm", "examiner": "ex1", "args": {
        "proposed": True, "machines": [{"key": key, "canonical": "COLLECTOR",
                                        "pairs": [[b, "BUILD"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    assert out["appended"] == 0 and "not a host" in out["refused"][0]["reason"]
    start(case, b)
    assert key not in machine(case, b, "BUILD").keys


# -- flagged now, not at page time


def test_confirm_all_skips_a_unit_flagged_after_the_page(case):
    """The page proposed the unit; a folder name its artifacts contradict
    arrives after it."""
    b = unit(case, "evidence/b", two("WKS01"))
    key = confirm(case, b, "WKS01", "WKS01")
    a = unit(case, "evidence/a", two("WKS01"))
    page = hi.load(case).obs_offset
    hi.append_observations(
        case,
        [
            {
                "kind": "name",
                "unit": a,
                "raw": "FILESRV",
                "evidence": "folder name",
                "origin": "folder",
            }
        ],
    )
    out = hi.append_decision_items(case, {"action": "confirm", "examiner": "ex1", "args": {
        "proposed": True, "machines": [{"key": key, "canonical": "WKS01",
                                        "pairs": [[a, "WKS01"]]}]}}, page)  # fmt: skip
    assert out["appended"] == 0 and "flagged now" in out["refused"][0]["reason"]


def test_start_now_makes_a_flagged_unit_its_own_machine_and_never_joins(case):
    b = unit(case, "evidence/b", two("WKS01"))
    key = confirm(case, b, "WKS01", "WKS01")
    thin = unit(case, "evidence/thin", [("WKS01", SYS)])  # one source: flagged
    out = start(case, thin)
    m = machine(case, thin, "WKS01")
    assert m is not None and key not in m.keys and out["refused"] == []


def test_start_now_still_adds_a_flagged_units_names_to_its_own_machine(case):
    from sift_common import host_guard

    thin = unit(case, "evidence/thin", [("WKS07", SYS)])  # one source: flagged
    start(case, thin)
    own = machine(case, thin, "WKS07")
    hi.append_observations(
        case,
        [
            {
                "kind": "name",
                "unit": thin,
                "raw": "WKS07.corp.example.test",
                "evidence": SYS,
                "origin": "artifact",
            }
        ],
    )  # still one source
    assert host_guard.unit_flag(hi.load(case), thin)  # flagged still
    out = start(case, thin, run="run-2")
    assert out["refused"] == []
    assert machine(case, thin, "WKS07.corp.example.test").id == own.id


def _two_domain_dc(case):
    """A machine the examiner confirmed holding DC01 in two domains (a
    conflict for the examiner), which the host list names."""
    eu = unit(case, "evidence/eu", two("DC01.eu.corp.example.test"))
    acq = unit(case, "evidence/acq", two("DC01.acq.example.test"))
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": "DC01.eu.corp.example.test",
         "pairs": [[eu, "DC01.eu.corp.example.test"], [acq, "DC01.acq.example.test"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    hp.upload_host_list(case, "DC01\n", "ex1")
    return key


def test_a_late_name_spelled_like_a_machines_name_never_joins_it_across_domains(case):
    key = _two_domain_dc(case)
    x = unit(case, "evidence/rows", two("WKS9"))
    got, _ = hi.get_or_mint(
        case, x, "DC01.acq.example.test", evidence="rows host column"
    )
    assert got != key  # neither the exact match nor the host list puts it there


def test_one_units_names_in_two_domains_are_judged_against_other_units_only(case):
    """T's seed: the list names DC01 through the unit's dc01.a.test; its other
    name, in another domain, goes with it."""
    dc = unit(case, "evidence/dc", two("DC01"))
    key = confirm(case, dc, "DC01", "DC01")
    hp.upload_host_list(case, "DC01\n", "ex1")
    u = unit(case, "evidence/u", [("wks01.corp-a.test", SYS), ("dc01.a.test", EVTX)])
    hp.apply_host_list(case, [u])
    assert machine(case, u, "dc01.a.test").keys[0] == key
    assert machine(case, u, "wks01.corp-a.test").keys[0] == key


def test_a_list_bundle_whose_link_is_refused_lands_none_of_its_names(case, monkeypatch):
    """The list puts the unit's WKS01 and its DC01 (the name the entry matched)
    on DC01's machine. When the guard refuses DC01, WKS01 never lands there
    alone."""
    from sift_common import host_guard

    dc = unit(case, "evidence/dc", two("DC01"))
    key = confirm(case, dc, "DC01", "DC01")
    hp.upload_host_list(case, "DC01\n", "ex1")
    u = unit(case, "evidence/u", [("WKS01", SYS), ("DC01", EVTX)])
    real = host_guard.check_binds

    def refuse_the_link(state, records, door):
        out = real(state, records, door)
        return out + [(i, "refused here") for i, r in enumerate(records)
                      if r.get("unit") == u and r.get("raw") == "DC01"]  # fmt: skip

    monkeypatch.setattr(host_guard, "check_binds", refuse_the_link)
    out = hp.apply_host_list(case, [u])
    assert (
        machine(case, u, "WKS01") is None or key not in machine(case, u, "WKS01").keys
    )
    assert {r["name"] for r in out.get("refused", [])} == {"DC01"}
