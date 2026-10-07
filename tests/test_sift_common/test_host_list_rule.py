"""The host list's one rule for confirming by itself: per unit, artifact
evidence only, an exact match in the entry's domain, no flag or conflict, the
examiner's decisions first, one machine per entry, and never an IP address.
The same rule judges names first met while ingesting. Names are synthetic
(RFC 2606 domains)."""

from __future__ import annotations

import pytest
from sift_common import host_identity as hi
from sift_common import host_proposal as hp


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def unit(case, locator, names, **attrs):
    """names: [(raw, evidence, origin)]"""
    u = hi.unit_key(locator)
    recs = [{"kind": "unit", "unit": u, "locator": locator, **attrs}]
    recs += [{"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": o}
             for r, e, o in names]  # fmt: skip
    hi.append_observations(case, recs)
    return u


def kape(case, where, *names, **attrs):
    """A host folder whose SYSTEM hive gives `names` (two sources)."""
    rows = [(where.rsplit("/", 1)[-1], "folder name", "folder")]
    rows += [(n, "SYSTEM ComputerName", "artifact") for n in names]
    return unit(case, where, rows, **attrs)


def machine(case, u, raw):
    return hi.load(case).machine_of_pair(u, raw)


def confirmed(case, u, raw) -> bool:
    m = machine(case, u, raw)
    return m is not None and m.state == hi.CONFIRMED


# 1. per unit, never per proposed group


def test_a_unit_whose_own_names_match_nothing_isnt_confirmed_with_a_group(case):
    a = kape(case, "evidence/SRV", "SRV")
    b = kape(case, "evidence/SRV-MEM", "SRV-MEM")
    hp.upload_host_list(case, "SRV\n", "ex1")
    assert confirmed(case, a, "SRV") and machine(case, b, "SRV-MEM") is None


def test_a_dated_collection_of_a_listed_name_isnt_merged_into_it(case):
    kape(case, "evidence/PC", "PC")
    b = kape(case, "evidence/PC-20240101", "PC-20240101")
    hp.upload_host_list(case, "PC\n", "ex1")
    assert machine(case, b, "PC-20240101") is None


# 2. artifact evidence the examiner put in the case, never the AI's


def test_a_name_the_ai_gave_isnt_confirmed_beside_the_same_name_from_evidence(case):
    mem = unit(case, "evidence/mem.raw", [("DC01", "hostname argument", "argument")])
    k = kape(case, "evidence/DC01", "DC01")
    hp.upload_host_list(case, "DC01\n", "ex1")
    assert confirmed(case, k, "DC01") and machine(case, mem, "DC01") is None


# 3. exact, in the entry's domain


def test_an_entrys_fqdn_keeps_a_unit_of_another_domain_out(case):
    u = kape(case, "evidence/DC01", "DC01", "dc01.corp-b.example.test")
    hp.upload_host_list(case, "DC01 dc01.corp-a.example.test\n", "ex1")
    assert not hi.load(case).machines


def test_a_late_name_in_another_domain_isnt_confirmed_by_the_entrys_fqdn(case):
    u = unit(case, "evidence/rows.csv", [("SRV01", "rows.csv host column", "artifact")])
    hp.upload_host_list(case, "DC01 dc01.corp-a.example.test\n", "ex1")
    key, _ = hi.get_or_mint(case, u, "dc01.corp-b.example.test")
    assert hi.load(case).machine_of_key(key).state == hi.NEW


# 4. no flag, no conflict


def test_two_units_with_different_machine_ids_on_one_entry_stay_held(case):
    a = kape(case, "evidence/a/DC01", "DC01", machine_guid="g-1")
    b = kape(case, "evidence/b/DC01", "DC01", machine_guid="g-2")
    hp.upload_host_list(case, "DC01\n", "ex1")
    assert not hi.load(case).machines
    # and ingest doesn't confirm them either: they were held at the scan
    for u in (a, b):
        key, _ = hi.get_or_mint(case, u, "DC01", origin="artifact")
        assert hi.load(case).machine_of_key(key).state == hi.NEW


def test_a_folder_its_logs_contradict_isnt_confirmed_even_while_ingesting(case):
    u = unit(case, "evidence/WKS01", [("WKS01", "folder name", "folder"),
                                      ("SRV99", "SYSTEM ComputerName", "artifact")])  # fmt: skip
    hp.upload_host_list(case, "WKS01\nSRV99\n", "ex1")
    assert not confirmed(case, u, "SRV99")
    key, _ = hi.get_or_mint(case, u, "WKS01", origin="folder")
    assert hi.load(case).machine_of_key(key).state == hi.NEW


def test_a_name_from_one_source_only_isnt_confirmed(case):
    u = unit(case, "evidence/x.evtx", [("WKS05", "Security.evtx Computer", "artifact")])
    hp.upload_host_list(case, "WKS05\n", "ex1")
    assert machine(case, u, "WKS05") is None


# 5. the examiner's decisions first


def test_a_name_the_examiner_marked_not_a_host_isnt_confirmed_by_the_list(case):
    u = kape(case, "evidence/BUILD01", "BUILD01")
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [[u, "BUILD01"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    hp.upload_host_list(case, "BUILD01\n", "ex1")
    assert machine(case, u, "BUILD01") is None


def test_a_not_a_host_machine_never_takes_another_units_name(case):
    a = kape(case, "evidence/a/BUILD01", "BUILD01")
    hi.append_decision(case, {"action": "not_a_host", "args": {
        "pairs": [[a, "BUILD01"]], "key": hi.new_machine_key()}},
        hi.load(case).obs_offset)  # fmt: skip
    b = kape(case, "evidence/b/BUILD01", "BUILD01")
    hp.upload_host_list(case, "BUILD01\n", "ex1")
    m = machine(case, b, "BUILD01")
    assert (
        m is not None
        and m.canonical == "BUILD01"
        and m is not machine(case, a, "BUILD01")
    )


# 6. one machine per entry, joined only when it agrees


def test_one_entry_names_one_machine_however_its_names_arrive(case):
    a = kape(case, "evidence/a/WKS01", "WKS01", machine_guid="g-1")
    b = kape(case, "evidence/b/WKS01", "WKS01", machine_guid="g-1")
    hp.upload_host_list(case, "WKS01\n", "ex1")
    rows = unit(
        case, "evidence/rows.csv", [("SRV09", "rows.csv host column", "artifact")]
    )
    key, _ = hi.get_or_mint(case, rows, "wks01")  # met while ingesting
    state = hi.load(case)
    ids = {state.machine_of_pair(a, "WKS01").id, state.machine_of_pair(b, "WKS01").id,
           state.machine_of_key(key).id}  # fmt: skip
    assert len(ids) == 1 and len(state.machines) == 1


def test_a_unit_of_another_domain_doesnt_join_the_entrys_machine(case):
    kape(case, "evidence/a/DC01", "DC01", "dc01.corp-a.example.test")
    hp.upload_host_list(case, "DC01\n", "ex1")
    b = kape(case, "evidence/b/DC01", "DC01", "dc01.corp-b.example.test")
    hp.apply_host_list(case, [b])
    assert machine(case, b, "DC01") is None


def test_a_unit_with_another_machine_id_doesnt_join_the_entrys_machine(case):
    kape(case, "evidence/a/DC01", "DC01", machine_guid="g-1")
    hp.upload_host_list(case, "DC01\n", "ex1")
    b = kape(case, "evidence/b/DC01", "DC01", machine_guid="g-2")
    hp.apply_host_list(case, [b])
    assert machine(case, b, "DC01") is None


# 7. never an IP address


def test_an_inventorys_address_column_names_no_host(case):
    assert hp.parse_host_list("WKS01,10.0.0.1\n10.0.0.2\n") == [{"name": "WKS01"}]
    hp.upload_host_list(case, "WKS01,10.0.0.1\n", "ex1")
    rows = unit(
        case, "evidence/rows.csv", [("SRV09", "rows.csv host column", "artifact")]
    )
    key, _ = hi.get_or_mint(case, rows, "10.0.0.1")
    assert hi.load(case).machine_of_key(key).state == hi.NEW


# binding safety and the ship switch


def test_a_shared_collector_client_never_joins_two_machine_ids(case):
    kape(case, "evidence/a/WKS01", "WKS01", machine_guid="g-1", client_id="C.1")
    kape(case, "evidence/b/LAPTOP7", "LAPTOP7", machine_guid="g-2", client_id="C.1")
    groups = hp.propose(hi.load(case))
    assert len(groups) == 2


def test_a_confirm_over_two_bound_machines_keeps_the_examiners_name(case):
    a = kape(case, "evidence/a/DC01", "DC01")
    b = kape(case, "evidence/b/dc-01", "dc-01")
    ka, _ = hi.get_or_mint(case, a, "DC01")
    kb, _ = hi.get_or_mint(case, b, "dc-01")
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": hi.new_machine_key(), "canonical": "DC01",
         "pairs": [[b, "dc-01"], [a, "DC01"]]}]}}, hi.load(case).obs_offset)  # fmt: skip
    m = machine(case, a, "DC01")
    assert m.canonical == "DC01" and m is machine(case, b, "dc-01")


def test_with_the_lists_confirmation_off_nothing_is_confirmed_by_it(case, monkeypatch):
    monkeypatch.setattr(hp, "LIST_AUTO_CONFIRM", False)
    u = kape(case, "evidence/WKS01", "WKS01")
    out = hp.upload_host_list(case, "WKS01\n", "ex1")
    assert out["confirmed"] == [] and machine(case, u, "WKS01") is None
    rows = unit(
        case, "evidence/rows.csv", [("SRV09", "rows.csv host column", "artifact")]
    )
    key, _ = hi.get_or_mint(case, rows, "WKS01")
    assert hi.load(case).machine_of_key(key).state == hi.NEW
    (g,) = [g for g in hp.propose(hi.load(case)) if (u, "WKS01") in g.pairs]
    assert g.list_entry == "WKS01"  # shown as the list's match, for the examiner


def test_the_scan_judges_only_its_own_units(case, monkeypatch):
    for n in range(5):
        kape(case, f"evidence/H{n}", f"H{n}")
    hp.upload_host_list(case, "H0\nH1\nH2\nH3\nH4\n", "ex1")
    late = kape(case, "evidence/H9", "H9")
    monkeypatch.setattr(
        hp, "propose", lambda state: pytest.fail("a whole-case propose")
    )
    seen = []
    real = hp._unit_held
    monkeypatch.setattr(
        hp, "_unit_held", lambda state, u, *a: seen.append(u) or real(state, u, *a)
    )
    hp.apply_host_list(case, [late])
    assert seen == [late]


def test_two_near_spellings_first_seen_in_one_scan_are_hinted(case):
    state = hi.load(case)
    a, b = hi.unit_key("evidence/a"), hi.unit_key("evidence/b")
    hints = hp.near_hints(state, [(a, "wkstn01"), (b, "wksn01")])
    assert [(h["raw"], h["near"]) for h in hints] == [("wksn01", "wkstn01")]


def test_two_units_of_one_name_in_different_domains_are_held(case):
    a = kape(case, "evidence/a/DC01", "DC01", "dc01.corp-a.example.test")
    b = kape(case, "evidence/b/DC01", "DC01", "dc01.corp-b.example.test")
    hp.upload_host_list(case, "DC01\n", "ex1")
    assert machine(case, a, "DC01") is None and machine(case, b, "DC01") is None


def _renamed(case, name, guid, unit_name, domain_name=None):
    """A machine the examiner confirmed as `name` from a unit whose own names
    are `unit_name` (and `domain_name`): renamed, so they don't match it."""
    names = [unit_name] + ([domain_name] if domain_name else [])
    u = kape(case, f"evidence/{unit_name}", *names, machine_guid=guid)
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": hi.new_machine_key(), "canonical": name,
         "pairs": [[u, n] for n in [unit_name, *names]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return u


def test_a_unit_with_another_machine_id_doesnt_join_a_machine_confirmed_by_name(case):
    _renamed(case, "DC01", "g-1", "SRV-OLD")
    hp.upload_host_list(case, "DC01\n", "ex1")
    b = kape(case, "evidence/b/DC01", "DC01", machine_guid="g-2")
    hp.apply_host_list(case, [b])
    assert machine(case, b, "DC01") is None


def test_a_unit_of_another_domain_doesnt_join_a_machine_confirmed_by_name(case):
    _renamed(case, "DC01", "", "SRV-OLD", "srv-old.corp-a.example.test")
    hp.upload_host_list(case, "DC01\n", "ex1")
    b = kape(case, "evidence/b/DC01", "DC01", "dc01.corp-b.example.test")
    hp.apply_host_list(case, [b])
    assert machine(case, b, "DC01") is None


def test_a_late_name_from_a_folder_isnt_confirmed_by_the_list(case):
    hp.upload_host_list(case, "WKS77\n", "ex1")
    rows = unit(
        case, "evidence/rows.csv", [("SRV09", "rows.csv host column", "artifact")]
    )
    key, _ = hi.get_or_mint(case, rows, "WKS77", origin="folder")
    assert hi.load(case).machine_of_key(key).state == hi.NEW


def test_a_machine_holding_a_not_a_host_name_is_still_its_entrys(case):
    u = kape(case, "evidence/WKS01", "WKS01")
    hp.upload_host_list(case, "WKS01\n", "ex1")
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "BUILD",
                                   "evidence": "x.csv host column", "origin": "artifact"}])  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "args": {"pairs": [[u, "BUILD"]]}},
                       hi.load(case).obs_offset)  # fmt: skip
    hi.get_or_mint(case, u, "BUILD")  # joins WKS01, as not a host
    b = kape(case, "evidence/b/WKS01", "WKS01")
    hp.apply_host_list(case, [b])
    assert machine(case, b, "WKS01") is machine(case, u, "WKS01")  # one machine
