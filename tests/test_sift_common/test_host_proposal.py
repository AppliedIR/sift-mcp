"""Proposals: which host names are one machine, how sure, what to call it,
and when the examiner's host list confirms it. Names are synthetic (RFC 2606
domains)."""

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
    """Record a scanned unit: names is [(raw, evidence, origin)]."""
    u = hi.unit_key(locator)
    recs = [{"kind": "unit", "unit": u, "locator": locator, **attrs}]
    recs += [
        {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": o}
        for r, e, o in names
    ]
    hi.append_observations(case, recs)
    return u


def folder(case, name, *artifact_names, where="", **attrs):
    """A host folder `name` (at `where`, default evidence/<name>) whose
    SYSTEM hive gives `artifact_names`."""
    names = [(name, "folder name", "folder")]
    names += [(n, "SYSTEM ComputerName", "artifact") for n in artifact_names]
    return unit(case, where or f"evidence/{name}", names, **attrs)


def groups(case):
    return hp.propose(hi.load(case))


def group_of(gs, raw):
    (g,) = [g for g in gs if any(p[1] == raw for p in g.pairs)]
    return g


# -- tiers


def test_one_hives_names_are_one_certain_machine(case):
    unit(case, "evidence/mail", [
        ("CORPORATE-MAIL-", "SYSTEM ComputerName", "artifact"),
        ("corporate-mail-server", "SYSTEM Tcpip Hostname", "artifact"),
        ("corporate-mail-server.corp.example.test", "SYSTEM Tcpip Hostname+Domain", "artifact"),
    ])  # fmt: skip
    (g,) = groups(case)
    assert len(g.pairs) == 3 and g.tier == hp.CERTAIN
    assert g.canonical == "corporate-mail-server.corp.example.test"


def test_spelling_equal_names_with_artifact_evidence_are_certain(case):
    folder(case, "WKS01", "WKS01", where="evidence/site-a/WKS01")
    folder(case, "wks01", "wks01", where="evidence/site-b/wks01")
    g = group_of(groups(case), "WKS01")
    assert {p[1] for p in g.pairs} >= {"WKS01", "wks01"} and g.tier == hp.CERTAIN


@pytest.mark.parametrize(
    "a,b",
    [("SQLPRODA01", "SQLPRODB01"), ("dc01.corp-a.example.test", "dc01.corp-b.example.test"),
     ("localhost", "localhost")],
)  # fmt: skip
def test_hard_negatives_are_never_one_certain_machine(case, a, b):
    folder(case, "u1", a)
    folder(case, "u2", b)
    gs = groups(case)
    together = [g for g in gs if {p[1] for p in g.pairs} >= {a, b} and len(g.pairs) >= 2
                and a != b or (a == b and sum(p[1] == a for p in g.pairs) == 2)]  # fmt: skip
    assert not [g for g in together if g.tier == hp.CERTAIN], [g.to_dict() for g in gs]
    if a == b:  # a generic name is never joined to another unit's
        assert not together


def test_one_short_name_in_two_domains_is_two_machines(case):
    folder(case, "u1", "dc01.corp-a.example.test")
    folder(case, "u2", "dc01.corp-b.example.test")
    gs = groups(case)
    a, b = (
        group_of(gs, "dc01.corp-a.example.test"),
        group_of(gs, "dc01.corp-b.example.test"),
    )
    assert a is not b


def test_a_unit_name_with_a_collection_token_is_proposed_with_its_names(case):
    unit(case, "evidence/WKS01-triage", [
        ("WKS01-triage", "folder name", "folder"),
        ("wks01.corp.example.test", "Security.evtx Computer", "artifact"),
    ])  # fmt: skip
    (g,) = groups(case)
    assert len(g.pairs) == 2 and g.tier == hp.PROPOSED


def test_a_netbios_name_is_close_to_its_full_name(case):
    assert hp.close("CORPORATE-MAIL-", "corporate-mail-server")
    assert not hp.close("WKS01", "WKS02")


def test_a_folder_whose_logs_name_another_machine_is_flagged(case):
    unit(case, "evidence/WKS01", [
        ("WKS01", "folder name", "folder"),
        ("SRV99.corp.example.test", "Security.evtx Computer", "artifact"),
    ])  # fmt: skip
    assert any(hp.FLAG_FOLDER in g.flags for g in groups(case))


def test_a_look_alike_name_is_separate_and_shows_its_code_points(case):
    folder(case, "u1", "admin01")
    folder(case, "u2", "аdmin01")  # Cyrillic а
    g = group_of(groups(case), "аdmin01")
    assert all(p[1] != "admin01" for p in g.pairs)
    assert any("U+0430" in f for f in g.flags)


def test_one_machine_id_under_two_names_is_proposed_and_flagged(case):
    folder(case, "WKS01", "WKS01", machine_guid="11111111-2222-3333-4444-555555555555")
    folder(
        case, "LAPTOP7", "LAPTOP7", machine_guid="11111111-2222-3333-4444-555555555555"
    )
    g = group_of(groups(case), "WKS01")
    assert any(p[1] == "LAPTOP7" for p in g.pairs) and hp.FLAG_CLONE in g.flags


def test_names_from_a_forwarded_log_are_their_own_machines(case):
    unit(case, "evidence/WEC01", [
        ("WEC01", "folder name", "folder"),
        ("WEC01", "Security.evtx Computer", "artifact"),
        *[(f"SRV{n}", "ForwardedEvents.evtx Computer", "artifact") for n in (1, 2, 3)],
    ])  # fmt: skip
    gs = groups(case)
    wec = group_of(gs, "WEC01")
    assert {p[1] for p in wec.pairs} == {"WEC01"}
    assert len({id(group_of(gs, f"SRV{n}")) for n in (1, 2, 3)}) == 3


def test_a_name_only_an_argument_gives_is_never_certain(case):
    unit(case, "evidence/m.raw", [("DC01", "hostname argument", "argument")])
    folder(case, "dc", "DC01")
    g = group_of(groups(case), "DC01")
    arg = [p for p in g.pairs if p[0] == hi.unit_key("evidence/m.raw")]
    assert not arg or g.tier != hp.CERTAIN
    alone = unit(case, "evidence/n.raw", [("SRV44", "hostname argument", "argument")])
    g = group_of(groups(case), "SRV44")
    assert g.pairs == [(alone, "SRV44")] and hp.FLAG_AI_ONLY in g.flags


def test_a_near_spelling_is_a_hint_not_a_group(case):
    folder(case, "u1", "WKSTN01")
    state = hi.load(case)
    u = hi.unit_key("evidence/WKSN01")
    hints = hp.near_hints(state, [(u, "WKSN01")])
    assert [(h["raw"], h["near"]) for h in hints] == [("WKSN01", "wkstn01")]
    assert hp.near_hints(state, [(u, "WKSTN02")]) == []  # its digits differ
    hi.append_observations(case, hints)
    folder(case, "WKSN01", "WKSN01")
    g = group_of(groups(case), "WKSN01")
    assert any(f.startswith(hp.FLAG_NEAR) for f in g.flags)
    assert all(p[1] != "WKSTN01" for p in g.pairs)


def test_a_second_machine_of_a_taken_name_gets_its_fqdn_or_domain(case):
    k = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": k, "canonical": "DC01", "pairs": [["x", "DC01"]]}]}}, 0)  # fmt: skip
    folder(case, "u2", "dc01.corp-b.example.test")
    g = group_of(groups(case), "dc01.corp-b.example.test")
    assert g.canonical == "dc01.corp-b.example.test"


# -- the host list


def test_a_listed_unit_confirms_and_unlisted_and_missing_names_are_shown(case):
    folder(case, "WKS01", "WKS01")
    folder(case, "SRV09", "SRV09")
    out = hp.upload_host_list(
        case, "name,fqdn\nWKS01\nDC01 dc01.corp-a.example.test\n", "ex1"
    )
    assert out["confirmed"] == ["WKS01"] and out["entries"] == 2
    state = hi.load(case)
    m = state.machine_of_pair(hi.unit_key("evidence/WKS01"), "WKS01")
    assert m.state == hi.CONFIRMED
    gs = hp.propose(state)
    assert hp.FLAG_NOT_LISTED in group_of(gs, "SRV09").flags
    assert hp.listed_without_data(state, gs) == ["DC01"]  # "no data yet"
    assert state.host_list["examiner"] == "ex1" and len(state.host_list["sha256"]) == 64


def test_a_listed_fqdn_confirms_one_domain_and_the_other_is_a_conflict(case):
    folder(case, "DC01", "DC01.corp-a.example.test", where="evidence/a/DC01")
    folder(case, "DC01", "DC01.corp-b.example.test", where="evidence/b/DC01")
    hp.upload_host_list(case, "DC01.corp-a.example.test\n", "ex1")
    state = hi.load(case)
    a = state.machine_of_pair(
        hi.unit_key("evidence/a/DC01"), "DC01.corp-a.example.test"
    )
    b = state.machine_of_pair(
        hi.unit_key("evidence/b/DC01"), "DC01.corp-b.example.test"
    )
    assert a is not None and a.state == hi.CONFIRMED and b is None


def test_two_units_matching_one_entry_with_different_ids_are_a_conflict(case):
    guid = "aaaaaaaa-0000-0000-0000-00000000000"
    folder(case, "DC01", "DC01", where="evidence/a/DC01", machine_guid=guid + "1")
    folder(case, "DC01", "DC01", where="evidence/b/DC01", machine_guid=guid + "2")
    hp.upload_host_list(case, "DC01\n", "ex1")
    state = hi.load(case)
    assert not state.machines  # nothing confirmed
    gs = hp.propose(state)
    assert len(gs) == 2  # one id each: never one machine
    assert all(any("different machine ids" in c for c in g.conflicts) for g in gs)


def test_a_unit_matching_two_entries_is_a_conflict(case):
    unit(case, "evidence/x", [("WKS01", "SYSTEM ComputerName", "artifact"),
                              ("wks01.corp.example.test", "SYSTEM Tcpip Hostname+Domain",
                               "artifact")])  # fmt: skip
    hp.upload_host_list(
        case, "WKS01 wks01.corp-x.example.test\nwks01.corp.example.test\n", "e"
    )
    state = hi.load(case)
    assert not state.machines
    (g,) = hp.propose(state)
    assert any(
        c.startswith("matches more than one host-list entry") for c in g.conflicts
    )


def test_a_name_the_ai_gave_never_confirms_from_the_list(case):
    unit(case, "extractions/x.csv", [("DC01", "extractions/x.csv host column", "ai")])
    unit(case, "evidence/m.raw", [("DC01", "hostname argument", "argument")])
    hp.upload_host_list(case, "DC01\n", "ex1")
    assert not hi.load(case).machines


def test_a_started_machine_confirmed_by_the_list_keeps_its_name(case):
    u = folder(case, "WKS01", "WKS01")
    k = hi.new_machine_key()
    hi.append_decision(case, {"action": "start_now", "args": {"machines": [
        {"key": k, "canonical": "WKS01", "pairs": [[u, "WKS01"]]}]}},
        (case / hi.OBSERVATIONS).stat().st_size)  # fmt: skip
    hp.upload_host_list(case, "WKS01 wks01.corp.example.test\n", "ex1")
    m = hi.load(case).machine_of_key(k)
    assert m.state == hi.CONFIRMED and m.canonical == "WKS01"


def test_a_list_is_needed_from_an_examiner(case):
    with pytest.raises(hi.HostLogError):
        hp.upload_host_list(case, "WKS01\n", "")


# -- names first met while ingesting


def test_a_late_name_on_the_list_joins_the_listed_machine(case):
    folder(case, "DC01", "DC01")
    hp.upload_host_list(case, "DC01\n", "ex1")
    (machine,) = hi.load(case).machines.values()
    key, canonical = hi.get_or_mint(case, "wec", "dc01")
    assert (key, canonical) == (machine.keys[0], "DC01")


def test_a_late_name_in_another_domain_does_not_join_the_listed_machine(case):
    folder(case, "DC01", "DC01.corp-a.example.test")
    hp.upload_host_list(case, "DC01\n", "ex1")
    (machine,) = hi.load(case).machines.values()
    key, _ = hi.get_or_mint(case, "wec", "DC01.corp-b.example.test")
    assert key not in machine.keys


def test_a_late_listed_name_with_no_machine_yet_is_confirmed_under_the_list_name(case):
    hp.upload_host_list(case, "SRV7 srv7.corp.example.test\n", "ex1")
    key, canonical = hi.get_or_mint(case, "wec", "srv7.corp.example.test")
    m = hi.load(case).machine_of_key(key)
    assert canonical == "SRV7" and m.state == hi.CONFIRMED


def test_a_late_ai_name_never_joins_from_the_list(case):
    hp.upload_host_list(case, "SRV7\n", "ex1")
    key, _ = hi.get_or_mint(case, "x", "SRV7", origin="argument")
    assert hi.load(case).machine_of_key(key).state == hi.NEW


# -- names that are never grouped, and what sets a name apart


@pytest.mark.parametrize(
    "raw, flag",
    [("unknown", hp.FLAG_NOT_HOST), ("10.0.0.5", hp.FLAG_NOT_HOST),
     ("CORP\\admin", hp.FLAG_NOT_HOST), ("WIN-4K2J8LQ", hp.FLAG_GENERIC)],
)  # fmt: skip
def test_a_value_that_is_no_host_name_is_flagged_and_left_alone(case, raw, flag):
    folder(case, "u1", raw)
    folder(case, "u2", raw)
    gs = [g for g in groups(case) if any(p[1] == raw for p in g.pairs)]
    assert len(gs) == 2 and all(flag in g.flags and g.tier == hp.FLAGGED for g in gs)


@pytest.mark.parametrize(
    "unit_name",
    ["Collection-WKS01-2026-10-01T10_00_00Z", "WKS01-20261001", "WKS01_mem"],
)
def test_a_collection_wrapper_or_date_is_set_aside(case, unit_name):
    unit(case, f"evidence/{unit_name}", [
        (unit_name, "folder name", "folder"),
        ("WKS01", "Security.evtx Computer", "artifact"),
    ])  # fmt: skip
    (g,) = groups(case)
    assert len(g.pairs) == 2 and hp.FLAG_FOLDER not in g.flags


def test_a_near_spelling_needs_more_than_half_its_letters(case):
    folder(case, "u1", "WKSTA01")
    u = hi.unit_key("evidence/x")
    assert hp.near_hints(hi.load(case), [(u, "WKSXB01")]) == []


def test_a_flagged_name_gets_no_near_spelling_hint(case):
    folder(case, "u1", "WIN-ABCD01")
    u = hi.unit_key("evidence/x")
    assert hp.near_hints(hi.load(case), [(u, "WIN-ABCE01")]) == []


def test_a_collector_with_only_forwarded_names_is_not_called_misfiled(case):
    unit(case, "evidence/WEC01", [
        ("WEC01", "folder name", "folder"),
        *[(f"SRV{n}", "ForwardedEvents.evtx Computer", "artifact") for n in (1, 2)],
    ])  # fmt: skip
    wec = group_of(groups(case), "WEC01")
    assert hp.FLAG_FOLDER not in wec.flags


def test_a_forwarded_log_naming_the_collector_itself_stays_with_it(case):
    unit(case, "evidence/WEC01", [
        ("WEC01", "folder name", "folder"),
        ("wec01.corp.example.test", "ForwardedEvents.evtx Computer", "artifact"),
    ])  # fmt: skip
    (g,) = groups(case)
    assert len(g.pairs) == 2


def test_one_units_names_in_two_domains_are_two_machines(case):
    unit(case, "evidence/x", [
        ("DC01.corp-a.example.test", "Security.evtx Computer", "artifact"),
        ("dc01.corp-b.example.test", "System.evtx Computer", "artifact"),
    ])  # fmt: skip
    assert len(groups(case)) == 2


def test_names_without_artifact_evidence_are_only_proposed_together(case):
    for where in ("a", "b"):  # two sources each, so neither is thin
        unit(case, f"evidence/{where}/WKS01",
             [("WKS01", "folder name", "folder"), ("WKS01", "volume label", "folder")])  # fmt: skip
    (g,) = groups(case)
    assert len(g.pairs) == 2 and g.tier == hp.PROPOSED


def test_one_name_under_two_machine_ids_is_two_machines(case):
    guid = "bbbbbbbb-0000-0000-0000-00000000000"
    folder(case, "DC01", "DC01", where="evidence/a/DC01", machine_guid=guid + "1")
    folder(case, "DC01", "DC01", where="evidence/b/DC01", machine_guid=guid + "2")
    assert len(groups(case)) == 2


def test_one_machine_id_in_two_domains_is_flagged(case):
    guid = "cccccccc-0000-0000-0000-000000000001"
    folder(case, "a", "dc01.corp-a.example.test", machine_guid=guid)
    folder(case, "b", "dc01.corp-b.example.test", machine_guid=guid)
    g = group_of(groups(case), "dc01.corp-a.example.test")
    assert hp.FLAG_DOMAINS in g.flags


def test_a_name_from_one_source_is_flagged_thin(case):
    unit(case, "evidence/x", [("SRV55", "Security.evtx Computer", "artifact")])
    (g,) = groups(case)
    assert hp.FLAG_THIN in g.flags and g.tier == hp.FLAGGED


# -- what a machine is called


def _confirmed(case, canonical, raw=None):
    k = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": k, "canonical": canonical, "pairs": [["x", raw or canonical]]}]}}, 0)  # fmt: skip
    return k


def test_a_second_machine_of_a_taken_short_name_is_numbered(case):
    _confirmed(case, "DC01")
    unit(case, "evidence/y", [("DC01", "SYSTEM ComputerName", "artifact")],
         machine_guid="dddddddd-0000-0000-0000-000000000001")  # fmt: skip
    g = [g for g in groups(case) if not g.machine][0]
    assert g.canonical == "DC01 (2)"


def test_a_second_machine_of_a_taken_fqdn_is_called_by_its_domain(case):
    _confirmed(case, "dc01.corp-b.example.test", "old")
    unit(case, "evidence/y", [
        ("dc01.corp-b.example.test", "SYSTEM Tcpip Hostname+Domain", "artifact")])  # fmt: skip
    g = [g for g in groups(case) if not g.machine][0]
    assert g.canonical == "dc01 (corp-b.example.test)"


def test_a_renamed_machine_whose_old_name_is_taken_is_called_by_its_other_name(case):
    _confirmed(case, "dc01.corp.example.test", "old")
    guid = "eeeeeeee-0000-0000-0000-000000000001"
    unit(case, "evidence/a", [
        ("dc01.corp.example.test", "SYSTEM Tcpip Hostname+Domain", "artifact")],
        machine_guid=guid)  # fmt: skip
    unit(case, "evidence/b", [("srv02.corp.example.test", "Security.evtx Computer", "artifact")],
         machine_guid=guid)  # fmt: skip
    g = [g for g in groups(case) if not g.machine][0]
    assert g.canonical == "srv02.corp.example.test"


def test_a_listed_machine_is_called_by_the_list_name(case):
    unit(case, "evidence/x", [
        ("wks01.corp.example.test", "SYSTEM Tcpip Hostname+Domain", "artifact"),
        ("WKS01", "SYSTEM ComputerName", "artifact")])  # fmt: skip
    hp.upload_host_list(case, "Workstation-1 wks01.corp.example.test\n", "ex1")
    (m,) = hi.load(case).machines.values()
    assert m.canonical == "Workstation-1"


# -- the list confirming


def test_a_flagged_unit_on_the_list_is_not_confirmed(case):
    unit(case, "evidence/WKS01", [
        ("WKS01", "folder name", "folder"),
        ("SRV99", "Security.evtx Computer", "artifact"),
    ])  # fmt: skip
    hp.upload_host_list(case, "SRV99\n", "ex1")
    assert not hi.load(case).machines


def test_a_list_uploaded_again_records_nothing_more(case):
    folder(case, "WKS01", "WKS01")
    hp.upload_host_list(case, "WKS01\n", "ex1")
    size = (case / hi.OBSERVATIONS).stat().st_size
    assert hp.apply_host_list(case) == {"confirmed": []}
    assert (case / hi.OBSERVATIONS).stat().st_size == size


def test_a_machine_the_examiner_confirmed_under_a_list_name_has_data(case):
    unit(case, "evidence/m.raw", [("SRV33", "hostname argument", "argument")])
    u = hi.unit_key("evidence/m.raw")
    k = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": k, "canonical": "SRV33", "pairs": [[u, "SRV33"]]}]}},
        (case / hi.OBSERVATIONS).stat().st_size)  # fmt: skip
    hp.upload_host_list(case, "SRV33\n", "ex1")
    state = hi.load(case)
    assert hp.listed_without_data(state, hp.propose(state)) == []


def test_a_list_name_spelled_unlike_the_machine_is_kept_as_its_name(case):
    u = folder(case, "WKS01", "WKS01")
    k = hi.new_machine_key()
    hi.append_decision(case, {"action": "start_now", "args": {"machines": [
        {"key": k, "canonical": "Workstation-1", "pairs": [[u, "WKS01"]]}]}},
        (case / hi.OBSERVATIONS).stat().st_size)  # fmt: skip
    hp.upload_host_list(case, "WKS01\n", "ex1")
    state = hi.load(case)
    m = state.machine_of_key(k)
    assert m.canonical == "Workstation-1" and m.state == hi.CONFIRMED
    assert state.machine_of_pair(hp.LIST_UNIT, "WKS01") is m


def test_the_list_keeps_each_pairs_own_key(case):
    a = folder(case, "WKS01", "WKS01", where="evidence/a/WKS01")
    b = folder(case, "WKS01", "WKS01", where="evidence/b/WKS01")
    ka, kb = hi.get_or_mint(case, a, "WKS01")[0], hi.get_or_mint(case, b, "WKS01")[0]
    hi.append_decision(case, {"action": "merge", "args": {"into": ka, "from": [kb]}},
                       (case / hi.OBSERVATIONS).stat().st_size)  # fmt: skip
    c = folder(case, "WKS01", "WKS01", where="evidence/c/WKS01")  # not bound yet
    hp.upload_host_list(case, "WKS01\n", "ex1")
    state = hi.load(case)
    assert state.bindings[(a, "WKS01")] == ka and state.bindings[(b, "WKS01")] == kb
    assert state.machine_of_pair(c, "WKS01") is state.machine_of_key(
        ka
    )  # the list confirmed it


def test_a_listed_unit_joins_the_machine_already_confirmed_for_the_entry(case):
    k = _confirmed(case, "SRV7")  # its pair was never scanned
    u = unit(case, "evidence/y", [("SRV7", "SYSTEM ComputerName", "artifact"),
                                  ("SRV7", "Security.evtx Computer", "artifact")])  # fmt: skip
    hp.upload_host_list(case, "SRV7\n", "ex1")
    assert hi.load(case).bindings[(u, "SRV7")] == k
