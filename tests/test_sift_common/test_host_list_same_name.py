"""Two host-list entries of one name in different domains are two machines,
and the list never confirms a unit with a scan flag, even when its own rule
says it may. Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import pytest
from sift_common import host_guard
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

LIST = "SRV-DUP srv-dup.corp.example.test\nSRV-DUP srv-dup.acq.example.test\n"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def unit(case, locator, names):
    """names: [(raw, evidence)] of artifact origin, or [(raw, evidence, origin)]"""
    u = hi.unit_key(locator)
    recs = [{"kind": "unit", "unit": u, "locator": locator}]
    recs += [{"kind": "name", "unit": u, "raw": n[0], "evidence": n[1],
              "origin": n[2] if len(n) > 2 else "artifact"} for n in names]  # fmt: skip
    hi.append_observations(case, recs)
    return u


def two_sources(name):
    return [(name, "SYSTEM ComputerName"), (name, "Security.evtx Computer")]


def machine(case, u, raw):
    return hi.load(case).machine_of_pair(u, raw)


# -- one name, two domains


def test_a_unit_in_each_domain_is_confirmed_to_its_own_entrys_machine(case):
    a = unit(case, "evidence/a", two_sources("srv-dup.corp.example.test"))
    b = unit(case, "evidence/b", two_sources("srv-dup.acq.example.test"))
    hp.upload_host_list(case, LIST, "ex1")
    ma, mb = (
        machine(case, a, "srv-dup.corp.example.test"),
        machine(case, b, "srv-dup.acq.example.test"),
    )
    assert ma is not None and mb is not None and ma.id != mb.id
    assert ma.state == mb.state == hi.CONFIRMED


def test_a_row_name_in_the_other_domain_gets_that_entrys_own_machine(case):
    """Before, the second entry's machine was the first's (minted under the
    name alone), and only the guard kept the two domains apart."""
    a = unit(case, "evidence/a", two_sources("srv-dup.corp.example.test"))
    rows = unit(case, "evidence/rows", [
        ("WKS9", "SYSTEM ComputerName"), ("WKS9", "Security.evtx Computer"),
        ("srv-dup.acq.example.test", "events.csv host column"),
    ])  # fmt: skip
    hp.upload_host_list(case, LIST, "ex1")
    state = hi.load(case)
    recs = hp.list_bindings(state)
    assert not host_guard.check_binds(
        state, recs, "list"
    )  # nothing for the guard to stop
    ma = machine(case, a, "srv-dup.corp.example.test")
    mr = machine(case, rows, "srv-dup.acq.example.test")
    assert ma is not None and mr is not None and ma.id != mr.id


def test_one_name_without_a_domain_matches_both_entries_and_waits(case):
    u = unit(case, "evidence/u", two_sources("SRV-DUP"))
    hp.upload_host_list(case, LIST, "ex1")
    assert machine(case, u, "SRV-DUP") is None
    (g,) = [g for g in hp.propose(hi.load(case)) if (u, "SRV-DUP") in g.pairs]
    assert any("more than one host-list entry" in c for c in g.conflicts)


def test_two_groups_on_the_two_entries_are_no_conflict_and_both_have_data(case):
    unit(case, "evidence/a", [("srv-dup.corp.example.test", "SYSTEM ComputerName")])
    unit(case, "evidence/b", [("srv-dup.acq.example.test", "SYSTEM ComputerName")])
    hi.append_observations(case, [{"kind": "list", "entries": hp.parse_host_list(LIST),
                                   "sha256": "0", "examiner": "ex1"}])  # fmt: skip
    groups = hp.propose(hi.load(case))
    assert not any(
        "is matched by evidence with" in c for g in groups for c in g.conflicts
    )
    assert hp.listed_without_data(hi.load(case), groups) == []


# -- a flagged unit, whatever the list's own rule says


FLAGGED = {
    "thin evidence": [("WKS7", "SYSTEM ComputerName")],
    "two domains": [("WKS7.corp.example.test", "SYSTEM ComputerName"),
                    ("WKS7.acq.example.test", "Security.evtx Computer")],
    "non-host name": [("WKS7", "SYSTEM ComputerName"), ("unknown", "Security.evtx Computer")],
    "folder name contradicted": [("WKS7", "SYSTEM ComputerName"), ("WKS7", "Security.evtx Computer"),
                                 ("FILESRV", "folder name", "folder")],
}  # fmt: skip


@pytest.mark.parametrize("names", FLAGGED.values(), ids=FLAGGED.keys())
def test_the_guard_refuses_the_lists_bind_of_a_flagged_unit(case, names):
    u = unit(case, "evidence/u", names)
    state = hi.load(case)
    assert host_guard.unit_flag(state, u)
    bind = {"kind": "bind", "unit": u, "raw": names[0][0], "key": hi.new_machine_key(),
            "canonical": "WKS7", "state": hi.CONFIRMED}  # fmt: skip
    ((_, why),) = host_guard.check_binds(state, [bind], "list")
    assert "never confirms a unit with a flag" in why
    # a name met later while ingesting, which the list matches: refused too
    ((_, late),) = host_guard.check_binds(state, [bind], "late")
    assert late == why


def test_a_near_spelling_is_a_flag_too(case):
    u = unit(case, "evidence/u", two_sources("WKS7"))
    hi.append_observations(
        case, [{"kind": "hint", "unit": u, "raw": "WKS7", "near": "WKS1"}]
    )
    assert host_guard.unit_flag(hi.load(case), u) == "a near spelling"


@pytest.mark.parametrize("names", FLAGGED.values(), ids=FLAGGED.keys())
def test_a_list_rule_that_lets_a_flagged_unit_through_still_confirms_nothing(
    case, monkeypatch, names
):
    u = unit(case, "evidence/u", names)
    monkeypatch.setattr(hp, "_unit_held", lambda *a: None)  # a regression of the rule
    hp.upload_host_list(case, "WKS7\n", "ex1")
    assert all(machine(case, u, n[0]) is None for n in names)


def test_an_unflagged_unit_is_still_confirmed_by_the_list(case):
    u = unit(case, "evidence/u", two_sources("WKS7"))
    assert host_guard.unit_flag(hi.load(case), u) == ""
    hp.upload_host_list(case, "WKS7\n", "ex1")
    assert machine(case, u, "WKS7").state == hi.CONFIRMED
