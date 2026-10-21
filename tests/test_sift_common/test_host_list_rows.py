"""The Hosts tab's Host list: each entry with the machines that match it, and
a list that names no host never replaces the examiner's list. Names are
synthetic (RFC 2606 domains)."""

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


def unit(case, locator, names):
    """names: [(raw, evidence)] of artifact origin"""
    u = hi.unit_key(locator)
    recs = [{"kind": "unit", "unit": u, "locator": locator}]
    recs += [{"kind": "name", "unit": u, "raw": n, "evidence": e, "origin": "artifact"}
             for n, e in names]  # fmt: skip
    hi.append_observations(case, recs)
    return u


def confirm(case, u, raw, canonical):
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": hi.new_machine_key(), "canonical": canonical, "pairs": [[u, raw]]}]}},
        (case / hi.OBSERVATIONS).stat().st_size)  # fmt: skip


def test_one_entry_shows_every_machine_it_matches(case):
    a = unit(case, "evidence/a", [("WKS01.corp-a.example.test", "SYSTEM")])
    b = unit(case, "evidence/b", [("WKS01.corp-b.example.test", "SYSTEM")])
    confirm(case, a, "WKS01.corp-a.example.test", "WKS01.corp-a.example.test")
    confirm(case, b, "WKS01.corp-b.example.test", "WKS01.corp-b.example.test")
    hp.upload_host_list(case, "WKS01\nDC01\n", "ex1")
    rows = hp.list_rows(hi.load(case), [])
    assert [r["name"] for r in rows] == ["WKS01", "DC01"]
    assert rows[0]["machines"] == [
        {"canonical": "WKS01.corp-a.example.test", "state": hi.CONFIRMED},
        {"canonical": "WKS01.corp-b.example.test", "state": hi.CONFIRMED},
    ]
    assert rows[1] == {"name": "DC01", "fqdn": "", "machines": [], "proposed": False}


def test_a_waiting_group_proposes_its_entry(case):
    unit(case, "evidence/s", [("SRV09", "SYSTEM ComputerName")])
    hi.append_observations(case, [{"kind": "list", "entries": hp.parse_host_list(
        "SRV09\nDC01\n"), "sha256": "0", "examiner": "ex1"}])  # fmt: skip
    state = hi.load(case)
    rows = hp.list_rows(state, hp.propose(state))
    assert [(r["name"], r["proposed"], r["machines"]) for r in rows] == [
        ("SRV09", True, []),
        ("DC01", False, []),
    ]


def test_a_group_matching_two_entries_leaves_both_unmatched(case):
    u = unit(case, "evidence/u", [("SRV-DUP", "SYSTEM ComputerName"),
                                  ("SRV-DUP", "Security.evtx Computer")])  # fmt: skip
    hp.upload_host_list(
        case,
        "SRV-DUP srv-dup.corp.example.test\nSRV-DUP srv-dup.acq.example.test\n",
        "ex1",
    )
    state = hi.load(case)
    groups = hp.propose(state)
    (g,) = [g for g in groups if (u, "SRV-DUP") in g.pairs]
    assert any("more than one host-list entry" in c for c in g.conflicts)
    rows = hp.list_rows(state, groups)
    assert [(r["fqdn"], r["proposed"], r["machines"]) for r in rows] == [
        ("srv-dup.corp.example.test", False, []),
        ("srv-dup.acq.example.test", False, []),
    ]


def test_no_list_has_no_rows(case):
    unit(case, "evidence/s", [("SRV09", "SYSTEM ComputerName")])
    state = hi.load(case)
    assert hp.list_rows(state, hp.propose(state)) == []


@pytest.mark.parametrize(
    "text, reason",
    [("10.0.0.1\n10.0.0.2\n", "2 skipped (an IP address, not a host name)"),
     ("\n  \n", None)],
)  # fmt: skip
def test_a_list_naming_no_host_keeps_the_current_list(case, text, reason):
    hp.upload_host_list(case, "WKS01\nDC01\n", "ex1")
    before = (case / hi.OBSERVATIONS).read_bytes()
    with pytest.raises(ValueError, match="names no hosts") as e:
        hp.upload_host_list(case, text, "ex2")
    if reason:
        assert str(e.value).endswith(": " + reason)
    assert (case / hi.OBSERVATIONS).read_bytes() == before
    listed = hi.load(case).host_list
    assert len(listed["entries"]) == 2 and listed["examiner"] == "ex1"
