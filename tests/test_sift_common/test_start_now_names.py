"""Start now names the waiting units' machines and never merges: a unit's
names join an existing machine only when it's the unit's own, or a
confirmed machine one of whose names the evidence matches exactly (a name
without a domain only when nothing else in the case holds its short name).
Everything else is a machine of that unit alone. A name first met while
ingesting follows the same rule for a bare name. Same-host units left apart
are merged later by the examiner. Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import pytest
from sift_common import host_gate
from sift_common import host_identity as hi

SYS, EVTX = "SYSTEM ComputerName", "Security.evtx Computer"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def unit(case, locator, names):
    """names: [(raw, evidence, origin)]"""
    u = hi.unit_key(locator)
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": locator}] + [
        {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": o} for r, e, o in names
    ])  # fmt: skip
    return u


def confirmed(case, locator, *names) -> tuple[str, str]:
    """A confirmed machine whose unit's evidence gives `names`: (unit, key)."""
    u = unit(case, locator, [(n, ev, "artifact") for n in names for ev in (SYS, EVTX)])
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": names[0], "pairs": [[u, n] for n in names]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return u, key


def start(case, *units):
    host_gate.record_wait(case, "run-1", list(units))
    return host_gate.start_now(case, "run-1", "ex1")


def machine(case, u, raw):
    return hi.load(case).machine_of_pair(u, raw)


# -- what T found joined, and now doesn't


@pytest.mark.parametrize(
    "evidence, origin",
    [("notes.md", "ai"), ("hostname argument", "argument")],
    ids=["the AI's notes", "a memory image's bare name"],
)
def test_a_name_from_outside_the_evidence_never_joins_a_confirmed_machine(
    case, evidence, origin
):
    a, key = confirmed(case, "evidence/DC01", "DC01")
    b = unit(case, "evidence/mem.raw", [("DC01", evidence, origin)])
    start(case, b)
    m = machine(case, b, "DC01")
    assert m is not None and key not in m.keys and m.canonical == "DC01 (2)"
    assert machine(case, a, "DC01").pairs == [(a, "DC01")]


def test_an_exports_bare_name_waits_apart_when_another_unit_holds_it_too(case):
    """An AD export's bare DC01, with DC01.eu.corp confirmed and a root-domain
    DC01 collected too: it isn't put on the eu machine."""
    a, key = confirmed(case, "evidence/DC01-EU", "DC01.eu.corp.example.test", "DC01")
    unit(case, "evidence/DC01-ROOT", [("DC01.corp.example.test", SYS, "artifact"),
                                      ("DC01", EVTX, "artifact")])  # fmt: skip
    x = unit(case, "evidence/ad.csv", [("DC01", "ad.csv host column", "artifact")])
    start(case, x)
    assert key not in machine(case, x, "DC01").keys


def test_an_exports_bare_name_joins_the_one_machine_that_holds_it(case):
    a, key = confirmed(case, "evidence/DC01-EU", "DC01.eu.corp.example.test", "DC01")
    x = unit(case, "evidence/ad.csv", [("DC01", "ad.csv host column", "artifact")])
    start(case, x)
    assert machine(case, x, "DC01").keys[0] == key


def test_an_exact_name_with_its_domain_joins_the_confirmed_machine(case):
    a, key = confirmed(case, "evidence/DC01-EU", "DC01.eu.corp.example.test")
    x = unit(case, "evidence/rows", [("DC01.eu.corp.example.test", "rows.csv host column",
                                      "artifact")])  # fmt: skip
    start(case, x)
    assert machine(case, x, "DC01.eu.corp.example.test").keys[0] == key


def test_two_units_of_one_name_are_two_machines_until_the_examiner_merges_them(case):
    """Expected: Start now never merges. The examiner merges them later."""
    u1 = unit(
        case,
        "evidence/WKS05-a",
        [("WKS05", SYS, "artifact"), ("WKS05", EVTX, "artifact")],
    )
    u2 = unit(
        case,
        "evidence/WKS05-b",
        [("WKS05", SYS, "artifact"), ("WKS05", EVTX, "artifact")],
    )
    start(case, u1, u2)
    m1, m2 = machine(case, u1, "WKS05"), machine(case, u2, "WKS05")
    assert m1.id != m2.id
    assert {m1.canonical, m2.canonical} == {"WKS05", "WKS05 (2)"}


# -- a name first met while ingesting


def test_a_late_bare_name_waits_when_another_unit_holds_it_too(case):
    a, key = confirmed(case, "evidence/DC01-EU", "DC01.eu.corp.example.test", "DC01")
    unit(case, "evidence/DC01-ROOT", [("DC01.corp.example.test", SYS, "artifact"),
                                      ("DC01", EVTX, "artifact")])  # fmt: skip
    x = unit(case, "evidence/root-export.csv", [("WKS1", SYS, "artifact")])
    got, _ = hi.get_or_mint(case, x, "DC01", evidence="export host column")
    assert got != key and machine(case, x, "DC01").state != hi.CONFIRMED


def test_a_late_bare_name_joins_the_one_machine_that_holds_it(case):
    a, key = confirmed(case, "evidence/DC01-EU", "DC01.eu.corp.example.test", "DC01")
    x = unit(case, "evidence/root-export.csv", [("WKS1", SYS, "artifact")])
    got, canonical = hi.get_or_mint(case, x, "DC01", evidence="export host column")
    assert got == key and canonical == "DC01.eu.corp.example.test"


def test_a_name_never_joins_another_units_started_now_machine(case):
    a = unit(
        case, "evidence/DC01-a", [("DC01", SYS, "artifact"), ("DC01", EVTX, "artifact")]
    )
    start(case, a)
    first = machine(case, a, "DC01")
    assert first.state == hi.STARTED_NOW
    b = unit(
        case, "evidence/DC01-b", [("DC01", SYS, "artifact"), ("DC01", EVTX, "artifact")]
    )
    host_gate.record_wait(case, "run-2", [b])
    host_gate.start_now(case, "run-2", "ex1")
    assert machine(case, b, "DC01").id != first.id


def test_a_bare_name_with_a_second_holder_in_another_domain_doesnt_join(case):
    """DC01.eu (which also holds a bare DC01) and DC01.corp both confirmed: a
    bare DC01 could be either, so it isn't put on the eu machine."""
    a, key = confirmed(case, "evidence/DC01-EU", "DC01.eu.corp.example.test", "DC01")
    confirmed(case, "evidence/DC01-ROOT", "DC01.corp.example.test")
    x = unit(case, "evidence/ad.csv", [("DC01", "ad.csv host column", "artifact")])
    start(case, x)
    assert key not in machine(case, x, "DC01").keys
