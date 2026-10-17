"""A name the examiner gave a unit stays the name of the unit's machine when the
evidence names it too: an address of the unit met later goes on that machine.

The unit is a memory image whose only name, its file name, is marked not a
host; the examiner names it WKS01. A later run reads WKS01 from the evidence
(the envars, or the hostname given to the run). An address met after that
went on a new placeholder machine instead of WKS01."""

from __future__ import annotations

import pytest
from sift_common import host_gate
from sift_common import host_guard as hgd
from sift_common import host_identity as hi

MEMORY = "/srv/data/memory/wks01-memory.img"
FILE_NAME = "wks01-memory"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def _decide(case, action, args):
    record = {"action": action, "examiner": "ex1", "origin": "portal", "args": args}
    hi.append_decision(case, record, hi.load(case).obs_offset)


def _observe(case, u, raw, evidence="windows.envars COMPUTERNAME", origin="artifact"):
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": raw,
                                   "evidence": evidence, "origin": origin}])  # fmt: skip


def _memory_unit(case, *names):
    """The memory unit waiting in run-1, its file name marked not a host."""
    u = hi.unit_key(MEMORY)
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": MEMORY},
        {"kind": "name", "unit": u, "raw": FILE_NAME, "evidence": "memory image file name",
         "origin": "file-name"},
    ])  # fmt: skip
    for n in names:
        _observe(case, u, n)
    _decide(case, "not_a_host", {"pairs": [[u, FILE_NAME]]})
    host_gate.record_wait(case, "run-1", [u])
    return u


def _name(case, u, *pairs):
    """The examiner's confirm of WKS01 for the unit, as the Portal writes it."""
    key = hi.new_machine_key()
    item = {"key": key, "canonical": "WKS01", "pairs": [[u, r] for r in pairs]}
    _decide(case, "confirm", {"machines": [item]})
    return key


def _address(case, u, raw):
    return hi.get_or_mint(case, u, raw, evidence="Hostname host column")


def test_an_address_met_after_the_evidence_names_the_unit_goes_on_its_machine(case):
    u = _memory_unit(case)
    key = _name(case, u, "WKS01", FILE_NAME)
    _observe(case, u, "WKS01")  # a later run reads the name the examiner gave
    assert "WKS01" in hgd.placeholder_of(hi.load(case), u)
    assert _address(case, u, "10.9.9.9") == (key, "WKS01")
    state = hi.load(case)
    assert len(state.machines) == 1
    assert state.machine_of_pair(u, "10.9.9.9").canonical == "WKS01"


def test_an_address_met_before_the_evidence_names_the_unit_goes_on_its_machine(case):
    """The twin: no observation of WKS01."""
    u = _memory_unit(case)
    key = _name(case, u, "WKS01", FILE_NAME)
    assert _address(case, u, "10.9.9.9") == (key, "WKS01")
    assert len(hi.load(case).machines) == 1


def test_an_address_bound_before_the_evidence_names_the_unit_stays(case):
    u = _memory_unit(case)
    key = _name(case, u, "WKS01", FILE_NAME)
    assert _address(case, u, "10.1.2.3") == (key, "WKS01")
    _observe(case, u, "WKS01")
    assert _address(case, u, "10.1.2.3") == (key, "WKS01")
    assert len(hi.load(case).machines) == 1


def test_a_name_the_evidence_gave_first_is_not_the_units_placeholder(case):
    """The evidence names WKS01 before the examiner confirms it: WKS01 is the
    unit's own machine, and its addresses share the unit's placeholder."""
    u = _memory_unit(case, "WKS01")
    _name(case, u, "WKS01")
    assert "WKS01" not in hgd.placeholder_of(hi.load(case), u)
    k1, c1 = _address(case, u, "10.1.2.3")
    _observe(case, u, "WKS01", "the hostname given to the run", "argument")
    k2, c2 = _address(case, u, "10.9.9.9")
    assert c1 == c2 == host_gate.placeholder_name(MEMORY)
    state = hi.load(case)
    assert state.machine_of_key(k1) is state.machine_of_key(k2)
    assert len(state.machines) == 2
