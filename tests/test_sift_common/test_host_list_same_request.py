"""A host with two units (a disk image and a triage image) that the host
list binds to its machine in one request: each unit's names hold the short
name the other's carry, and neither unit's names have joined yet. The guard
counts a unit as on the machine when the same request binds its names there
without refusal, whatever the record order. A unit the request binds to
another machine, or whose own bind is refused, still holds the name.
Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import pytest
from sift_common import host_gate as hg
from sift_common import host_guard
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

SHORT = "would join through a short name"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def unit(case, locator, *raws, flagged=False):
    """A unit whose hive and logs both name it each of `raws`."""
    u = hi.unit_key(locator)
    rows = [
        (r, e) for r in raws for e in ("SYSTEM ComputerName", "Security.evtx Computer")
    ]
    if flagged:
        rows.append(("unknown", "Security.evtx Computer"))
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": locator}] + [
        {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": "artifact"}
        for r, e in rows
    ])  # fmt: skip
    return u


def confirm(case, u, canonical, *raws) -> str:
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": canonical, "pairs": [[u, r] for r in raws]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return key


def bind(u, raw, key, canonical):
    return {"kind": "bind", "unit": u, "raw": raw, "key": key, "canonical": canonical,
            "state": hi.CONFIRMED}  # fmt: skip


def on(case, u, raw):
    m = hi.load(case).machine_of_pair(u, raw)
    return m.canonical if m is not None and m.state == hi.CONFIRMED else None


def _host(case, flagged=False):
    """WKS1 confirmed from its memory image; its disk and triage images both
    carry WKS1 and the template name it had before it was renamed."""
    mem = unit(case, "evidence/wks1.mem", "WKS1")
    key = confirm(case, mem, "WKS1", "WKS1")
    disk = unit(case, "evidence/wks1.E01@0", "WKS1", "WIN-AAAA1111")
    triage = unit(case, "evidence/wks1-triage", "WKS1", "WIN-AAAA1111", flagged=flagged)
    return key, disk, triage


@pytest.mark.parametrize("order", ["disk first", "triage first"])
def test_two_units_of_one_host_bound_to_its_machine_in_one_request_both_join(
    case, order
):
    key, disk, triage = _host(case)
    units = [disk, triage] if order == "disk first" else [triage, disk]
    records = [bind(u, r, key, "WKS1") for u in units for r in ("WKS1", "WIN-AAAA1111")]
    assert host_guard.check_binds(hi.load(case), records, "list") == []


def test_the_host_list_confirms_both_units_of_one_host(case):
    _, disk, triage = _host(case)
    hp.upload_host_list(case, "WKS1\n", "ex1")
    for u in (disk, triage):
        assert (on(case, u, "WKS1"), on(case, u, "WIN-AAAA1111")) == ("WKS1", "WKS1")
        assert hg.unresolved(hi.load(case), [u]) == []
    assert len(hi.load(case).machines) == 1


@pytest.mark.parametrize("order", ["srv1 first", "srv2 first"])
def test_a_shared_name_the_request_binds_to_two_machines_is_still_refused(case, order):
    k1 = confirm(case, unit(case, "evidence/srv1.mem", "SRV1"), "SRV1", "SRV1")
    k2 = confirm(case, unit(case, "evidence/srv2.mem", "SRV2"), "SRV2", "SRV2")
    a = unit(case, "evidence/srv1.E01@0", "SRV1", "WIN-TEMPLATE1")
    b = unit(case, "evidence/srv2.E01@0", "SRV2", "WIN-TEMPLATE1")
    records = [
        bind(a, "WIN-TEMPLATE1", k1, "SRV1"),
        bind(b, "WIN-TEMPLATE1", k2, "SRV2"),
    ]
    if order == "srv2 first":
        records.reverse()
    refused = host_guard.check_binds(hi.load(case), records, "list")
    assert [i for i, _ in refused] == [0, 1]
    assert all(SHORT in why for _, why in refused)


@pytest.mark.parametrize("flagged", [True, False], ids=["flagged", "not flagged"])
@pytest.mark.parametrize("order", ["disk first", "triage first"])
def test_a_unit_whose_own_bind_is_refused_still_holds_the_name(case, order, flagged):
    key, disk, triage = _host(case, flagged=flagged)
    records = [bind(disk, "WKS1", key, "WKS1"), bind(triage, "WKS1", key, "WKS1")]
    if order == "triage first":
        records.reverse()
    refused = dict(host_guard.check_binds(hi.load(case), records, "list"))
    at = {r["unit"]: i for i, r in enumerate(records)}
    if not flagged:
        assert refused == {}
        return
    assert "never confirms a unit with a flag" in refused[at[triage]]
    assert SHORT in refused[at[disk]]
