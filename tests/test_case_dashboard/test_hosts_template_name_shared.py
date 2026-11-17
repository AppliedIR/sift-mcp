"""A name that units of different machines each carry (a template or clone
build) is proposed flagged as shared, and Confirm all leaves it to the
examiner; a name of one machine's collections, or a forwarded or generic name,
is not. Each row goes through the proposal and the Portal's Confirm all.
Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import case_dashboard.routes as D
import pytest
from sift_common import host_identity as hi
from sift_common import host_proposal as hp
from starlette.testclient import TestClient

# Each template name has two sources, so it is "certain" (not thin) at the base, as in the
# real fold, and Confirm all would bind it to one machine.
TPL = [
    ("tpl-packer", "Amazon EC2Launch.evtx Computer"),
    ("tpl-packer", "Application.evtx Computer"),
]
TPL2 = [("OFFDEVS-TUHMGJE", "Microsoft-Windows-CodeIntegrity%4Operational.evtx Computer"),
        ("OFFDEVS-TUHMGJE", "System.evtx Computer")]  # fmt: skip


def host(name, *extra):
    """A unit's own names: its hive's, then `extra`."""
    return [(name, "SYSTEM ComputerName"),
            (f"{name.lower()}.example.test", "SYSTEM Tcpip Hostname+Domain"), *extra]  # fmt: skip


def fwd(name):
    return (name, "ForwardedEvents.evtx Computer")


# units: [(locator, names)]; confirms: [(unit index, canonical, raws)];
# shared / unshared: the (unit index, raw) pairs whose group is / isn't flagged.
ROWS = {
    "i_two_machines_one_template_name": (
        [("evidence/rd01.E01", host("RD01", *TPL)), ("evidence/wkstn05.vhdx", host("WKSTN05", *TPL))],
        [], [(0, "tpl-packer")], [(0, "RD01"), (1, "WKSTN05")]),
    "i_b_two_machines_two_template_names": (
        [("evidence/rd01.E01", host("RD01", *TPL, *TPL2)),
         ("evidence/wkstn05.vhdx", host("WKSTN05", *TPL, *TPL2))],
        [], [(0, "tpl-packer"), (0, "OFFDEVS-TUHMGJE")], [(0, "RD01"), (1, "WKSTN05")]),
    "i_c_one_name_over_three_units_another_over_two_machines": (
        [("evidence/a/wks01", host("WKS01", *TPL, *TPL2)), ("evidence/b/wks01", host("WKS01", *TPL)),
         ("evidence/srv09", host("SRV09", *TPL, *TPL2))],
        [], [(0, "tpl-packer"), (0, "OFFDEVS-TUHMGJE")], [(0, "WKS01"), (2, "SRV09")]),
    "i_d_two_collections_and_another_machine": (
        [("evidence/a/wks01", host("WKS01", *TPL)), ("evidence/b/wks01", host("WKS01", *TPL)),
         ("evidence/srv09", host("SRV09", *TPL))],
        [], [(0, "tpl-packer")], [(0, "WKS01"), (2, "SRV09")]),
    "i_e_one_machine_renamed_between_collections": (  # known, the safe direction
        [("evidence/a/old", host("OLDNAME01", *TPL)), ("evidence/b/new", host("NEWNAME02", *TPL))],
        [], [(0, "tpl-packer")], [(0, "OLDNAME01"), (1, "NEWNAME02")]),
    "ii_two_collections_of_one_machine": (
        [("evidence/a/wks01", host("WKS01")), ("evidence/b/wks01", host("WKS01"))],
        [], [], [(0, "WKS01")]),
    "ii_b_one_machine_also_sharing_a_template_name": (
        [("evidence/a/wks01", host("WKS01", *TPL)), ("evidence/b/wks01", host("WKS01", *TPL))],
        [], [], [(0, "WKS01"), (0, "tpl-packer")]),
    "ii_c_one_collector_forwarding_two_machines": (
        [("evidence/a/wec01", host("WEC01", fwd("SRV01"))),
         ("evidence/b/wec01", host("WEC01", fwd("SRV02")))],
        [], [], [(0, "WEC01")]),
    "ii_d_one_machine_with_a_generic_name_each": (
        [("evidence/a/wks01", host("WKS01", ("localhost", "Security.evtx Computer"))),
         ("evidence/b/wks01", host("WKS01", ("localhost", "Security.evtx Computer")))],
        [], [], [(0, "WKS01")]),
    "iii_confirmed_apart_template_name": (
        [("evidence/rd01.E01", host("RD01", *TPL)), ("evidence/wkstn05.vhdx", host("WKSTN05", *TPL))],
        [(0, "rd01", ("RD01", "rd01.example.test", "tpl-packer")),
         (1, "wkstn05", ("WKSTN05", "wkstn05.example.test"))],
        [(1, "tpl-packer")], []),
    "iv_one_unit": (
        [("evidence/rd01.E01", host("RD01", *TPL, *TPL2))], [], [],
        [(0, "RD01"), (0, "tpl-packer"), (0, "OFFDEVS-TUHMGJE")]),
    "iv_b_a_unit_with_no_other_name": (
        [("evidence/rd01.E01", host("RD01", *TPL)), ("evidence/tpl.vhdx", TPL)],
        [], [], [(0, "tpl-packer")]),
}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    (d / "findings.json").write_text("[]")
    (d / "timeline.json").write_text("[]")
    hi.ensure_host_files(d)
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    return d


def _build(case, units, confirms):
    keys = []
    for loc, names in units:
        u = hi.unit_key(loc)
        keys.append(u)
        hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": loc}] + [
            {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": "artifact"}
            for r, e in names])  # fmt: skip
    for i, canonical, raws in confirms:
        key = hi.new_machine_key()
        hi.append_observations(case, [
            {"kind": "bind", "unit": keys[i], "raw": r, "key": key, "canonical": canonical,
             "state": hi.CONFIRMED} for r in raws])  # fmt: skip
    return keys


@pytest.mark.parametrize("row", list(ROWS))
def test_a_name_of_more_than_one_machine_is_flagged_and_left_to_the_examiner(case, row):
    units, confirms, shared, unshared = ROWS[row]
    keys = _build(case, units, confirms)
    gs = hp.propose(hi.load(case))
    shown = [g.to_dict() for g in gs]

    def group(i, raw):
        (g,) = [g for g in gs if (keys[i], raw) in g.pairs]
        return g

    client = TestClient(D.create_dashboard_v2_app(), raise_server_exceptions=False)
    page = client.get("/api/hosts").json()
    r = client.post("/api/hosts/decisions", json={
        "action": "confirm_all", "args": {"seen_decisions": page["dec_offset"]},
        "seen_offset": page["obs_offset"]})  # fmt: skip
    assert r.status_code == 200, r.text
    body = r.json()

    def reasons(i, raw):
        return [s["reason"] for s in body["skipped"] if [keys[i], raw] in s["pairs"]]

    for i, raw in shared:
        assert (keys[i], raw) not in hi.load(case).bindings, body  # left unconfirmed
        assert any(hp.FLAG_SHARED in s for s in reasons(i, raw)), body
    for i, raw in unshared:
        assert not any(hp.FLAG_SHARED in s for s in reasons(i, raw)), body

    for i, raw in shared:  # the proposal, read before Confirm all
        g = group(i, raw)
        assert hp.FLAG_SHARED in g.flags and g.tier == hp.FLAGGED, shown
    for i, raw in unshared:
        assert hp.FLAG_SHARED not in group(i, raw).flags, shown
