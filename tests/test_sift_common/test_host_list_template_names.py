"""A unit's default template names (WIN-…, EC2AMAZ-…) stop holding it once
its real name is known: the host list binds them to the unit's own machine,
never across units. A unit with only template names, a template name two
machines share, a name met only in another host's records, and machines
already made keep today's answers. Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import pytest
from sift_common import host_gate as hg
from sift_common import host_guard
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


def disk(case, locator, real, *template, folder=None, **attrs):
    """A unit whose hive and logs name it `real`, and whose older logs name it
    by the template names it had before it was renamed."""
    rows = [(n, e, "artifact") for n in (real,) if n
            for e in ("SYSTEM ComputerName", "Security.evtx Computer")]  # fmt: skip
    rows += [(t, e, "artifact") for t in template
             for e in ("System.evtx Computer", "Security.evtx Computer")]  # fmt: skip
    if folder:
        rows.append((folder, "folder name", "folder"))
    return unit(case, locator, rows, **attrs)


def on(case, u, raw):
    m = hi.load(case).machine_of_pair(u, raw)
    return m.canonical if m is not None and m.state == hi.CONFIRMED else None


def waiting(case, u) -> list:
    return [(w["raw"], w["reason"]) for w in hg.unresolved(hi.load(case), [u])]


DEV_T = ("EC2AMAZ-AAAA111", "WIN-BBBB2222", "EC2AMAZ-DDDD444")
DC_T = ("EC2AMAZ-CCCC333",)


def _two_hosts(case, triage_folder=None):
    """Two renamed hosts, each with a disk image and a triage collection whose
    older logs carry its template names (R1/R2)."""
    return {
        "dev01 disk": disk(case, "evidence/dev01.E01@0", "DEV01", *DEV_T),
        "dev01 triage": disk(case, "evidence/dev01-triage", "DEV01", *DEV_T[:2],
                             folder=triage_folder and f"dev01-{triage_folder}"),
        "dc01 disk": disk(case, "evidence/dc01.E01@0", "DC01", *DC_T),
        "dc01 triage": disk(case, "evidence/dc01-triage", "DC01", *DC_T,
                            folder=triage_folder and f"dc01-{triage_folder}"),
    }  # fmt: skip


def test_the_list_binds_a_renamed_hosts_template_names_to_its_machine(case):
    units = _two_hosts(case)
    hp.upload_host_list(case, "DEV01\nDC01\n", "ex1")
    st = hi.load(case)
    for label, u in units.items():
        host = label.split()[0].upper()
        pairs = [p for p in st.names if p[0] == u]
        assert {p[1]: on(case, *p) for p in pairs} == dict.fromkeys(
            (p[1] for p in pairs), host
        ), label
        assert waiting(case, u) == [], label
    # one machine per host: both units and every template name
    assert sorted(m.canonical for m in st.machines.values()) == ["DC01", "DEV01"]


def test_a_contradicting_folder_name_still_holds_its_unit(case):
    units = _two_hosts(case, triage_folder="triage-0a1b2c3d-nbd3p1")
    hp.upload_host_list(case, "DEV01\nDC01\n", "ex1")
    assert waiting(case, units["dev01 disk"]) == []
    st = hi.load(case)
    entries = hp._list_entries(st)
    for label in ("dev01 triage", "dc01 triage"):
        u = units[label]
        ps, own, _ = hp._sides(st, u)
        assert hp._unit_held(st, u, ps, own, entries, {}) == hp.FLAG_FOLDER, label
        assert on(case, u, label.split()[0].upper()) is None, label
        assert waiting(case, u), label


def test_the_guard_lets_the_list_bind_a_template_name_of_a_named_unit(case):
    u = disk(case, "evidence/dev01.E01@0", "DEV01", *DEV_T)
    state = hi.load(case)
    assert host_guard.unit_flag(state, u) == ""
    key = hi.new_machine_key()
    binds = [{"kind": "bind", "unit": u, "raw": raw, "key": key, "canonical": "DEV01",
              "state": hi.CONFIRMED} for raw in ("DEV01", *DEV_T)]  # fmt: skip
    assert host_guard.check_binds(state, binds, "list") == []


@pytest.mark.parametrize(
    "generic",
    ["localhost", "localhost.localdomain", "ubuntu", "kali", "debian", "minwinpc",
     "DESKTOP-ABC1234", "MININT-ABC1234", "ip-10-0-0-1"],
)  # fmt: skip
def test_every_generic_name_is_released_the_same_way(case, generic):
    assert hp.generic_only(generic)
    u = disk(case, "evidence/u", "WKS7", generic)
    hp.upload_host_list(case, "WKS7\n", "ex1")
    assert (on(case, u, "WKS7"), on(case, u, generic)) == ("WKS7", "WKS7")
    assert waiting(case, u) == []


@pytest.mark.parametrize("other", ["unknown", "WKS7 backup copy"])
def test_a_flag_other_than_generic_still_holds_the_unit(case, other):
    u = disk(case, "evidence/u", "WKS7", "localhost", other)
    hp.upload_host_list(case, "WKS7\n", "ex1")
    st = hi.load(case)
    ps, own, _ = hp._sides(st, u)
    held = hp._unit_held(st, u, ps, own, hp._list_entries(st), {})
    assert held == "an unusual or non-host name"
    assert host_guard.unit_flag(st, u) == held
    assert [on(case, u, n) for n in ("WKS7", "localhost", other)] == [None] * 3
    assert waiting(case, u)


def test_a_unit_with_only_template_names_stays_held_and_loud(case):
    u = disk(case, "evidence/web.E01@0", None, "WIN-AAAA1111")
    assert hp.upload_host_list(case, "WEB01\n", "ex1").get("confirmed") == []
    assert on(case, u, "WIN-AAAA1111") is None
    assert waiting(case, u)


def test_a_template_name_two_machines_share_never_merges_them(case):
    u1 = disk(case, "evidence/srv1.E01@0", "SRV1", "WIN-TEMPLATE1", machine_guid="g1")
    u2 = disk(case, "evidence/srv2.E01@0", "SRV2", "WIN-TEMPLATE1", machine_guid="g2")
    hp.upload_host_list(case, "SRV1\nSRV2\n", "ex1")
    assert (on(case, u1, "WIN-TEMPLATE1"), on(case, u2, "WIN-TEMPLATE1")) == (
        "SRV1",
        "SRV2",
    )
    # a later unit of srv2 is refused loudly through the shared template name
    u3 = disk(case, "evidence/srv2-triage", "SRV2", "WIN-TEMPLATE1", machine_guid="g2")
    res = hp.apply_host_list(case, [u3])
    assert res["confirmed"] == []
    assert any("would join through a short name" in r["reason"] for r in res["refused"])
    assert on(case, u3, "WIN-TEMPLATE1") is None and waiting(case, u3)
    assert len(hi.load(case).machines) == 2


def test_a_template_name_only_another_hosts_records_carry_stays_unbound(case):
    u = disk(case, "evidence/srv1.E01@0", "SRV1")
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "WIN-OTHER99",
                                   "evidence": "net.csv host column",
                                   "origin": "artifact"}])  # fmt: skip
    hp.upload_host_list(case, "SRV1\n", "ex1")
    assert on(case, u, "SRV1") == "SRV1"
    assert on(case, u, "WIN-OTHER99") is None
    assert [r for r, _ in waiting(case, u)] == ["WIN-OTHER99"]


def test_machines_already_made_for_template_names_change_only_by_merge(case):
    u = disk(case, "evidence/dev01.E01@0", "DEV01", *DEV_T[:1])
    key, _ = hi.get_or_mint(case, u, DEV_T[0], origin="artifact", evidence="x",
                            canonical=DEV_T[0])  # fmt: skip
    before = {m.id: m.canonical for m in hi.load(case).machines.values()}
    hp.upload_host_list(case, "DEV01\n", "ex1")
    st = hi.load(case)
    assert st.machine_of_pair(u, DEV_T[0]).id == key
    assert {k: v for k, v in ((m.id, m.canonical) for m in st.machines.values())
            if k in before} == before  # fmt: skip


def test_after_the_list_no_record_sits_under_a_template_machine(case):
    # an ingest stamps each record with get_or_mint's machine for the name it
    # carries: every template name lands on the host's real machine, for the
    # units the list confirmed and for a later unit of the same host
    units = _two_hosts(case)
    hp.upload_host_list(case, "DEV01\nDC01\n", "ex1")
    units["dev01 later"] = later = disk(case, "evidence/dev01-later", "DEV01", *DEV_T)
    assert hp.apply_host_list(case, [later])["confirmed"]
    for label, u in units.items():
        host = label.split()[0].upper()
        for raw in [p[1] for p in hi.load(case).names if p[0] == u]:
            _, canonical = hi.get_or_mint(case, u, raw, origin=hi.ARTIFACT)
            assert canonical == host, (label, raw)
    assert sorted(m.canonical for m in hi.load(case).machines.values()) == [
        "DC01",
        "DEV01",
    ]
