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


def _late(case, u, raw, evidence="Security.evtx Computer"):
    """A name first met while ingesting the unit's records: (machine, state)."""
    _, canonical = hi.get_or_mint(case, u, raw, origin=hi.ARTIFACT,
                                  evidence=evidence)  # fmt: skip
    return canonical, hi.load(case).machine_of_pair(u, raw).state


def _confirm(case, u, canonical, *raws):
    """The examiner confirms `raws` of unit `u` as one machine by hand."""
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": canonical, "pairs": [[u, r] for r in raws]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return key


@pytest.mark.parametrize(
    ("listed", "a_guid", "e_guid", "raw"),
    [("DEV01\nSRV9\n", None, None, "EC2AMAZ-AAAA111"),
     ("DEV01\n", None, None, "EC2AMAZ-AAAA111"),
     ("DEV01\nSRV9\n", None, "g2", "EC2AMAZ-AAAA111"),
     ("DEV01\nSRV9\n", "g1", None, "EC2AMAZ-AAAA111"),
     ("DEV01\nSRV9\n", None, None, "WIN-BBBB2222"),
     ("DEV01\nSRV9\n", "g1", "g2", "EC2AMAZ-AAAA111")],
)  # fmt: skip
def test_another_hosts_late_template_name_never_joins_a_machine_through_it(
    case, listed, a_guid, e_guid, raw
):
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111", "WIN-BBBB2222",
             **({"machine_guid": a_guid} if a_guid else {}))  # fmt: skip
    e = disk(case, "evidence/srv9.E01@0", "SRV9",
             **({"machine_guid": e_guid} if e_guid else {}))  # fmt: skip
    hp.upload_host_list(case, listed, "ex1")
    assert on(case, a, raw) == "DEV01"
    # the other host's records name it later: its own machine, never DEV01
    assert _late(case, e, raw) == (raw, hi.NEW)
    st = hi.load(case)
    assert st.machine_of_pair(a, "DEV01").id != st.machine_of_pair(e, raw).id


@pytest.mark.parametrize(
    ("e_guid", "first", "raw"),
    [(None, "DEV01", "EC2AMAZ-AAAA111"),
     ("g2", "DEV01", "EC2AMAZ-AAAA111"),
     (None, "DEV01.example.com", "EC2AMAZ-AAAA111"),
     (None, "DEV01", "WIN-BBBB2222"),
     (None, "DEV01", "ec2amaz-aaaa111")],
)  # fmt: skip
def test_a_host_name_read_late_first_never_carries_a_template_name_after_it(
    case, e_guid, first, raw
):
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111", "WIN-BBBB2222")
    e = disk(case, "evidence/srv9.E01@0", "SRV9",
             **({"machine_guid": e_guid} if e_guid else {}))  # fmt: skip
    hp.upload_host_list(case, "DEV01\nSRV9\n", "ex1")
    # SRV9's logs name DEV01 (a copied or forwarded record): it joins DEV01
    assert _late(case, e, first) == ("DEV01", hi.CONFIRMED)
    # that join is not SRV9's own name: DEV01's template name read next by
    # SRV9 gets a machine of its own, never DEV01
    assert _late(case, e, raw) == (raw, hi.NEW)
    st = hi.load(case)
    assert st.machine_of_pair(a, "DEV01").id != st.machine_of_pair(e, raw).id


def test_a_forwarded_host_name_in_the_scan_never_carries_a_template_name(case):
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    e = unit(case, "evidence/collector.E01@0",
             [("SRV9", "SYSTEM ComputerName", "artifact"),
              ("SRV9", "Security.evtx Computer", "artifact"),
              ("DEV01", "ForwardedEvents.evtx Computer", "artifact")])  # fmt: skip
    hp.upload_host_list(case, "DEV01\nSRV9\n", "ex1")
    assert on(case, a, "EC2AMAZ-AAAA111") == "DEV01"
    assert on(case, e, "SRV9") == "SRV9"  # no flag holds the collector
    assert on(case, e, "DEV01") == "DEV01"  # its forwarded name sits on DEV01
    # the collector's scan holds DEV01 only from forwarded logs: not its own
    assert _late(case, e, "EC2AMAZ-AAAA111") == ("EC2AMAZ-AAAA111", hi.NEW)


def test_a_triage_unit_of_the_same_host_gets_a_machine_for_a_late_template_name(case):
    # as on base: a template name read late joins only the machine it names,
    # so the same host's other unit gets a new machine, shown for the examiner
    disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    b = disk(case, "evidence/dev01-triage.vhdx@0", "DEV01")
    hp.upload_host_list(case, "DEV01\n", "ex1")
    assert on(case, b, "DEV01") == "DEV01"
    assert _late(case, b, "EC2AMAZ-AAAA111") == ("EC2AMAZ-AAAA111", hi.NEW)


def test_another_hosts_late_template_name_with_a_domain_never_joins_through_it(case):
    fqdn = "EC2AMAZ-AAAA111.corp.example.com"
    a = disk(case, "evidence/dev01.E01@0", "DEV01.corp.example.com", fqdn)
    e = disk(case, "evidence/srv9.E01@0", "SRV9.corp.example.com")
    hp.upload_host_list(case, "DEV01.corp.example.com\nSRV9.corp.example.com\n", "ex1")
    assert on(case, a, fqdn) == "DEV01.corp.example.com"
    assert _late(case, e, fqdn) == (fqdn, hi.NEW)


# a template name with a line ending kept (a CRLF list, a CR-padded log field)
# or a compatibility letter (U+212A KELVIN SIGN for K) is still a template name
PADDED = ["EC2AMAZ-AAAA111\n", "EC2AMAZ-AAAA111\r\n", "WIN-KBBB2222"]


@pytest.mark.parametrize("raw", PADDED)
def test_another_hosts_late_padded_template_name_never_joins_a_machine_through_it(
    case, raw
):
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111", "WIN-KBBB2222")
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    hp.upload_host_list(case, "DEV01\nSRV9\n", "ex1")
    assert on(case, a, hi.spelling(raw).upper()) == "DEV01"
    machine, state = _late(case, e, raw)
    assert (machine != "DEV01", state) == (True, hi.NEW)
    st = hi.load(case)
    assert st.machine_of_pair(a, "DEV01").id != st.machine_of_pair(e, raw).id


@pytest.mark.parametrize("raw", PADDED)
def test_a_late_padded_template_name_of_its_own_unit_joins_its_machine(case, raw):
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111", "WIN-KBBB2222")
    disk(case, "evidence/srv9.E01@0", "SRV9")
    hp.upload_host_list(case, "DEV01\nSRV9\n", "ex1")
    assert _late(case, a, raw) == ("DEV01", hi.CONFIRMED)
    assert len(hi.load(case).machines) == 2


@pytest.mark.parametrize("raw", ["ec2amaz-aaaa111", "EC2AMAZ-AAAA111."])
def test_a_late_template_name_spelled_another_way_joins_its_units_machine(case, raw):
    # the list put the unit's template name on DEV01; the same unit spells it
    # another way in a later artifact, so it joins the machine it already holds
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    hp.upload_host_list(case, "DEV01\n", "ex1")
    assert on(case, a, "EC2AMAZ-AAAA111") == "DEV01"
    assert _late(case, a, raw) == ("DEV01", hi.CONFIRMED)
    assert len(hi.load(case).machines) == 1


def test_a_template_name_no_machine_confirmed_gets_a_machine_per_spelling(case):
    # as on base: nothing confirmed the unit's template name, so each spelling
    # read late gets a machine of its own
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    assert _late(case, a, "EC2AMAZ-AAAA111") == ("EC2AMAZ-AAAA111", hi.NEW)
    assert _late(case, a, "ec2amaz-aaaa111") == ("ec2amaz-aaaa111 (2)", hi.NEW)
    assert len(hi.load(case).machines) == 2


def test_a_listed_triage_unit_gets_a_machine_for_a_late_template_name(case):
    # as on base: another unit of the same host, bound by the list, reads it late
    disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    hp.upload_host_list(case, "DEV01\n", "ex1")
    b = disk(case, "evidence/dev01-triage.vhdx@0", "DEV01")
    assert hp.apply_host_list(case, [b])["confirmed"]
    assert _late(case, b, "EC2AMAZ-AAAA111") == ("EC2AMAZ-AAAA111", hi.NEW)


def test_a_late_host_name_still_joins_across_units(case):
    disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    hp.upload_host_list(case, "DEV01\nSRV9\n", "ex1")
    assert _late(case, e, "DEV01") == ("DEV01", hi.CONFIRMED)


GENERIC_HOST = "DESKTOP-ABC1234"


@pytest.mark.parametrize(
    ("raw", "evidence"),
    [(GENERIC_HOST, "Security.evtx Computer"),
     (GENERIC_HOST, "ForwardedEvents.evtx Computer"),
     (GENERIC_HOST, "syslog host column"),
     ("desktop-abc1234", "Security.evtx Computer")],
)  # fmt: skip
def test_a_host_whose_own_name_is_generic_is_joined_when_read_late(case, raw, evidence):
    assert hp.generic_only(GENERIC_HOST)
    w = disk(case, "evidence/ws.E01@0", GENERIC_HOST)
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    _confirm(case, w, GENERIC_HOST, GENERIC_HOST)
    _confirm(case, e, "SRV9", "SRV9")
    # the machine's own name: another unit's records join it, as on base
    assert _late(case, e, raw, evidence) == (GENERIC_HOST, hi.CONFIRMED)
    assert len(hi.load(case).machines) == 2


def test_a_host_started_now_under_its_generic_name_is_joined_when_read_late(case):
    w = disk(case, "evidence/ws.E01@0", GENERIC_HOST)
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    _confirm(case, e, "SRV9", "SRV9")
    hg.record_wait(case, "run-1", [w])
    hg.start_now(case, "run-1", "ex1")
    assert hi.load(case).machine_of_pair(w, GENERIC_HOST).state == hi.STARTED_NOW
    assert _late(case, e, GENERIC_HOST) == (GENERIC_HOST, hi.STARTED_NOW)
    assert len(hi.load(case).machines) == 2


def test_a_renamed_hosts_former_generic_name_is_joined_when_read_late(case):
    w = disk(case, "evidence/ws.E01@0", GENERIC_HOST)
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    key = _confirm(case, w, GENERIC_HOST, GENERIC_HOST)
    _confirm(case, e, "SRV9", "SRV9")
    hi.append_decision(case, {"action": "rename", "examiner": "ex1",
                              "args": {"machine": key, "canonical": "WS01"}},
                       hi.load(case).obs_offset, door="R")  # fmt: skip
    assert hi.load(case).machine_of_pair(w, GENERIC_HOST).former == [GENERIC_HOST]
    assert _late(case, e, GENERIC_HOST) == ("WS01", hi.CONFIRMED)


@pytest.mark.parametrize(
    ("first", "renames", "raw", "joined"),
    [(GENERIC_HOST, ["WS01", "WS02"], GENERIC_HOST, "WS02"),
     (GENERIC_HOST, ["WIN-ZZZZ999"], GENERIC_HOST, "WIN-ZZZZ999"),
     (GENERIC_HOST + ".corp.example.com", [],
      GENERIC_HOST.lower() + ".corp.example.com.",
      GENERIC_HOST + ".corp.example.com")],
)  # fmt: skip
def test_a_generic_name_a_machine_has_had_is_joined_when_read_late(
    case, first, renames, raw, joined
):
    domain = first.partition(".")[2]
    srv = "SRV9" + (f".{domain}" if domain else "")
    w = disk(case, "evidence/ws.E01@0", first)
    e = disk(case, "evidence/srv9.E01@0", srv)
    key = _confirm(case, w, first, first)
    _confirm(case, e, srv, srv)
    for new in renames:
        hi.append_decision(case, {"action": "rename", "examiner": "ex1",
                                  "args": {"machine": key, "canonical": new}},
                           hi.load(case).obs_offset, door="R")  # fmt: skip
    assert _late(case, e, raw) == (joined, hi.CONFIRMED)
    assert len(hi.load(case).machines) == 2


@pytest.mark.parametrize("listed", [None, "DEV01\nSRV9\n"])
@pytest.mark.parametrize("raw", ["EC2AMAZ-AAAA111", "ec2amaz-aaaa111"])
def test_a_template_name_confirmed_by_hand_as_an_alias_is_not_joined_late(
    case, listed, raw
):
    # a change from base, on purpose: a template name the examiner put on DEV01
    # by hand, read late by another unit, gets a new machine, never DEV01
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    _confirm(case, a, "DEV01", "DEV01", "EC2AMAZ-AAAA111")
    _confirm(case, e, "SRV9", "SRV9")
    if listed:
        hp.upload_host_list(case, listed, "ex1")
    assert on(case, a, "EC2AMAZ-AAAA111") == "DEV01"
    assert _late(case, e, raw) == (raw, hi.NEW)
    assert len(hi.load(case).machines) == 3


def test_a_hand_alias_another_unit_reads_with_a_carriage_return_is_not_joined(case):
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    _confirm(case, a, "DEV01", "DEV01", "EC2AMAZ-AAAA111")
    _confirm(case, e, "SRV9", "SRV9")
    machine, state = _late(case, e, "EC2AMAZ-AAAA111\r")
    assert (machine != "DEV01", state) == (True, hi.NEW)
    assert len(hi.load(case).machines) == 3


def test_a_hand_alias_its_own_unit_spells_another_way_joins_its_machine(case):
    # the unit whose alias the examiner confirmed by hand reads it late spelled
    # another way: it joins the machine it already holds the alias on
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    _confirm(case, a, "DEV01", "DEV01", "EC2AMAZ-AAAA111")
    assert on(case, a, "EC2AMAZ-AAAA111") == "DEV01"
    assert _late(case, a, "ec2amaz-aaaa111") == ("DEV01", hi.CONFIRMED)
    assert len(hi.load(case).machines) == 1


def test_a_template_name_marked_not_a_host_on_its_unit_is_not_joined_late(case):
    # the unit's own pair is marked not a host, so it can't carry the join,
    # though the machine holds the name from another unit
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    b = disk(case, "evidence/dev01b.E01@0", "", "EC2AMAZ-AAAA111")
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": "DEV01", "pairs": [
            [a, "DEV01"], [a, "EC2AMAZ-AAAA111"], [b, "EC2AMAZ-AAAA111"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    hi.append_decision(case, {"action": "not_a_host", "examiner": "ex1", "args": {
        "pairs": [[a, "EC2AMAZ-AAAA111"]], "key": key}}, hi.load(case).obs_offset)  # fmt: skip
    st = hi.load(case)
    assert hi.FLAG_NOT_A_HOST in st.pair_flags.get((a, "EC2AMAZ-AAAA111"), [])
    assert on(case, b, "EC2AMAZ-AAAA111") == "DEV01"
    assert _late(case, a, "ec2amaz-aaaa111") == ("ec2amaz-aaaa111", hi.NEW)


def test_a_template_name_its_unit_joined_late_carries_no_other_spelling(case):
    # a pair a late read joined (matched during ingest) is not the examiner's:
    # the unit's next spelling of the name gets a machine of its own
    a = disk(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111")
    e = disk(case, "evidence/srv9.E01@0", "SRV9")
    key = _confirm(case, a, "DEV01", "DEV01", "EC2AMAZ-AAAA111")
    _confirm(case, e, "SRV9", "SRV9")
    hi.append_observations(case, [
        {"kind": "name", "unit": e, "raw": "EC2AMAZ-AAAA111",
         "evidence": "Security.evtx Computer", "origin": "artifact"},
        {"kind": "bind", "unit": e, "raw": "EC2AMAZ-AAAA111", "key": key,
         "flags": [hi.FLAG_MATCHED_DURING_INGEST]}])  # fmt: skip
    assert on(case, e, "EC2AMAZ-AAAA111") == "DEV01"
    assert _late(case, e, "ec2amaz-aaaa111") == ("ec2amaz-aaaa111", hi.NEW)


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
