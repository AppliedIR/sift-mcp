"""The ingest gate: what keeps a run's units from writing, Start now, cancel,
and the wait. Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import json
import threading

import pytest
from sift_common import host_gate as hg
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
    """Record a scanned unit: names is [(raw, evidence, origin)]."""
    u = hi.unit_key(locator)
    recs = [{"kind": "unit", "unit": u, "locator": locator}]
    recs += [
        {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": o}
        for r, e, o in names
    ]
    hi.append_observations(case, recs)
    return u


def folder(case, name, *artifact_names):
    names = [(name, "folder name", "folder")]
    names += [(n, "SYSTEM ComputerName", "artifact") for n in artifact_names]
    return unit(case, f"evidence/{name}", names)


def pending(case, *units):
    return hg.unresolved(hi.load(case), units)


def confirm(case, key, canonical, pairs):
    hi.append_decision(
        case,
        {"action": "confirm", "examiner": "ex1",
         "args": {"machines": [{"key": key, "canonical": canonical,
                                "pairs": [list(p) for p in pairs]}]}},
        hi.load(case).obs_offset,
    )  # fmt: skip


# -- what waits


def test_an_unconfirmed_unit_waits_with_each_name_and_why(case):
    u = folder(case, "WKS01", "WKS01")
    assert pending(case, u) == [
        {
            "unit": u,
            "locator": "evidence/WKS01",
            "raw": "WKS01",
            "reason": "not confirmed",
        }
    ]


def test_a_unit_the_host_list_names_does_not_wait(case):
    u = folder(case, "WKS01", "WKS01")
    hp.upload_host_list(case, "WKS01\n", "ex1")
    assert pending(case, u) == []


def test_a_unit_whose_names_are_all_confirmed_does_not_wait(case):
    u = folder(case, "WKS01", "WKS01")
    confirm(case, hi.new_machine_key(), "WKS01", [(u, "WKS01")])
    assert pending(case, u) == []


def test_one_confirm_of_a_name_two_waiting_files_share_releases_both(case):
    # files held together: their shared host column name is one proposed group
    u, v = (
        unit(
            case,
            f"kansa/{f}.tsv",
            [("WKSTN05", f"kansa/{f}.tsv host column", "artifact")],
        )
        for f in ("arp", "dnscache")
    )
    hg.record_wait(case, "run-1", [u])
    hg.record_wait(case, "run-2", [v])
    (g,) = hp.propose(hi.load(case))
    assert sorted(g.pairs) == sorted([(u, "WKSTN05"), (v, "WKSTN05")])
    confirm(case, hi.new_machine_key(), "WKSTN05", g.pairs)
    assert pending(case, u, v) == []


def test_a_name_bound_while_ingesting_as_new_still_waits(case):
    u = folder(case, "WKS01", "WKS01")
    hi.get_or_mint(case, u, "WKS01", origin="folder")  # a machine in state new
    assert [e["raw"] for e in pending(case, u)] == ["WKS01"]


def test_a_name_only_the_ai_gave_waits_and_says_so(case):
    u = unit(case, "evidence/m.raw", [("DC01", "hostname argument", "argument")])
    (entry,) = pending(case, u)
    assert entry["reason"] == "named only by the hostname given to the run"


BY_FILE_NAME = "named only by its file name"


def test_a_registered_image_named_by_its_file_name_says_so_not_the_ai(case):
    # an examiner's ingest of a registered memory image, no hostname given
    u = unit(
        case, "evidence/rd01-memory.img", [("rd01-memory", "file name", "file-name")]
    )
    (entry,) = pending(case, u)
    assert entry["reason"] == BY_FILE_NAME
    assert "AI" not in entry["reason"] and "unregistered" not in entry["reason"]


def test_a_name_from_more_than_one_ai_origin_names_each():
    assert hg.reason_named_by({"unregistered", "argument"}) == (
        "named only by the hostname given to the run or an unregistered file"
    )


# -- a file name's host form (Tool-HOST): Kansa's module lands in it


def kansa(case, module, host_origin="artifact"):
    loc = f"kansa/WKSTN05-{module}.tsv"
    return unit(
        case,
        loc,
        [
            ("WKSTN05", f"{loc} host column", host_origin),
            (module, f"WKSTN05-{module}.tsv file name", "file-name"),
        ],
    )


def held(case, *units):
    return [(e["raw"], e["reason"]) for e in pending(case, *units)]


def test_a_file_name_form_stops_holding_once_an_artifact_name_is_confirmed(case):
    u = kansa(case, "Arp")
    confirm(case, hi.new_machine_key(), "WKSTN05", [(u, "WKSTN05")])
    assert held(case, u) == []


def test_start_now_releases_a_unit_with_a_file_name_form_as_today(case):
    # Start now binds every held name, the file name's form too
    u = kansa(case, "Arp")
    hg.record_wait(case, "run-1", [u])
    hg.start_now(case, "run-1", "ex1")
    assert held(case, u) == []


def test_a_unit_named_only_by_its_file_name_still_waits(case):
    u = unit(case, "kansa/WKSTN05-Arp.tsv", [("Arp", "file name", "file-name")])
    assert held(case, u) == [("Arp", BY_FILE_NAME)]


def test_an_unconfirmed_artifact_name_holds_the_unit_on_both_names(case):
    u = kansa(case, "Arp")
    assert held(case, u) == [
        ("WKSTN05", hg.REASON_UNCONFIRMED),
        ("Arp", BY_FILE_NAME),
    ]


@pytest.mark.parametrize("origin", ["argument", "ai", "unregistered"])
def test_a_confirmed_name_the_ai_gave_does_not_release_the_file_name_form(case, origin):
    u = kansa(case, "Arp", host_origin=origin)
    confirm(case, hi.new_machine_key(), "WKSTN05", [(u, "WKSTN05")])
    assert held(case, u) == [("Arp", BY_FILE_NAME)]


@pytest.mark.parametrize("with_key", [False, True])
def test_a_unit_whose_only_artifact_name_is_not_a_host_still_waits_on_its_file_name(
    case, with_key
):
    # with a key, the not-a-host name is bound to a confirmed machine of its own
    u = kansa(case, "Arp")
    args = {"pairs": [[u, "WKSTN05"]]}
    if with_key:
        args["key"] = hi.new_machine_key()
    hi.append_decision(
        case,
        {"action": "not_a_host", "examiner": "ex1", "args": args},
        hi.load(case).obs_offset,
    )
    assert held(case, u) == [("Arp", BY_FILE_NAME)]


def test_a_name_the_file_name_and_an_argument_both_gave_still_holds(case):
    # only a name the file name alone gave is released
    loc = "kansa/WKSTN05-Arp.tsv"
    u = unit(
        case,
        loc,
        [
            ("WKSTN05", f"{loc} host column", "artifact"),
            ("Arp", "WKSTN05-Arp.tsv file name", "file-name"),
            ("Arp", "hostname argument", "argument"),
        ],
    )
    confirm(case, hi.new_machine_key(), "WKSTN05", [(u, "WKSTN05")])
    assert held(case, u) == [
        ("Arp", "named only by the hostname given to the run or its file name")
    ]


def test_a_confirmed_artifact_name_of_another_unit_does_not_release_this_one(case):
    other = unit(case, "evidence/WKSTN05", [("WKSTN05", "SYSTEM", "artifact")])
    u = unit(
        case,
        "kansa/WKSTN05-Arp.tsv",
        [("Arp", "WKSTN05-Arp.tsv file name", "file-name")],
    )
    confirm(case, hi.new_machine_key(), "WKSTN05", [(other, "WKSTN05")])
    assert held(case, u) == [("Arp", BY_FILE_NAME)]


def test_a_file_name_form_the_examiner_confirmed_resolves_as_today(case):
    u = unit(case, "kansa/WKSTN05-Arp.tsv", [("Arp", "file name", "file-name")])
    confirm(case, hi.new_machine_key(), "WKSTN05", [(u, "Arp")])
    assert held(case, u) == []


def test_a_file_name_form_marked_not_a_host_never_holds_as_today(case):
    u = kansa(case, "Arp")
    not_a_host(case, u, "Arp")
    assert held(case, u) == [("WKSTN05", hg.REASON_UNCONFIRMED)]


def test_a_unit_with_no_name_waits_and_says_so(case):
    u = hi.unit_key("evidence/x.csv")
    hi.append_observations(
        case, [{"kind": "unit", "unit": u, "locator": "evidence/x.csv"}]
    )
    assert pending(case, u) == [
        {
            "unit": u,
            "locator": "evidence/x.csv",
            "raw": "",
            "reason": "no host name found",
        }
    ]


def test_a_unit_with_no_name_resolves_once_the_examiner_names_it(case):
    u = hi.unit_key("evidence/mem.raw")
    hi.append_observations(
        case, [{"kind": "unit", "unit": u, "locator": "evidence/mem.raw"}]
    )
    confirm(case, hi.new_machine_key(), "DC01", [(u, "DC01")])
    assert pending(case, u) == []


def test_only_the_runs_own_units_count(case):
    a = folder(case, "WKS01", "WKS01")
    folder(case, "WKS02", "WKS02")
    hp.upload_host_list(case, "WKS01\n", "ex1")
    assert pending(case, a) == []


# -- Start now and cancel


def test_start_now_binds_the_runs_names_to_their_proposed_machines(case):
    u = folder(case, "WKS01", "WKS01", "wks01.corp.example.test")
    v = folder(case, "SRV09", "SRV09")
    hg.record_wait(case, "run-1", [u, v])
    proposed = sorted(g.canonical for g in hp.propose(hi.load(case)))
    out = hg.start_now(case, "run-1", "ex1")
    state = hi.load(case)
    assert pending(case, u, v) == []
    a = state.machine_of_pair(u, "WKS01")
    assert a.state == hi.STARTED_NOW
    assert a is state.machine_of_pair(u, "wks01.corp.example.test")  # one proposal
    assert state.machine_of_pair(v, "SRV09").state == hi.STARTED_NOW
    assert sorted(m["canonical"] for m in out["machines"]) == proposed


def test_start_now_reaches_only_the_waiting_runs_units(case):
    u = folder(case, "WKS01", "WKS01")
    other = folder(case, "WKS02", "WKS02")
    hg.record_wait(case, "run-1", [u])
    hg.start_now(case, "run-1", "ex1")
    assert hi.load(case).machine_of_pair(other, "WKS02") is None


def test_start_now_joins_a_machine_a_name_already_belongs_to(case):
    u = folder(case, "WKS01", "WKS01")
    k = hi.new_machine_key()
    confirm(case, k, "WKS01", [(u, "WKS01")])
    v = folder(case, "WKS01-triage", "WKS01")
    hg.record_wait(case, "run-2", [v])
    hg.start_now(case, "run-2", "ex1")
    state = hi.load(case)
    assert state.machine_of_pair(v, "WKS01").id == state.machine_of_key(k).id


def test_start_now_never_reuses_a_taken_name(case, monkeypatch):
    u = folder(case, "WKS01", "WKS01")
    confirm(case, hi.new_machine_key(), "WKS01", [(u, "WKS01")])
    # two other units whose own evidence gives the taken name
    v = unit(case, "evidence/v", [("WKS01", "rows.csv host column", "artifact")])
    w = unit(case, "evidence/w", [("WKS01", "rows.csv host column", "artifact")])
    monkeypatch.setattr(hp, "propose", lambda state: [
        hp.Group(pairs=[(v, "WKS01")], tier=hp.PROPOSED, canonical="WKS01"),
        hp.Group(pairs=[(w, "WKS01")], tier=hp.PROPOSED, canonical="WKS01"),
    ])  # fmt: skip
    hg.record_wait(case, "run-3", [v, w])
    out = hg.start_now(case, "run-3", "ex1")
    assert [m["canonical"] for m in out["machines"]] == ["WKS01 (2)", "WKS01 (3)"]


def test_a_later_unchanged_confirm_keeps_the_key_and_confirms(case):
    u = folder(case, "WKS01", "WKS01")
    hg.record_wait(case, "run-1", [u])
    (m,) = hg.start_now(case, "run-1", "ex1")["machines"]
    confirm(case, m["key"], m["canonical"], [(u, "WKS01")])
    state = hi.load(case)
    after = state.machine_of_pair(u, "WKS01")
    assert after.state == hi.CONFIRMED and m["key"] in after.keys
    assert state.bindings[(u, "WKS01")] == m["key"]  # the docs' key is unchanged


def test_start_now_needs_a_waiting_run_and_an_examiner(case):
    with pytest.raises(hi.HostLogError, match="no run 'run-x' is waiting"):
        hg.start_now(case, "run-x", "ex1")
    hg.record_wait(case, "run-1", [folder(case, "WKS01", "WKS01")])
    with pytest.raises(hi.HostLogError, match="examiner"):
        hg.start_now(case, "run-1", "")


def test_a_cancel_is_folded_for_its_run_only(case):
    u = folder(case, "WKS01", "WKS01")
    hg.record_wait(case, "run-1", [u])
    hg.record_wait(case, "run-2", [u])
    hg.cancel(case, "run-1", "ex1")
    state = hi.load(case)
    assert "run-1" in state.cancelled and "run-2" not in state.cancelled
    with pytest.raises(hi.HostLogError, match="examiner"):
        hg.cancel(case, "run-2", "")


def test_a_cancel_needs_a_waiting_run_not_yet_cancelled(case):
    with pytest.raises(hi.HostLogError, match="no run 'run-9' is waiting"):
        hg.cancel(case, "run-9", "ex1")
    hg.record_wait(case, "run-1", [folder(case, "WKS01", "WKS01")])
    hg.cancel(case, "run-1", "ex1")
    with pytest.raises(hi.HostLogError, match="already cancelled"):
        hg.cancel(case, "run-1", "ex1")


# -- names that can't name a unit


def not_a_host(case, unit, raw):
    hi.append_decision(
        case,
        {"action": "not_a_host", "examiner": "ex1", "args": {"pairs": [[unit, raw]]}},
        hi.load(case).obs_offset,
    )


def test_a_unit_whose_only_name_is_not_a_host_needs_a_name(case):
    u = unit(
        case,
        "evidence/disk.raw@1048576",
        [("BUILD", "SYSTEM ComputerName", "artifact")],
    )
    not_a_host(case, u, "BUILD")
    (entry,) = pending(case, u)
    assert entry["raw"] == "" and entry["reason"] == hg.REASON_NEEDS_NAME


def test_a_name_marked_not_a_host_never_holds_a_unit_with_other_names(case):
    u = folder(case, "WKS01", "WKS01")
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "BUILD",
                                   "evidence": "x.csv host column", "origin": "artifact"}])  # fmt: skip
    not_a_host(case, u, "BUILD")
    assert [e["raw"] for e in pending(case, u)] == ["WKS01"]


def test_start_now_gives_a_nameless_or_not_a_host_unit_its_placeholder(case):
    a = unit(
        case,
        "evidence/disk.raw@1048576",
        [("BUILD", "SYSTEM ComputerName", "artifact")],
    )
    not_a_host(case, a, "BUILD")
    b = hi.unit_key("evidence/mem.raw")
    hi.append_observations(
        case, [{"kind": "unit", "unit": b, "locator": "evidence/mem.raw"}]
    )
    hg.record_wait(case, "run-1", [a, b])
    out = hg.start_now(case, "run-1", "ex1")
    state = hi.load(case)
    assert pending(case, a, b) == []
    names = sorted(m["canonical"] for m in out["machines"])
    assert names == sorted([hg.placeholder_name("evidence/disk.raw@1048576"),
                            hg.placeholder_name("evidence/mem.raw")])  # fmt: skip
    assert all("BUILD" not in n for n in names)  # never the rejected name
    m = state.machine_of_pair(a, "BUILD")  # its records go to the placeholder
    assert m.canonical == hg.placeholder_name("evidence/disk.raw@1048576")
    assert m.state == hi.STARTED_NOW


def test_the_placeholder_is_named_as_a_hostless_volume_is():
    assert hg.placeholder_name("evidence/disk.raw@22020096").startswith("disk-")
    assert hg.placeholder_name("evidence/disk.raw@22020096").endswith("-22020096")
    assert hg.placeholder_name("evidence/disks.zip!d2.E01@0").startswith("d2-")
    assert hg.placeholder_name("evidence/a.raw") != hg.placeholder_name("other/a.raw")


def test_a_not_a_host_name_met_while_ingesting_joins_its_units_machine(case):
    u = folder(case, "WKS01", "WKS01")
    confirm(case, k := hi.new_machine_key(), "WKS01", [(u, "WKS01")])
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "BUILD",
                                   "evidence": "x.csv host column", "origin": "artifact"}])  # fmt: skip
    not_a_host(case, u, "BUILD")
    key, canonical = hi.get_or_mint(case, u, "BUILD")
    assert (key, canonical) == (k, "WKS01")  # never a machine called BUILD


def test_start_now_records_the_offset_the_page_showed(case):
    u = folder(case, "WKS01", "WKS01")
    hg.record_wait(case, "run-1", [u])
    page = hi.load(case).obs_offset
    folder(case, "WKS02", "WKS02")  # arrives after the page was built
    hg.start_now(case, "run-1", "ex1", seen_offset=page)
    last = (case / hi.DECISIONS).read_text().splitlines()[-1]
    import json

    assert json.loads(last)["offset"] == page


def test_the_proposal_is_computed_once_per_state_of_the_logs(case, monkeypatch):
    folder(case, "WKS01", "WKS01")
    calls = []
    real = hp.propose
    monkeypatch.setattr(hp, "propose", lambda state: calls.append(1) or real(state))
    hp.cached_propose(case)
    hp.cached_propose(case)
    assert calls == [1]
    folder(case, "WKS02", "WKS02")
    hp.cached_propose(case)
    assert calls == [1, 1]


def test_with_the_lists_confirmation_off_the_hint_says_matches_are_proposed(
    case, monkeypatch
):
    monkeypatch.setattr(hp, "LIST_AUTO_CONFIRM", False)
    assert hg.host_list_hint(case) == hg.HOST_LIST_HINT_PROPOSED


# -- the wait


def test_the_wait_returns_when_the_examiner_confirms(case):
    u = folder(case, "WKS01", "WKS01")
    seen = []

    def confirm_later():
        while not seen:
            threading.Event().wait(0.01)
        confirm(case, hi.new_machine_key(), "WKS01", [(u, "WKS01")])

    t = threading.Thread(target=confirm_later)
    t.start()
    hg.wait_for_hosts(case, "run-1", [u], seen.append, poll=0.02)
    t.join()
    assert seen[0]["status"] == "awaiting host confirmation"
    assert seen[0]["unresolved"] == 1 and seen[0]["message"] == hg.WAIT_MESSAGE
    assert hi.load(case).waits == {"run-1": [u]}  # Start now can find the run


def test_the_wait_ends_when_the_run_is_cancelled(case):
    u = folder(case, "WKS01", "WKS01")

    def cancel_later(summary):
        hg.cancel(case, "run-1", "ex1")

    with pytest.raises(hg.RunCancelled):
        hg.wait_for_hosts(case, "run-1", [u], cancel_later, poll=0.02)


def test_the_wait_for_a_resolved_run_records_nothing(case):
    u = folder(case, "WKS01", "WKS01")
    hp.upload_host_list(case, "WKS01\n", "ex1")
    size = (case / hi.OBSERVATIONS).stat().st_size
    hg.wait_for_hosts(case, "run-1", [u], poll=0.02)
    assert (case / hi.OBSERVATIONS).stat().st_size == size


def test_the_wait_applies_the_host_list_once_a_host_operation_ends(case):
    """The unit was scanned while a host rename ran, so the list's
    confirmation of it was skipped: the wait applies it once the rename
    ends, and returns."""
    hp.upload_host_list(case, "WKS01\n", "ex1")
    op = {"kind": "rename", "canonical": "WKS02"}
    (case / hi.OPS).write_text(
        json.dumps({"ops": {"op-1": {**op, "state": "running"}}})
    )
    u = folder(case, "WKS01", "WKS01")
    seen = []

    def end_the_rename(summary):
        seen.append(summary)
        if len(seen) == 2:
            (case / hi.OPS).write_text(
                json.dumps({"ops": {"op-1": {**op, "state": "done"}}})
            )
        if len(seen) > 50:  # never applied: end it
            hg.cancel(case, "run-1", "ex1")

    hg.wait_for_hosts(case, "run-1", [u], end_the_rename, poll=0.02)
    assert len(seen) == 2
    assert hi.load(case).machine_of_pair(u, "WKS01").canonical == "WKS01"


def test_the_host_list_hint_is_given_only_without_a_list(case):
    assert hg.host_list_hint(case) == hg.HOST_LIST_HINT
    hp.upload_host_list(case, "WKS01\n", "ex1")
    assert hg.host_list_hint(case) == ""
