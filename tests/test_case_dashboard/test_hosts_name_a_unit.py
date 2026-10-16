"""The examiner names a unit no name of its evidence can name (its only names
were marked not a host, or it has none) from the Hosts tab, through confirm.

One made-up pair, [unit, the typed name], is accepted, for such a unit of a
waiting run only. The server adds the unit's rejected names. A typed name a
machine already has joins that machine and is never suffixed. The machine is
confirmed and the run stops waiting. Start now is unchanged.

Uses test_hosts_tab's own fixtures and the real routes. Names are synthetic.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from sift_common import host_gate as hg
from sift_common import host_guard as hgd
from sift_common import host_identity as hi

from .test_hosts_tab import (  # noqa: F401
    _DOCUMENT,
    PORTAL,
    _audit,
    _decide,
    _decisions,
    _js_function,
    case,
    client,
    unit,
)

MEMORY = "/srv/data/memory/rd01-memory.img"


def _memory_unit(case, *names):
    u = hi.unit_key(MEMORY)
    recs = [{"kind": "unit", "unit": u, "locator": MEMORY}]
    recs += [
        {"kind": "name", "unit": u, "raw": n, "evidence": "memory image file name",
         "origin": "file-name"}
        for n in names
    ]  # fmt: skip
    hi.append_observations(case, recs)
    return u


def _waiting(case, client, names=("rd01-memory",), run="run-1"):
    """The memory unit, its names marked not a host, waiting in `run`."""
    u = _memory_unit(case, *names)
    if names:
        page = client.get("/api/hosts").json()
        pairs = [[u, n] for n in names]
        r = _decide(client, page, "not_a_host", {"pairs": pairs})
        assert r.status_code == 200, r.text
    hg.record_wait(case, run, [u])
    (w,) = client.get("/api/hosts/runs").json()["runs"]
    assert [e["raw"] for e in w["unresolved"]] == [""], w
    return u, client.get("/api/hosts").json()


def _name(client, page, canonical, pairs):
    return _decide(
        client, page, "confirm", {"groups": [{"canonical": canonical, "pairs": pairs}]}
    )


def _machine_of(case, u):
    state = hi.load(case)
    ms = {m.id: m for m in state.machines.values() if any(p[0] == u for p in m.pairs)}
    assert len(ms) <= 1, ms
    return next(iter(ms.values()), None)


def _runs(client):
    return client.get("/api/hosts/runs").json()["runs"]


# --- the two shapes the examiner sends -----------------------------------------


def test_naming_a_rejected_unit_through_its_seen_name(case, client):
    u, page = _waiting(case, client)
    r = _name(client, page, "RD01", [[u, "rd01-memory"]])
    assert r.status_code == 200, r.text
    m = _machine_of(case, u)
    assert (m.canonical, m.state) == ("RD01", hi.CONFIRMED)
    assert set(m.pairs) == {(u, "RD01"), (u, "rd01-memory")}
    assert _runs(client) == []


def test_naming_a_rejected_unit_by_a_new_name(case, client):
    u, page = _waiting(case, client)
    r = _name(client, page, "RD01", [[u, "RD01"]])
    assert r.status_code == 200, r.text
    m = _machine_of(case, u)
    assert (m.canonical, m.state) == ("RD01", hi.CONFIRMED)
    assert set(m.pairs) == {(u, "RD01"), (u, "rd01-memory")}
    assert _runs(client) == []


def test_a_unit_with_no_name_at_all_is_named_the_same_way(case, client):
    u, page = _waiting(case, client, names=())
    (w,) = _runs(client)
    assert w["unresolved"][0]["reason"] == hg.REASON_NO_NAME
    r = _name(client, page, "RD01", [[u, "RD01"]])
    assert r.status_code == 200, r.text
    m = _machine_of(case, u)
    assert (m.canonical, m.state, m.pairs) == ("RD01", hi.CONFIRMED, [(u, "RD01")])
    assert _runs(client) == []


def test_a_unit_with_two_rejected_names_takes_both(case, client):
    u, page = _waiting(case, client, names=("rd01-memory", "memdump"))
    r = _name(client, page, "RD01", [[u, "RD01"]])
    assert r.status_code == 200, r.text
    assert set(_machine_of(case, u).pairs) == {
        (u, "RD01"),
        (u, "rd01-memory"),
        (u, "memdump"),
    }
    assert _runs(client) == []


def test_the_name_is_stored_as_typed_after_strip(case, client):
    u, page = _waiting(case, client)
    r = _name(client, page, "  Rd01.Example.Test  ", [[u, "Rd01.Example.Test"]])
    assert r.status_code == 200, r.text
    assert _machine_of(case, u).canonical == "Rd01.Example.Test"


def test_the_decision_and_its_audit_carry_the_made_up_pair_and_the_added_names(
    case, client
):
    u, page = _waiting(case, client)
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 200
    d = _decisions(case)[-1]
    assert (d["action"], d["origin"], d["examiner"]) == ("confirm", "portal", "tester")
    (item,) = d["args"]["machines"]
    assert item["canonical"] == "RD01"
    assert item["pairs"] == [[u, "RD01"], [u, "rd01-memory"]]
    a = _audit(case)[-1]
    assert a["tool"] == "host_confirm"
    assert a["params"]["machines"] == [item]


# --- a typed name a machine has joins it, never suffixed ------------------------


def test_a_name_an_existing_machine_has_joins_it_in_one_step(case, client):
    disk = unit(case, "evidence/RD01.E01", "RD01")
    page = client.get("/api/hosts").json()
    r = _decide(
        client,
        page,
        "confirm",
        {"groups": [{"canonical": "RD01", "pairs": [[disk, "RD01"]]}]},
    )
    assert r.status_code == 200, r.text
    u, page = _waiting(case, client)
    r = _name(client, page, "rd01", [[u, "rd01"]])  # its spelling, in another case
    assert r.status_code == 200, r.text
    state = hi.load(case)
    (m,) = state.machines.values()
    assert (m.canonical, m.state) == ("RD01", hi.CONFIRMED)
    assert set(m.pairs) == {(disk, "RD01"), (u, "rd01"), (u, "rd01-memory")}
    assert not any("(2)" in x.canonical for x in state.machines.values())
    assert _runs(client) == []


def test_joining_through_the_rejected_name_also_joins_the_existing_machine(
    case, client
):
    disk = unit(case, "evidence/RD01.E01", "RD01")
    page = client.get("/api/hosts").json()
    assert _decide(client, page, "confirm", {"groups": [{"canonical": "RD01", "pairs": [[disk, "RD01"]]}]}).status_code == 200  # fmt: skip
    u, page = _waiting(case, client)
    r = _name(client, page, "RD01", [[u, "rd01-memory"]])
    assert r.status_code == 200, r.text
    (m,) = hi.load(case).machines.values()
    assert set(m.pairs) == {(disk, "RD01"), (u, "RD01"), (u, "rd01-memory")}


# --- refused: 400, nothing written ------------------------------------------------


def _refused(case, r, status=400):
    assert r.status_code == status, r.text
    return r.json()["error"]


def test_a_made_up_pair_for_a_unit_that_does_not_need_a_name_is_refused(case, client):
    """The twin: the unit has a name of its own waiting."""
    w = unit(case, "evidence/WKS01", "WKS01")
    hg.record_wait(case, "run-1", [w])
    page = client.get("/api/hosts").json()
    before = _decisions(case)
    err = _refused(case, _name(client, page, "WKS99", [[w, "WKS99"]]))
    assert err == "every pair must be a host name the case has seen"
    assert _decisions(case) == before


def test_a_made_up_pair_for_a_unit_no_run_waits_on_is_refused(case, client):
    u = _memory_unit(case, "rd01-memory")
    page = client.get("/api/hosts").json()
    assert (
        _decide(client, page, "not_a_host", {"pairs": [[u, "rd01-memory"]]}).status_code
        == 200
    )
    page = client.get("/api/hosts").json()
    _refused(case, _name(client, page, "RD01", [[u, "RD01"]]))


def test_a_made_up_pair_for_a_cancelled_run_is_refused(case, client):
    u, page = _waiting(case, client)
    hg.cancel(case, "run-1", "tester")
    page = client.get("/api/hosts").json()
    _refused(case, _name(client, page, "RD01", [[u, "RD01"]]))


def test_a_unit_once_named_is_not_named_again(case, client):
    u, page = _waiting(case, client)
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 200
    page = client.get("/api/hosts").json()
    _refused(case, _name(client, page, "RD02", [[u, "RD02"]]))
    assert _machine_of(case, u).canonical == "RD01"


def test_the_typed_name_is_validated(case, client):
    u, page = _waiting(case, client)
    long = "r" * 256
    cases = [
        ("RD01", [[u, "RD02"]]),  # the pair isn't the name typed
        ("", [[u, ""]]),
        ("   ", [[u, "   "]]),
        ("10.1.2.3", [[u, "10.1.2.3"]]),  # an address never names a machine
        ("[fe80::1]:445", [[u, "[fe80::1]:445"]]),
        (long, [[u, long]]),
        ("RD01", [[u, "RD01"], [u, "rd01"]]),  # one name per unit
        ("RD01", [[u, "RD01"], [u, "RD01"]]),
    ]
    before = _decisions(case)
    for canonical, pairs in cases:
        _refused(case, _name(client, page, canonical, pairs))
    for bad in (123, ["RD01"], {"x": 1}, None):
        r = _decide(
            client,
            page,
            "confirm",
            {"groups": [{"canonical": bad, "pairs": [[u, "RD01"]]}]},
        )
        _refused(case, r)
    assert _decisions(case) == before
    assert _runs(client) != []


def test_one_unit_named_in_two_groups_is_refused(case, client):
    u, page = _waiting(case, client)
    r = _decide(client, page, "confirm", {"groups": [
        {"canonical": "RD01", "pairs": [[u, "RD01"]]},
        {"canonical": "RD02", "pairs": [[u, "RD02"]]},
    ]})  # fmt: skip
    _refused(case, r)


def test_two_units_named_one_name_in_one_request_is_refused(case, client):
    u, page = _waiting(case, client)
    v = hi.unit_key("/srv/data/memory/rd02.img")
    hi.append_observations(
        case, [{"kind": "unit", "unit": v, "locator": "/srv/data/memory/rd02.img"}]
    )
    hg.record_wait(case, "run-2", [v])
    page = client.get("/api/hosts").json()
    r = _decide(client, page, "confirm", {"groups": [
        {"canonical": "RD01", "pairs": [[u, "RD01"]]},
        {"canonical": "rd01", "pairs": [[v, "rd01"]]},
    ]})  # fmt: skip
    _refused(case, r)
    assert hi.load(case).machines == {}


def test_without_an_examiner_nothing_is_named(case, client, monkeypatch):
    u, page = _waiting(case, client)
    before = (_decisions(case), _audit(case))
    monkeypatch.delenv("VHIR_EXAMINER")
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 401
    assert (_decisions(case), _audit(case)) == before


def test_only_the_portal_and_start_now_write_host_decisions():
    """The AI's MCP servers have no door to it: the decision writers are
    called from the Hosts tab's routes and the host modules only."""
    pkgs = Path(__file__).parents[2] / "packages"
    callers = set()
    for f in pkgs.rglob("*.py"):
        if "/tests/" in f.as_posix():
            continue
        if re.search(r"\bappend_decision(_items)?\(|\bstart_now\(", f.read_text()):
            callers.add(f.relative_to(pkgs).as_posix())
    assert callers == {
        "case-dashboard/src/case_dashboard/hosts.py",
        "sift-common/src/sift_common/host_gate.py",
        "sift-common/src/sift_common/host_identity.py",
    }


# --- Start now is unchanged -------------------------------------------------------


def test_start_now_still_gives_a_nameless_unit_its_placeholder(case, client):
    u, page = _waiting(case, client)
    r = _decide(client, page, "start_now", {"run_id": "run-1"})
    assert r.status_code == 200, r.text
    m = _machine_of(case, u)
    assert m.state == hi.STARTED_NOW
    assert m.canonical == hg.placeholder_name(MEMORY)


# --- names met after the naming go on the named machine ---------------------------


def test_an_address_met_later_goes_on_the_named_machine(case, client):
    u, page = _waiting(case, client)
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 200
    m = _machine_of(case, u)
    assert hgd.placeholder_of(hi.load(case), u) >= {"RD01"}
    key, canonical = hi.get_or_mint(case, u, "10.1.2.3", evidence="netscan")
    assert (key, canonical) == (m.keys[0], "RD01")
    assert len(hi.load(case).machines) == 1


def test_a_rejected_name_met_later_goes_on_the_named_machine(case, client):
    u, page = _waiting(case, client)
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 200
    page = client.get("/api/hosts").json()
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "memdump",
                                   "evidence": "memory image file name", "origin": "file-name"}])  # fmt: skip
    page = client.get("/api/hosts").json()
    assert (
        _decide(client, page, "not_a_host", {"pairs": [[u, "memdump"]]}).status_code
        == 200
    )
    key, canonical = hi.get_or_mint(case, u, "memdump", origin="file-name")
    assert canonical == "RD01"


def test_start_now_puts_a_later_address_on_the_named_machine(case, client):
    u, page = _waiting(case, client)
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 200
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "10.1.2.3",
                                   "evidence": "netscan", "origin": "artifact"}])  # fmt: skip
    (w,) = _runs(client)  # the address holds the run again
    assert [e["raw"] for e in w["unresolved"]] == ["10.1.2.3"]
    page = client.get("/api/hosts").json()
    r = _decide(client, page, "start_now", {"run_id": "run-1"})
    assert r.status_code == 200, r.text
    state = hi.load(case)
    assert len(state.machines) == 1
    assert state.machine_of_pair(u, "10.1.2.3").canonical == "RD01"


def test_an_address_met_after_its_placeholder_is_merged_goes_on_the_machine(
    case, client
):
    """Start now gives the unit its placeholder, the examiner merges that into
    a confirmed RD01, then the unit's address is met: it joins RD01."""
    disk = unit(case, "evidence/RD01.E01", "RD01")
    page = client.get("/api/hosts").json()
    assert _name(client, page, "RD01", [[disk, "RD01"]]).status_code == 200
    u = _memory_unit(case)
    hg.record_wait(case, "run-1", [u])
    page = client.get("/api/hosts").json()
    assert _decide(client, page, "start_now", {"run_id": "run-1"}).status_code == 200
    state = hi.load(case)
    rd = state.machine_of_pair(disk, "RD01")
    (placeholder,) = [m for m in state.machines.values() if m.id != rd.id]
    merge = {"action": "merge", "examiner": "tester", "origin": "portal",
             "args": {"into": rd.keys[0], "from": [placeholder.keys[0]]}}  # fmt: skip
    hi.append_decision(case, merge, state.obs_offset, door="R")
    key, canonical = hi.get_or_mint(case, u, "10.1.2.3", evidence="netscan")
    state = hi.load(case)
    assert canonical == "RD01"
    (m,) = state.machines.values()
    assert key in m.keys
    assert state.machine_of_pair(u, "10.1.2.3").canonical == "RD01"


def test_an_address_bind_for_another_unit_still_goes_only_on_its_placeholder(
    case, client
):
    """The twin: a made-up pair names its own unit's machine only."""
    u, page = _waiting(case, client)
    assert _name(client, page, "RD01", [[u, "RD01"]]).status_code == 200
    other = unit(case, "evidence/WKS01", "WKS01")
    state = hi.load(case)
    assert "RD01" not in hgd.placeholder_of(state, other)
    m = _machine_of(case, u)
    bind = {"kind": "bind", "unit": other, "raw": "10.9.9.9", "key": m.keys[0]}
    assert hgd.check_binds(state, [bind], "late") == [(0, hgd.ADDRESS_BIND)]


# --- the Hosts tab --------------------------------------------------------------


def _node(script: str) -> str:
    return subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout


def _runs_html(runs) -> str:
    names = ["safeStr", "escapeHtml", "escapeAttr", "hostRunsHtml"]
    return _node(_DOCUMENT + "".join(_js_function(n) for n in names)
                 + f"process.stdout.write(hostRunsHtml({json.dumps(runs)}));")  # fmt: skip


RUNS = [{"run_id": "run-1", "units": 2, "unresolved": [
    {"unit": "u1", "locator": "/m/rd01.img", "raw": "", "reason": hg.REASON_NEEDS_NAME},
    {"unit": "u2", "locator": "/e/WKS01", "raw": "WKS01", "reason": hg.REASON_UNCONFIRMED},
]}]  # fmt: skip


def test_a_nameless_entry_has_a_name_box_and_a_name_it_button(case):
    html = _runs_html(RUNS)
    assert html.count('data-host-act="name_unit"') == 1
    assert html.count("data-host-name=") == 1
    assert ">Name it</button>" in html
    # the run's own buttons keep their labels
    assert ">Start now with the proposed names</button>" in html
    assert ">Cancel the run</button>" in html


def test_the_name_it_button_sends_the_typed_name_through_confirm(case):
    script = (
        "var hostsView = {runs: "
        + json.dumps(RUNS)
        + "};\n"
        + "var document = {querySelector: function(s) {"
        + " return s === '[data-host-name=\"0-0\"]' ? {value: '  RD01 '} : null; }};\n"
        + _js_function("hostNameArgs")
        + "process.stdout.write(JSON.stringify(hostNameArgs('0-0')));"
    )
    assert json.loads(_node(script)) == {
        "groups": [{"canonical": "RD01", "pairs": [["u1", "RD01"]]}]
    }


def test_the_name_box_escapes_a_hostile_locator(case):
    evil = '"><img src=x onerror=alert(1)>'
    runs = [{"run_id": evil, "units": 1, "unresolved": [
        {"unit": evil, "locator": evil, "raw": "", "reason": hg.REASON_NO_NAME}]}]  # fmt: skip
    html = _runs_html(runs)
    assert "<img" not in html


def test_a_run_with_no_waiting_list_has_no_name_box(case):
    html = _runs_html([{"run_id": "run-2", "units": 1}])
    assert "0 waiting" in html
    assert "data-host-name=" not in html


def test_an_entry_with_no_locator_shows_its_unit_and_no_name(case):
    runs = [{"run_id": "run-3", "units": 1, "unresolved": [
        {"unit": "u9", "raw": "", "reason": hg.REASON_NO_NAME}]}]  # fmt: skip
    assert "<li>u9: (no name) &mdash; " in _runs_html(runs)


def test_with_no_name_box_the_name_sent_is_empty(case):
    script = (
        "var hostsView = {runs: " + json.dumps(RUNS) + "};\n"
        "var document = {querySelector: function(s) { return null; }};\n"
        + _js_function("hostNameArgs")
        + "process.stdout.write(JSON.stringify(hostNameArgs('0-0')));"
    )
    assert json.loads(_node(script)) == {
        "groups": [{"canonical": "", "pairs": [["u1", ""]]}]
    }


def _click_handler() -> str:
    start = PORTAL.index("document.addEventListener('click', async function(ev) {\n"
                         "  var el = ev.target.closest && ev.target.closest('[data-host-act]');")  # fmt: skip
    return PORTAL[start : PORTAL.index("\n});\n", start) + 5]


def test_clicking_name_it_confirms_the_typed_name(case):
    acts = re.search(r"^var HOST_DECISION_ACTS = .*$", PORTAL, re.M)[0]
    script = (
        "var listeners = {}, sent = [];\n"
        "var document = {addEventListener: function(t, f) { listeners[t] = f; },"
        " querySelector: function(s) {"
        " return s === '[data-host-name=\"0-0\"]' ? {value: '  RD01 '} : null; }};\n"
        + acts
        + "\n"
        + "var hostsView = {runs: "
        + json.dumps(RUNS)
        + ", data: {}};\n"
        "function hostDecide(a, args) { sent.push([a, args]); }\n"
        "function hostOpUnfinished() { return false; }\n"
        "function showToast() {}\n"
        + _js_function("hostNameArgs")
        + _click_handler()
        + "var el = {getAttribute: function(k) {"
        " return {'data-host-act': 'name_unit', 'data-i': '0-0'}[k]; }};\n"
        "listeners.click({target: {closest: function() { return el; }},"
        " preventDefault: function() {}}).then(function() {"
        " process.stdout.write(JSON.stringify(sent)); });"
    )
    assert json.loads(_node(script)) == [
        ["confirm", {"groups": [{"canonical": "RD01", "pairs": [["u1", "RD01"]]}]}]
    ]
