"""A host name typed in the Hosts tab that is exactly one confirmed machine's
name joins that machine: a memory image's names, or a renamed disk's earlier
template names, confirmed under it. Two machines never share a spelling, and a
machine not yet confirmed keeps the answer it had. An error message stays on
screen long enough to read. Names are synthetic."""

from __future__ import annotations

import json
import subprocess

import pytest
from sift_common import host_identity as hi

from .test_hosts_tab import _decide, _js_function, case, client, unit  # noqa: F401


def _confirmed(case, client, locator, name):
    u = unit(case, locator, name)
    page = client.get("/api/hosts").json()
    group = {"pairs": [[u, name]], "canonical": name}
    assert _decide(client, page, "confirm", {"groups": [group]}).status_code == 200
    m = hi.load(case).machine_of_pair(u, name)
    assert m.state == hi.CONFIRMED
    return u, m.id


def _confirm(case, client, pairs, typed):
    page = client.get("/api/hosts").json()
    group = {"pairs": [list(p) for p in pairs], "canonical": typed}
    return _decide(client, page, "confirm", {"groups": [group]})


def test_a_memory_images_names_typed_as_a_confirmed_machine_join_it(case, client):
    _, dc01 = _confirmed(case, client, "evidence/dc01.E01@0", "DC01")
    mem = unit(case, "evidence/dc01-memory.raw", "dc01-memory")
    resp = _confirm(case, client, [(mem, "dc01-memory")], "DC01")
    assert resp.status_code == 200, resp.json()
    st = hi.load(case)
    assert st.machine_of_pair(mem, "dc01-memory").id == dc01
    assert [m.canonical for m in st.machines.values()] == ["DC01"]


def test_a_renamed_disks_template_names_typed_as_its_machine_join_it(case, client):
    u = unit(case, "evidence/dev01.E01@0", "DEV01", "EC2AMAZ-AAAA111", "WIN-BBBB2222")
    page = client.get("/api/hosts").json()
    first = {"pairs": [[u, "DEV01"]], "canonical": "DEV01"}
    assert _decide(client, page, "confirm", {"groups": [first]}).status_code == 200
    dev01 = hi.load(case).machine_of_pair(u, "DEV01").id
    pairs = [(u, "EC2AMAZ-AAAA111"), (u, "WIN-BBBB2222")]
    assert _confirm(case, client, pairs, "DEV01").status_code == 200
    st = hi.load(case)
    assert {st.machine_of_pair(*p).id for p in pairs} == {dev01}
    assert len(st.machines) == 1


def test_the_typed_name_joins_whatever_its_case(case, client):
    _, dc01 = _confirmed(case, client, "evidence/dc01.E01@0", "DC01")
    mem = unit(case, "evidence/dc01-memory.raw", "dc01-memory")
    assert _confirm(case, client, [(mem, "dc01-memory")], "dc01").status_code == 200
    st = hi.load(case)
    assert st.machine_of_pair(mem, "dc01-memory").id == dc01
    assert st.machines[dc01].canonical == "DC01"


def test_two_machines_never_share_a_spelling_so_a_typed_name_joins_one(case, client):
    _, srv_a = _confirmed(case, client, "evidence/a.E01@0", "SRV-A")
    b, _ = _confirmed(case, client, "evidence/b.E01@0", "SRV-B")
    # a confirm line the guard refuses today (a case from before it): the
    # store still gives the second machine its own spelling
    m = hi.load(case).machine_of_pair(b, "SRV-B")
    size = (case / hi.OBSERVATIONS).stat().st_size
    line = {"t": "2026-01-01T00:00:00Z", "action": "confirm", "examiner": "tester",
            "origin": "portal", "args": {"machines": [{"key": m.keys[0],
            "canonical": "srv-a", "pairs": [[b, "SRV-B"]]}]}, "offset": size,
            "at": size}  # fmt: skip
    with (case / hi.DECISIONS).open("a") as f:
        f.write(json.dumps(line) + "\n")
    st = hi.load(case)
    assert sorted(x.canonical for x in st.machines.values()) == ["SRV-A", "srv-a (2)"]
    mem = unit(case, "evidence/srv-a-memory.raw", "srv-a-memory")
    assert _confirm(case, client, [(mem, "srv-a-memory")], "srv-a").status_code == 200
    assert hi.load(case).machine_of_pair(mem, "srv-a-memory").id == srv_a


def test_a_machine_not_yet_confirmed_is_not_joined_by_a_typed_name(case, client):
    u = unit(case, "evidence/dc01.E01@0", "DC01")
    key, _ = hi.get_or_mint(
        case, u, "DC01", origin="artifact", evidence="x", canonical="DC01"
    )
    assert hi.load(case).machines[key].state == hi.NEW
    mem = unit(case, "evidence/dc01-memory.raw", "dc01-memory")
    resp = _confirm(case, client, [(mem, "dc01-memory")], "DC01")
    assert resp.status_code == 409, resp.json()
    assert hi.load(case).machine_of_pair(mem, "dc01-memory") is None


@pytest.mark.parametrize(
    "kind,ms", [("error", 10000), ("info", 2500), ("success", 2500), (None, 2500)]
)
def test_an_error_toast_stays_long_enough_to_read(kind, ms):
    script = (
        "var made = []; var timers = []; var gone = 0;\n"
        "var document = {body: {appendChild: function(e) { made.push(e); }},\n"
        "  createElement: function() { return {classList: {add: function() {}},\n"
        "    remove: function() { gone++; }}; }};\n"
        "function setTimeout(f, ms) { timers.push(ms); f(); }\n"
        + _js_function("showToast")
        + f"showToast('Merge refused', {json.dumps(kind)});\n"
        "process.stdout.write(JSON.stringify([made[0].className, timers, gone]));"
    )
    out = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout
    assert json.loads(out) == [f"toast toast-{kind or 'info'}", [10, ms], 1]
