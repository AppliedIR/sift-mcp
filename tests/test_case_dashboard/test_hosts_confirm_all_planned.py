"""Confirm all with many units of one group joining a machine by its bare
name, on each route that joins automatically: a confirm-all item into an
existing machine, the host list, and a machine made now. The units one
decision plans for the machine count as on it; a unit or machine outside
that decision holding the name still refuses the join, and what the
examiner must decide stays theirs. Names are synthetic."""

from __future__ import annotations

import case_dashboard.routes as D
import pytest
from sift_common import host_identity as hi
from starlette.testclient import TestClient

SHORT = "would join through a short name another machine or unit in the case also holds"
BARE = "is a bare name another machine or unit in the case also holds"
NOT_READ = "not every name was read from evidence"
EXAMINER = "needs the examiner: "
THIN = (
    "thin evidence: one source only; named only by an argument, a file name or a"
    " file the AI can write"
)


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


@pytest.fixture
def client():
    return TestClient(D.create_dashboard_v2_app(), raise_server_exceptions=False)


def unit(case, locator, names):
    """names: [(raw, evidence, origin)]"""
    u = hi.unit_key(locator)
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": locator}] + [
        {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": o}
        for r, e, o in names
    ])  # fmt: skip
    return u


def machine(case, name):
    """A confirmed machine `name`, from a host folder its SYSTEM hive agrees with."""
    u = unit(case, f"evidence/{name}", [(name, "folder name", "folder"),
                                        (name, "SYSTEM ComputerName", "artifact")])  # fmt: skip
    hi.append_decision(case, {"action": "confirm", "examiner": "tester", "args": {
        "machines": [{"key": hi.new_machine_key(), "canonical": name,
                      "pairs": [[u, name]]}]}}, hi.load(case).obs_offset)  # fmt: skip
    return u


def json_unit(case, f, host="wkstn05", shape="read"):
    """An ingested JSON file named for `host`: by the run's hostname argument
    and its host column ("read"), the argument only ("argument"), or the
    host column only ("thin")."""
    loc = f"evidence/json/{f}"
    names = {
        "read": [(host, "hostname argument", "argument"),
                 (host, f"{loc} host column", "artifact")],
        "argument": [(host, "hostname argument", "argument")],
        "thin": [(host, f"{loc} host column", "artifact")],
    }[shape]  # fmt: skip
    return unit(case, loc, names)


def wkstn07(case):
    """A unit of machine wkstn07 whose source column names wkstn05."""
    return unit(case, "evidence/x.json", [
        ("wkstn07", "hostname argument", "argument"),
        ("wkstn07", "evidence/x.json host column", "artifact"),
        ("wkstn05", "evidence/x.json source column", "artifact"),
    ])  # fmt: skip


def _decide(client, action, args, page=None):
    page = page or client.get("/api/hosts").json()
    return client.post(
        "/api/hosts/decisions",
        json={"action": action, "args": args, "seen_offset": page["obs_offset"]},
    )


def _confirm_all(client, page=None):
    page = page or client.get("/api/hosts").json()
    r = _decide(client, "confirm_all", {"seen_decisions": page["dec_offset"]}, page)
    assert r.status_code == 200, r.text
    return r.json()


def _list(client):
    r = _decide(client, "list", {"text": "wkstn05\n"})
    assert r.status_code == 200, r.text
    return r.json()


def _on(case, units, name="wkstn05"):
    """The units whose `name` is bound to the machine called `name`."""
    st = hi.load(case)
    m = next((m for m in st.machines.values() if m.canonical == name), None)
    return [u for u in units if m and (u, name) in m.pairs]


def _canonicals(case):
    return [m.canonical for m in hi.load(case).machines.values()]


def _reasons(body, name="wkstn05"):
    """Why the click left the units named `name` waiting."""
    return [
        s["reason"]
        for s in body.get("skipped", [])
        if hi.split_name(s["canonical"])[0] == name
    ] + [r["reason"] for r in body.get("refused", []) if r["name"] == name]


def _keys(case):
    return {m.canonical: m.keys[0] for m in hi.load(case).machines.values()}


def _request(case, items):
    """One Confirm-all request of `items` [(key, canonical, pairs)]."""
    machines = [{"key": k, "canonical": c, "pairs": p} for k, c, p in items]
    return hi.append_decision_items(case, {"action": "confirm", "examiner": "tester",
        "origin": "portal", "args": {"proposed": True, "machines": machines}},
        hi.load(case).obs_offset)  # fmt: skip


ROUTES = ["item", "list", "made_now"]


def _run(case, client, route, n, shape="read", outside=None):
    """N units named wkstn05 waiting (an existing machine wkstn05 first, but
    for a machine made now), `outside` adding machines holding the short
    name; then the route's one click. (units, body)"""
    if route != "made_now":
        machine(case, "wkstn05")
    if outside == "machine":  # for a machine made now, two: one would be joined
        for d in ["other"] if route != "made_now" else ["a", "b"]:
            machine(case, f"wkstn05.{d}.example")
    units = [json_unit(case, f"wkstn05-{i:02}.json", shape=shape) for i in range(n)]
    body = _list(client) if route == "list" else _confirm_all(client)
    return units, body


# 1. N units with the bare name joining the machine: confirmed


@pytest.mark.parametrize("n", [1, 2, 22])
@pytest.mark.parametrize("route", ROUTES)
def test_units_of_one_group_join_the_machine_by_its_bare_name(case, client, route, n):
    units, body = _run(case, client, route, n)
    assert _on(case, units) == units, body
    assert _reasons(body) == [], body


# 2. a unit outside the decision holding the bare name: refused. Confirm all
# gathers every unit holding the name into the group, so its request is sent
# here as Confirm all sends it, with the holder outside it


@pytest.mark.parametrize("n", [1, 2, 22])
@pytest.mark.parametrize("route", ROUTES)
def test_a_unit_outside_the_decision_holding_the_name_refuses_the_join(
    case, client, route, n
):
    if route == "made_now" and n == 1:
        pytest.skip(
            "a machine made from one unit links nothing: no bare name is judged"
        )
    if route != "made_now":
        machine(case, "wkstn05")
    units = [json_unit(case, f"wkstn05-{i:02}.json") for i in range(n)]
    json_unit(case, "other.json", "wkstn05.other.example", "argument")
    if route == "list":
        why = _reasons(_list(client))
    else:
        key = next(iter(_keys(case).values()), None) or hi.new_machine_key()
        out = _request(case, [(key, "wkstn05", [[u, "wkstn05"] for u in units])])
        why = [r["reason"] for r in out["refused"]]
    assert _on(case, units) == [], why
    assert why and all((SHORT if route != "made_now" else BARE) in w for w in why)


# 3. a second machine holding the short name: refused


@pytest.mark.parametrize("n", [1, 2, 22])
@pytest.mark.parametrize("route", ROUTES)
def test_a_second_machine_holding_the_short_name_refuses_the_join(
    case, client, route, n
):
    units, body = _run(case, client, route, n, outside="machine")
    assert all(_on(case, units, m) == [] for m in _canonicals(case)), body
    if route != "list":  # the list binds no name two machines hold: none to refuse
        assert _reasons(body), body


# 4 and 5. what the examiner decides stays theirs


@pytest.mark.parametrize("n", [1, 2, 22])
@pytest.mark.parametrize("route", ["item", "made_now"])
def test_units_named_only_by_an_argument_still_wait(case, client, route, n):
    units, body = _run(case, client, route, n, shape="argument")
    assert _on(case, units) == [], body
    # with no machine to agree with, an argument alone is thin evidence too
    assert _reasons(body) == [NOT_READ if route == "item" else EXAMINER + THIN], body


@pytest.mark.parametrize("n", [1, 2, 22])
@pytest.mark.parametrize("route", ["item", "made_now"])
def test_a_thin_evidence_unit_still_needs_the_examiner(case, client, route, n):
    if route != "made_now":
        machine(case, "wkstn05")
    units = [json_unit(case, f"wkstn05-{i:02}.json") for i in range(n - 1)]
    units.append(json_unit(case, "wkstn05-thin.json", shape="thin"))
    body = _confirm_all(client)
    assert units[-1] not in _on(case, units), body
    why = _reasons(body)
    assert len(why) == 1 and "thin evidence" in why[0] and "examiner" in why[0], body


# 6. a holder that lands between the page and the click


@pytest.mark.parametrize("n", [1, 2, 22])
def test_a_holder_landing_after_the_page_still_refuses_the_join(case, client, n):
    machine(case, "wkstn05")
    units = [json_unit(case, f"wkstn05-{i:02}.json") for i in range(n)]
    page = client.get("/api/hosts").json()
    json_unit(case, "late.json", "wkstn05.late.example", "argument")
    body = _confirm_all(client, page)
    assert _on(case, units) == [], body
    assert any(SHORT in w for w in _reasons(body)), body


# 7. two items in one request: one item's unit on another machine still counts


@pytest.mark.parametrize("n", [1, 2, 22])
def test_a_unit_another_item_binds_elsewhere_still_holds_the_name(case, n):
    machine(case, "wkstn07")
    m05 = machine(case, "wkstn05")
    x = wkstn07(case)
    units = [json_unit(case, f"wkstn05-{i:02}.json") for i in range(n)]
    key = _keys(case)
    out = _request(case, [
        (key["wkstn07"], "wkstn07", [[x, "wkstn07"]]),
        (key["wkstn05"], "wkstn05", [[u, "wkstn05"] for u in units]),
    ])  # fmt: skip
    assert [r["index"] for r in out["refused"]] == [1], out
    assert SHORT in out["refused"][0]["reason"], out
    assert _on(case, [m05, *units]) == [m05]
