"""The host list from the examiner's side: an inventory export uploads as it
reads, the upload says what it listed, confirmed and skipped, and a list the
AI prepared waits in the Hosts tab as a draft that confirms nothing until the
examiner uploads it. Only the examiner's upload records a list. Names are
synthetic (RFC 2606 domains)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import case_dashboard.routes as D
import pytest
from sift_common import host_gate as hg
from sift_common import host_identity as hi
from sift_common import host_proposal as hp
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
PORTAL = (Path(D.__file__).parent / "static" / "v2" / "index.html").read_text()
_EVIL = '<img src=x onerror=alert(1)>"\' onmouseover="alert(2)'


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


@pytest.fixture
def prepare(case, tmp_path, monkeypatch):
    """case-mcp's tool for an AI-prepared list, on this case."""
    import case_mcp.server as cs

    monkeypatch.setattr(cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(case / "audit"))
    return cs.create_server()._tool_manager._tools["prepare_host_list"].fn


def folder(case, name):
    """A host folder `name` whose SYSTEM hive says the same name."""
    u = hi.unit_key(f"evidence/{name}")
    hi.append_observations(
        case,
        [
            {"kind": "unit", "unit": u, "locator": f"evidence/{name}"},
            {"kind": "name", "unit": u, "raw": name, "evidence": "folder name",
             "origin": "folder"},
            {"kind": "name", "unit": u, "raw": name, "evidence": "SYSTEM",
             "origin": "artifact"},
        ],
    )  # fmt: skip
    return u


def _decide(client, action, args):
    page = client.get("/api/hosts").json()
    return client.post(
        "/api/hosts/decisions",
        json={"action": action, "args": args, "seen_offset": page["obs_offset"]},
    )


def _audit(case) -> list[dict]:
    path = case / "audit" / "case-dashboard.jsonl"
    return (
        [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
    )


def _host_files(case) -> dict:
    return {n: (case / n).read_bytes() for n in hi.HOST_FILES}


# Uploads


def test_an_inventory_export_confirms_the_host_it_names(case, client):
    folder(case, "WKS01")
    resp = _decide(client, "list", {"text": "IP,Hostname\n10.0.0.5,WKS01\n"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["confirmed"] == ["WKS01"] and body["entries"] == 1
    assert body["summary"].startswith("1 listed, 1 confirmed")
    assert client.get("/api/hosts").json()["counts"]["confirmed"] == 1


def test_an_upload_reply_names_each_skipped_row(case, client):
    body = _decide(
        client, "list", {"text": "IP,Hostname\n10.0.0.5,WKS01\n10.0.0.6,\n"}
    ).json()
    assert body["skipped"] == [
        {"canonical": "line 3", "reason": "no name in the host column"}
    ]
    assert body["summary"] == (
        "1 listed, 0 confirmed, 1 skipped: "
        "the list confirms hosts as evidence names them"
    )


def _toast(reply) -> list:
    """The toast hostDecide shows for the route's reply, run under node."""
    start = PORTAL.index("async function hostDecide(")
    fn = PORTAL[start : PORTAL.index("\n}\n", start) + 3]
    script = (
        "var toasts = [];\n"
        "var document = {activeElement: null};\n"
        "var hostsView = {data: {obs_offset: 0}};\n"
        f"async function apiFetch() {{ return {json.dumps(reply)}; }}\n"
        "function showToast(m, t) { toasts.push([m, t]); }\n"
        "function renderHosts() {}\n"
        + fn
        + "hostDecide('list', {text: ''}).then(function() {"
        " process.stdout.write(JSON.stringify(toasts)); });"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                         check=True).stdout  # fmt: skip
    return json.loads(out)


def test_a_list_that_matches_nothing_says_0_confirmed_and_why(case, client):
    folder(case, "WKS01")
    reply = _decide(client, "list", {"text": "SRV09\n"}).json()
    [(text, _)] = _toast(reply)
    assert "0 confirmed" in text and "as evidence names them" in text
    assert "Saved" not in text


def test_a_list_with_no_host_names_is_a_warning(case, client):
    reply = _decide(client, "list", {"text": "# hosts to come\n"}).json()
    assert reply["entries"] == 0 and reply["warning"] is True
    assert reply["skipped"] == []
    [(text, level)] = _toast(reply)
    assert text.startswith("0 listed") and level == "warning"


def test_a_skipped_row_list_is_capped_in_the_reply(case, client):
    text = "IP,Hostname\n" + "".join(
        f"10.0.{i // 256}.{i % 256},\n" for i in range(500)
    )
    body = _decide(client, "list", {"text": text}).json()
    assert len(body["skipped"]) == hp.SKIPPED_SHOWN
    assert "500 skipped" in body["summary"]


# The AI-prepared draft


def test_a_prepared_list_waits_as_a_draft_and_changes_no_host_state(
    case, client, prepare
):
    folder(case, "WKS01")
    before = _host_files(case)
    out = prepare(text="Hostname\nWKS01\n", source="inventory.pdf")
    assert "error" not in out, out
    assert out["entries"] == [{"name": "WKS01"}] and "Hosts tab" in out["next_step"]
    page = client.get("/api/hosts").json()
    assert page["draft"]["text"] == "Hostname\nWKS01\n"
    assert page["draft"]["source"] == "inventory.pdf"
    assert page["draft"]["entries"] == 1
    assert page["counts"]["confirmed"] == 0 and page["host_list"] is None
    assert _host_files(case) == before


def test_a_prepared_list_over_the_cap_is_refused(case, prepare):
    out = prepare(text="W" * (hp.LIST_MAX + 1))
    assert "error" in out and hp.read_host_list_draft(case) is None


def test_an_upload_clears_the_draft(case, client, prepare):
    prepare(text="WKS01\n")
    assert _decide(client, "list", {"text": "WKS01\n"}).status_code == 200
    assert client.get("/api/hosts").json()["draft"] is None


def test_dismiss_drops_the_draft_and_is_audited(case, client, prepare):
    prepare(text="WKS01\n")
    before = _host_files(case)
    resp = _decide(client, "draft_dismiss", {})
    assert resp.status_code == 200, resp.text
    assert client.get("/api/hosts").json()["draft"] is None
    assert _host_files(case) == before
    assert [e["tool"] for e in _audit(case)] == ["host_draft_dismiss"]


def test_no_mcp_tool_records_a_host_list():
    """Only the Portal's upload route records a list (the ingest wait applies
    the examiner's recorded one)."""
    packages = ROOT / "packages"
    callers = sorted(
        str(p.relative_to(packages))
        for p in packages.rglob("*.py")
        if "upload_host_list(" in p.read_text()
    )
    assert callers == [
        "case-dashboard/src/case_dashboard/hosts.py",
        "sift-common/src/sift_common/host_proposal.py",
    ]
    case_mcp = (packages / "case-mcp/src/case_mcp/server.py").read_text()
    assert '"kind": "list"' not in case_mcp and "append_observations" not in case_mcp


# The draft in the page


def _draft_html(draft) -> str:
    names = ["safeStr", "escapeHtml", "hostDraftHtml"]
    start = [PORTAL.index(f"function {n}(") for n in names]
    fns = "".join(PORTAL[s : PORTAL.index("\n}\n", s) + 3] for s in start)
    script = (
        "const document = {createElement: () => ({set textContent(s) {"
        "this.innerHTML = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')"
        ".replace(/>/g, '&gt;');}})};\n"
        + fns
        + f"process.stdout.write(hostDraftHtml({json.dumps(draft)}));"
    )
    return subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout


def test_a_hostile_draft_source_renders_as_text():
    html = _draft_html({"text": _EVIL, "source": _EVIL, "entries": 3})
    assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "3 entries" in html and 'data-host-act="draft_dismiss"' in html
    assert _draft_html(None) == ""


def test_the_draft_text_goes_into_the_text_box_as_its_value():
    lines = [x for x in PORTAL.splitlines() if "hostListText" in x]
    assert any(".value = " in x and "draft.text" in x for x in lines), lines
    assert not any("innerHTML" in x for x in lines), lines


# What the AI is told


def test_the_hint_names_the_formats_and_the_ai_prepared_draft():
    for hint in (hg.HOST_LIST_HINT, hg.HOST_LIST_HINT_PROPOSED):
        assert "prepare_host_list" in hint and "header row" in hint
        assert "Tell the examiner" in hint and "never say a list was" in hint


# What the examiner reads in the Hosts tab: the Portal's own wording, never
# the AI's instruction


@pytest.mark.parametrize("auto", [True, False])
def test_the_hosts_tab_hint_speaks_to_the_examiner(case, client, monkeypatch, auto):
    monkeypatch.setattr(hp, "LIST_AUTO_CONFIRM", auto)
    hint = client.get("/api/hosts").json()["host_list_hint"]
    assert "Tell the examiner" not in hint and "never say" not in hint
    assert "prepare_host_list" not in hint
    assert "header row" in hint and "prepare a draft" in hint
    assert ("confirms matching hosts automatically" in hint) is auto
    assert ("proposes matching hosts" in hint) is not auto
    # the panel the hint points to is on the tab, below the header
    assert PORTAL.index('id="hostsHeader"') < PORTAL.index(
        "<summary>Upload a host list</summary>"
    )
    assert '"Upload a host list" below' in hint
    portal = "PORTAL_HOST_LIST_HINT" if auto else "PORTAL_HOST_LIST_HINT_PROPOSED"
    assert hint == getattr(hg, portal)


@pytest.mark.parametrize("auto", [True, False])
def test_with_a_list_loaded_the_hosts_tab_shows_no_hint(
    case, client, monkeypatch, auto
):
    monkeypatch.setattr(hp, "LIST_AUTO_CONFIRM", auto)
    assert _decide(client, "list", {"text": "WKS01\n"}).status_code == 200
    page = client.get("/api/hosts").json()
    assert page["host_list"] and page["host_list_hint"] == ""


def test_the_upload_panel_says_what_a_list_does_in_both_modes():
    panel = PORTAL[PORTAL.index('<details id="hostListPanel"') :]
    text = " ".join(re.search(r"<p[^>]*>(.*?)</p>", panel, re.S).group(1).split())
    assert (
        "Hosts it matches are confirmed automatically, or proposed for you to "
        "confirm when automatic confirmation is off." in text
    )
    assert "header row" in text and "draft" in text


def test_the_ingest_skill_tells_the_examiner_about_the_list():
    skill = " ".join((ROOT / "skills/vhir-ingest/SKILL.md").read_text().split())
    assert "## Host list" in skill and "prepare_host_list" in skill
    assert "Only the examiner's Upload applies a list" in skill
    assert "Start now" in skill


# A folder the AI named for its host, as the evidence names it

MODULES = ("Arp", "Netstat", "SchedTasks")


def by_host(case, fqdn, folder_name=None, artifact_names=None):
    """One host's per-host folder as a recursive ingest of a collector's
    output records it: the folder name as the run's hostname argument, the
    host column's names as artifact names, and each file name's module."""
    short = fqdn.split(".")[0]
    name = folder_name or short
    u = hi.unit_key(f"evidence/by-host/{name}")
    recs = [
        {"kind": "unit", "unit": u, "locator": f"evidence/by-host/{name}"},
        {"kind": "name", "unit": u, "raw": name, "evidence": "hostname argument",
         "origin": "argument"},
    ]  # fmt: skip
    for raw in artifact_names if artifact_names is not None else (short.upper(), fqdn):
        recs.append({"kind": "name", "unit": u, "raw": raw,
                     "evidence": f"{fqdn}-Arp.csv host column", "origin": "artifact"})  # fmt: skip
    for m in MODULES:
        recs.append({"kind": "name", "unit": u, "raw": m,
                     "evidence": f"{fqdn}-{m}.csv file name", "origin": "file-name"})  # fmt: skip
    return _observe(case, u, recs)


def _observe(case, unit, recs):
    state = hi.load(case)
    new = sorted({(r["unit"], r["raw"]) for r in recs if r["kind"] == "name"})
    hi.append_observations(case, recs + hp.near_hints(state, new))
    hp.apply_host_list(case, [unit])
    return unit


def _confirm_all(client):
    page = client.get("/api/hosts").json()
    resp = client.post(
        "/api/hosts/decisions",
        json={"action": "confirm_all", "seen_offset": page["obs_offset"],
              "args": {"seen_decisions": page["dec_offset"]}},
    )  # fmt: skip
    assert resp.status_code == 200, resp.text
    return resp.json()


def _bound(case, unit, raw) -> bool:
    return (unit, raw) in hi.load(case).bindings


HOSTS = ("wks01.corp.example", "wks02.corp.example", "dc01.corp.example")


def test_confirm_all_confirms_hosts_whose_folders_are_named_as_the_evidence_does(
    case, client
):
    units = [by_host(case, f) for f in HOSTS]
    body = _confirm_all(client)
    assert sorted(body["confirmed"]) == sorted(HOSTS), body
    st = hi.load(case)
    assert hg.unresolved(st, units) == []  # the module names released with them
    page = client.get("/api/hosts").json()
    assert page["proposed"] == [] and page["counts"]["confirmed"] == len(HOSTS)


def test_a_list_confirms_the_folder_name_that_agrees_with_the_evidence(case, client):
    units = [by_host(case, f) for f in HOSTS]
    resp = _decide(client, "list", {"text": "\n".join(HOSTS) + "\n"})
    assert resp.status_code == 200, resp.text
    assert hg.unresolved(hi.load(case), units) == []
    assert client.get("/api/hosts").json()["proposed"] == []
    for u, f in zip(units, HOSTS, strict=True):
        assert _bound(case, u, f.split(".")[0])


# Names that must stay with the examiner


def _a_memory_image(case, name):
    """A unit with no artifact name: the hostname argument and a file name."""
    u = hi.unit_key(f"evidence/{name}-memory.img")
    return _observe(case, u, [
        {"kind": "unit", "unit": u, "locator": f"evidence/{name}-memory.img"},
        {"kind": "name", "unit": u, "raw": name, "evidence": "hostname argument",
         "origin": "argument"},
        {"kind": "name", "unit": u, "raw": f"{name}-memory",
         "evidence": "memory image file name", "origin": "file-name"},
    ])  # fmt: skip


def test_a_unit_with_no_artifact_name_holds_its_group_under_confirm_all(case, client):
    by_host(case, "wks01.corp.example")
    by_host(case, "wks02.corp.example")
    mem = _a_memory_image(case, "wks01")
    body = _confirm_all(client)
    assert body["confirmed"] == ["wks02.corp.example"], body
    held = [s for s in body["skipped"] if s["canonical"] == "wks01.corp.example"]
    assert held and held[0]["reason"] == "not every name was read from evidence"
    assert not _bound(case, mem, "wks01") and not _bound(case, mem, "wks01-memory")


def test_a_list_leaves_a_unit_with_no_artifact_name_waiting(case, client):
    by_host(case, "wks01.corp.example")
    mem = _a_memory_image(case, "wks01")
    _decide(client, "list", {"text": "wks01.corp.example\n"})
    assert not _bound(case, mem, "wks01")
    assert {e["raw"] for e in hg.unresolved(hi.load(case), [mem])} == {
        "wks01", "wks01-memory"
    }  # fmt: skip


@pytest.mark.parametrize("folder_name,artifact_names", [
    ("dc01", ("WKS05", "wks05.corp.example")),  # another host's folder name
    ("wks05.corp.example", ("WKS05",)),  # a full name; the evidence has the short one
])  # fmt: skip
def test_a_folder_name_the_evidence_does_not_give_stays_held(
    case, client, folder_name, artifact_names
):
    u = by_host(case, "wks05.corp.example", folder_name, artifact_names)
    body = _confirm_all(client)
    assert [s["reason"] for s in body["skipped"] if [u, folder_name] in s["pairs"]]
    assert not _bound(case, u, folder_name)
    _decide(client, "list", {"text": "wks05.corp.example\n"})
    assert _bound(case, u, "WKS05") and not _bound(case, u, folder_name)


@pytest.mark.parametrize("origin", ["ai", "unregistered", "file-name"])
def test_a_name_from_another_ai_origin_stays_held_though_it_agrees(
    case, client, origin
):
    u = by_host(case, "wks05.corp.example")
    hi.append_observations(case, [{"kind": "name", "unit": u, "raw": "wks05.",
                                   "evidence": "x", "origin": origin}])  # fmt: skip
    _confirm_all(client)
    _decide(client, "list", {"text": "wks05.corp.example\n"})
    assert _bound(case, u, "WKS05") and not _bound(case, u, "wks05.")


def test_a_folder_name_agreeing_only_with_another_units_evidence_stays_held(
    case, client
):
    dc = by_host(case, "dc01.corp.example")
    other = _observe(case, hi.unit_key("evidence/by-host/x"), [
        {"kind": "unit", "unit": hi.unit_key("evidence/by-host/x"),
         "locator": "evidence/by-host/x"},
        {"kind": "name", "unit": hi.unit_key("evidence/by-host/x"), "raw": "dc01",
         "evidence": "hostname argument", "origin": "argument"},
    ])  # fmt: skip
    _confirm_all(client)
    _decide(client, "list", {"text": "dc01.corp.example\n"})
    assert _bound(case, dc, "dc01") and not _bound(case, other, "dc01")


def test_a_planted_file_name_is_not_bound_into_a_real_host(case, client):
    dc = by_host(case, "dc01.corp.example")
    u = hi.unit_key("evidence/DC01-x.csv")
    _observe(case, u, [
        {"kind": "unit", "unit": u, "locator": "evidence/DC01-x.csv"},
        {"kind": "name", "unit": u, "raw": "DC01", "evidence": "DC01-x.csv file name",
         "origin": "file-name"},
        {"kind": "name", "unit": u, "raw": "WKS05", "evidence": "SYSTEM",
         "origin": "artifact"},
    ])  # fmt: skip
    _confirm_all(client)
    _decide(client, "list", {"text": "dc01.corp.example\n"})
    assert _bound(case, dc, "DC01") and not _bound(case, u, "DC01")


# A hostname argument judged by its unit's own evidence


def _named(case, loc, names):
    u = hi.unit_key(loc)
    return _observe(case, u, [{"kind": "unit", "unit": u, "locator": loc}] + [
        {"kind": "name", "unit": u, "raw": r, "evidence": e, "origin": o}
        for r, e, o in names
    ])  # fmt: skip


def _real_dc01(case):
    return _named(case, "evidence/dc01-image", [
        ("DC01.corp.example", "SYSTEM", "artifact"),
        ("DC01.corp.example", "Security.evtx Computer", "artifact"),
    ])  # fmt: skip


_ARG_DC01 = ("DC01", "hostname argument", "argument")
_FORWARDED_DC01 = ("DC01.corp.example", "ForwardedEvents.evtx Computer", "artifact")
_WKS05 = [
    ("WKS05", "SYSTEM", "artifact"),
    ("WKS05", "Security.evtx Computer", "artifact"),
]
OTHER_MACHINES_NAMES = {
    # a workstation whose hive and log name it, holding DC01's forwarded events
    "forwarded events on a workstation": [*_WKS05, _FORWARDED_DC01, _ARG_DC01],
    # a collector's folder: only DC01's forwarded events
    "a collector's folder": [_FORWARDED_DC01, _ARG_DC01],
    # a row's host column names DC01 in full; the hive names the unit WKS05
    "a host column the hive disagrees with": [
        *_WKS05, ("DC01.corp.example", "logons.csv host column", "artifact"), _ARG_DC01
    ],
}  # fmt: skip


@pytest.mark.parametrize("shape", OTHER_MACHINES_NAMES)
def test_confirm_all_never_takes_another_machines_name_as_the_arguments_evidence(
    case, client, shape
):
    _real_dc01(case)
    x = _named(case, "evidence/x", OTHER_MACHINES_NAMES[shape])
    _confirm_all(client)
    assert not _bound(case, x, "DC01")


@pytest.mark.parametrize("shape", OTHER_MACHINES_NAMES)
def test_a_list_never_takes_another_machines_name_as_the_arguments_evidence(
    case, client, shape
):
    dc = _real_dc01(case)
    x = _named(case, "evidence/x", OTHER_MACHINES_NAMES[shape])
    _decide(client, "list", {"text": "DC01.corp.example\nWKS05\n"})
    assert _bound(case, dc, "DC01.corp.example") and not _bound(case, x, "DC01")


def test_a_short_argument_agrees_with_the_full_name_in_a_host_column(case, client):
    x = _named(case, "evidence/by-host/rd01", [
        ("rd01", "hostname argument", "argument"),
        ("rd01.corp.example", "rd01-Arp.csv host column", "artifact"),
    ])  # fmt: skip
    assert _confirm_all(client)["confirmed"] == ["rd01.corp.example"]
    assert _bound(case, x, "rd01")


@pytest.mark.parametrize("build", ["Application.evtx Computer", "SYSTEM"])
def test_a_name_marked_not_a_host_never_outvotes_the_argument(case, client, build):
    x = _named(case, "evidence/by-host/rd01", [
        ("rd01", "hostname argument", "argument"),
        ("rd01.corp.example", "rd01-Arp.csv host column", "artifact"),
        ("BUILD", build, "artifact"),
    ])  # fmt: skip
    assert _decide(client, "not_a_host", {"pairs": [[x, "BUILD"]]}).status_code == 200
    assert _confirm_all(client)["confirmed"] == ["rd01.corp.example"]
    assert _bound(case, x, "rd01")
