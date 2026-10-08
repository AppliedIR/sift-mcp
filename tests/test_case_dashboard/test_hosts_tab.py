"""The Hosts tab's API: machines and pending host names from the host logs,
and the examiner's decisions on them.

A decision needs the examiner of the request and no password. It is written
with origin "portal" and the observation offset the page was built from, and
audited to the case's dashboard log. Names are synthetic (RFC 2606 domains).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import case_dashboard.routes as D
import pytest
from sift_common import host_gate as hg
from sift_common import host_identity as hi
from sift_common import host_proposal as hp
from starlette.testclient import TestClient


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


def unit(case, locator, *names):
    """A scanned unit whose SYSTEM hive names it `names`."""
    u = hi.unit_key(locator)
    recs = [{"kind": "unit", "unit": u, "locator": locator}]
    recs += [
        {
            "kind": "name",
            "unit": u,
            "raw": r,
            "evidence": "SYSTEM ComputerName",
            "origin": "artifact",
        }
        for r in names
    ]
    hi.append_observations(case, recs)
    return u


def folder(case, name):
    """A host folder `name` whose SYSTEM hive says the same name."""
    u = hi.unit_key(f"evidence/{name}")
    hi.append_observations(
        case,
        [
            {"kind": "unit", "unit": u, "locator": f"evidence/{name}"},
            {
                "kind": "name",
                "unit": u,
                "raw": name,
                "evidence": "folder name",
                "origin": "folder",
            },
            {
                "kind": "name",
                "unit": u,
                "raw": name,
                "evidence": "SYSTEM",
                "origin": "artifact",
            },
        ],
    )
    return u


def _decisions(case) -> list[dict]:
    text = (case / hi.DECISIONS).read_text()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _audit(case) -> list[dict]:
    path = case / "audit" / "case-dashboard.jsonl"
    return (
        [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
    )


def _decide(client, page, action, args):
    return client.post(
        "/api/hosts/decisions",
        json={"action": action, "args": args, "seen_offset": page["obs_offset"]},
    )


class TestDecisions:
    def test_a_confirmation_needs_no_challenge_and_is_audited_from_the_portal(
        self, case, client
    ):
        u = unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        (group,) = page["proposed"]
        resp = _decide(
            client, page, "confirm", {"groups": [{**group, "canonical": "WKS01"}]}
        )
        assert resp.status_code == 200, resp.text
        (rec,) = _decisions(case)
        assert (rec["action"], rec["examiner"], rec["origin"]) == (
            "confirm",
            "tester",
            "portal",
        )
        assert rec["offset"] == page["obs_offset"]
        (entry,) = _audit(case)
        assert (entry["tool"], entry["examiner"], entry["origin"]) == (
            "host_confirm",
            "tester",
            "portal",
        )
        state = hi.load(case)
        assert state.machine_of_pair(u, "WKS01").state == hi.CONFIRMED
        # Committing findings still needs the password challenge
        assert client.post("/api/commit", json={}).status_code >= 400

    def test_without_an_examiner_nothing_is_written(self, case, client, monkeypatch):
        unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        monkeypatch.delenv("VHIR_EXAMINER")
        resp = _decide(client, page, "confirm", {"groups": page["proposed"]})
        assert resp.status_code == 401
        assert _decisions(case) == [] and _audit(case) == []

    def test_a_page_from_after_the_log_s_end_is_refused(self, case, client):
        unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        page["obs_offset"] += 10_000
        resp = _decide(client, page, "confirm", {"groups": page["proposed"]})
        assert resp.status_code == 409
        assert "past the log's end" in resp.json()["error"]
        assert _decisions(case) == []

    @pytest.mark.parametrize("action", ["merge", "split", "rename", "nonsense"])
    def test_other_actions_are_refused(self, case, client, action):
        unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        assert _decide(client, page, action, {}).status_code == 400
        assert _decisions(case) == []

    def test_a_pair_the_case_never_saw_is_refused(self, case, client):
        unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        group = {"pairs": [["ffffffffffffffff", "WKS01"]], "canonical": "WKS01"}
        assert _decide(client, page, "confirm", {"groups": [group]}).status_code == 400
        assert _decisions(case) == []

    def test_a_machine_in_use_is_confirmed_under_its_own_name_only(self, case, client):
        u = unit(case, "evidence/WKS01", "WKS01")
        hi.get_or_mint(
            case, u, "WKS01", origin="artifact", evidence="x", canonical="WKS01"
        )
        page = client.get("/api/hosts").json()
        (m,) = page["machines"]
        assert m["state"] == hi.NEW
        renamed = {"machine": m["id"], "canonical": "OTHER"}
        assert (
            _decide(client, page, "confirm", {"groups": [renamed]}).status_code == 409
        )
        same = {"machine": m["id"], "canonical": "WKS01"}
        assert _decide(client, page, "confirm", {"groups": [same]}).status_code == 200
        assert hi.load(case).machines[m["id"]].state == hi.CONFIRMED

    def test_not_a_host_flags_the_name(self, case, client):
        u = unit(case, "evidence/WKS01", "WORKGROUP")
        page = client.get("/api/hosts").json()
        resp = _decide(client, page, "not_a_host", {"pairs": [[u, "WORKGROUP"]]})
        assert resp.status_code == 200
        assert hi.FLAG_NOT_A_HOST in hi.load(case).pair_flags[(u, "WORKGROUP")]

    def test_a_host_list_confirms_what_it_matches(self, case, client):
        folder(case, "WKS01")
        folder(case, "WKS02")
        page = client.get("/api/hosts").json()
        resp = _decide(client, page, "list", {"text": "WKS01\n"})
        assert resp.status_code == 200, resp.text
        after = client.get("/api/hosts").json()
        assert after["counts"]["confirmed"] == 1 and after["counts"]["proposed"] == 1
        assert (
            after["host_list"]["entries"] == 1
            and after["host_list"]["examiner"] == "tester"
        )
        assert [e["tool"] for e in _audit(case)] == ["host_list"]

    def test_confirm_all_proposed(self, case, client):
        for i in range(3):
            folder(case, f"WKS0{i}")
        page = client.get("/api/hosts").json()
        assert page["counts"]["proposed"] == 3
        assert (
            _decide(
                client, page, "confirm_all", {"seen_decisions": page["dec_offset"]}
            ).status_code
            == 200
        )
        after = client.get("/api/hosts").json()
        assert (after["counts"]["confirmed"], after["counts"]["proposed"]) == (3, 0)


class TestPivots:
    def test_a_host_text_naming_two_machines_is_marked_under_both(self, case, client):
        """Two units each call themselves DC01; the examiner keeps them apart."""
        a = unit(case, "evidence/site-a/DC01", "DC01")
        b = unit(case, "evidence/site-b/DC01", "DC01")
        page = client.get("/api/hosts").json()
        groups = [
            {"pairs": [[a, "DC01"]], "canonical": "DC01"},
            {"pairs": [[b, "DC01"]], "canonical": "DC01-B"},
        ]
        assert _decide(client, page, "confirm", {"groups": groups}).status_code == 200
        (case / "findings.json").write_text(
            json.dumps([{"id": "F-tester-001", "title": "Logon", "host": "DC01"}])
        )
        machines = {
            m["canonical"]: m for m in client.get("/api/hosts").json()["machines"]
        }
        assert machines["DC01"]["pivots"][0]["ambiguous_with"] == ["DC01-B"]
        assert machines["DC01-B"]["pivots"][0]["ambiguous_with"] == ["DC01"]

    def test_an_fqdn_and_a_former_name_pivot_to_the_machine(self, case, client):
        u = unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        assert (
            _decide(client, page, "confirm", {"groups": page["proposed"]}).status_code
            == 200
        )
        (case / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "F-tester-001",
                        "title": "x",
                        "host": "wks01.corp.example.test",
                    }
                ]
            )
        )
        (m,) = client.get("/api/hosts").json()["machines"]
        assert [(p["id"], p["ambiguous_with"]) for p in m["pivots"]] == [
            ("F-tester-001", [])
        ]
        assert m["query"] == 'host.id:"WKS01"'
        detail = client.get(f"/api/hosts/{m['id']}").json()
        assert [h["action"] for h in detail["history"]] == ["confirm"]
        assert u in detail["units"]


def test_five_thousand_machines_page_and_filter(case, client):
    recs, items = [], []
    for i in range(5000):
        u = hi.unit_key(f"evidence/H{i:04d}")
        recs += [
            {"kind": "unit", "unit": u, "locator": f"evidence/H{i:04d}"},
            {
                "kind": "name",
                "unit": u,
                "raw": f"H{i:04d}",
                "evidence": "e",
                "origin": "artifact",
            },
        ]
        items.append(
            {
                "key": hi.new_machine_key(),
                "canonical": f"H{i:04d}",
                "pairs": [[u, f"H{i:04d}"]],
            }
        )
    size = hi.append_observations(case, recs)
    hi.append_decision(
        case, {"action": "confirm", "examiner": "t", "args": {"machines": items}}, size
    )
    started = time.monotonic()
    page = client.get("/api/hosts?page=1").json()
    assert time.monotonic() - started < 10
    assert (page["total"], len(page["machines"]), page["counts"]["confirmed"]) == (
        5000,
        50,
        5000,
    )
    assert page["machines"][0]["canonical"] == "H0000"
    assert client.get("/api/hosts?state=new").json()["total"] == 0
    assert [
        m["canonical"] for m in client.get("/api/hosts?q=H4999").json()["machines"]
    ] == ["H4999"]
    assert (
        client.get("/api/hosts?page=100").json()["machines"][-1]["canonical"] == "H4999"
    )


class TestPendingRuns:
    def test_a_waiting_run_is_listed_and_start_now_releases_it(self, case, client):
        u = unit(case, "evidence/WKS01", "WKS01")
        hg.record_wait(case, "run-1", [u])
        runs = client.get("/api/hosts/runs").json()["runs"]
        assert [(r["run_id"], [w["raw"] for w in r["unresolved"]]) for r in runs] == [
            ("run-1", ["WKS01"])
        ]
        page = client.get("/api/hosts").json()
        resp = _decide(client, page, "start_now", {"run_id": "run-1"})
        assert resp.status_code == 200, resp.text
        assert client.get("/api/hosts/runs").json()["runs"] == []
        assert hi.load(case).machine_of_pair(u, "WKS01").state == hi.STARTED_NOW
        (entry,) = _audit(case)
        assert (entry["tool"], entry["origin"]) == ("host_start_now", "portal")

    def test_cancel_drops_the_run(self, case, client):
        u = unit(case, "evidence/WKS01", "WKS01")
        hg.record_wait(case, "run-1", [u])
        page = client.get("/api/hosts").json()
        assert (
            _decide(client, page, "cancel_run", {"run_id": "run-1"}).status_code == 200
        )
        assert client.get("/api/hosts/runs").json()["runs"] == []
        assert "run-1" in hi.load(case).cancelled

    @pytest.mark.parametrize("action", ["start_now", "cancel_run"])
    def test_a_run_that_isn_t_waiting_is_refused(self, case, client, action):
        unit(case, "evidence/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        resp = _decide(client, page, action, {"run_id": "no-such-run"})
        assert resp.status_code == 409
        assert _decisions(case) == [] and _audit(case) == []

    def test_a_case_without_a_host_list_is_encouraged_to_load_one(self, case, client):
        assert client.get("/api/hosts").json()["host_list_hint"] == hg.HOST_LIST_HINT


# The tab's rendering, run under node. textContent in, innerHTML out, as a
# browser escapes a text node: & < > only (not quotes).
PORTAL = (Path(D.__file__).parent / "static" / "v2" / "index.html").read_text()
_DOCUMENT = (
    "const document = {createElement: () => ({set textContent(s) {"
    "this.innerHTML = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')"
    ".replace(/>/g, '&gt;');}})};\n"
)
_EVIL = '<img src=x onerror=alert(1)>"\' onmouseover="alert(2)'


def _js_function(name: str) -> str:
    start = PORTAL.index(f"function {name}(")
    return PORTAL[start : PORTAL.index("\n}\n", start) + 3]


def _render(call: str, data) -> str:
    names = ["escapeHtml", "escapeAttr", "hostNamesHtml", "hostsHeaderHtml", "hostRunsHtml",
             "hostProposedHtml", "hostPivotsHtml", "hostRowsHtml", "hostDetailHtml"]  # fmt: skip
    script = (
        _DOCUMENT
        + "".join(_js_function(n) for n in names)
        + f"const data = {json.dumps(data)};\n"
        + f"process.stdout.write({call});"
    )
    return subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout


def _evil_name():
    return {"unit": "u1", "raw": _EVIL, "locator": _EVIL, "evidence": [_EVIL],
            "origins": ["artifact"], "flags": [_EVIL]}  # fmt: skip


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
class TestTheTabRendersCaseTextAsText:
    def _clean(self, out: str):
        # No case text opens a tag or lands inside one (a quote in text is harmless)
        assert "<img" not in out, out
        tags = re.sub(r'="[^"]*"', '=""', out)  # quoted attribute values are inert
        assert not re.search(r"<[^>]*(onerror|onmouseover)", tags), out
        assert "&lt;img src=x onerror=alert(1)&gt;" in out

    def test_machines_names_evidence_flags_and_pivots(self):
        machine = {
            "id": "m1", "canonical": _EVIL, "state": "new", "former": [_EVIL],
            "names": [_evil_name()], "units": ["u1"], "flags": [_EVIL], "query": _EVIL,
            "pivots": [{"kind": "finding", "id": _EVIL, "title": _EVIL, "ambiguous_with": [_EVIL]}],
        }  # fmt: skip
        self._clean(_render("hostRowsHtml(data)", [machine]))

    def test_proposed_groups_keep_the_quote_inside_the_input(self):
        group = {"pairs": [["u1", _EVIL]], "canonical": _EVIL, "names": [_evil_name()],
                 "flags": [_EVIL], "conflicts": [_EVIL]}  # fmt: skip
        out = _render("hostProposedHtml(data)", [group])
        self._clean(out)
        assert (
            'value="&lt;img src=x onerror=alert(1)&gt;&quot;&#39; onmouseover=&quot;alert(2)"'
            in out
        )

    def test_runs_header_and_history(self):
        runs = [
            {
                "run_id": _EVIL,
                "unresolved": [
                    {"unit": "u1", "locator": _EVIL, "raw": _EVIL, "reason": _EVIL}
                ],
            }
        ]
        self._clean(_render("hostRunsHtml(data)", runs))
        header = {"counts": {}, "host_list": {"entries": 1, "sha256": _EVIL, "examiner": _EVIL},
                  "listed_without_data": [_EVIL]}  # fmt: skip
        self._clean(_render("hostsHeaderHtml(data)", header))
        detail = {
            "canonical": _EVIL,
            "history": [
                {"t": _EVIL, "examiner": _EVIL, "origin": _EVIL, "action": _EVIL}
            ],
        }
        self._clean(_render("hostDetailHtml(data)", detail))

    def test_the_ambiguity_marker_is_shown(self):
        machine = {"canonical": "DC01", "query": 'host.id:"DC01"',
                   "pivots": [{"kind": "finding", "id": "F-1", "title": "Logon", "ambiguous_with": ["DC01-B"]}]}  # fmt: skip
        assert "ambiguous: also matches DC01-B" in _render(
            "hostPivotsHtml(data)", machine
        )


class TestAMachineInUseKeepsItsName:
    def _in_use(self, case, name="WKS01"):
        u = unit(case, f"evidence/{name}", name)
        hi.get_or_mint(case, u, name, origin="artifact", evidence="x", canonical=name)
        return u

    def test_a_confirmation_through_its_pairs_can_t_rename_it(self, case, client):
        """A page that still shows the name as proposed, sent after ingest bound it."""
        u = self._in_use(case)
        page = client.get("/api/hosts").json()
        group = {"pairs": [[u, "WKS01"]], "canonical": "EVIL"}
        resp = _decide(client, page, "confirm", {"groups": [group]})
        assert resp.status_code == 409
        assert "done with rename" in resp.json()["error"]
        (m,) = hi.load(case).machines.values()
        assert (m.canonical, m.former) == ("WKS01", [])
        assert _decisions(case) == []

    def test_names_of_two_machines_are_a_merge_not_a_confirmation(self, case, client):
        a = self._in_use(case, "WKS01")
        b = self._in_use(case, "WKS02")
        page = client.get("/api/hosts").json()
        group = {"pairs": [[a, "WKS01"], [b, "WKS02"]], "canonical": "WKS01"}
        resp = _decide(client, page, "confirm", {"groups": [group]})
        assert resp.status_code == 409 and "merge" in resp.json()["error"]
        assert len(hi.load(case).machines) == 2

    def test_a_group_that_joins_a_machine_is_shown_and_confirmed_under_it(
        self, case, client
    ):
        self._in_use(case, "WKS01")
        b = unit(case, "evidence/again/WKS01", "WKS01")
        page = client.get("/api/hosts").json()
        joining = [g for g in page["proposed"] if g["joins"]]
        assert [g["joins"] for g in joining] == ["WKS01"], page["proposed"]
        (g,) = joining
        sent = {"pairs": g["pairs"], "machine": g["machine"], "canonical": g["joins"]}
        assert _decide(client, page, "confirm", {"groups": [sent]}).status_code == 200
        state = hi.load(case)
        assert state.machine_of_pair(b, "WKS01").id == g["machine"]
        assert len(state.machines) == 1


def test_a_former_name_pivots_to_the_machine(case, client):
    """Named FIRST at confirmation, then renamed: a finding that still says
    FIRST (neither the raw name nor the current one) pivots to it."""
    u = unit(case, "evidence/WKS-RAW", "WKS-RAW")
    page = client.get("/api/hosts").json()
    (g,) = page["proposed"]
    first = {"pairs": g["pairs"], "canonical": "FIRST"}
    assert _decide(client, page, "confirm", {"groups": [first]}).status_code == 200
    (m,) = hi.load(case).machines.values()
    size = (case / hi.OBSERVATIONS).stat().st_size
    rename = {"machine": m.keys[0], "canonical": "SECOND"}
    # A rename is R's (the host operation); written here as R writes it
    hi.append_decision(
        case, {"action": "rename", "examiner": "t", "args": rename}, size, door="R"
    )
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-tester-001", "title": "x", "host": "FIRST"}])
    )
    (row,) = client.get("/api/hosts").json()["machines"]
    assert (row["canonical"], row["former"]) == ("SECOND", ["FIRST"])
    assert [p["id"] for p in row["pivots"]] == ["F-tester-001"]
    assert u in row["units"]


def test_a_page_holds_at_most_200_machines(case, client):
    recs, items = [], []
    for i in range(250):
        u = hi.unit_key(f"evidence/P{i:03d}")
        recs += [
            {"kind": "unit", "unit": u, "locator": f"evidence/P{i:03d}"},
            {
                "kind": "name",
                "unit": u,
                "raw": f"P{i:03d}",
                "evidence": "e",
                "origin": "artifact",
            },
        ]
        items.append(
            {
                "key": hi.new_machine_key(),
                "canonical": f"P{i:03d}",
                "pairs": [[u, f"P{i:03d}"]],
            }
        )
    size = hi.append_observations(case, recs)
    hi.append_decision(
        case, {"action": "confirm", "examiner": "t", "args": {"machines": items}}, size
    )
    page = client.get("/api/hosts?per_page=1000").json()
    assert (page["per_page"], len(page["machines"]), page["total"]) == (200, 200, 250)


class TestStartNowAndProposals:
    def test_a_unit_whose_only_name_isn_t_a_host_starts_under_its_placeholder(
        self, case, client
    ):
        u = unit(case, "evidence/disk1", "WORKGROUP")
        page = client.get("/api/hosts").json()
        assert (
            _decide(
                client, page, "not_a_host", {"pairs": [[u, "WORKGROUP"]]}
            ).status_code
            == 200
        )
        hg.record_wait(case, "run-1", [u])
        (run,) = client.get("/api/hosts/runs").json()["runs"]
        assert [w["reason"] for w in run["unresolved"]] == [hg.REASON_NEEDS_NAME]
        page = client.get("/api/hosts").json()
        assert (
            _decide(client, page, "start_now", {"run_id": "run-1"}).status_code == 200
        )
        (m,) = client.get("/api/hosts").json()["machines"]
        assert m["state"] == hi.STARTED_NOW
        assert m["canonical"] == hg.placeholder_name("evidence/disk1")
        assert "WORKGROUP" not in [m["canonical"], *m["former"]]

    def test_start_now_records_the_page_s_offset(self, case, client):
        u = unit(case, "evidence/WKS01", "WKS01")
        hg.record_wait(case, "run-1", [u])
        page = client.get("/api/hosts").json()
        unit(case, "evidence/LATER", "LATER")  # the log grows after the page
        assert (
            _decide(client, page, "start_now", {"run_id": "run-1"}).status_code == 200
        )
        (rec,) = [r for r in _decisions(case) if r["action"] == "start_now"]
        assert rec["offset"] == page["obs_offset"]

    def test_proposals_are_worked_out_once_per_state_of_the_logs(
        self, case, client, monkeypatch
    ):
        unit(case, "evidence/WKS01", "WKS01")
        calls = []
        real = hp.propose
        monkeypatch.setattr(hp, "propose", lambda state: calls.append(1) or real(state))
        hp._proposals.clear()
        client.get("/api/hosts")
        client.get("/api/hosts?page=1")
        assert len(calls) == 1
        unit(case, "evidence/WKS02", "WKS02")
        client.get("/api/hosts")
        assert len(calls) == 2

    def test_the_proposed_names_are_paged(self, case, client):
        recs = []
        for i in range(60):
            u = hi.unit_key(f"evidence/Q{i:02d}")
            recs += [
                {"kind": "unit", "unit": u, "locator": f"evidence/Q{i:02d}"},
                {
                    "kind": "name",
                    "unit": u,
                    "raw": f"Q{i:02d}",
                    "evidence": "e",
                    "origin": "artifact",
                },
            ]
        hi.append_observations(case, recs)
        first = client.get("/api/hosts").json()
        assert (len(first["proposed"]), first["proposed_total"]) == (50, 60)
        second = client.get("/api/hosts?proposed_page=2").json()
        assert len(second["proposed"]) == 10


def _confirm_all(client, page):
    return _decide(client, page, "confirm_all", {"seen_decisions": page["dec_offset"]})


class TestConfirmAllIsPerItem:
    """Confirm all confirms the page's proposals, each on its own: one that
    can't be confirmed is skipped and reported, and the rest go ahead."""

    def test_a_name_bound_since_the_page_is_skipped_and_the_rest_confirmed(
        self, case, client
    ):
        a = folder(case, "WKS01")
        folder(case, "WKS02")
        page = client.get("/api/hosts").json()
        hi.get_or_mint(
            case, a, "WKS01", origin="artifact", evidence="x", canonical="WKS01"
        )
        resp = _confirm_all(client, page)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["confirmed"] == ["WKS02"]
        assert [(s["canonical"], s["reason"]) for s in body["skipped"]] == [
            ("WKS01", "changed since the page")
        ]

    def test_a_name_that_arrived_after_the_page_isn_t_included(self, case, client):
        folder(case, "WKS01")
        page = client.get("/api/hosts").json()
        late = folder(case, "LATE")
        body = _confirm_all(client, page).json()
        assert body["confirmed"] == ["WKS01"]
        assert hi.load(case).machine_of_pair(late, "LATE") is None

    def test_a_name_the_ai_gave_is_skipped(self, case, client):
        u = hi.unit_key("evidence/mem.raw")
        hi.append_observations(
            case,
            [
                {"kind": "unit", "unit": u, "locator": "evidence/mem.raw"},
                {
                    "kind": "name",
                    "unit": u,
                    "raw": "GUESS",
                    "evidence": "x",
                    "origin": "argument",
                },
            ],
        )
        folder(case, "WKS01")
        page = client.get("/api/hosts").json()
        body = _confirm_all(client, page).json()
        assert body["confirmed"] == ["WKS01"]
        (skip,) = body["skipped"]
        assert skip["canonical"] == "GUESS"

    def test_a_flagged_group_read_from_evidence_is_skipped(self, case, client):
        unit(case, "evidence/WKS01", "WKS01")  # one hive name: thin evidence
        folder(case, "WKS02")
        page = client.get("/api/hosts").json()
        body = _confirm_all(client, page).json()
        assert body["confirmed"] == ["WKS02"]
        (skip,) = body["skipped"]
        assert skip["canonical"] == "WKS01"
        assert skip["reason"].startswith("needs the examiner: thin evidence")

    def test_an_unflagged_group_with_a_name_the_ai_gave_is_skipped(self, case, client):
        u = hi.unit_key("evidence/WKS03")
        hi.append_observations(
            case,
            [
                {"kind": "unit", "unit": u, "locator": "evidence/WKS03"},
                {"kind": "name", "unit": u, "raw": "WKS03", "evidence": "folder name",
                 "origin": "folder"},
                {"kind": "name", "unit": u, "raw": "WKS03", "evidence": "x",
                 "origin": "argument"},
            ],
        )  # fmt: skip
        folder(case, "WKS02")
        page = client.get("/api/hosts").json()
        (group,) = (g for g in page["proposed"] if g["canonical"] == "WKS03")
        assert not group["flags"]  # skipped for its origin, not a flag
        body = _confirm_all(client, page).json()
        assert body["confirmed"] == ["WKS02"]
        assert [(s["canonical"], s["reason"]) for s in body["skipped"]] == [
            ("WKS03", "not every name was read from evidence")
        ]

    def test_without_the_page_s_decision_offset_nothing_is_written(self, case, client):
        folder(case, "WKS01")
        page = client.get("/api/hosts").json()
        assert _decide(client, page, "confirm_all", {}).status_code == 400
        assert _decisions(case) == []


def test_one_confirmation_with_a_name_in_two_groups_is_refused_whole(case, client):
    u = unit(case, "evidence/WKS01", "WKS01")
    unit(case, "evidence/WKS02", "WKS02")
    page = client.get("/api/hosts").json()
    groups = [
        {"pairs": [[u, "WKS01"]], "canonical": "WKS01"},
        {"pairs": [[u, "WKS01"]], "canonical": "OTHER"},
    ]
    resp = _decide(client, page, "confirm", {"groups": groups})
    assert resp.status_code == 400 and "more than one group" in resp.json()["error"]
    assert _decisions(case) == []


class TestTheGuardsRefusalsAreReported:
    def test_confirm_all_reports_an_item_the_guard_refuses(
        self, case, client, monkeypatch
    ):
        folder(case, "WKS01")
        folder(case, "WKS02")
        page = client.get("/api/hosts").json()
        sent = {}

        def guard(case_dir, record, seen_offset, door="portal"):
            sent.update(record=record, door=door)
            return {
                "size": 0,
                "appended": 1,
                "refused": [{"index": 0, "reason": "two machine ids"}],
            }

        monkeypatch.setattr(hi, "append_decision_items", guard)
        body = _confirm_all(client, page).json()
        assert sent["record"]["args"]["proposed"] is True and sent["door"] == "portal"
        first, second = (i["canonical"] for i in sent["record"]["args"]["machines"])
        assert [(x["canonical"], x["reason"]) for x in body["skipped"]] == [
            (first, "two machine ids")
        ]
        assert body["confirmed"] == [second]

    def test_confirm_all_reports_a_unit_flagged_since_the_page(self, case, client):
        """The real guard: a near spelling noted after the page flags the unit
        now, so its group is skipped with the guard's reason, and the rest go."""
        a = folder(case, "WKS01")
        folder(case, "WKS02")
        page = client.get("/api/hosts").json()
        assert not any(g["flags"] for g in page["proposed"])
        hi.append_observations(
            case, [{"kind": "hint", "unit": a, "raw": "WKS01", "near": "WKS07"}]
        )
        body = _confirm_all(client, page).json()
        assert body["confirmed"] == ["WKS02"]
        assert [(s["canonical"], s["reason"]) for s in body["skipped"]] == [
            ("WKS01", "the unit is flagged now (a near spelling); the examiner decides")
        ]
        assert hi.load(case).machine_of_pair(a, "WKS01") is None

    def test_start_now_reports_what_the_guard_refused(self, case, client, monkeypatch):
        u = unit(case, "evidence/WKS01", "WKS01")
        hg.record_wait(case, "run-1", [u])
        page = client.get("/api/hosts").json()
        monkeypatch.setattr(
            hg,
            "start_now",
            lambda *a, **k: {
                "run_id": "run-1",
                "machines": [],
                "refused": [
                    {
                        "index": 0,
                        "reason": "not its unit's machine",
                        "machine": {"canonical": "WKS01"},
                    }
                ],
            },
        )
        body = _decide(client, page, "start_now", {"run_id": "run-1"}).json()
        assert body["summary"] == "0 started now for run run-1, 1 refused"
        assert body["skipped"] == [
            {"canonical": "WKS01", "reason": "not its unit's machine"}
        ]
