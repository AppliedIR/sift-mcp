"""The Hosts tab's API: machines and pending host names from the host logs,
and the examiner's decisions on them.

A decision needs the examiner of the request and no password. It is written
with origin "portal" and the observation offset the page was built from, and
audited to the case's dashboard log. Names are synthetic (RFC 2606 domains).
"""

from __future__ import annotations

import json
import time

import case_dashboard.routes as D
import pytest
from sift_common import host_gate as hg
from sift_common import host_identity as hi
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
            _decide(client, page, "confirm", {"groups": [renamed]}).status_code == 400
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
            unit(case, f"evidence/WKS0{i}", f"WKS0{i}")
        page = client.get("/api/hosts").json()
        assert page["counts"]["proposed"] == 3
        assert (
            _decide(client, page, "confirm", {"groups": page["proposed"]}).status_code
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
