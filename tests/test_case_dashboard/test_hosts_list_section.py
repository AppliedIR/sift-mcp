"""The Hosts tab's Host list section on the server: each list entry with the
machines that match it, paged and searched as the machines are, the
Overview's listed count, and the page revalidated after an update. Names are
synthetic (RFC 2606 domains)."""

from __future__ import annotations

import time

import case_dashboard.routes as D
import pytest
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


def folder(case, name, artifact_name=None):
    """A host folder `name` whose SYSTEM hive says `artifact_name` (default the same)."""
    u = hi.unit_key(f"evidence/{name}")
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": f"evidence/{name}"},
        {"kind": "name", "unit": u, "raw": name, "evidence": "folder name", "origin": "folder"},
        {"kind": "name", "unit": u, "raw": artifact_name or name, "evidence": "SYSTEM",
         "origin": "artifact"},
    ])  # fmt: skip
    return u


def upload(client, text):
    page = client.get("/api/hosts").json()
    resp = client.post("/api/hosts/decisions", json={
        "action": "list", "args": {"text": text}, "seen_offset": page["obs_offset"]})  # fmt: skip
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_no_list_has_no_rows(case, client):
    page = client.get("/api/hosts").json()
    assert page["listed"] == [] and page["listed_total"] == 0
    assert "listed_without_data" not in page


def test_each_entry_shows_its_machine_or_no_data(case, client):
    folder(case, "WKS01")
    upload(client, "name,fqdn\nWKS01\nDC01,dc01.corp.example.test\n")
    page = client.get("/api/hosts").json()
    assert page["listed"] == [
        {"name": "WKS01", "fqdn": "", "proposed": False,
         "machines": [{"canonical": "WKS01", "state": hi.CONFIRMED}]},
        {"name": "DC01", "fqdn": "dc01.corp.example.test", "proposed": False,
         "machines": []},
    ]  # fmt: skip
    assert page["listed_total"] == 2


def test_the_list_pages_with_the_tables_per_page(case, client):
    upload(client, "".join(f"WKS{i:03}\n" for i in range(45)))
    page = client.get("/api/hosts?per_page=20&listed_page=3").json()
    assert [r["name"] for r in page["listed"]] == [f"WKS{i:03}" for i in range(40, 45)]
    assert page["listed_total"] == 45 and page["listed_page"] == 3
    assert client.get("/api/hosts?per_page=20&listed_page=9").json()["listed"] == []


def test_a_listed_page_that_is_no_number_is_refused(case, client):
    resp = client.get("/api/hosts?listed_page=x")
    assert resp.status_code == 400
    assert resp.json() == {"error": "listed_page must be a number"}


def test_the_search_matches_a_name_an_fqdn_or_a_machine_it_shows(case, client):
    u = folder(case, "SRV05")
    hi.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": hi.new_machine_key(), "canonical": "Fileserver-Old",
         "pairs": [[u, "SRV05"]]}]}}, (case / hi.OBSERVATIONS).stat().st_size)  # fmt: skip
    upload(client, "name,fqdn\nSRV05\nDC01,dc01.corp.example.test\nWKS01\n")

    def names(q):
        page = client.get("/api/hosts", params={"q": q}).json()
        assert page["listed_total"] == len(page["listed"])
        return [r["name"] for r in page["listed"]]

    assert names("wks") == ["WKS01"]
    assert names("corp.example") == ["DC01"]
    assert names("FILESERVER") == ["SRV05"]  # the machine its evidence name is under
    assert names("nothing-like-it") == []


def test_the_summary_counts_the_listed_hosts(case, client):
    folder(case, "WKS01")
    upload(client, "WKS01\nDC01\nSRV05\n")
    assert client.get("/api/summary").json()["hosts"] == {"machines": 1, "listed": 3}


def test_a_thousand_entries_by_twenty_machines_answers_in_a_second(case, client):
    for i in range(20):
        folder(case, f"WKS{i:04}")
    upload(client, "".join(f"WKS{i:04}\n" for i in range(1000)))
    client.get("/api/hosts")  # the proposal cache, once per state of the logs
    t = time.perf_counter()
    page = client.get("/api/hosts", params={"q": "wks0"}).json()
    elapsed = time.perf_counter() - t
    assert page["listed_total"] == 1000 and len(page["listed"]) == page["per_page"]
    assert sum(bool(r["machines"]) for r in page["listed"]) == min(20, page["per_page"])
    assert elapsed < 1.0, elapsed


def test_the_portal_page_is_revalidated_on_every_load(case, client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-cache"
