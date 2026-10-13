"""Only the portal's one static asset skips the API key check, and the retired
legacy dashboard's paths only redirect to the Portal.

A portal API path ending in an asset suffix (.js, .png, ...) used to skip
authentication, so a request without a key could read a finding or drop a
pending review. Every /dashboard path, whatever the method and with or
without the key, answers 303 to the fixed /portal/ and runs no handler. The
real gateway app runs in-process; nothing binds a port and no backend starts.
"""

from __future__ import annotations

import json

import pytest
from sift_gateway.server import Gateway
from starlette.testclient import TestClient

KEY = "vhir_gw_" + "a" * 24
AUTH = {"Authorization": f"Bearer {KEY}"}


@pytest.fixture
def portal(tmp_path, monkeypatch):
    return _gateway(tmp_path, monkeypatch)


def _gateway(tmp_path, monkeypatch):
    case = tmp_path / "cases" / "C-portal"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: C-portal\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    app = Gateway(
        {
            "gateway": {"host": "127.0.0.1", "port": 0},
            "backends": {},
            "api_keys": {KEY: {"examiner": "alice", "role": "lead"}},
        }
    ).create_app()
    return case, TestClient(app)  # no `with`: the lifespan (backends) never runs


def _pending(case, *ids):
    items = [{"id": i, "type": "finding", "action": "reject"} for i in ids]
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-portal", "items": items})
    )


def _pending_ids(case):
    return [
        i["id"]
        for i in json.loads((case / "pending-reviews.json").read_text())["items"]
    ]


@pytest.mark.parametrize(
    "path, item",
    [
        (f"/portal/api/delta/X.{ext}", f"X.{ext}")
        for ext in ("png", "jpg", "svg", "ico", "css", "js")
    ]
    + [("/portal/api/delta/E%2Ejs", "E.js")],
)
def test_dropping_a_pending_review_needs_the_key_whatever_its_name_ends_in(
    portal, path, item
):
    case, client = portal
    _pending(case, item)
    assert client.delete(path).status_code == 401
    assert _pending_ids(case) == [item]


def test_dropping_a_pending_review_without_the_key_is_refused(portal):
    case, client = portal
    _pending(case, "X")
    assert client.delete("/portal/api/delta/X").status_code == 401
    assert _pending_ids(case) == ["X"]


@pytest.mark.parametrize(
    "path", ["/portal/api/findings/F-alice-001.js", "/portal/api/audit/F-alice-001.js"]
)
def test_reading_a_finding_whose_id_ends_in_an_asset_suffix_needs_the_key(portal, path):
    case, client = portal
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-alice-001.js", "title": "t"}])
    )
    r = client.get(path)
    assert r.status_code == 401
    assert "F-alice-001.js" not in r.text


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_the_portal_icon_loads_without_the_key(portal, method):
    _, client = portal
    r = client.request(method, "/portal/valhuntir-icon.png")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"


def test_the_portal_page_loads_without_the_key(portal):
    _, client = portal
    assert client.get("/portal/").status_code == 200


def test_any_other_asset_name_needs_the_key(portal):
    _, client = portal
    assert client.get("/portal/nonexistent.js").status_code == 401


RETIRED = ["/dashboard", "/dashboard/", "/dashboard/x.png", "/dashboard/api/findings",
           "/dashboard/api/delta/Q.js", "/dashboard/api/commit?next=https://evil.example/",
           "/dashboard//evil.example/", "/dashboard/%2e%2e/portal/api/findings"]  # fmt: skip


@pytest.mark.parametrize("path", RETIRED)
@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "DELETE"])
@pytest.mark.parametrize("key", [False, True], ids=["no key", "key"])
def test_every_retired_dashboard_path_redirects_to_the_fixed_portal_url(
    portal, path, method, key
):
    _, client = portal
    r = client.request(
        method, path, headers=AUTH if key else {}, follow_redirects=False
    )
    assert (r.status_code, r.headers.get("location")) == (303, "/portal/"), r.text
    assert "<html" not in r.text.lower()


def test_a_write_to_a_retired_dashboard_api_path_runs_no_handler(tmp_path, monkeypatch):
    from case_dashboard import routes, signing

    ran = []
    for name in ("post_commit_plan", "post_commit_key", "post_commit"):
        monkeypatch.setattr(signing, name, lambda request, _n=name: ran.append(_n))
    monkeypatch.setattr(
        routes, "delete_delta_item", lambda request: ran.append("delete")
    )
    case, client = _gateway(tmp_path, monkeypatch)
    _pending(case, "Q")
    for method, path in [("POST", "/dashboard/api/commit"), ("POST", "/dashboard/api/commit/plan"),
                         ("DELETE", "/dashboard/api/delta/Q")]:  # fmt: skip
        r = client.request(
            method, path, headers=AUTH, json={"x": 1}, follow_redirects=False
        )
        assert (r.status_code, r.headers.get("location")) == (303, "/portal/")
    assert ran == [] and _pending_ids(case) == ["Q"]


def test_the_api_works_with_the_key(portal):
    _, client = portal
    assert client.get("/portal/api/findings", headers=AUTH).status_code == 200
