"""Only the gateway owner may mint a join code.

`vhir setup join-code` runs on the SIFT box with the owner's key, the first
api_keys entry; joiners' keys are appended after it. A joined examiner's key
must not mint a code: redeemed as a wintools join, that code would replace the
gateway's wintools backend. Every row goes through the real REST routes and
AuthMiddleware, with a scratch HOME and synthetic keys.
"""

from __future__ import annotations

import pytest
import sift_gateway.join as join_mod
import yaml
from starlette.applications import Starlette
from starlette.testclient import TestClient

OWNER = "vhir_gw_" + "a" * 24
EXAMINER = "vhir_gw_" + "b" * 24
WINTOOLS_TOKEN = "vhir_wt_" + "c" * 24
CERT = "-----BEGIN CERTIFICATE-----\nMIIBsyntheticAAAA\n-----END CERTIFICATE-----\n"
WINTOOLS_URL = "https://192.0.2.10:4624/mcp"
OTHER_URL = "http://203.0.113.66:4624/mcp"


class _Gateway:
    def __init__(self, cfg):
        self.config = cfg
        self._api_keys = cfg.get("api_keys", {})
        self._pending_backends = {}
        self.backends = {}

        class _Event:
            def set(self):
                pass

        self._reload_event = _Event()


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    """A gateway.yaml in a scratch HOME, and a client over the real routes."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(join_mod, "_STATE_FILE", tmp_path / ".join_state.json")
    monkeypatch.setattr(join_mod, "_STATE_DIR", tmp_path)
    join_mod._join_failures.clear()
    vhir = tmp_path / ".vhir"

    def make(api_keys, wintools=True):
        (vhir / "tls").mkdir(parents=True)
        cfg = {"gateway": {"host": "127.0.0.1", "port": 4508}, "backends": {}}
        if api_keys is not None:
            cfg["api_keys"] = api_keys
        if wintools:
            (vhir / "tls" / "wintools-cert.pem").write_text(CERT)
            cfg["backends"]["wintools-mcp"] = {
                "type": "http",
                "url": WINTOOLS_URL,
                "bearer_token": WINTOOLS_TOKEN,
                "tls_cert": str(vhir / "tls" / "wintools-cert.pem"),
                "enabled": True,
            }
        (vhir / "gateway.yaml").write_text(yaml.dump(cfg, sort_keys=False))

        import sift_gateway.rest as rest
        from sift_gateway.auth import AuthMiddleware

        gw = _Gateway(cfg)
        app = Starlette(routes=rest.rest_routes())
        app.state.gateway = gw
        app.add_middleware(AuthMiddleware, api_keys=gw._api_keys)
        return TestClient(app), gw

    def wintools():
        cfg = yaml.safe_load((vhir / "gateway.yaml").read_text()) or {}
        return cfg.get("backends", {}).get("wintools-mcp")

    def api_keys():
        return (yaml.safe_load((vhir / "gateway.yaml").read_text()) or {}).get(
            "api_keys", {}
        )

    make.wintools, make.api_keys = wintools, api_keys
    return make


TWO_KEYS = {
    OWNER: {"examiner": "owner", "role": "lead"},
    EXAMINER: {"examiner": "laptop1", "role": "examiner"},
}


def _mint(client, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(
        "/api/v1/setup/join-code", headers=headers, json={"expires_hours": 2}
    )


def _wintools_join(client, code, url, token, cert=None):
    body = {
        "code": code,
        "machine_type": "wintools",
        "hostname": "WINBOX",
        "wintools_url": url,
        "wintools_token": token,
    }
    if cert:
        body["wintools_cert"] = cert
    return client.post("/api/v1/setup/join", json=body)


def test_a_joined_examiners_key_cannot_mint_a_join_code(gateway):
    client, _ = gateway(dict(TWO_KEYS))
    r = _mint(client, EXAMINER)
    assert r.status_code == 403
    assert r.json() == {"error": "Only the gateway owner can create join codes"}


def test_a_joined_examiner_cannot_repoint_the_wintools_backend(gateway):
    client, gw = gateway(dict(TWO_KEYS))
    before = gateway.wintools()
    r = _mint(client, EXAMINER)
    if r.status_code == 200:
        _wintools_join(client, r.json()["code"], OTHER_URL, "other")
    assert gateway.wintools() == before
    assert "wintools-mcp" not in gw._pending_backends


def test_the_owner_mints_and_an_examiner_joins(gateway):
    client, _ = gateway(dict(TWO_KEYS))
    r = _mint(client, OWNER)
    assert r.status_code == 200
    joined = client.post(
        "/api/v1/setup/join",
        json={
            "code": r.json()["code"],
            "machine_type": "examiner",
            "hostname": "laptop2",
        },
    )
    assert joined.status_code == 200
    token = joined.json()["gateway_token"]
    assert gateway.api_keys()[token] == {"examiner": "laptop2", "role": "examiner"}
    assert list(gateway.api_keys())[0] == OWNER
    ok = client.get("/api/v1/backends", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200


@pytest.mark.parametrize(
    "existing, url, cert",
    [
        (False, "https://192.0.2.11:4624/mcp", CERT),
        (True, "https://192.0.2.11:4624/mcp", CERT),
        (True, "http://192.0.2.11:4624/mcp", None),
    ],
    ids=["first join", "re-join", "re-join over http without a cert"],
)
def test_the_owner_mints_and_a_wintools_host_joins(gateway, existing, url, cert):
    client, gw = gateway(dict(TWO_KEYS), wintools=existing)
    r = _mint(client, OWNER)
    assert r.status_code == 200
    token = "vhir_wt_" + "d" * 24
    joined = _wintools_join(client, r.json()["code"], url, token, cert)
    assert joined.status_code == 200
    after = gateway.wintools()
    assert after["url"] == url and after["bearer_token"] == token
    assert bool(after.get("tls_cert")) == bool(cert)
    assert gw._pending_backends["wintools-mcp"]["url"] == url


def test_single_user_mode_mints_without_a_key(gateway):
    client, _ = gateway(None)
    assert _mint(client, None).status_code == 200


def test_an_owner_key_without_a_role_mints(gateway):
    keys = {
        OWNER: {"examiner": "owner"},
        EXAMINER: {"examiner": "laptop1", "role": "examiner"},
    }
    client, _ = gateway(keys)
    assert _mint(client, OWNER).status_code == 200
    assert _mint(client, EXAMINER).status_code == 403
