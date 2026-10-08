"""A join gets an examiner name the portal and `vhir enrol` accept.

The gateway named a joined token after the machine's host name as sent, so a
LAN examiner's name could fail the name rule, or collide with the box
owner's. A join now normalises the name (or the one chosen with
`vhir join --name`), refuses a name a token or an enrolled credential holds,
and returns the exact `vhir enrol --name` line. A code the owner binds to a
name (`vhir setup join-code --name NAME`) joins as that name and ends its
earlier tokens. Every row goes through the real routes and AuthMiddleware.
"""

from __future__ import annotations

import json

import pytest
import sift_gateway.join as join_mod
import sift_gateway.rest as rest
import yaml
from starlette.applications import Starlette
from starlette.testclient import TestClient

OWNER = "vhir_gw_" + "a" * 24
LAB2 = "vhir_gw_" + "b" * 24


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
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(join_mod, "_STATE_FILE", tmp_path / ".join_state.json")
    monkeypatch.setattr(join_mod, "_STATE_DIR", tmp_path)
    for name in ("passwords", "keys"):
        (tmp_path / name).mkdir()
    monkeypatch.setattr(rest, "_PASSWORDS_DIR", str(tmp_path / "passwords"))
    monkeypatch.setattr(rest, "_KEYS_DIR", str(tmp_path / "keys"))
    join_mod._join_failures.clear()
    vhir = tmp_path / ".vhir"
    vhir.mkdir()

    def make(api_keys):
        cfg = {"gateway": {"host": "127.0.0.1", "port": 4508}, "backends": {}}
        if api_keys is not None:
            cfg["api_keys"] = api_keys
        (vhir / "gateway.yaml").write_text(yaml.dump(cfg, sort_keys=False))
        from sift_gateway.auth import AuthMiddleware

        gw = _Gateway(cfg)
        app = Starlette(routes=rest.rest_routes())
        app.state.gateway = gw
        app.add_middleware(AuthMiddleware, api_keys=gw._api_keys)
        return TestClient(app), gw

    make.config = lambda: (vhir / "gateway.yaml").read_bytes()
    make.tokens = lambda: (
        yaml.safe_load((vhir / "gateway.yaml").read_text()) or {}
    ).get("api_keys", {})
    make.dir = tmp_path
    return make


KEYS = {OWNER: {"examiner": "steve", "role": "lead"}}


def _mint(client, name=None, token=OWNER):
    body = {"expires_hours": 2}
    if name is not None:
        body["name"] = name
    return client.post(
        "/api/v1/setup/join-code",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )


def _join(client, code, hostname="laptop", **extra):
    return client.post(
        "/api/v1/setup/join",
        json={"code": code, "machine_type": "examiner", "hostname": hostname, **extra},
    )


def test_a_host_name_is_normalised_and_the_enrol_line_returned(gateway):
    client, _ = gateway(dict(KEYS))
    r = _join(client, _mint(client).json()["code"], "Lab-Laptop.local")
    assert r.status_code == 200, r.text
    assert r.json()["examiner"] == "lab-laptop"
    assert r.json()["enrol_command"] == "vhir enrol --name lab-laptop"
    assert "lab-laptop" in [v["examiner"] for v in gateway.tokens().values()]


def test_a_chosen_name_is_used(gateway):
    client, _ = gateway(dict(KEYS))
    r = _join(client, _mint(client).json()["code"], "Lab-Laptop.local", name="lab2")
    assert r.json()["examiner"] == "lab2"


def test_a_name_with_nothing_usable_is_refused_and_the_code_kept(gateway):
    client, _ = gateway(dict(KEYS))
    code = _mint(client).json()["code"]
    r = _join(client, code, "___")
    assert r.status_code == 400 and "vhir join --name" in r.json()["error"]
    assert _join(client, code, "laptop").status_code == 200  # still usable


def test_a_host_that_becomes_the_owner_s_name_is_refused(gateway):
    client, _ = gateway(dict(KEYS))
    code = _mint(client).json()["code"]
    before = gateway.config()
    r = _join(client, code, "Steve.local")
    assert r.status_code == 409 and r.json()["code"] == "NAME_IN_USE"
    text = r.json()["error"]
    assert "vhir setup join-code --name steve" in text and "vhir join --name" in text
    assert gateway.config() == before
    assert _join(client, code, "Steve.local", name="lab2").json()["examiner"] == "lab2"


@pytest.mark.parametrize("folder", ["passwords", "keys"])
def test_an_enrolled_name_is_refused(gateway, folder):
    client, _ = gateway(dict(KEYS))
    (gateway.dir / folder / "lab2.json").write_text("{}")
    r = _join(client, _mint(client).json()["code"], "lab2")
    assert r.status_code == 409 and r.json()["code"] == "NAME_IN_USE"


def test_an_enrolled_lab2_rejoining_with_an_unbound_code_is_refused(gateway):
    client, _ = gateway({**KEYS, LAB2: {"examiner": "lab2", "role": "examiner"}})
    r = _join(client, _mint(client).json()["code"], "lab2")
    assert r.status_code == 409
    assert "vhir setup join-code --name lab2" in r.json()["error"]


def test_a_bound_code_rejoins_lab2_and_ends_its_earlier_token(gateway):
    client, gw = gateway({**KEYS, LAB2: {"examiner": "lab2", "role": "examiner"}})
    (gateway.dir / "keys" / "lab2.json").write_text('{"credential": "lab2"}')
    minted = _mint(client, name="lab2")
    assert minted.status_code == 200 and minted.json()["name"] == "lab2"
    r = _join(client, minted.json()["code"], "Other.Host", name="ignored")
    assert r.status_code == 200, r.text
    assert r.json()["examiner"] == "lab2" and r.json()["bound"] is True
    new = r.json()["gateway_token"]
    tokens = gateway.tokens()
    assert LAB2 not in tokens and new in tokens  # the file
    assert LAB2 not in gw._api_keys and new in gw._api_keys  # the running gateway
    old = client.get(
        "/api/v1/setup/join-status", headers={"Authorization": f"Bearer {LAB2}"}
    )
    assert old.status_code in (401, 403)
    assert (gateway.dir / "keys" / "lab2.json").read_text() == '{"credential": "lab2"}'


def test_a_code_bound_to_the_owner_s_name_is_refused(gateway):
    client, _ = gateway(dict(KEYS))
    r = _mint(client, name="steve")
    assert r.status_code == 400 and "box owner's name" in r.json()["error"]


@pytest.mark.parametrize("bad", ["Bad_Name", "", "x" * 21])
def test_a_code_bound_to_an_invalid_name_is_refused(gateway, bad):
    client, _ = gateway(dict(KEYS))
    assert _mint(client, name=bad).status_code == 400


def test_without_api_keys_no_bound_code_is_minted(gateway):
    client, _ = gateway(None)
    before = (gateway.dir / ".join_state.json").exists()
    r = client.post("/api/v1/setup/join-code", json={"name": "lab2"})
    assert r.status_code == 403 and r.json()["code"] == "NO_API_KEYS"
    assert (gateway.dir / ".join_state.json").exists() == before
    assert client.post("/api/v1/setup/join-code", json={}).status_code == 200


def test_a_stored_invalid_bound_name_refuses_the_join(gateway):
    client, _ = gateway(dict(KEYS))
    code = _mint(client, name="lab2").json()["code"]
    state = json.loads((gateway.dir / ".join_state.json").read_text())
    for entry in state["codes"].values():
        entry["bound_name"] = "Not A Name"
    (gateway.dir / ".join_state.json").write_text(json.dumps(state))
    before = gateway.config()
    r = _join(client, code, "laptop")
    assert r.status_code == 403
    assert gateway.config() == before  # no token, never the host name
    assert _join(client, code, "laptop").status_code == 403  # consumed


def test_a_wintools_join_skips_the_name_rules_and_makes_no_token(gateway):
    client, _ = gateway(dict(KEYS))
    before = gateway.config()
    r = client.post(
        "/api/v1/setup/join",
        json={"code": _mint(client).json()["code"], "machine_type": "wintools",
              "hostname": "steve"},
    )  # fmt: skip
    assert r.status_code == 200 and "gateway_token" not in r.json()
    assert gateway.config() == before


def test_a_bound_code_is_refused_for_a_wintools_join(gateway):
    client, _ = gateway(dict(KEYS))
    r = client.post(
        "/api/v1/setup/join",
        json={"code": _mint(client, name="lab2").json()["code"],
              "machine_type": "wintools", "hostname": "WINBOX"},
    )  # fmt: skip
    assert r.status_code == 403


def test_the_name_rule_is_vhir_s():
    identity = pytest.importorskip("vhir_cli.identity")
    for raw in ["Lab-Laptop.local", "STEVE", "a_b c", "-x", "..x", "é-host", "x" * 30,
                "lab2", "a\n", "9a"]:  # fmt: skip
        assert join_mod.join_name(raw) == identity.join_name(raw), raw
        assert join_mod.valid_name(raw) == identity.valid_name(raw), raw
