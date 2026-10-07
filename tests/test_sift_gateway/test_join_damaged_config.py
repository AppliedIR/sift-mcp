"""A join never rebuilds gateway.yaml from nothing.

Each join reads gateway.yaml, adds the new key or backend and writes it back.
A file it couldn't read or parse was treated as empty, so the write left only
the new entry: after a restart the joiner owned the gateway, or (for a
wintools join) auth was off. Such a join is now refused and the file is left
byte-identical. The routes are the real ones, over a scratch HOME.
"""

from __future__ import annotations

import os

import pytest
import sift_gateway.join as join_mod
import yaml
from starlette.applications import Starlette
from starlette.testclient import TestClient

OWNER = "vhir_gw_" + "a" * 24
GOOD = {
    "gateway": {"host": "127.0.0.1", "port": 4508},
    "api_keys": {OWNER: {"examiner": "owner", "role": "lead"}},
    "backends": {
        "opencti-mcp": {
            "type": "stdio",
            "command": "python",
            "env": {"OPENCTI_TOKEN": "${OPENCTI_TOKEN}"},
        }
    },
}


class _Gateway:
    def __init__(self, cfg):
        self.config = cfg
        self._api_keys = dict(cfg.get("api_keys", {}))
        self._pending_backends = {}
        self.backends = {}

        class _Event:
            def set(self):
                pass

        self._reload_event = _Event()


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    """Start from a valid gateway.yaml; the test then damages it on disk."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(join_mod, "_STATE_FILE", tmp_path / ".join_state.json")
    monkeypatch.setattr(join_mod, "_STATE_DIR", tmp_path)
    join_mod._join_failures.clear()
    (tmp_path / ".vhir").mkdir()
    path = tmp_path / ".vhir" / "gateway.yaml"
    path.write_text(yaml.dump(GOOD, sort_keys=False))

    import sift_gateway.rest as rest
    from sift_gateway.auth import AuthMiddleware

    gw = _Gateway(GOOD)
    app = Starlette(routes=rest.rest_routes())
    app.state.gateway = gw
    app.add_middleware(AuthMiddleware, api_keys=gw._api_keys)
    client = TestClient(app)
    code = client.post(
        "/api/v1/setup/join-code",
        headers={"Authorization": f"Bearer {OWNER}"},
        json={"expires_hours": 2},
    ).json()["code"]
    return client, gw, path, code


def _join(client, code, wintools=False):
    body = {"code": code, "machine_type": "examiner", "hostname": "laptop2"}
    if wintools:
        body = {
            "code": code,
            "machine_type": "wintools",
            "hostname": "WINBOX",
            "wintools_url": "https://192.0.2.10:4624/mcp",
            "wintools_token": "vhir_wt_" + "c" * 24,
        }
    return client.post("/api/v1/setup/join", json=body)


def _truncated() -> bytes:
    text = yaml.dump(GOOD, sort_keys=False, default_flow_style=None)
    text += "allowed: [127.0.0.1, 10.0.0.0/8]\n"
    return text[: text.index("[") + 6].encode()  # cut inside a flow list


@pytest.mark.parametrize("wintools", [False, True], ids=["examiner", "wintools"])
@pytest.mark.parametrize(
    "damage",
    ["truncated", "empty", "a dangling link"],
    ids=lambda d: d.replace(" ", "-"),
)
def test_a_join_over_a_damaged_config_is_refused_and_changes_nothing(
    gateway, damage, wintools
):
    client, gw, path, code = gateway
    if damage == "truncated":
        path.write_bytes(_truncated())
    elif damage == "empty":
        path.write_bytes(b"")
    else:
        path.unlink()
        path.symlink_to(path.parent / "gone.yaml")
    before = os.readlink(path) if path.is_symlink() else path.read_bytes()
    keys = dict(gw._api_keys)
    r = _join(client, code, wintools)
    assert r.status_code == 500
    assert "gateway.yaml" in r.text and "gateway_token" not in r.text
    after = os.readlink(path) if path.is_symlink() else path.read_bytes()
    assert after == before
    assert gw._api_keys == keys
    assert gw._pending_backends == {}


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a mode-000 file, so it can't be made unreadable",
)
def test_a_join_over_an_unreadable_config_is_refused_and_changes_nothing(gateway):
    client, gw, path, code = gateway
    before = path.read_bytes()
    path.chmod(0o000)
    try:
        r = _join(client, code)
        mode = path.stat().st_mode & 0o777
    finally:
        path.chmod(0o600)
    assert r.status_code == 500 and "gateway.yaml" in r.text
    assert mode == 0
    assert path.read_bytes() == before
    assert list(gw._api_keys) == [OWNER]


def test_a_join_over_a_config_that_is_a_list_is_refused(gateway):
    client, _, path, code = gateway
    path.write_text("- not\n- a mapping\n")
    r = _join(client, code)
    assert r.status_code == 500
    assert path.read_text() == "- not\n- a mapping\n"


def test_a_valid_config_keeps_everything_and_its_placeholders(gateway):
    client, _, path, code = gateway
    r = _join(client, code)
    assert r.status_code == 200
    cfg = yaml.safe_load(path.read_text())
    assert list(cfg["api_keys"])[0] == OWNER and len(cfg["api_keys"]) == 2
    assert cfg["gateway"] == GOOD["gateway"]
    assert cfg["backends"]["opencti-mcp"]["env"]["OPENCTI_TOKEN"] == "${OPENCTI_TOKEN}"


def test_an_absent_config_is_still_created(gateway):
    client, _, path, code = gateway
    path.unlink()
    r = _join(client, code)
    assert r.status_code == 200
    assert yaml.safe_load(path.read_text())["api_keys"]
