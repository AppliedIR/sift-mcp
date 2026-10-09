"""The threat-intel backend has one name on every install: a gateway.yaml
entry under its earlier name (`opencti-mcp`, an upgraded install) is loaded,
listed and routed as `threatintel-mcp`, in memory only, and both names keep
answering. gateway.yaml is never rewritten for it. The backend is a stand-in
that answers lookup_ioc; the config, routes and REST are the gateway's own."""

from __future__ import annotations

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock, MagicMock

import mcp.types as types
import pytest
import yaml
from mcp.types import CallToolResult, TextContent, Tool
from sift_gateway.config import load_config
from sift_gateway.mcp_endpoint import create_backend_mcp_server
from sift_gateway.rest import rest_routes, save_joined_backend
from sift_gateway.server import Gateway
from starlette.applications import Starlette
from starlette.testclient import TestClient

ENTRY = {"type": "http", "url": "http://127.0.0.1:9/mcp", "token": "x"}


@pytest.fixture
def yaml_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path / ".vhir" / "gateway.yaml"


def _write(path, name):
    path.write_text(
        yaml.safe_dump({"gateway": {}, "api_keys": {}, "backends": {name: ENTRY}})
    )


def _gateway(path) -> Gateway:
    gw = Gateway(load_config(str(path)))
    for b in gw.backends.values():
        b._started = True
        b._tools_cache = [Tool(name="lookup_ioc", inputSchema={})]
        b._session = MagicMock()
        b._session.send_ping = AsyncMock()
        b._session.call_tool = AsyncMock(return_value=CallToolResult(
            content=[TextContent(type="text", text=json.dumps({"found": False}))]))  # fmt: skip
        gw._tool_map = {"lookup_ioc": b.name}
    return gw


def _rest(gw) -> TestClient:
    app = Starlette(routes=rest_routes())
    app.state.gateway = gw
    return TestClient(app)


def _answers(gw, route: str) -> bool:
    server = create_backend_mcp_server(gw, route)
    req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="lookup_ioc", arguments={"ioc": "8.8.8.8"}
        ),
    )
    return not asyncio.run(
        server.request_handlers[types.CallToolRequest](req)
    ).root.isError


def _mounts(gw) -> set[str]:
    return {
        r.path
        for r in gw.create_app().routes
        if getattr(r, "path", "").startswith("/mcp/")
    }


def _sha(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_an_upgraded_config_is_listed_and_routed_under_the_one_name(yaml_path):
    _write(yaml_path, "opencti-mcp")
    before = _sha(yaml_path)
    gw = _gateway(yaml_path)
    assert list(gw.backends) == ["threatintel-mcp"]
    listed = [s["name"] for s in _rest(gw).get("/api/v1/services").json()["services"]]
    assert listed == ["threatintel-mcp"]
    assert {"/mcp/threatintel-mcp", "/mcp/opencti-mcp"} <= _mounts(gw)
    assert _answers(gw, "threatintel-mcp")
    assert _sha(yaml_path) == before  # started: never written


def test_reload_leaves_one_backend_and_the_file_untouched(yaml_path):
    _write(yaml_path, "opencti-mcp")
    before = _sha(yaml_path)
    gw = _gateway(yaml_path)
    out = _rest(gw).post("/api/v1/backends/reload").json()
    assert out["pending"] == [] and list(gw.backends) == ["threatintel-mcp"]
    assert _sha(yaml_path) == before


def test_a_join_keeps_the_earlier_entry_under_its_key_byte_for_byte(yaml_path):
    _write(yaml_path, "opencti-mcp")
    _gateway(yaml_path)
    save_joined_backend("wintools-mcp", {"type": "http", "url": "https://10.0.0.5:4624/mcp",
                                         "token": "t"})  # fmt: skip
    backends = yaml.safe_load(yaml_path.read_text())["backends"]
    assert sorted(backends) == ["opencti-mcp", "wintools-mcp"]
    assert backends["opencti-mcp"] == ENTRY  # never renamed on disk


@pytest.mark.parametrize("name", ["opencti-mcp", "threatintel-mcp"])
def test_start_stop_and_restart_take_either_name(yaml_path, name):
    _write(yaml_path, "opencti-mcp")
    gw = _gateway(yaml_path)
    c = _rest(gw)
    started = c.post(f"/api/v1/services/{name}/start").json()
    assert started == {"status": "already_running", "name": "threatintel-mcp"}
    assert c.post(f"/api/v1/services/{name}/restart").status_code != 404


def test_a_new_config_is_unchanged_anchor(yaml_path):
    _write(yaml_path, "threatintel-mcp")
    gw = _gateway(yaml_path)
    assert list(gw.backends) == ["threatintel-mcp"]
    assert {"/mcp/threatintel-mcp", "/mcp/opencti-mcp"} <= _mounts(gw)
    assert _answers(gw, "threatintel-mcp")


def test_both_names_configured_keep_todays_behaviour(yaml_path, caplog):
    yaml_path.write_text(yaml.safe_dump({"backends": {"opencti-mcp": ENTRY,
                                                      "threatintel-mcp": ENTRY}}))  # fmt: skip
    gw = Gateway(load_config(str(yaml_path)))
    assert sorted(gw.backends) == ["opencti-mcp", "threatintel-mcp"]
    assert "Both threatintel-mcp and opencti-mcp are configured" in caplog.text
