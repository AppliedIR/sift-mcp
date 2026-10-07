"""The threat-intel backend's earlier name, opencti-mcp, stays a route to it.

A gateway configured with threatintel-mcp also serves /mcp/opencti-mcp: the
same backend, its tools and instructions, not a second backend. So the bare
tool names stay routable and the services list names the backend once. A
gateway with both names configured logs an error naming both.
"""

from __future__ import annotations

import json
import logging
from unittest.mock import patch

import pytest
from sift_common.instructions import OPENCTI
from sift_gateway.server import Gateway
from starlette.testclient import TestClient

from .conftest import MockBackend, make_tool

HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
TOOLS = {
    "threatintel-mcp": ["lookup_ioc", "search_threat_intel"],
    "opencti-mcp": ["lookup_ioc", "search_threat_intel"],
    "sift-mcp": ["run_command"],
}


def _gateway(*names: str) -> Gateway:
    config = {
        "gateway": {"host": "127.0.0.1", "port": 0},
        "api_keys": {},
        "backends": {name: {"type": "stdio", "command": "unused"} for name in names},
    }

    def create(name, backend_config):
        return MockBackend(
            name, backend_config, tools=[make_tool(t) for t in TOOLS[name]]
        )

    with patch("sift_gateway.server.create_backend", side_effect=create):
        return Gateway(config)


def _rpc(client, path, method, params=None, session=None, id_=1):
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if id_ is not None:
        body["id"] = id_
    headers = dict(HEADERS, **({"mcp-session-id": session} if session else {}))
    resp = client.post(path, json=body, headers=headers)
    assert resp.status_code in (200, 202), (path, resp.status_code, resp.text)
    if id_ is None:
        return resp, None
    text = resp.text
    if text.lstrip().startswith("{"):
        return resp, json.loads(text)
    data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    return resp, json.loads(data[-1])


def _session(client, path):
    """Initialize at `path`; returns (initialize result, tool names)."""
    resp, init = _rpc(
        client,
        path,
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"},
        },
    )
    session = resp.headers.get("mcp-session-id")
    _rpc(client, path, "notifications/initialized", session=session, id_=None)
    _, listed = _rpc(client, path, "tools/list", session=session, id_=2)
    return init["result"], sorted(t["name"] for t in listed["result"]["tools"])


def test_the_new_name_is_also_served_at_the_earlier_one():
    gw = _gateway("threatintel-mcp", "sift-mcp")
    with TestClient(gw.create_app()) as client:
        new_init, new_tools = _session(client, "/mcp/threatintel-mcp")
        old_init, old_tools = _session(client, "/mcp/opencti-mcp")
        services = client.get("/api/v1/services").json()["services"]
        tool_map = dict(gw._tool_map)
    assert new_tools == old_tools == ["lookup_ioc", "search_threat_intel"]
    assert new_init["instructions"] == old_init["instructions"] == OPENCTI
    assert old_init["serverInfo"]["name"] == "sift-gateway/threatintel-mcp"
    assert sorted(s["name"] for s in services) == ["sift-mcp", "threatintel-mcp"]
    assert tool_map["lookup_ioc"] == "threatintel-mcp"  # bare, not prefixed


@pytest.mark.parametrize("path", ["/mcp/opencti-mcp", "/mcp/opencti-mcp/"])
def test_the_earlier_name_reaches_the_backend_not_the_aggregate(path):
    gw = _gateway("threatintel-mcp", "sift-mcp")
    with TestClient(gw.create_app()) as client:
        _, tools = _session(client, path)
    assert "run_command" not in tools


def test_a_config_with_the_earlier_name_is_served_as_before():
    gw = _gateway("opencti-mcp", "sift-mcp")
    with TestClient(gw.create_app()) as client:
        _, tools = _session(client, "/mcp/opencti-mcp")
        services = client.get("/api/v1/services").json()["services"]
        tool_map = dict(gw._tool_map)
    assert tools == ["lookup_ioc", "search_threat_intel"]
    assert sorted(s["name"] for s in services) == ["opencti-mcp", "sift-mcp"]
    assert tool_map["lookup_ioc"] == "opencti-mcp"


def test_both_names_configured_is_logged_as_an_error(caplog):
    with caplog.at_level(logging.ERROR, logger="sift_gateway.server"):
        gw = _gateway("threatintel-mcp", "opencti-mcp")
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert any(
        "threatintel-mcp" in m and "opencti-mcp" in m and "lookup_ioc" in m
        for m in errors
    ), errors
    # each name stays its own backend's route
    with TestClient(gw.create_app()) as client:
        services = client.get("/api/v1/services").json()["services"]
        reached = {
            name: _session(client, f"/mcp/{name}")[0]["serverInfo"]["name"]
            for name in ("opencti-mcp", "threatintel-mcp")
        }
    assert reached == {
        "opencti-mcp": "sift-gateway/opencti-mcp",
        "threatintel-mcp": "sift-gateway/threatintel-mcp",
    }
    assert sorted(s["name"] for s in services) == ["opencti-mcp", "threatintel-mcp"]


def test_one_name_configured_logs_no_error(caplog):
    with caplog.at_level(logging.ERROR, logger="sift_gateway.server"):
        _gateway("threatintel-mcp", "sift-mcp")
        _gateway("opencti-mcp", "sift-mcp")
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
