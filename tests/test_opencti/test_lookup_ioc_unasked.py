"""lookup_ioc never answers NO_MATCH when a provider couldn't be asked.

A lookup that couldn't ask is UNAVAILABLE with the reason, `found: false` and a
`note`, which callers that predate `outcome` already treat as unconfirmed. A
reachable server that has no match answers NO_MATCH with no note. The backend
asks again on every lookup, so one started while OpenCTI was down answers once
it is back, without a restart.
"""

from __future__ import annotations

import httpx
import pytest
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.errors import OpenCTIMCPError
from opencti_mcp.server import OpenCTIMCPServer

from .threatintel_rig import IP, NEIGHBOUR, REPLIES, config, lookup, recorded, server


def _reply(status, body=None, text=None):
    if text is not None:
        return lambda q, v: httpx.Response(status, text=text)
    return lambda q, v: httpx.Response(status, json=body)


@pytest.mark.parametrize(
    "route, reason",
    [
        (lambda q, v: httpx.ConnectError("Connection refused"), "can't reach OpenCTI"),
        (lambda q, v: httpx.ConnectTimeout("connect timed out"), "timed out"),
        (lambda q, v: httpx.ReadTimeout("read timed out"), "timed out"),
        (lambda q, v: REPLIES["v6:auth_required"], "AUTH_REQUIRED"),
        (lambda q, v: REPLIES["v7:auth_required"], "AUTH_REQUIRED"),
        (lambda q, v: REPLIES["v6:validation_error"], "x_opencti_no_such_field"),
        (lambda q, v: REPLIES["v7:validation_error"], "x_opencti_no_such_field"),
        (lambda q, v: REPLIES["v6:database_error"], "provider storage error"),
        (_reply(500, {"errors": [{"message": "boom"}]}), "HTTP 500"),
        (_reply(200, text="<html>proxy error</html>"), "not JSON"),
        (lambda q, v: {"data": None}, "no data"),
        (lambda q, v: [], "unexpected shape"),
        (lambda q, v: {"data": {"about": {"version": "6.9.10"}}}, "unexpected shape"),
        (lambda q, v: {"data": {"indicators": {"edges": [None]}}}, "unexpected shape"),
    ],
    ids=[
        "unreachable",
        "connect timeout",
        "read timeout",
        "bad token 6",
        "bad token 7",
        "field not in schema 6",
        "field not in schema 7",
        "storage down",
        "http 500",
        "not json",
        "null data",
        "not an object",
        "no indicators",
        "null edge",
    ],
)
async def test_a_lookup_that_couldnt_ask_is_unavailable_with_the_reason(
    provider_transport, route, reason
):
    provider_transport(route)
    resp = await lookup(server(), IP)
    block = resp["providers"]["opencti"]
    assert block["outcome"] == resp["outcome"] == "UNAVAILABLE"
    assert reason in block["reason"], block
    assert block["matches"] == []
    assert resp["found"] is False
    assert "note" in resp and reason in resp["reason"]


async def test_storage_down_keeps_the_version_it_reported(provider_transport):
    provider_transport(lambda q, v: REPLIES["v6:database_error"])
    block = (await lookup(server(), IP))["providers"]["opencti"]
    assert block["version"] == "6.9.10"


async def test_a_failure_after_a_good_lookup_is_unavailable(provider_transport):
    srv = server()
    provider_transport(recorded("6"))
    assert (await lookup(srv, IP))["outcome"] == "MATCH"
    provider_transport(lambda q, v: httpx.ReadTimeout("read timed out"))
    assert (await lookup(srv, IP))["outcome"] == "UNAVAILABLE"


async def test_a_reachable_server_without_a_match_says_no_match(provider_transport):
    provider_transport(recorded("6"))
    resp = await lookup(server(), NEIGHBOUR)
    assert resp["outcome"] == "NO_MATCH" and resp["found"] is False
    assert "note" not in resp and "error" not in resp


async def test_a_backend_started_while_opencti_was_down_answers_once_it_is_up(
    provider_transport,
):
    client = OpenCTIClient(config())
    client._degraded = True  # the startup probe failed
    client._degraded_reason = "server unreachable within 10s: ConnectTimeout"
    srv = OpenCTIMCPServer(config(), client=client, provider_names=["opencti"])
    provider_transport(lambda q, v: httpx.ConnectError("Connection refused"))
    assert (await lookup(srv, IP))["outcome"] == "UNAVAILABLE"
    provider_transport(recorded("6"))
    assert (await lookup(srv, IP))["outcome"] == "MATCH"


async def test_every_lookup_asks_again(provider_transport):
    t = provider_transport(recorded("6"))
    srv = server()
    await lookup(srv, NEIGHBOUR)
    await lookup(srv, NEIGHBOUR)
    assert len(t.lookups()) == 2


async def test_another_tool_on_a_degraded_start_still_raises_a_query_error():
    client = OpenCTIClient(config())
    client._degraded = True
    client._degraded_reason = "server unreachable within 10s: ConnectTimeout"
    srv = OpenCTIMCPServer(config(), client=client, provider_names=["opencti"])
    try:
        resp = await srv._dispatch_tool("search_threat_intel", {"query": "example"})
    except OpenCTIMCPError as e:
        resp = {"error": type(e).__name__.lower(), "message": e.safe_message}
    assert resp["error"] == "queryerror", resp
