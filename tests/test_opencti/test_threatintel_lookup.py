"""lookup_ioc asks each configured threat-intel provider and passes its records
through: every exact match with the platform's own fields, MATCH, NO_MATCH or
UNAVAILABLE per provider, and no verdict.

OpenCTI replies were recorded from 6.9.10 and 7.261002.0 instances seeded with
synthetic records; stubs stand in only for injected faults and for providers
that only a test knows. Nothing reaches a network.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types

import httpx
import opencti_mcp.providers.opencti as opencti_provider
import pytest
from mcp.types import ListToolsRequest
from opencti_mcp import providers
from opencti_mcp.errors import RateLimitError
from opencti_mcp.server import OpenCTIMCPServer

from .threatintel_rig import (
    IP,
    NEIGHBOUR,
    REPLIES,
    REVOKED,
    block,
    config,
    fake_provider,
    lookup,
    recorded,
    server,
)

RECORD_FIELDS = {
    "id",
    "name",
    "created",
    "revoked",
    "confidence",
    "x_opencti_score",
    "valid_from",
    "valid_until",
    "x_opencti_detection",
    "indicator_types",
    "objectLabel",
}

# --- OpenCTI's records, passed through -------------------------------------


@pytest.mark.parametrize("version", ["6", "7"])
async def test_every_exact_indicator_is_returned_with_its_validity(
    provider_transport, version
):
    provider_transport(recorded(version))
    resp = await lookup(server(), IP)
    answer = resp["providers"]["opencti"]
    assert resp["outcome"] == answer["outcome"] == "MATCH"
    assert len(answer["matches"]) == 3
    assert all(set(m) == RECORD_FIELDS for m in answer["matches"])
    assert sorted(m["revoked"] for m in answer["matches"]) == [False, True, True]
    assert answer["version"] == {"6": "6.9.10", "7": "7.261002.0"}[version]
    assert answer["queried_at"].endswith("+00:00")
    assert "verdict" not in json.dumps(resp).lower()


@pytest.mark.parametrize("version", ["6", "7"])
async def test_a_revoked_indicator_says_so(provider_transport, version):
    provider_transport(recorded(version))
    (record,) = (await lookup(server(), REVOKED))["providers"]["opencti"]["matches"]
    assert record["revoked"] is True
    assert record["valid_until"] == "2025-02-01T00:00:00.000Z"
    assert record["x_opencti_score"] == 100


@pytest.mark.parametrize("version", ["6", "7"])
async def test_lookups_answer_without_pycti(provider_transport, monkeypatch, version):
    monkeypatch.setitem(sys.modules, "pycti", None)  # `import pycti` fails
    provider_transport(recorded(version))
    assert (await lookup(server(), IP))["outcome"] == "MATCH"


def _many(count: int) -> dict:
    node = REPLIES["v6:lookup:ip3"]["data"]["indicators"]["edges"][0]["node"]
    edges = [{"node": {**node, "id": f"indicator--{i:04d}"}} for i in range(count)]
    return {
        "data": {
            "about": {"version": "6.9.10"},
            "indicators": {"pageInfo": {"globalCount": count}, "edges": edges},
        }
    }


def _route_many(count: int):
    return lambda q, v: (
        _many(count)
        if "Lookup" in q
        else {"data": {"stixCoreRelationships": {"edges": []}}}
    )


async def test_more_than_a_hundred_matches_are_capped_and_say_so(provider_transport):
    t = provider_transport(_route_many(101))
    answer = (await lookup(server(), IP))["providers"]["opencti"]
    assert len(answer["matches"]) == 100
    assert answer["truncated"] is True
    assert "101" in answer["note"]
    assert [r["variables"]["first"] for r in t.lookups()] == [101]  # one request


async def test_a_hundred_matches_are_not_marked_truncated(provider_transport):
    provider_transport(_route_many(100))
    answer = (await lookup(server(), IP))["providers"]["opencti"]
    assert len(answer["matches"]) == 100 and "truncated" not in answer


def test_opencti_requests_fit_the_lookup_budget():
    assert opencti_provider.create(config(timeout_seconds=60)).timeout == 12
    assert opencti_provider.create(config(timeout_seconds=5)).timeout == 5


async def test_a_request_is_given_only_the_time_left(provider_transport):
    t = provider_transport(recorded("6"))
    await lookup(server(), REVOKED)
    timeouts = [r["timeout"] for r in t.requests]
    assert len(timeouts) == 2 and all(0 < x <= 12 for x in timeouts)
    assert timeouts[1] <= timeouts[0]


async def test_the_configured_tls_setting_is_used(provider_transport):
    t = provider_transport(recorded("6"))
    await lookup(server(cfg=config(ssl_verify=False)), IP)
    assert {r["verify"] for r in t.requests} == {False}


async def test_a_provider_past_its_budget_is_unavailable_in_time(monkeypatch):
    def slow(ioc):
        time.sleep(3)
        return block("MATCH", matches=[{}])

    fake_provider(monkeypatch, "slowintel", slow, timeout=0.2)
    start = time.monotonic()
    resp = await lookup(server(["slowintel"], cfg=None), IP)
    assert time.monotonic() - start < 0.5
    assert resp["providers"]["slowintel"]["outcome"] == "UNAVAILABLE"
    assert "timed out" in resp["providers"]["slowintel"]["reason"]


async def test_providers_are_asked_at_the_same_time(monkeypatch):
    def slow(ioc):
        time.sleep(0.6)
        return block("NO_MATCH")

    fake_provider(monkeypatch, "slowa", slow)
    fake_provider(monkeypatch, "slowb", slow)
    start = time.monotonic()
    await lookup(server(["slowa", "slowb"], cfg=None), IP)
    assert time.monotonic() - start < 1.1


# --- the reply and its compatibility keys -----------------------------------


@pytest.mark.parametrize("version", ["6", "7"])
async def test_the_earlier_keys_summarise_every_matched_record(
    provider_transport, version
):
    provider_transport(recorded(version))
    resp = await lookup(server(), IP)
    records = resp["providers"]["opencti"]["matches"]
    assert resp["found"] is True
    assert resp["entity_type"] == "indicator" and resp["name"] == IP
    assert resp["confidence"] == max(r["confidence"] for r in records) == 90
    assert resp["labels"] == ["c2"]
    assert resp["created"] == min(r["created"] for r in records)
    assert resp["source"] == "opencti"
    assert "description" not in resp


async def test_no_match_carries_no_record_summary(provider_transport):
    provider_transport(recorded("6"))
    resp = await lookup(server(), NEIGHBOUR)
    assert resp["found"] is False
    assert not {"entity_type", "confidence", "labels", "note"} & set(resp)


async def test_a_rate_limited_lookup_is_the_existing_error_and_asks_no_one(
    provider_transport,
):
    t = provider_transport(recorded("6"))
    srv = server()
    srv._lookup_limiter = types.SimpleNamespace(
        check_and_record=lambda: False, wait_time=lambda: 4.0
    )
    with pytest.raises(RateLimitError):
        await lookup(srv, IP)
    assert t.requests == []


async def test_lookups_share_opencti_s_query_limit(provider_transport):
    srv = server()
    assert srv._lookup_limiter is srv.client._query_limiter


def test_the_tool_description_says_it_is_no_verdict():
    srv = server()
    handler = srv.server.request_handlers[ListToolsRequest]
    tools = asyncio.run(handler(ListToolsRequest(method="tools/list"))).root.tools
    (tool,) = [t for t in tools if t.name == "lookup_ioc"]
    assert "not a verdict" in tool.description
    assert "providers.* is the authoritative answer" in tool.description


# --- several providers ------------------------------------------------------


async def test_any_provider_matching_is_a_match(provider_transport, monkeypatch):
    import httpx

    provider_transport(lambda q, v: httpx.ConnectError("Connection refused"))
    fake_provider(monkeypatch, "fakeintel", block("MATCH", matches=[{"v": IP}]))
    resp = await lookup(server(["opencti", "fakeintel"]), IP)
    assert resp["outcome"] == "MATCH" and resp["found"] is True
    assert resp["providers"]["opencti"]["outcome"] == "UNAVAILABLE"
    assert resp["providers"]["fakeintel"]["matches"] == [{"v": IP}]
    assert "note" not in resp and "entity_type" not in resp


async def test_one_provider_down_and_none_matching_is_unavailable(
    provider_transport, monkeypatch
):
    provider_transport(recorded("6"))
    fake_provider(monkeypatch, "fakeintel", block("UNAVAILABLE", reason="HTTP 403"))
    resp = await lookup(server(["opencti", "fakeintel"]), NEIGHBOUR)
    assert resp["outcome"] == "UNAVAILABLE"
    assert resp["providers"]["opencti"]["outcome"] == "NO_MATCH"
    assert resp["reason"] == "fakeintel: HTTP 403"


async def test_every_provider_answering_no_match_is_no_match(
    provider_transport, monkeypatch
):
    provider_transport(recorded("6"))
    fake_provider(monkeypatch, "fakeintel", block("NO_MATCH"))
    resp = await lookup(server(["opencti", "fakeintel"]), NEIGHBOUR)
    assert resp["outcome"] == "NO_MATCH"


async def test_a_provider_module_is_found_by_its_name(monkeypatch):
    calls = fake_provider(monkeypatch, "fakeintel", block("NO_MATCH"))
    resp = await lookup(server(["fakeintel"], cfg=None), IP)
    assert list(resp["providers"]) == ["fakeintel"]
    assert calls == [(IP, "ipv4")]


@pytest.mark.parametrize(
    "answer",
    [None, {"outcome": "MALICIOUS", "matches": []}, {"outcome": "MATCH"}, "x"],
    ids=["none", "unknown outcome", "no matches", "not a dict"],
)
async def test_a_provider_answer_off_the_contract_is_unavailable(monkeypatch, answer):
    fake_provider(monkeypatch, "fakeintel", answer)
    resp = await lookup(server(["fakeintel"], cfg=None), IP)
    assert resp["providers"]["fakeintel"]["outcome"] == "UNAVAILABLE"


async def test_a_provider_that_raises_is_unavailable(monkeypatch):
    def boom(ioc):
        raise RuntimeError("socket closed")

    fake_provider(monkeypatch, "fakeintel", boom)
    answer = (await lookup(server(["fakeintel"], cfg=None), IP))["providers"][
        "fakeintel"
    ]
    assert answer["outcome"] == "UNAVAILABLE"
    assert "socket closed" in answer["reason"]


# --- configuration ----------------------------------------------------------


@pytest.mark.parametrize("raw", [None, "", " , "])
def test_unset_providers_mean_opencti(monkeypatch, raw):
    if raw is None:
        monkeypatch.delenv("THREATINTEL_PROVIDERS", raising=False)
    else:
        monkeypatch.setenv("THREATINTEL_PROVIDERS", raw)
    assert providers.configured_names() == ["opencti"]


def test_providers_are_read_in_order_once_each(monkeypatch):
    monkeypatch.setenv("THREATINTEL_PROVIDERS", " MISP, opencti ,misp")
    assert providers.configured_names() == ["misp", "opencti"]


async def test_an_unset_provider_list_asks_opencti(provider_transport, monkeypatch):
    monkeypatch.delenv("THREATINTEL_PROVIDERS", raising=False)
    provider_transport(recorded("6"))
    resp = await lookup(OpenCTIMCPServer(config()), IP)
    assert list(resp["providers"]) == ["opencti"]


@pytest.mark.parametrize("name", ["bogus", "../client", "Opencti-x", "client"])
async def test_an_unknown_provider_is_unavailable_not_skipped(provider_transport, name):
    provider_transport(recorded("6"))
    resp = await lookup(server(["opencti", name]), NEIGHBOUR)
    assert resp["providers"][name]["outcome"] == "UNAVAILABLE"
    assert resp["outcome"] == "UNAVAILABLE"


async def test_an_unknown_provider_says_so(provider_transport):
    provider_transport(recorded("6"))
    resp = await lookup(server(["opencti", "bogus"]), NEIGHBOUR)
    assert resp["providers"]["bogus"]["reason"] == "unknown provider 'bogus'"


async def test_a_provider_missing_its_settings_is_unavailable(monkeypatch):
    module = types.ModuleType("opencti_mcp.providers.needsurl")

    def create():
        raise providers.ProviderConfigError("NEEDSURL_URL is not set")

    module.create = create
    monkeypatch.setitem(sys.modules, module.__name__, module)
    answer = (await lookup(server(["needsurl"], cfg=None), IP))["providers"]["needsurl"]
    assert answer["outcome"] == "UNAVAILABLE"
    assert "NEEDSURL_URL is not set" in answer["reason"]


def test_opencti_without_a_token_is_a_configuration_error(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    with pytest.raises(providers.ProviderConfigError, match="token"):
        opencti_provider.create()


async def test_listed_opencti_without_settings_is_unavailable_with_the_reason():
    srv = server(["opencti"], cfg=None, opencti_reason="token not found")
    resp = await lookup(srv, IP)
    assert resp["providers"]["opencti"]["outcome"] == "UNAVAILABLE"
    assert "token not found" in resp["providers"]["opencti"]["reason"]
    tool = await srv._dispatch_tool("search_reports", {"query": "x"})
    assert tool == {"error": "opencti_not_configured", "message": "token not found"}


@pytest.mark.parametrize(
    "tool, arguments",
    [
        ("get_health", {}),
        ("search_threat_intel", {"query": "x"}),
        ("search_entity", {"type": "malware", "query": "x"}),
        ("get_recent_indicators", {}),
        ("get_entity", {"entity_id": "550e8400-e29b-41d4-a716-446655440000"}),
        ("get_relationships", {"entity_id": "550e8400-e29b-41d4-a716-446655440000"}),
        ("search_reports", {"query": "x"}),
    ],
)
async def test_opencti_tools_say_when_opencti_is_not_listed(
    monkeypatch, tool, arguments
):
    fake_provider(monkeypatch, "fakeintel", block("NO_MATCH"))
    srv = server(["fakeintel"], cfg=None)
    assert srv.client is None
    assert await srv._dispatch_tool(tool, arguments) == {
        "error": "opencti_not_configured",
        "message": "OpenCTI is not configured in this threat-intel backend.",
    }


# --- a slow provider never holds up another --------------------------------


def _trickler_and_healthy(monkeypatch):
    def trickle(ioc):
        time.sleep(5)  # far past its budget, like a server dribbling its reply
        return block("NO_MATCH")

    fake_provider(monkeypatch, "trickler", trickle, timeout=0.2)
    fake_provider(monkeypatch, "healthy", block("MATCH", matches=[{"v": IP}]))
    return server(["trickler", "healthy"], cfg=None)


async def test_a_trickling_provider_never_blocks_a_healthy_one(monkeypatch):
    srv = _trickler_and_healthy(monkeypatch)
    reasons = []
    for _ in range(20):
        start = time.monotonic()
        resp = await lookup(srv, IP)
        assert time.monotonic() - start < 0.6
        assert resp["providers"]["healthy"]["outcome"] == "MATCH"
        assert resp["outcome"] == "MATCH"
        assert resp["providers"]["trickler"]["outcome"] == "UNAVAILABLE"
        reasons.append(resp["providers"]["trickler"]["reason"])
    assert reasons[: providers.MAX_IN_FLIGHT] == ["timed out after 0.2s"] * 4
    assert all(r.startswith("busy") for r in reasons[providers.MAX_IN_FLIGHT :])


async def test_concurrent_lookups_with_a_trickling_provider_all_answer(monkeypatch):
    srv = _trickler_and_healthy(monkeypatch)
    start = time.monotonic()
    replies = await asyncio.gather(*(lookup(srv, IP) for _ in range(20)))
    assert time.monotonic() - start < 3
    assert {r["providers"]["healthy"]["outcome"] for r in replies} == {"MATCH"}


class _Trickle(httpx.SyncByteStream):
    def __init__(self, chunks, delay):
        self.chunks, self.delay = chunks, delay

    def __iter__(self):
        for chunk in self.chunks:
            time.sleep(self.delay)
            yield chunk


def test_an_exchange_ends_within_its_budget_however_slowly_the_reply_comes():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=_Trickle([b"x"] * 100, 0.05))
    )
    start = time.monotonic()
    with pytest.raises(httpx.ReadTimeout):
        providers.http_request(
            "POST", "http://opencti.invalid/graphql", timeout=0.3, transport=transport
        )
    assert time.monotonic() - start < 0.5


def test_an_exchange_within_its_budget_returns_the_whole_reply():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            201, headers={"x-a": "1"}, stream=_Trickle([b'{"a"', b": 1}"], 0.01)
        )
    )
    response = providers.http_request(
        "POST",
        "http://opencti.invalid/graphql",
        json={},
        timeout=2,
        transport=transport,
    )
    assert response.status_code == 201 and response.json() == {"a": 1}
    assert response.headers["x-a"] == "1"


def test_an_oversized_reply_is_not_read_to_the_end(monkeypatch):
    monkeypatch.setattr(providers, "MAX_REPLY_BYTES", 10)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=_Trickle([b"x" * 8] * 3, 0))
    )
    with pytest.raises(httpx.ReadError, match="too large"):
        providers.http_request(
            "GET", "http://opencti.invalid/", timeout=2, transport=transport
        )


async def test_the_adapter_uses_the_bounded_exchange(monkeypatch):
    calls = []

    def fake(method, url, **kw):
        calls.append((method, url, kw["timeout"]))
        raise httpx.ReadTimeout("the reply did not arrive within the budget")

    monkeypatch.setattr(opencti_provider, "http_request", fake)
    monkeypatch.setattr(opencti_provider, "_http_post", opencti_provider._post)
    resp = await lookup(server(), IP)
    assert resp["providers"]["opencti"]["reason"] == "timed out after 12s"
    assert calls and calls[0][0] == "POST" and calls[0][1].endswith("/graphql")
