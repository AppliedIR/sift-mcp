"""`lookup_ioc` matches only indicators that are the IOC itself.

OpenCTI is asked for indicators whose name equals the IOC (never a full-text
search), and the answer is checked again here: IP addresses compare as
addresses, fuzzy hashes as given, anything else ignoring case. Replies were
recorded from OpenCTI 6.9.10 and 7.261002.0 instances with synthetic records.
"""

from __future__ import annotations

import json

import pytest
from opencti_mcp import providers

from .threatintel_rig import (
    IP,
    NEIGHBOUR,
    REPLIES,
    SSDEEP_OTHER_CASE,
    SSDEEP_STORED,
    UPPER,
    lookup,
    recorded,
    server,
)


@pytest.mark.parametrize("version", ["6", "7"])
async def test_an_indicator_that_only_shares_a_word_is_not_a_match(
    provider_transport, version
):
    t = provider_transport(recorded(version))
    resp = await lookup(server(), NEIGHBOUR)
    assert resp["outcome"] == "NO_MATCH"
    assert resp["providers"]["opencti"]["matches"] == []
    assert resp["found"] is False
    (request,) = t.requests
    assert "search" not in request["variables"]
    assert request["variables"]["filters"]["filters"] == [
        {"key": ["name"], "values": [NEIGHBOUR], "operator": "eq", "mode": "or"}
    ]


async def test_a_non_exact_name_the_server_returns_is_dropped(provider_transport):
    reply = json.loads(json.dumps(REPLIES["v6:lookup:ip3"]))
    reply["data"]["indicators"]["edges"][0]["node"]["name"] = f"{IP} sinkhole"
    provider_transport(lambda q, v: reply)
    matches = (await lookup(server(), IP))["providers"]["opencti"]["matches"]
    assert [m["name"] for m in matches] == [IP, IP]


@pytest.mark.parametrize("version", ["6", "7"])
async def test_a_hash_stored_in_the_other_case_matches(provider_transport, version):
    provider_transport(recorded(version))
    resp = await lookup(server(), UPPER)
    assert resp["outcome"] == "MATCH"
    assert resp["providers"]["opencti"]["matches"][0]["name"] == UPPER.upper()


@pytest.mark.parametrize("version", ["6", "7"])
async def test_a_fuzzy_hash_differing_only_in_case_is_not_a_match(
    provider_transport, version
):
    provider_transport(recorded(version))
    assert (await lookup(server(), SSDEEP_OTHER_CASE))["outcome"] == "NO_MATCH"
    assert (await lookup(server(), SSDEEP_STORED))["outcome"] == "MATCH"


async def test_an_observable_without_an_indicator_is_not_looked_for(
    provider_transport,
):
    t = provider_transport(recorded("6"))
    await lookup(server(), NEIGHBOUR)
    assert t.requests and all("Observable" not in r["query"] for r in t.requests)


@pytest.mark.parametrize("padded", [f"  {IP}", f"{IP}\n", f"\t{IP} "])
async def test_surrounding_whitespace_is_not_part_of_the_ioc(
    provider_transport, padded
):
    t = provider_transport(recorded("6"))
    resp = await lookup(server(), padded)
    assert resp["ioc"] == IP and resp["outcome"] == "MATCH"
    assert t.requests[0]["variables"]["filters"]["filters"][0]["values"] == [IP]


async def test_a_padded_private_address_is_not_looked_up(provider_transport):
    t = provider_transport(recorded("6"))
    resp = await lookup(server(), " 10.1.2.3 ")
    assert resp["outcome"] == "UNAVAILABLE" and resp["providers"] == {}
    assert "Internal address (10.1.2.3)" in resp["reason"]
    assert resp["found"] is False and "note" in resp
    assert t.requests == []


@pytest.mark.parametrize(
    "value, ioc, same",
    [
        ("11.0.113.10", "11.0.113.10", True),
        ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111", True),
        ("11.0.113.10", "11.0.113.100", False),
        ("Evil-Sample.Example", "evil-sample.example", True),
        ("EVIL-sample.example", "evil-sample.example.net", False),
        ("96:AbCd:EfGh", "96:AbCd:EfGh", True),
        ("96:AbCd:EfGh", "96:abcd:efgh", False),
        ("T1" + "A" * 70, "T1" + "a" * 70, False),
        ("T1" + "A" * 70, "T1" + "A" * 70, True),
        (None, "x", False),
        ("", "", False),
    ],
)
def test_what_counts_as_the_same_value(value, ioc, same):
    assert providers.same_value(value, ioc) is same
