"""lookup_ioc says when the related actors, malware and techniques couldn't be read.

The indicator lookup succeeds, then the relationships query fails. The reply
is still MATCH with the records, and `relationships_unavailable` names the
failure so the empty lists don't read as "no known relationships". It must not
be `note` or `error`: enrichment treats both as a different result.
"""

from __future__ import annotations

import httpx
import pytest

from .threatintel_rig import REPLIES, REVOKED, lookup, recorded, server


def _relationships_fail(answer):
    def route(query, variables):
        if "ThreatIntelRelationships" in query:
            return answer
        return recorded("6")(query, variables)

    return route


@pytest.mark.parametrize(
    "answer, words",
    [
        (REPLIES["v6:validation_error"], "GraphQL error"),
        (httpx.Response(502, text="bad gateway"), "HTTP 502"),
        ({"data": {"stixCoreRelationships": {"edges": [None]}}}, "unexpected shape"),
        (httpx.ReadTimeout("timed out"), "timed out"),
    ],
    ids=["graphql error", "server error", "relationship without a node", "timeout"],
)
async def test_a_failed_relationships_query_is_marked_unavailable(
    provider_transport, answer, words
):
    provider_transport(_relationships_fail(answer))
    resp = await lookup(server(), REVOKED)
    block = resp["providers"]["opencti"]
    assert words in block["relationships_unavailable"]
    assert resp["relationships_unavailable"] == block["relationships_unavailable"]
    assert block["relationships"] == []


async def test_a_failed_relationships_query_keeps_the_rest_of_the_reply(
    provider_transport,
):
    provider_transport(_relationships_fail(httpx.Response(502, text="x")))
    resp = await lookup(server(), REVOKED)
    assert resp["outcome"] == resp["providers"]["opencti"]["outcome"] == "MATCH"
    assert resp["found"] is True and resp["confidence"] == 100
    assert len(resp["providers"]["opencti"]["matches"]) == 1
    assert "note" not in resp and "error" not in resp


async def test_an_empty_relationships_reply_is_not_marked(provider_transport):
    provider_transport(
        _relationships_fail(
            {"data": {"stixCoreRelationships": {"pageInfo": {}, "edges": []}}}
        )
    )
    resp = await lookup(server(), REVOKED)
    assert "relationships_unavailable" not in resp
    assert resp["related_malware"] == resp["mitre_techniques"] == []


@pytest.mark.parametrize("version", ["6", "7"])
async def test_relationships_are_opencti_s_and_feed_the_related_lists(
    provider_transport, version
):
    t = provider_transport(recorded(version))
    resp = await lookup(server(), REVOKED)
    block = resp["providers"]["opencti"]
    assert len(block["relationships"]) == 3
    assert resp["related_malware"] == ["ExampleRAT"]
    assert resp["mitre_techniques"] == ["T1999"]
    assert resp["related_threat_actors"] == ["Example Set"]
    (rel,) = [r for r in t.requests if "Relationships" in r["query"]]
    assert rel["variables"]["fromId"] == [m["id"] for m in block["matches"]]


async def test_relationships_are_read_once_for_every_matched_record(
    provider_transport,
):
    t = provider_transport(recorded("6"))
    await lookup(server(), "11.0.113.10")
    rels = [r for r in t.requests if "Relationships" in r["query"]]
    assert len(rels) == 1 and len(rels[0]["variables"]["fromId"]) == 3


async def test_more_relationships_than_are_read_say_so(provider_transport):
    many = {
        "data": {
            "stixCoreRelationships": {"pageInfo": {"globalCount": 501}, "edges": []}
        }
    }
    provider_transport(_relationships_fail(many))
    block = (await lookup(server(), REVOKED))["providers"]["opencti"]
    assert block["relationships_truncated"] is True
