"""lookup_ioc says when the related actors, malware and techniques couldn't be read.

The indicator lookup succeeds, then the relationships query fails. The reply
still says `found: true`, and `relationships_unavailable` names the failure so
the empty lists don't read as "no known relationships". It must not be `note`
or `error`: enrichment treats both as a different result. Everything here is
offline; the pycti client is a stub.
"""

from unittest.mock import MagicMock

import pytest
import requests
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.config import Config
from opencti_mcp.errors import OpenCTIMCPError
from opencti_mcp.server import OpenCTIMCPServer
from pydantic import SecretStr

IOC = "5f0c2a9e1b7d4c3a8e6f9b0d2c4a6e81"  # a synthetic MD5
INDICATOR = {
    "id": "indicator--1",
    "name": IOC,
    "pattern": f"[file:hashes.MD5 = '{IOC}']",
    "pattern_type": "stix",
    "confidence": 90,
    "created": "2026-01-01T00:00:00Z",
}


def _config():
    return Config(
        opencti_url="http://127.0.0.1:9",
        opencti_token=SecretStr("dummy-not-a-real-token-0000"),
        max_retries=0,
    )


async def _lookup(relationships):
    client = OpenCTIClient(_config())
    fake = MagicMock()
    fake.indicator.list.return_value = [INDICATOR]
    fake.stix_cyber_observable.list.return_value = []
    if isinstance(relationships, Exception):
        fake.stix_core_relationship.list.side_effect = relationships
    else:
        fake.stix_core_relationship.list.return_value = relationships
    client._client = fake
    client.connect = lambda: fake
    server = OpenCTIMCPServer(_config(), client=client)
    try:
        return await server._dispatch_tool("lookup_ioc", {"ioc": IOC})
    except OpenCTIMCPError as e:
        return {"error": type(e).__name__.lower(), "message": e.safe_message}


@pytest.mark.parametrize(
    "failure, name",
    [
        (
            ValueError({"name": "GRAPHQL_VALIDATION_FAILED", "message": "x"}),
            "ValueError",
        ),
        (requests.exceptions.HTTPError("500 Server Error"), "HTTPError"),
        ([{"to": None, "relationship_type": "indicates"}], "AttributeError"),
    ],
    ids=["graphql error", "server error", "relationship without a target"],
)
async def test_a_failed_relationships_query_is_marked_unavailable(failure, name):
    reply = await _lookup(failure)
    assert reply.get("found") is True, reply
    assert f"({name})" in reply.get("relationships_unavailable", ""), reply
    assert "note" not in reply and "error" not in reply, reply


async def test_an_empty_relationships_reply_is_not_marked():
    reply = await _lookup([])
    assert reply.get("found") is True and "relationships_unavailable" not in reply, (
        reply
    )


async def test_a_failed_relationships_query_keeps_the_rest_of_the_reply():
    # enrichment reads found/confidence and skips on note or error: these match a success
    good = await _lookup([{"to": {"entity_type": "Malware", "name": "ExampleRAT"}}])
    bad = await _lookup(ValueError("relationship backend timeout"))
    assert good["related_malware"] == ["ExampleRAT"]
    same = ("found", "confidence", "type", "name")
    assert {k: bad.get(k) for k in same} == {k: good.get(k) for k in same}
    assert not {"note", "error"} & set(bad)
