"""The GraphQL client the OpenCTI tools use in place of pycti.

It keeps the calls the client code makes (``indicator.list``,
``stix_domain_object.read``, ``query``, ...), sends every value as a GraphQL
variable, flattens connections the way the formatters expect, and raises the
error classes the retry and circuit-breaker code tells apart.
"""

from __future__ import annotations

import json

import httpx
import opencti_mcp.graphql as opencti_graphql
import pytest
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.graphql import (
    AuthenticationError,
    GraphQLClient,
    GraphQLError,
    GraphQLHTTPError,
)

from .threatintel_rig import REPLIES, config


@pytest.fixture
def sent(monkeypatch):
    """Answer every request with `answer` (set by the test); returns the
    requests made."""
    state: dict = {"answer": {"data": {}}, "made": []}

    def post(url, json=None, headers=None, timeout=None, verify=None):
        state["made"].append(
            {
                "url": url,
                "headers": headers,
                "timeout": timeout,
                "verify": verify,
                **json,
            }
        )
        answer = state["answer"]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)

    monkeypatch.setattr(opencti_graphql, "_http_post", post)
    return state


def _client(**kw) -> GraphQLClient:
    return GraphQLClient(
        "https://opencti.example/", "token-1", requests_timeout=7, **kw
    )


def test_a_list_sends_its_values_as_variables(sent):
    sent["answer"] = {"data": {"indicators": {"edges": []}}}
    search = 'x") { id } } mutation { deleteAll'
    _client().indicator.list(
        search=search, first=5, orderBy="created", orderMode="desc"
    )
    (request,) = sent["made"]
    assert request["url"] == "https://opencti.example/graphql"
    assert request["headers"]["Authorization"] == "Bearer token-1"
    assert request["timeout"] == 7
    assert request["variables"] == {"first": 5, "search": search}
    assert search not in request["query"]
    assert "orderBy: created, orderMode: desc" in request["query"]


@pytest.mark.parametrize(
    "kwargs", [{"orderBy": "name) { id } x: indicators(first: 1"}, {"orderMode": "up"}]
)
def test_an_ordering_outside_the_known_values_is_refused(sent, kwargs):
    with pytest.raises(ValueError):
        _client().indicator.list(search="x", **kwargs)
    assert sent["made"] == []


def test_connections_inside_an_entity_become_lists(sent):
    sent["answer"] = {
        "data": {
            "stixDomainObject": {
                "id": "m1",
                "entity_type": "Malware",
                "name": "ExampleRAT",
                "aliases": None,
                "objectLabel": [{"value": "malware"}],
                "externalReferences": {
                    "edges": [{"node": {"source_name": "vendor", "url": "https://x"}}]
                },
            }
        }
    }
    entity = _client().stix_domain_object.read(id="m1")
    assert entity["externalReferences"] == [
        {"source_name": "vendor", "url": "https://x"}
    ]
    assert entity["objectLabel"] == [{"value": "malware"}]
    assert sent["made"][0]["variables"] == {"id": "m1"}


def test_a_read_of_nothing_is_none(sent):
    sent["answer"] = {"data": {"stixDomainObject": None}}
    assert _client().stix_domain_object.read(id="missing") is None


def test_a_list_returns_its_nodes(sent):
    sent["answer"] = REPLIES["v7:lookup:ip3"]
    nodes = _client().indicator.list(search="11.0.113.10")
    assert [n["name"] for n in nodes] == ["11.0.113.10"] * 3


@pytest.mark.parametrize(
    "types, root",
    [(["Organization"], "organizations"), (["Sector"], "sectors")],
)
def test_identities_are_read_from_their_own_root(sent, types, root):
    sent["answer"] = {"data": {root: {"edges": []}}}
    _client().identity.list(search="x", first=3, types=types)
    assert f"{root}(" in sent["made"][0]["query"]
    assert "types" not in sent["made"][0]["variables"]


def test_relationships_take_their_ends_and_types_as_lists(sent):
    sent["answer"] = {"data": {"stixCoreRelationships": {"edges": []}}}
    _client().stix_core_relationship.list(
        fromId="a", first=2, relationship_type=["uses"]
    )
    variables = sent["made"][0]["variables"]
    assert variables["fromId"] == ["a"]
    assert variables["relationship_type"] == ["uses"]


def test_query_returns_the_whole_reply(sent):
    sent["answer"] = {"data": {"about": {"version": "7.261002.0"}}}
    assert _client().query("{ about { version } }") == sent["answer"]


def test_the_tls_setting_is_used(sent):
    sent["answer"] = {"data": {"indicators": {"edges": []}}}
    _client(ssl_verify=False).indicator.list(search="x")
    assert sent["made"][0]["verify"] is False


def test_the_timeout_can_change_after_creation(sent):
    sent["answer"] = {"data": {"indicators": {"edges": []}}}
    client = _client()
    client.requests_timeout = 90  # the adaptive timeout does this
    client.indicator.list(search="x")
    assert sent["made"][0]["timeout"] == 90


def test_a_null_root_is_none_found(sent):
    sent["answer"] = {"data": {"indicators": None}}
    assert _client().indicator.list(search="x") == []
    sent["answer"] = {"data": {"stixDomainObject": None}}
    assert _client().stix_domain_object.read(id="m1") is None


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.indicator.list(search="x"),
        lambda c: c.stix_domain_object.read(id="m1"),
    ],
    ids=["list", "read"],
)
def test_a_reply_without_its_root_is_an_error_not_none_found(sent, call):
    sent["answer"] = {"data": {}}
    with pytest.raises(GraphQLError, match="has no"):
        call(_client())


def test_a_reply_without_its_root_reads_as_unavailable(sent):
    sent["answer"] = {"data": {}}
    assert OpenCTIClient(config()).is_available() is False


def test_relationship_ends_name_every_named_type(sent):
    sent["answer"] = {"data": {"stixCoreRelationships": {"edges": []}}}
    _client().stix_core_relationship.list(fromId="a", first=1)
    query = sent["made"][0]["query"]
    for kind in (
        "Case",
        "Channel",
        "DataComponent",
        "DataSource",
        "Event",
        "Narrative",
    ):
        assert f"... on {kind} {{ name description }}" in query, kind
    assert "... on Language { name }" in query  # Language has no description


# --- errors keep the classes the retry and breaker code reads ---------------


@pytest.mark.parametrize(
    "answer, kind",
    [
        (httpx.ConnectError("refused"), ConnectionError),
        (httpx.ReadTimeout("slow"), TimeoutError),
        (httpx.Response(502, text="bad gateway"), GraphQLHTTPError),
        (REPLIES["v6:auth_required"], AuthenticationError),
        (REPLIES["v6:validation_error"], GraphQLError),
        (REPLIES["v6:database_error"], GraphQLError),
        (httpx.Response(200, text="<html>"), GraphQLError),
        ({"data": None}, GraphQLError),
        ({"data": {"indicators": {"edges": "x"}}}, GraphQLError),
    ],
    ids=[
        "unreachable",
        "timeout",
        "http error",
        "token refused",
        "schema",
        "storage",
        "not json",
        "no data",
        "bad shape",
    ],
)
def test_each_failure_raises_its_class(sent, answer, kind):
    sent["answer"] = answer
    with pytest.raises(kind):
        _client().indicator.list(search="x")


def test_the_retry_code_reads_the_failures_as_before():
    client = OpenCTIClient(config())
    assert client._is_transient_error(ConnectionError("x"))
    assert client._is_transient_error(TimeoutError("x"))
    assert client._is_transient_error(GraphQLHTTPError(httpx.Response(503, text="")))
    assert not client._is_transient_error(GraphQLError("x"))
    assert client._is_auth_error(AuthenticationError("AUTH_REQUIRED: log in"))
    assert client._is_auth_error(GraphQLHTTPError(httpx.Response(401, text="")))
    assert not client._is_auth_error(GraphQLError("DATABASE_ERROR: x"))


def test_a_transient_failure_is_retried_and_then_answers(sent, monkeypatch):
    replies = [httpx.ConnectError("refused"), REPLIES["v6:lookup:ip3"]]

    def post(url, json=None, **kwargs):
        answer = replies.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return httpx.Response(200, json=answer)

    monkeypatch.setattr(opencti_graphql, "_http_post", post)
    client = OpenCTIClient(config(max_retries=1, retry_base_delay=0.01))
    results = client.search_indicators("11.0.113.10")
    assert len(results) == 3 and replies == []


def test_the_recorded_tools_fixture_is_well_formed():
    from pathlib import Path

    data = json.loads(
        Path(__file__).with_name("opencti_tools_replies.json").read_text()
    )
    for version in ("v6", "v7"):
        assert len(data[version]["calls"]) == 26
        assert all("data" in r["body"] for r in data[version]["replies"])
