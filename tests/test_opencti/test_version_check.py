"""The OpenCTI tools answer OpenCTI 6 and 7 alike, with no pycti installed.

There is no client library whose major has to match the server's: the tools
send their own GraphQL selections, each valid on 6.9 and 7. The replies here
were recorded from OpenCTI 6.9.10 and 7.261002.0 instances seeded with
synthetic records, while every tool was called once
(``opencti_tools_replies.json``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import opencti_mcp.graphql as opencti_graphql
import pytest
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.server import OpenCTIMCPServer

from .threatintel_rig import config

RECORDED = json.loads(
    Path(__file__).with_name("opencti_tools_replies.json").read_text()
)


def _key(query: str, variables: dict) -> str:
    # get_recent_indicators asks for "created since <now - days>".
    variables = json.loads(json.dumps(variables))
    for f in (variables.get("filters") or {}).get("filters", []):
        if f.get("key") == "created":
            f["values"] = ["<since>"]
    return json.dumps([query, variables], sort_keys=True)


@pytest.fixture
def replay(monkeypatch):
    """Answer the tools' requests from one version's recording; returns the
    requests made."""

    def install(version: str) -> list[dict]:
        replies = {
            _key(r["query"], r["variables"]): r for r in RECORDED[version]["replies"]
        }
        made: list[dict] = []

        def post(url, json=None, headers=None, timeout=None, verify=None):
            made.append(json)
            reply = replies[_key(json["query"], json["variables"])]
            return httpx.Response(reply["status"], json=reply["body"])

        monkeypatch.setattr(opencti_graphql, "_http_post", post)
        return made

    return install


@pytest.mark.parametrize("version", ["v6", "v7"])
async def test_every_opencti_tool_answers_without_pycti(replay, monkeypatch, version):
    monkeypatch.setitem(sys.modules, "pycti", None)  # `import pycti` fails
    made = replay(version)
    server = OpenCTIMCPServer(config(), provider_names=["opencti"])
    answered = 0
    for tool, arguments in RECORDED[version]["calls"]:
        result = await server._dispatch_tool(tool, arguments)
        rows = (
            result.get("results")
            or result.get("relationships")
            or ([result["entity"]] if result.get("entity") else None)
            or [x for key in ("malware", "reports") for x in result.get(key, [])]
        )
        assert rows or result.get("status") == "healthy", (tool, arguments, result)
        answered += 1
    assert answered == len(RECORDED[version]["calls"]) == 26
    assert len(made) == len(RECORDED[version]["replies"])


@pytest.mark.parametrize("version", ["v6", "v7"])
async def test_an_entity_without_aliases_is_formatted(replay, version):
    replay(version)
    server = OpenCTIMCPServer(config(), provider_names=["opencti"])
    malware_id = RECORDED[version]["ids"][0]
    result = await server._dispatch_tool("get_entity", {"entity_id": malware_id})
    assert result["found"] is True
    assert result["entity"]["entity_type"] == "Malware"
    assert result["entity"]["aliases"] == []


def test_connecting_makes_no_request_and_needs_no_pycti(monkeypatch):
    monkeypatch.setitem(sys.modules, "pycti", None)
    made = []
    monkeypatch.setattr(opencti_graphql, "_http_post", lambda *a, **k: made.append(1))
    client = OpenCTIClient(config(timeout_seconds=42, ssl_verify=False))
    graphql = client.connect()
    assert isinstance(graphql, opencti_graphql.GraphQLClient)
    assert graphql.requests_timeout == 42 and graphql._ssl_verify is False
    assert client.connect() is graphql  # one client, reused
    assert made == []


@pytest.mark.parametrize("server_version", ["6.4.10", "6.9.10", "7.261002.0", "8.0.0"])
async def test_no_server_version_is_refused(monkeypatch, server_version):
    def post(url, json=None, **kwargs):
        if "about" in json["query"]:
            return httpx.Response(
                200, json={"data": {"about": {"version": server_version}}}
            )
        return httpx.Response(200, json={"data": {"reports": {"edges": []}}})

    monkeypatch.setattr(opencti_graphql, "_http_post", post)
    server = OpenCTIMCPServer(config(), provider_names=["opencti"])
    result = await server._dispatch_tool("search_reports", {"query": "x"})
    assert result["results"] == []
