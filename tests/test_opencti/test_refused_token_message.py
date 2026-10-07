"""Each OpenCTI tool says when the token is refused or the server can't be
reached.

OpenCTI answers a refused token with HTTP 200 and AUTH_REQUIRED. Six tools
reported it, and an unreachable server too, as "Query failed. Check server
logs for details.": the examiner was
sent to the logs for a setting. Other query failures keep that message.
get_health isn't covered here.
"""

from __future__ import annotations

import json

import httpx
import opencti_mcp.graphql as opencti_graphql
import opencti_mcp.providers.opencti as opencti_provider
import pytest
from mcp.types import CallToolRequest, CallToolRequestParams

from .threatintel_rig import REPLIES, server

UUID = "00000000-0000-4000-8000-000000000000"
TOOLS = [
    ("search_threat_intel", {"query": "x"}),
    ("search_entity", {"type": "malware", "query": "x"}),
    ("lookup_ioc", {"ioc": "11.0.113.10"}),
    ("get_recent_indicators", {"days": 7}),
    ("get_entity", {"entity_id": UUID}),
    ("get_relationships", {"entity_id": UUID}),
    ("search_reports", {"query": "x"}),
]  # get_health's reason is registered separately
TOKEN = "refused the"  # "refused the API token" / "refused the token"
UNREACHABLE = "reach OpenCTI"  # "Can't reach OpenCTI" / "can't reach OpenCTI"
LOGS = "Query failed. Check server logs for details."


def _answer(monkeypatch, answer) -> None:
    """Every GraphQL request, the tools' and lookup_ioc's, gets `answer`."""

    def post(*args, **kwargs):
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)

    monkeypatch.setattr(opencti_graphql, "_http_post", post)
    monkeypatch.setattr(opencti_provider, "_http_post", post)


async def _text(tool: str, arguments: dict) -> str:
    srv = server()
    handler = srv.server.request_handlers[CallToolRequest]
    reply = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name=tool, arguments=arguments),
        )
    )
    return reply.root.content[0].text


def _said(text: str) -> str:
    """The message the examiner reads: error message, reason or note."""
    doc = json.loads(text)
    return " ".join(str(doc.get(k, "")) for k in ("message", "reason", "note"))


@pytest.mark.parametrize(
    "answer",
    [REPLIES["v6:auth_required"], REPLIES["v7:auth_required"]],
    ids=["refused 6", "refused 7"],
)
@pytest.mark.parametrize("tool, arguments", TOOLS, ids=[t for t, _ in TOOLS])
async def test_a_refused_token_is_named_by_every_tool(
    monkeypatch, tool, arguments, answer
):
    _answer(monkeypatch, answer)
    said = _said(await _text(tool, arguments))
    assert TOKEN in said and LOGS not in said, said


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("tool, arguments", TOOLS, ids=[t for t, _ in TOOLS])
async def test_an_http_refusal_is_named_as_a_refused_token(
    monkeypatch, tool, arguments, status
):
    _answer(monkeypatch, httpx.Response(status, text="unauthorized"))
    said = _said(await _text(tool, arguments))
    assert TOKEN in said and LOGS not in said, said


@pytest.mark.parametrize("tool, arguments", TOOLS, ids=[t for t, _ in TOOLS])
async def test_a_server_that_can_t_be_reached_says_so(monkeypatch, tool, arguments):
    _answer(monkeypatch, httpx.ConnectError("[Errno 111] Connection refused"))
    said = _said(await _text(tool, arguments))
    assert UNREACHABLE in said and LOGS not in said, said


SEARCHES = [t for t in TOOLS if t[0] != "lookup_ioc"]


@pytest.mark.parametrize("tool, arguments", SEARCHES, ids=[t for t, _ in SEARCHES])
async def test_a_server_that_doesn_t_answer_in_time_says_so(
    monkeypatch, tool, arguments
):
    _answer(monkeypatch, httpx.ReadTimeout("timed out"))
    said = _said(await _text(tool, arguments))
    assert UNREACHABLE in said and LOGS not in said, said


@pytest.mark.parametrize("tool, arguments", SEARCHES, ids=[t for t, _ in SEARCHES])
async def test_anchor_another_failure_still_points_to_the_logs(
    monkeypatch, tool, arguments
):
    _answer(monkeypatch, REPLIES["v6:validation_error"])
    assert json.loads(await _text(tool, arguments))["message"] == LOGS
