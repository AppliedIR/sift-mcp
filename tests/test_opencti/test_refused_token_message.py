"""An OpenCTI tool whose token is refused says so.

OpenCTI answers a refused token with HTTP 200 and AUTH_REQUIRED. The tools
reported it as "Query failed. Check server logs for details.", sending the
examiner to the logs for a setting.
"""

from __future__ import annotations

import httpx
import opencti_mcp.graphql as opencti_graphql
import pytest
from opencti_mcp.errors import QueryError

from .threatintel_rig import REPLIES, server


@pytest.mark.parametrize(
    "answer",
    [
        REPLIES["v6:auth_required"],
        REPLIES["v7:auth_required"],
        httpx.Response(401, text="unauthorized"),
    ],
    ids=["refused 6", "refused 7", "http 401"],
)
async def test_a_refused_token_is_named(monkeypatch, answer):
    monkeypatch.setattr(
        opencti_graphql,
        "_http_post",
        lambda *a, **k: (
            answer
            if isinstance(answer, httpx.Response)
            else httpx.Response(200, json=answer)
        ),
    )
    with pytest.raises(QueryError) as raised:
        await server()._dispatch_tool("search_threat_intel", {"query": "x"})
    assert "refused the API token" in raised.value.safe_message


async def test_anchor_another_failure_still_points_to_the_logs(monkeypatch):
    monkeypatch.setattr(
        opencti_graphql,
        "_http_post",
        lambda *a, **k: httpx.Response(200, json=REPLIES["v6:validation_error"]),
    )
    with pytest.raises(QueryError) as raised:
        await server()._dispatch_tool("search_threat_intel", {"query": "x"})
    assert raised.value.safe_message == "Query failed. Check server logs for details."
