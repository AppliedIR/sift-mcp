"""lookup_ioc never answers `found: false` when OpenCTI couldn't be asked.

A failed lookup returns the error with its reason and no `found`, the shape
every other tool's failure has. A reachable server that has no match still
answers `found: false`. Everything here is offline: the pycti client is a
stub, and the configured URL is never reached.
"""

from unittest.mock import MagicMock

import pytest
import requests
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.config import Config
from opencti_mcp.errors import OpenCTIMCPError
from opencti_mcp.server import OpenCTIMCPServer
from pydantic import SecretStr

IOC = "8.8.8.8"


def _config():
    return Config(
        opencti_url="http://127.0.0.1:9",
        opencti_token=SecretStr("dummy-not-a-real-token-0000"),
        max_retries=0,
    )


async def _call(client, tool, arguments):
    server = OpenCTIMCPServer(_config(), client=client)
    try:
        return await server._dispatch_tool(tool, arguments)
    except OpenCTIMCPError as e:
        return {"error": type(e).__name__.lower(), "message": e.safe_message}


def _warm_client():
    """A client that has answered once; `failure` makes every later query raise."""
    client = OpenCTIClient(_config())
    state = {"failure": None}

    def query(**kwargs):
        if state["failure"] is not None:
            raise state["failure"]
        return []

    fake = MagicMock()
    fake.indicator.list.side_effect = query
    fake.stix_cyber_observable.list.side_effect = query
    client._client = fake
    client.connect = lambda: fake
    return client, state


def _assert_unavailable(resp, reason):
    assert "found" not in resp, resp
    assert reason.lower() in resp.get("error", "").lower(), resp


async def test_the_first_lookup_after_a_degraded_start_is_an_error():
    client = OpenCTIClient(_config())
    client._degraded = True
    client._degraded_reason = "server unreachable within 10s: ConnectTimeout"
    _assert_unavailable(await _call(client, "lookup_ioc", {"ioc": IOC}), "DEGRADED")


@pytest.mark.parametrize(
    "failure, reason",
    [
        (
            requests.exceptions.ReadTimeout("Read timed out. (read timeout=2)"),
            "timed out",
        ),
        (
            requests.exceptions.ConnectTimeout("Connection to 127.0.0.1 timed out."),
            "timed out",
        ),
        (
            ValueError('{"errors":[{"message":"You must be logged in to do this."}]}'),
            "logged in",
        ),
        (
            ValueError(
                {"name": "GRAPHQL_VALIDATION_FAILED", "error_message": "Unknown type"}
            ),
            "GRAPHQL_VALIDATION_FAILED",
        ),
    ],
    ids=["read timeout", "connect timeout", "not logged in", "graphql error"],
)
async def test_a_failure_after_a_good_lookup_is_an_error(failure, reason):
    client, state = _warm_client()
    first = await _call(client, "lookup_ioc", {"ioc": IOC})
    assert first.get("found") is False and "error" not in first, first
    state["failure"] = failure
    _assert_unavailable(await _call(client, "lookup_ioc", {"ioc": IOC}), reason)


async def test_a_reachable_server_without_a_match_still_says_not_found():
    client, _ = _warm_client()
    resp = await _call(client, "lookup_ioc", {"ioc": IOC})
    assert resp.get("found") is False and "error" not in resp, resp


async def test_another_tool_on_a_degraded_start_still_raises_a_query_error():
    client = OpenCTIClient(_config())
    client._degraded = True
    client._degraded_reason = "server unreachable within 10s: ConnectTimeout"
    resp = await _call(client, "search_threat_intel", {"query": "example"})
    assert resp["error"] == "queryerror", resp
