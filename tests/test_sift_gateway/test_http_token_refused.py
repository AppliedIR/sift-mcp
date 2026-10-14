"""A remote that answers the gateway's token with 401 or 403 is named as a
refused token, with its fix, wherever the error shows; anything else keeps
its own description. (wintools gives 401 for a missing token and 403
"Invalid API key" for a wrong one.)"""

from __future__ import annotations

import sys

import httpx
import pytest
from sift_gateway.backends.http_backend import (
    HttpMCPBackend,
    describe,
    refused_status,
    token_refused_text,
)

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup


def _status_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://192.0.2.10:4624/mcp")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError(
        f"Client error {status}", request=request, response=response
    )


def _wrapped(inner: BaseException) -> BaseException:
    """As anyio hands it on: in a group, behind the error raised from it."""
    try:
        try:
            raise BaseExceptionGroup("unhandled errors", [inner])
        except BaseExceptionGroup as group:
            raise RuntimeError("connect failed") from group
    except RuntimeError as outer:
        return outer


@pytest.mark.parametrize("status", [401, 403])
def test_a_401_or_403_anywhere_is_a_refused_token(status):
    assert refused_status(_status_error(status)) == status
    assert refused_status(_wrapped(_status_error(status))) == status


@pytest.mark.parametrize("status", [404, 500, 502])
def test_other_statuses_and_errors_are_not(status):
    assert refused_status(_status_error(status)) is None
    assert refused_status(_wrapped(ConnectionRefusedError("refused"))) is None


@pytest.mark.parametrize(
    ("status", "reason"), [(401, "401 Unauthorized"), (403, "403 Forbidden")]
)
def test_the_text_names_the_token_and_the_fix(status, reason):
    assert token_refused_text("wintools-mcp", status) == (
        f"wintools-mcp rejected the gateway's token ({reason}): the bearer token in "
        "gateway.yaml isn't one it accepts. To fix, join it again: a code from "
        "`vhir setup join-code` on this box, then the join on wintools-mcp's host"
    )


def test_the_backend_names_a_refused_token_and_describes_anything_else():
    backend = HttpMCPBackend(
        "wintools-mcp", {"type": "http", "url": "https://192.0.2.10:4624/mcp"}
    )
    assert backend._why(_wrapped(_status_error(403))) == token_refused_text(
        "wintools-mcp", 403
    )
    other = _wrapped(ConnectionRefusedError("refused"))
    assert backend._why(other) == describe(other)
