"""lookup_ioc's reason for an OpenCTI or MISP failure says what kind of
failure it was, in the product's own words, and nothing else.

The reason passed the transport's and the server's text through, so a TLS or
resolve failure, a GraphQL message or an HTTP error body put the server's host
name, a URL, an IP address or the looked-up IOC into the reply. Each reason is
now written from its category: unreachable, timed out, HTTP status, the
credential refused, rate-limited (with "Too Many Requests", which enrichment's
backoff reads). No text from the failure itself appears.
"""

from __future__ import annotations

import httpx
import opencti_mcp.providers.opencti as opencti_provider
import pytest
from opencti_mcp.config import Config
from opencti_mcp.server import OpenCTIMCPServer
from pydantic import SecretStr

from .threatintel_rig import (
    REPLIES,
    REVOKED,
    Transport,
    lookup,
    misp_env,
    misp_recorded,
    server,
)

HOST = "opencti-int.corp.example"
MISP_HOST = "misp-int.corp.example"
IOC = "11.0.113.10"
# What a failure's own text carries here, and no reason may contain
SECRETS = (HOST, MISP_HOST, "10.20.30.40", "fd00:1234::7", "8443", "corp")
LOUD = f"{HOST} {MISP_HOST}:8443 10.20.30.40 [fd00:1234::7] {IOC} corp"


def _gql(code: str, message: str) -> dict:
    return {"errors": [{"message": message, "extensions": {"code": code}}]}


CATEGORIES = [
    (httpx.ConnectError(f"[Errno 111] refused {LOUD}"), "can't reach {p}"),
    (
        httpx.ConnectError(f"[Errno -2] Name or service not known {LOUD}"),
        "can't reach {p}",
    ),
    (
        httpx.ConnectError(f"[SSL: CERTIFICATE_VERIFY_FAILED] for {LOUD}"),
        "can't reach {p}: its TLS certificate wasn't accepted",
    ),
    (httpx.ReadTimeout(f"timed out reading {LOUD}"), "timed out after"),
    (httpx.Response(500, text=f"upstream {LOUD}"), "{p} answered HTTP 500"),
    (httpx.Response(401, json={"message": LOUD}), "{p} refused the {c} (HTTP 401)"),
    (httpx.Response(403, json={"message": LOUD}), "{p} refused the {c} (HTTP 403)"),
    (
        httpx.Response(429, json={"message": LOUD}),
        "{p} rate-limited the lookup: Too Many Requests (HTTP 429)",
    ),
]
IDS = [
    "refused",
    "dns",
    "tls",
    "timeout",
    "http 500",
    "http 401",
    "http 403",
    "http 429",
]


def _opencti_server():
    cfg = Config(
        opencti_url=f"https://{HOST}:8443",
        opencti_token=SecretStr("dummy-not-a-real-token-0"),
    )
    return OpenCTIMCPServer(cfg, provider_names=["opencti"])


async def _opencti(monkeypatch, answer) -> str:
    monkeypatch.setattr(opencti_provider, "_http_post", Transport(lambda q, v: answer))
    reply = await lookup(_opencti_server(), IOC)
    return reply["providers"]["opencti"]["reason"]


async def _misp(monkeypatch, misp_transport, search=None, check=None) -> dict:
    recorded = misp_recorded("25")

    def route(method, path, body):
        if path == "/attributes/restSearch" and search is not None:
            return search
        if path == "/warninglists/checkValue" and check is not None:
            return check
        return recorded(method, path, body)

    misp_transport(route)
    misp_env(monkeypatch, MISP_URL=f"https://{MISP_HOST}:8443")
    return (await lookup(server(["misp"], cfg=None), IOC))["providers"]["misp"]


def _clean(reason: str) -> None:
    assert not [s for s in SECRETS if s in reason], reason
    assert IOC not in reason, reason


@pytest.mark.parametrize("answer, expected", CATEGORIES, ids=IDS)
async def test_an_opencti_reason_is_its_category_only(monkeypatch, answer, expected):
    reason = await _opencti(monkeypatch, answer)
    assert expected.format(p="OpenCTI", c="token") in reason, reason
    _clean(reason)


@pytest.mark.parametrize("answer, expected", CATEGORIES, ids=IDS)
async def test_a_misp_reason_is_its_category_only(
    monkeypatch, misp_transport, answer, expected
):
    reason = (await _misp(monkeypatch, misp_transport, search=answer))["reason"]
    assert expected.format(p="MISP", c="API key") in reason, reason
    _clean(reason)


@pytest.mark.parametrize(
    "errors, expected",
    [
        (
            _gql("AUTH_REQUIRED", f"You must be logged in {LOUD}"),
            "refused the token (AUTH_REQUIRED)",
        ),
        (_gql("FORBIDDEN_ACCESS", LOUD), "refused the token (FORBIDDEN_ACCESS)"),
        (
            _gql("GRAPHQL_VALIDATION_FAILED", LOUD),
            "rejected the query (GRAPHQL_VALIDATION_FAILED)",
        ),
        (_gql("DATABASE_ERROR", LOUD), "storage error (DATABASE_ERROR)"),
        (
            _gql("RATE_LIMITED", f"Too Many Requests {LOUD}"),
            "rate-limited the lookup: Too Many Requests",
        ),
        (_gql(f"weird {LOUD}", "x"), "rejected the query (no code)"),
    ],
    ids=["auth", "forbidden", "validation", "storage", "rate limit", "not a code"],
)
async def test_a_graphql_error_is_named_by_its_code_only(monkeypatch, errors, expected):
    reason = await _opencti(monkeypatch, errors)
    assert expected in reason, reason
    _clean(reason)


async def test_a_relationships_failure_is_its_category_only(monkeypatch):
    def route(query, variables):
        if "ThreatIntelRelationships" in query:
            return httpx.ConnectError(f"reset by {LOUD}")
        return REPLIES["v7:lookup:revoked"]

    monkeypatch.setattr(opencti_provider, "_http_post", Transport(route))
    reply = str(await lookup(server(), REVOKED))
    assert "Relationships query failed (can't reach OpenCTI)" in reply, reply
    assert not [s for s in SECRETS if s in reply], reply


async def test_a_misp_warninglist_failure_is_its_category_only(
    monkeypatch, misp_transport
):
    answer = await _misp(
        monkeypatch, misp_transport, check=httpx.ConnectError(f"reset by {LOUD}")
    )
    assert answer["warninglists_unavailable"] == (
        "Warninglist check failed (can't reach MISP)."
    )


async def test_a_provider_crash_names_the_kind_of_failure_only(monkeypatch):
    def crash(*a, **k):
        raise RuntimeError(f"bad state {LOUD}")

    monkeypatch.setattr(opencti_provider, "_http_post", crash)
    reply = await lookup(_opencti_server(), IOC)
    reason = reply["providers"]["opencti"]["reason"]
    assert "RuntimeError" in reason, reason
    _clean(reason)
