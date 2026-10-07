"""lookup_ioc's reason for an OpenCTI or MISP failure doesn't carry the
server's address.

The reason passed the transport's and the server's text through as written,
so a TLS or resolve failure, or a GraphQL or MISP message, put the configured host
name, a URL or an IP address into the reply. They are now taken out; the
reason itself stays, as does the IOC that was looked up.
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
URL = f"https://{HOST}:8080"
LEAKS = (HOST, "10.20.30.40", "fd00:1234::7", "opencti-int.CORP.example")


def _server():
    cfg = Config(opencti_url=URL, opencti_token=SecretStr("dummy-not-a-real-token-0"))
    return OpenCTIMCPServer(cfg, provider_names=["opencti"])


def _gql(code: str, message: str) -> dict:
    return {"errors": [{"message": message, "extensions": {"code": code}}]}


async def _reason(monkeypatch, answer, ioc="11.0.113.10") -> str:
    monkeypatch.setattr(opencti_provider, "_http_post", Transport(lambda q, v: answer))
    reply = await lookup(_server(), ioc)
    return str(reply)


@pytest.mark.parametrize(
    "answer, kept",
    [
        (
            httpx.ConnectError(
                f"[SSL: CERTIFICATE_VERIFY_FAILED] Hostname mismatch, certificate "
                f"is not valid for '{HOST}' (host='{HOST}', port=8080) {URL}/graphql"
                " 10.20.30.40"
            ),
            "can't reach OpenCTI",
        ),
        (
            _gql(
                "AUTH_REQUIRED",
                f"You must be logged in at {URL}/graphql from fd00:1234::7",
            ),
            "logged in",
        ),
        (
            _gql(
                "GRAPHQL_VALIDATION_FAILED",
                "GRAPHQL_VALIDATION_FAILED near opencti-int.CORP.example:8080",
            ),
            "GRAPHQL_VALIDATION_FAILED",
        ),
    ],
    ids=["tls", "auth", "validation"],
)
async def test_the_reason_names_no_server_address(monkeypatch, answer, kept):
    reason = await _reason(monkeypatch, answer)
    assert not [leak for leak in LEAKS if leak in reason], reason
    assert kept in reason, reason


async def test_a_relationships_failure_names_no_server_address(monkeypatch):
    def route(query, variables):
        if "ThreatIntelRelationships" in query:
            return httpx.ConnectError(f"reset by {HOST} (10.20.30.40)")
        return REPLIES["v7:lookup:revoked"]

    monkeypatch.setattr(opencti_provider, "_http_post", Transport(route))
    reply = str(await lookup(_server(), REVOKED))
    assert "Relationships query failed" in reply
    assert not [leak for leak in LEAKS if leak in reply], reply


async def test_anchor_a_time_and_the_looked_up_ioc_stay(monkeypatch):
    answer = _gql(
        "GRAPHQL_VALIDATION_FAILED",
        "Too Many Requests at 10:48:01 for 11.0.113.10",
    )
    reason = await _reason(monkeypatch, answer)
    assert "Too Many Requests at 10:48:01 for 11.0.113.10" in reason, reason


MISP_HOST = "misp-int.corp.example"
MISP_LEAKS = (MISP_HOST, "10.20.30.40", "MISP-INT.corp.example")


async def _misp(monkeypatch, misp_transport, search=None, check=None):
    recorded = misp_recorded("25")

    def route(method, path, body):
        if path == "/attributes/restSearch" and search is not None:
            return search
        if path == "/warninglists/checkValue" and check is not None:
            return check
        return recorded(method, path, body)

    misp_transport(route)
    misp_env(monkeypatch, MISP_URL=f"https://{MISP_HOST}")
    return str(await lookup(server(["misp"], cfg=None), "11.0.113.10"))


@pytest.mark.parametrize(
    "search, kept",
    [
        (
            httpx.ConnectError("no route to MISP-INT.corp.example (10.20.30.40)"),
            "can't reach MISP",
        ),
        (
            httpx.Response(
                403, json={"message": f"Forbidden at https://{MISP_HOST}/users"}
            ),
            "MISP answered HTTP 403: Forbidden at",
        ),
    ],
    ids=["transport", "http"],
)
async def test_a_misp_reason_names_no_server_address(
    monkeypatch, misp_transport, search, kept
):
    reason = await _misp(monkeypatch, misp_transport, search=search)
    assert not [leak for leak in MISP_LEAKS if leak in reason], reason
    assert kept in reason, reason


async def test_a_misp_warninglist_failure_names_no_server_address(
    monkeypatch, misp_transport
):
    check = httpx.ConnectError(f"reset by {MISP_HOST} (10.20.30.40)")
    reply = await _misp(monkeypatch, misp_transport, check=check)
    assert "Warninglist check failed" in reply
    assert not [leak for leak in MISP_LEAKS if leak in reply], reply


SHORT = "http://opencti:8080"


@pytest.mark.parametrize(
    "text, ioc, expected",
    [
        (
            f"reset by {SHORT}/graphql",
            "11.0.113.10",
            "reset by http://<OpenCTI host>:8080/graphql",
        ),
        (
            "no indicator named evil-opencti.com; opencti-backup.example.org is down",
            "evil-opencti.com",
            "no indicator named evil-opencti.com; opencti-backup.example.org is down",
        ),
        ("from ::ffff:10.0.0.5", "x", "from <IP address>"),
        ("from 0:0:0:0:0:ffff:10.0.0.5.", "x", "from <IP address>."),
        (
            "10.0.0.5:8080 at 10:48:01, v6.9.10",
            "x",
            "<IP address>:8080 at 10:48:01, v6.9.10",
        ),
    ],
    ids=[
        "host in a url",
        "host inside other names",
        "mapped v6",
        "mapped v6 long",
        "port, time, version",
    ],
)
def test_redact_takes_out_only_the_address(text, ioc, expected):
    from opencti_mcp.providers import redact

    assert redact(text, SHORT, ioc, "OpenCTI") == expected


async def test_a_domain_ioc_holding_the_host_name_is_kept(monkeypatch):
    cfg = Config(opencti_url=SHORT, opencti_token=SecretStr("dummy-not-a-real-token-0"))
    srv = OpenCTIMCPServer(cfg, provider_names=["opencti"])
    answer = _gql(
        "GRAPHQL_VALIDATION_FAILED",
        f"Invalid value evil-opencti.com at {SHORT}/graphql",
    )
    monkeypatch.setattr(opencti_provider, "_http_post", Transport(lambda q, v: answer))
    reply = str(await lookup(srv, "evil-opencti.com"))
    assert "Invalid value evil-opencti.com at http://<OpenCTI host>:8080" in reply, (
        reply
    )
