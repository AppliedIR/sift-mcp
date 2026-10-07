"""Shared pieces for the lookup_ioc tests: OpenCTI GraphQL replies recorded
from 6.9.10 and 7.261002.0 instances seeded with synthetic records
(``opencti_graphql_replies.json``), a transport that answers the adapter's
requests from them, and a way to install a provider only a test knows."""

from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

import httpx
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.server import OpenCTIMCPServer

REPLIES = json.loads(
    Path(__file__).with_name("opencti_graphql_replies.json").read_text()
)
MISP_REPLIES = json.loads(
    Path(__file__).with_name("misp_rest_replies.json").read_text()
)

IP = "11.0.113.10"  # three indicators
REVOKED = "a" * 63 + "1"  # one revoked indicator with three relationships
UPPER = "c" * 63 + "3"  # stored upper case
NEIGHBOUR = "11.0.113.77"  # only an indicator named "11.0.113.77 sinkhole notes"
SSDEEP_STORED = "96:AbCdEfGh:IjKlMn"
SSDEEP_OTHER_CASE = "96:abcdefgh:ijklmn"

_RECORDED = {
    IP: "ip3",
    REVOKED: "revoked",
    UPPER: "upper",
    NEIGHBOUR: "neighbour",
    SSDEEP_OTHER_CASE: "ssdeep_lower",
    SSDEEP_STORED: "ssdeep_lower",  # the server's eq ignores case
}


def config(**kw) -> Config:
    return Config(
        opencti_url="http://127.0.0.1:9",
        opencti_token=SecretStr("dummy-not-a-real-token-0000"),
        **kw,
    )


class Transport:
    """Answers the adapter's requests from a route, and records each one."""

    def __init__(self, route):
        self.route = route
        self.requests: list[dict] = []

    def __call__(self, url, json=None, headers=None, timeout=None, verify=None):
        self.requests.append(
            {"url": url, "timeout": timeout, "verify": verify, **(json or {})}
        )
        answer = self.route(json["query"], json["variables"])
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)

    def lookups(self) -> list[dict]:
        return [r for r in self.requests if "ThreatIntelLookup" in r["query"]]


def recorded(version: str, current: bool = False):
    """Route requests to the replies recorded from OpenCTI 6 or 7. With
    current=True, the revoked indicator is served as not revoked."""

    def route(query, variables):
        if "ThreatIntelRelationships" in query:
            return REPLIES[f"v{version}:relationships:revoked"]
        ioc = variables["filters"]["filters"][0]["values"][0]
        reply = REPLIES[f"v{version}:lookup:{_RECORDED[ioc]}"]
        if current and _RECORDED[ioc] == "revoked":
            reply = copy.deepcopy(reply)
            for edge in reply["data"]["indicators"]["edges"]:
                edge["node"]["revoked"] = False
        return reply

    return route


def server(names=("opencti",), cfg="default", **kw) -> OpenCTIMCPServer:
    return OpenCTIMCPServer(
        config() if cfg == "default" else cfg, provider_names=list(names), **kw
    )


async def lookup(srv, ioc):
    return await srv._dispatch_tool("lookup_ioc", {"ioc": ioc})


def block(outcome, **kw) -> dict:
    return {"outcome": outcome, "version": "1", "queried_at": "t", "matches": [], **kw}


def fake_provider(monkeypatch, name, answer, timeout=5.0) -> list:
    """Install a provider module that only this test knows about; returns the
    (ioc, ioc_type) of each lookup it gets."""
    calls: list = []

    class Adapter:
        def __init__(self):
            self.timeout = timeout

        def lookup(self, ioc, ioc_type):
            calls.append((ioc, ioc_type))
            return answer(ioc) if callable(answer) else answer

    module = types.ModuleType(f"opencti_mcp.providers.{name}")
    module.create = Adapter
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return calls


class MispTransport:
    """Answers the MISP adapter's requests from a route, and records each one."""

    def __init__(self, route):
        self.route = route
        self.requests: list[dict] = []

    def __call__(self, method, url, json=None, headers=None, timeout=None, verify=None):
        path = "/" + url.split("/", 3)[3]
        self.requests.append(
            {
                "method": method,
                "path": path,
                "body": json,
                "headers": headers,
                "timeout": timeout,
                "verify": verify,
            }
        )
        answer = self.route(method, path, json)
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)

    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]


MISP_SHA = "d" * 63 + "4"
_MISP_RECORDED = {
    "11.0.113.10": "ip2",
    "8.8.8.8": "listed",
    MISP_SHA: "sha",
    "11.0.113.20": "composite",
    "11.0.113.99": "none",
    "EVIL-SAMPLE.EXAMPLE": "domain",
}


def misp_recorded(version: str):
    """Route requests to the replies recorded from MISP 2.4 or 2.5."""

    def reply(key):
        recorded = MISP_REPLIES[f"misp{version}:{key}"]
        return httpx.Response(recorded["status"], json=recorded["body"])

    def route(method, path, body):
        if path == "/attributes/restSearch":
            return reply(f"search:{_MISP_RECORDED[body['value']]}")
        if path == "/warninglists/checkValue":
            return reply(f"check:{_MISP_RECORDED[body['value']]}")
        return reply(
            {
                "/servers/getVersion": "version",
                "/warninglists/index": "warninglists",
                "/decayingModel/index": "models",
            }[path]
        )

    return route


def misp_env(monkeypatch, **extra):
    monkeypatch.setenv("MISP_URL", "https://127.0.0.1:9")
    monkeypatch.setenv("MISP_KEY", "0" * 40)
    for name, value in extra.items():
        monkeypatch.setenv(name, value)
