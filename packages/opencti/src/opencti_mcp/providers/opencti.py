"""OpenCTI over its GraphQL API, without pycti.

One request per lookup: the server's version and every indicator whose name is
exactly the IOC, with a fixed selection that is valid on OpenCTI 6 and 7. If it
fails validation (a field the server doesn't have), the provider is
UNAVAILABLE. When indicators match, one more request reads their relationships.
"""

from __future__ import annotations

import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..config import Config
from ..errors import ConfigurationError
from . import (
    MATCH,
    MAX_IN_FLIGHT,
    MAX_MATCHES,
    NO_MATCH,
    ProviderConfigError,
    budget,
    follow_up,
    now_utc,
    same_value,
    unavailable,
)

SELECTION = (
    "id name created revoked confidence x_opencti_score valid_from valid_until "
    "x_opencti_detection indicator_types objectLabel { value }"
)

LOOKUP_QUERY = (
    "query ThreatIntelLookup($filters: FilterGroup, $first: Int) {"
    " about { version }"
    " indicators(first: $first, filters: $filters) {"
    f" pageInfo {{ globalCount }} edges {{ node {{ {SELECTION} }} }} }} }}"
)

MAX_RELATIONSHIPS = 500

RELATIONSHIPS_QUERY = (
    "query ThreatIntelRelationships($fromId: [String], $first: Int) {"
    " stixCoreRelationships(fromId: $fromId, first: $first) {"
    " pageInfo { globalCount } edges { node {"
    " id relationship_type from { ... on BasicObject { id } }"
    " to { ... on BasicObject { id entity_type }"
    " ... on AttackPattern { name x_mitre_id } ... on Malware { name }"
    " ... on IntrusionSet { name } ... on ThreatActorGroup { name } } } } } }"
)

# Leave at least this much of the budget for the relationships request;
# with less, they are reported unavailable rather than started.
RELATIONSHIPS_MIN_SECONDS = 1.0

# The transport the requests use: None is the network. Tests set a mock one.
_transport: httpx.BaseTransport | None = None


def _post(url, *, json, headers, timeout, verify):
    with httpx.Client(verify=verify, timeout=timeout, transport=_transport) as client:
        return client.post(url, json=json, headers=headers)


# The one network call; tests replace it.
_http_post = _post


class _Failure(Exception):
    """The request didn't give a usable answer; the message is the reason."""

    data: dict | None = None  # what the reply did hold, if anything


# Candidates for a literal IP address in error text; each is checked with
# ipaddress, so a time such as 10:48:01 is left alone.
_ADDRESS = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"
)


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _redact(text: str, url: str, ioc: str) -> str:
    """Error text without the server's address: its configured host name and
    any literal IP address other than the IOC looked up. The reason and
    everything else stay."""
    host = urlsplit(url).hostname
    if host:
        text = re.sub(re.escape(host), "<OpenCTI host>", text, flags=re.IGNORECASE)
    return _ADDRESS.sub(
        lambda m: (
            "<IP address>" if m.group() != ioc and _is_address(m.group()) else m.group()
        ),
        text,
    )


def _name_eq(ioc: str) -> dict:
    return {
        "mode": "and",
        "filters": [{"key": ["name"], "values": [ioc], "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }


def _describe(errors: Any) -> str:
    if not isinstance(errors, list) or not errors:
        return "GraphQL error"
    first = errors[0] if isinstance(errors[0], dict) else {}
    code = (first.get("extensions") or {}).get("code") or first.get("name") or ""
    message = str(first.get("message", ""))[:200]
    if code == "DATABASE_ERROR":
        return f"provider storage error: {message}"
    if code in ("AUTH_REQUIRED", "FORBIDDEN_ACCESS"):
        return f"OpenCTI refused the token ({code}): {message}"
    return f"GraphQL error ({code or 'no code'}): {message}"


class OpenCTIAdapter:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.timeout = budget(config.timeout_seconds)
        # The relationships request runs here, so a slow one can't hold back
        # the answer to the lookup.
        self._follow_ups = ThreadPoolExecutor(
            max_workers=MAX_IN_FLIGHT, thread_name_prefix="opencti-follow-up"
        )

    def _query(self, query: str, variables: dict, deadline: float) -> dict:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Failure(f"timed out after {self.timeout:g}s")
        try:
            response = _http_post(
                f"{self.config.opencti_url}/graphql",
                json={"query": query, "variables": variables},
                headers={
                    "Authorization": "Bearer "
                    + self.config.opencti_token.get_secret_value()
                },
                timeout=remaining,
                verify=self.config.ssl_verify,
            )
        except httpx.TimeoutException as e:
            raise _Failure(f"timed out after {self.timeout:g}s") from e
        except httpx.HTTPError as e:
            raise _Failure(f"can't reach OpenCTI: {type(e).__name__}: {e}") from e
        if response.status_code in (401, 403):
            raise _Failure(f"OpenCTI refused the token (HTTP {response.status_code})")
        if response.status_code != 200:
            raise _Failure(f"OpenCTI answered HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as e:
            raise _Failure("OpenCTI's reply is not JSON") from e
        if not isinstance(body, dict):
            raise _Failure("OpenCTI's reply has an unexpected shape")
        if body.get("errors"):
            failure = _Failure(_describe(body["errors"]))
            if isinstance(body.get("data"), dict):
                failure.data = body["data"]
            raise failure
        if not isinstance(body.get("data"), dict):
            raise _Failure("OpenCTI's reply has no data")
        return body["data"]

    @staticmethod
    def _nodes(connection: Any, named: bool = False) -> list[dict]:
        if not isinstance(connection, dict) or not isinstance(
            connection.get("edges"), list
        ):
            raise _Failure("OpenCTI's reply has an unexpected shape")
        nodes = [
            edge.get("node") if isinstance(edge, dict) else None
            for edge in connection["edges"]
        ]
        if not all(isinstance(node, dict) for node in nodes):
            raise _Failure("OpenCTI's reply has an unexpected shape")
        if named and not all(isinstance(node.get("name"), str) for node in nodes):
            raise _Failure("malformed provider data: an indicator without a name")
        return nodes

    def lookup(self, ioc: str, ioc_type: str) -> dict:
        queried_at = now_utc()
        deadline = time.monotonic() + self.timeout
        version = None
        try:
            data = self._query(
                LOOKUP_QUERY,
                {"filters": _name_eq(ioc), "first": MAX_MATCHES + 1},
                deadline,
            )
            version = (data.get("about") or {}).get("version")
            connection = data.get("indicators")
            nodes = self._nodes(connection, named=True)
            total = (connection.get("pageInfo") or {}).get("globalCount")
        except _Failure as e:
            if version is None and e.data:
                version = (e.data.get("about") or {}).get("version")
            return unavailable(_redact(str(e), self.config.opencti_url, ioc), version)

        # The server's `eq` ignores case; fuzzy hashes are compared as given.
        matches = [node for node in nodes if same_value(node.get("name"), ioc)]
        truncated = len(nodes) > MAX_MATCHES or (
            isinstance(total, int) and total > MAX_MATCHES
        )
        if truncated and not matches:
            # The exact record may be past the ones read: not an absence.
            return unavailable(
                f"too many candidate matches: {total} indicators are named like "
                f"{ioc}, and none of the first {len(nodes)} is exactly it",
                version,
            )
        answer: dict[str, Any] = {
            "outcome": MATCH if matches else NO_MATCH,
            "version": version,
            "queried_at": queried_at,
            "matches": matches[:MAX_MATCHES],
        }
        if truncated:
            answer["truncated"] = True
            answer["note"] = (
                f"{total if isinstance(total, int) else 'More than ' + str(MAX_MATCHES)}"
                f" indicators are named {ioc}; only the first {MAX_MATCHES} are listed."
            )
        if matches and deadline - time.monotonic() < RELATIONSHIPS_MIN_SECONDS:
            answer["relationships"] = []
            answer["relationships_unavailable"] = (
                "Relationships were not read: the lookup's time ran out. "
                "The related lists are incomplete."
            )
        elif matches:
            variables = {
                "fromId": [m["id"] for m in answer["matches"]],
                "first": MAX_RELATIONSHIPS,
            }
            try:
                data, late = follow_up(
                    self._follow_ups,
                    lambda: self._query(RELATIONSHIPS_QUERY, variables, deadline),
                    deadline,
                )
                if late:
                    raise _Failure(f"{late} after {self.timeout:g}s")
                connection = data.get("stixCoreRelationships")
                answer["relationships"] = self._nodes(connection)
                count = (connection.get("pageInfo") or {}).get("globalCount")
                if isinstance(count, int) and count > MAX_RELATIONSHIPS:
                    answer["relationships_truncated"] = True
            except _Failure as e:
                answer["relationships"] = []
                reason = _redact(str(e), self.config.opencti_url, ioc)
                answer["relationships_unavailable"] = (
                    f"Relationships query failed ({reason}): the related lists are "
                    "incomplete."
                )
        return answer


def create(config: Config | None = None) -> OpenCTIAdapter:
    if config is None:
        try:
            config = Config.load()
        except ConfigurationError as e:
            raise ProviderConfigError(str(e)) from e
    return OpenCTIAdapter(config)
