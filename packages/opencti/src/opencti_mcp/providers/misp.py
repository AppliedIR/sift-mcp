"""MISP over its REST API.

Each lookup is one attribute search for the value, matched exactly here
(either half of a composite such as ``domain|ip`` counts), and one warninglist
check of the value. The search never filters on to_ids, published, deleted,
decay or warninglists: the records come back as MISP holds them.

Settings: MISP_URL, MISP_KEY, MISP_SSL_VERIFY (true, false, or a CA bundle
path; default true) and MISP_TIMEOUT (seconds; default 30, at most the lookup
budget is used).

The platform facts (MISP's version and how many warninglists and decaying
models are enabled) are read at most once a minute and never decide an
outcome; each is None when it can't be read.
"""

from __future__ import annotations

import os
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from . import (
    MATCH,
    MAX_MATCHES,
    NO_MATCH,
    ProviderConfigError,
    budget,
    now_utc,
    same_value,
    unavailable,
)

EVENT_FIELDS = ("uuid", "threat_level_id", "analysis", "published")
FACTS_SECONDS = 60.0

# The transport the requests use: None is the network. Tests set a mock one.
_transport: httpx.BaseTransport | None = None


def _send(method, url, *, json, headers, timeout, verify):
    with httpx.Client(verify=verify, timeout=timeout, transport=_transport) as client:
        return client.request(method, url, json=json, headers=headers)


# The one network call; tests replace it.
_http_request = _send


class _Failure(Exception):
    """The request didn't give a usable answer; the message is the reason."""


def _record(attribute: dict) -> dict:
    record = {k: attribute.get(k) for k in ("uuid", "type", "value", "to_ids")}
    if "decay_score" in attribute:
        record["decay_score"] = attribute["decay_score"]
    event = attribute.get("Event")
    if isinstance(event, dict):
        record["Event"] = {k: event[k] for k in EVENT_FIELDS if k in event}
    return record


def _is_the_ioc(attribute: dict, ioc: str) -> bool:
    value = attribute.get("value")
    if not isinstance(value, str):
        return False
    halves = value.split("|") if "|" in str(attribute.get("type", "")) else [value]
    return any(same_value(half, ioc) for half in halves)


def _count_enabled(items: Any, key: str) -> int | None:
    if isinstance(items, dict):
        items = items.get(f"{key}s", items.get(key))
    if not isinstance(items, list):
        return None
    count = 0
    for item in items:
        if not isinstance(item, dict):
            return None
        entry = item.get(key, item)
        if str(entry.get("enabled")).lower() in ("1", "true"):
            count += 1
    return count


class MispAdapter:
    def __init__(self, url: str, key: str, verify: Any, timeout: float) -> None:
        self.url = url
        self.key = key
        self.verify = verify
        self.timeout = budget(timeout)
        self._facts: dict[str, Any] = {
            "version": None,
            "warninglists_enabled": None,
            "decaying_models_enabled": None,
        }
        self._facts_at = 0.0
        self._facts_lock = threading.Lock()

    def _request(self, method: str, path: str, body: Any, deadline: float) -> Any:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Failure(f"timed out after {self.timeout:g}s")
        try:
            response = _http_request(
                method,
                f"{self.url}{path}",
                json=body,
                headers={
                    "Authorization": self.key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=remaining,
                verify=self.verify,
            )
        except httpx.TimeoutException as e:
            raise _Failure(f"timed out after {self.timeout:g}s") from e
        except httpx.HTTPError as e:
            raise _Failure(f"can't reach MISP: {type(e).__name__}: {e}") from e
        try:
            reply = response.json()
        except ValueError:
            reply = None
        if response.status_code != 200:
            detail = ""
            if isinstance(reply, dict):
                detail = str(reply.get("message") or reply.get("name") or "")[:200]
            raise _Failure(
                f"MISP answered HTTP {response.status_code}"
                + (f": {detail}" if detail else "")
            )
        if reply is None:
            raise _Failure("MISP's reply is not JSON")
        return reply

    def _platform_facts(self, deadline: float) -> dict[str, Any]:
        """The facts, refreshed when older than a minute and time is left."""
        with self._facts_lock:
            if time.monotonic() - self._facts_at < FACTS_SECONDS:
                return dict(self._facts)
            facts: dict[str, Any] = {}
            for name, path, read in (
                ("version", "/servers/getVersion", lambda r: r.get("version")),
                (
                    "warninglists_enabled",
                    "/warninglists/index",
                    lambda r: _count_enabled(r, "Warninglist"),
                ),
                (
                    "decaying_models_enabled",
                    "/decayingModel/index",
                    lambda r: _count_enabled(r, "DecayingModel"),
                ),
            ):
                try:
                    reply = self._request("GET", path, None, deadline)
                    value = read(reply) if isinstance(reply, (dict, list)) else None
                except (_Failure, AttributeError):
                    value = None
                facts[name] = value if isinstance(value, (str, int)) else None
            self._facts = facts
            self._facts_at = time.monotonic()
            return dict(facts)

    def lookup(self, ioc: str, ioc_type: str) -> dict:
        queried_at = now_utc()
        deadline = time.monotonic() + self.timeout
        try:
            reply = self._request(
                "POST",
                "/attributes/restSearch",
                {
                    "returnFormat": "json",
                    "value": ioc,
                    "includeContext": 1,
                    "includeDecayScore": 1,
                    "limit": MAX_MATCHES + 1,
                },
                deadline,
            )
            attributes = (reply.get("response") or {}).get("Attribute")
            if not isinstance(attributes, list) or not all(
                isinstance(a, dict) for a in attributes
            ):
                raise _Failure("MISP's reply has an unexpected shape")
            if not all(isinstance(a.get("value"), str) for a in attributes):
                raise _Failure("malformed provider data: an attribute without a value")
        except (_Failure, AttributeError) as e:
            reason = (
                str(e)
                if isinstance(e, _Failure)
                else "MISP's reply has an unexpected shape"
            )
            return unavailable(reason, **self._platform_facts(deadline))

        matches = [_record(a) for a in attributes if _is_the_ioc(a, ioc)]
        if len(attributes) > MAX_MATCHES and not matches:
            # The exact attribute may be past the ones read: not an absence.
            return unavailable(
                f"too many candidate matches: more than {MAX_MATCHES} attributes "
                f"match {ioc}, and none of those read is exactly it",
                **self._platform_facts(deadline),
            )
        answer: dict[str, Any] = {
            "outcome": MATCH if matches else NO_MATCH,
            "queried_at": queried_at,
            "matches": matches[:MAX_MATCHES],
        }
        if len(attributes) > MAX_MATCHES:
            answer["truncated"] = True
            answer["note"] = (
                f"More than {MAX_MATCHES} attributes have the value {ioc}; "
                f"only the first {MAX_MATCHES} are listed."
            )
        try:
            answer["warninglist_hits"] = self._request(
                "POST", "/warninglists/checkValue", {"value": ioc}, deadline
            )
        except _Failure as e:
            answer["warninglist_hits"] = None
            answer["warninglists_unavailable"] = f"Warninglist check failed ({e})."
        facts = self._platform_facts(deadline)
        return {
            "outcome": answer.pop("outcome"),
            "version": facts.pop("version"),
            **answer,
            **facts,
        }


def _verify(raw: str) -> Any:
    value = raw.strip()
    if value.lower() in ("", "true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    if not os.path.isfile(value):
        raise ProviderConfigError(
            f"MISP_SSL_VERIFY names a CA bundle that doesn't exist: {value}"
        )
    return ssl.create_default_context(cafile=value)


def create() -> MispAdapter:
    url = os.getenv("MISP_URL", "").strip().rstrip("/")
    key = os.getenv("MISP_KEY", "").strip()
    if not url:
        raise ProviderConfigError("MISP_URL is not set")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProviderConfigError(f"MISP_URL is not an http(s) URL: {url}")
    if not key:
        raise ProviderConfigError("MISP_KEY is not set")
    raw_timeout = os.getenv("MISP_TIMEOUT", "30")
    try:
        timeout = float(raw_timeout)
    except ValueError as e:
        raise ProviderConfigError(f"MISP_TIMEOUT is not a number: {raw_timeout}") from e
    if timeout <= 0:
        raise ProviderConfigError(f"MISP_TIMEOUT must be positive: {raw_timeout}")
    return MispAdapter(url, key, _verify(os.getenv("MISP_SSL_VERIFY", "true")), timeout)
