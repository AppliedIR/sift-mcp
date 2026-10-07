"""Threat-intel providers: one adapter per platform.

Each adapter answers a lookup with the platform's own records for an exact
match of the IOC, passed through under the platform's own field names. No
adapter computes a verdict, score or freshness.

An adapter is a module in this package, named in ``THREATINTEL_PROVIDERS``
(comma-separated; unset means ``opencti``). The module's ``create()`` reads its
own settings and returns an object with a ``lookup(ioc, ioc_type)`` method and
a ``timeout`` in seconds; it raises ``ProviderConfigError`` when a required
setting is missing. ``lookup`` returns::

    {"outcome": "MATCH" | "NO_MATCH" | "UNAVAILABLE",
     "version": <the platform's version, or None>,
     "queried_at": <UTC ISO time>,
     "matches": [<record>, ...],          # every exact match, up to 100
     "truncated": True,                   # only when more than 100 match
     "reason": <why>,                     # UNAVAILABLE only
     ...}                                 # the platform's own facts

Any failure is UNAVAILABLE with the reason, never NO_MATCH. Nothing is cached:
every lookup asks the platform.
"""

from __future__ import annotations

import importlib
import ipaddress
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

MATCH = "MATCH"
NO_MATCH = "NO_MATCH"
UNAVAILABLE = "UNAVAILABLE"
OUTCOMES = frozenset({MATCH, NO_MATCH, UNAVAILABLE})

MAX_MATCHES = 100

# Enrichment calls lookup_ioc with a 15 s timeout: each provider answers, or
# is reported UNAVAILABLE, within this budget.
LOOKUP_BUDGET_SECONDS = 12.0

_NAME_RE = re.compile(r"[a-z][a-z0-9_]*\Z")

# Fuzzy hashes are case-sensitive: SSDEEP is base64 text, and TLSH is compared
# as given.
_SSDEEP_RE = re.compile(r"\d+:[0-9A-Za-z/+]+:[0-9A-Za-z/+]+(,.*)?\Z")
_TLSH_RE = re.compile(r"(T1)?[0-9A-Fa-f]{70}\Z")

_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="threatintel")


class ProviderConfigError(Exception):
    """A provider's required setting is missing or invalid."""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def budget(configured: float) -> float:
    """A provider's lookup time: its own timeout, within the lookup budget."""
    return min(float(configured), LOOKUP_BUDGET_SECONDS)


def unavailable(reason: str, version: str | None = None, **facts: Any) -> dict:
    return {
        "outcome": UNAVAILABLE,
        "version": version,
        "queried_at": now_utc(),
        "matches": [],
        "reason": reason,
        **facts,
    }


def case_sensitive(ioc: str) -> bool:
    return bool(_SSDEEP_RE.match(ioc) or _TLSH_RE.match(ioc))


def same_value(value: Any, ioc: str) -> bool:
    """Whether a platform record's value is exactly the IOC: IP addresses as
    addresses, fuzzy hashes as given, anything else ignoring case."""
    if not isinstance(value, str) or not value:
        return False
    try:
        return ipaddress.ip_address(value) == ipaddress.ip_address(ioc)
    except ValueError:
        pass
    if case_sensitive(ioc):
        return value == ioc
    return value.lower() == ioc.lower()


def configured_names() -> list[str]:
    """The providers named in THREATINTEL_PROVIDERS, in order; unset means
    OpenCTI alone, so an existing configuration keeps working."""
    raw = os.getenv("THREATINTEL_PROVIDERS", "")
    names: list[str] = []
    for name in raw.split(","):
        name = name.strip().lower()
        if name and name not in names:
            names.append(name)
    return names or ["opencti"]


class Unavailable:
    """Stands in for a provider that can't be used, so every lookup says why."""

    timeout = 0.0

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def lookup(self, ioc: str, ioc_type: str) -> dict:
        return unavailable(self.reason)


def load(names: list[str], prebuilt: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build each named provider. A name with no module, or a module that
    can't be set up, becomes an Unavailable provider with the reason: never
    silently left out. ``prebuilt`` supplies adapters built elsewhere."""
    adapters: dict[str, Any] = {}
    for name in names:
        if prebuilt and name in prebuilt:
            adapters[name] = prebuilt[name]
            continue
        if not _NAME_RE.match(name):
            adapters[name] = Unavailable(f"unknown provider '{name}'")
            continue
        module_name = f"{__name__}.{name}"
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as e:
            if e.name == module_name:
                adapters[name] = Unavailable(f"unknown provider '{name}'")
            else:
                adapters[name] = Unavailable(f"provider '{name}' can't be loaded: {e}")
            continue
        except Exception as e:
            adapters[name] = Unavailable(
                f"provider '{name}' can't be loaded: {type(e).__name__}: {e}"
            )
            continue
        try:
            adapters[name] = module.create()
        except ProviderConfigError as e:
            adapters[name] = Unavailable(f"{name} is not configured: {e}")
        except Exception as e:
            adapters[name] = Unavailable(
                f"provider '{name}' can't be set up: {type(e).__name__}: {e}"
            )
    return adapters


def _checked(answer: Any) -> dict:
    """An adapter's answer, or UNAVAILABLE when its shape isn't the contract's."""
    if (
        not isinstance(answer, dict)
        or answer.get("outcome") not in OUTCOMES
        or not isinstance(answer.get("matches"), list)
    ):
        return unavailable("the provider gave an answer of an unexpected shape")
    if answer["outcome"] == UNAVAILABLE and not answer.get("reason"):
        answer["reason"] = "no reason given"
    return answer


def _ask(adapter: Any, ioc: str, ioc_type: str) -> dict:
    try:
        return _checked(adapter.lookup(ioc, ioc_type))
    except Exception as e:
        logger.warning("Threat-intel provider failed: %s: %s", type(e).__name__, e)
        return unavailable(f"{type(e).__name__}: {e}")


def lookup_all(adapters: dict[str, Any], ioc: str, ioc_type: str) -> dict[str, dict]:
    """Ask every provider at once; each answers within its budget, or is
    UNAVAILABLE ("timed out")."""
    start = time.monotonic()
    futures = {
        name: (adapter, _POOL.submit(_ask, adapter, ioc, ioc_type))
        for name, adapter in adapters.items()
    }
    answers: dict[str, dict] = {}
    for name, (adapter, future) in futures.items():
        limit = budget(getattr(adapter, "timeout", LOOKUP_BUDGET_SECONDS))
        # A second's grace: the adapter's own requests time out first.
        wait = max(0.0, start + limit + 1.0 - time.monotonic())
        try:
            answers[name] = future.result(timeout=wait)
        except FutureTimeout:
            future.cancel()
            answers[name] = unavailable(f"timed out after {limit:g}s")
    return answers


def aggregate(answers: dict[str, dict]) -> str:
    """MATCH when any provider matched; otherwise UNAVAILABLE when any
    couldn't be asked; otherwise NO_MATCH."""
    outcomes = {answer["outcome"] for answer in answers.values()}
    if MATCH in outcomes:
        return MATCH
    if UNAVAILABLE in outcomes or not outcomes:
        return UNAVAILABLE
    return NO_MATCH
