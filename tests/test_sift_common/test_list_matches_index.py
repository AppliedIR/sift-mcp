"""The host list's matching answers exactly as it always has, now from names
worked out once per entry and an index per list: a seeded comparison with the
plain rule over random lists and names. Names are synthetic."""

from __future__ import annotations

import random

import pytest
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

SHORTS = ["WKS01", "wks01", "DC01", "SRV-DUP1", "srv-dup1", "FS9"]
DOMAINS = [
    "",
    "corp.example.test",
    "CORP.example.test",
    "acq.example.test",
    "eu.corp.example.test",
]
ADDRESSES = ["10.1.2.3", "010.001.002.003", "fe80::1", "[2001:db8::1]:445"]


def _plain(raw: str, entries: list[dict]) -> list[dict]:
    """The rule, computed from scratch for every entry and name."""
    if hp.is_address(raw):
        return []
    s = hi.spelling(raw)
    short, domain = hi.split_name(raw)
    found = []
    for e in entries:
        names = [
            e["name"],
            *([e["fqdn"]] if e.get("fqdn") else []),
            *(e.get("aliases") or []),
        ]
        names = [n for n in names if isinstance(n, str) and n and not hp.is_address(n)]
        ed = next((hi.split_name(n)[1] for n in names if hi.split_name(n)[1]), "")
        if any(hi.spelling(n) == s or (hi.split_name(n)[0] == short
                                        and (not domain or not ed or domain == ed))
               for n in names):  # fmt: skip
            found.append(e)
    return found


def _name(rng) -> str:
    if rng.random() < 0.1:
        return rng.choice(ADDRESSES)
    d = rng.choice(DOMAINS)
    n = rng.choice(SHORTS) + (f".{d}" if d else "")
    return n + ("." if rng.random() < 0.05 else "")


def _entry(rng) -> dict:
    e = {"name": _name(rng)}
    if rng.random() < 0.4:
        e["fqdn"] = _name(rng)
    if rng.random() < 0.3:
        e["aliases"] = [_name(rng) for _ in range(rng.randint(1, 3))]
    return e


@pytest.mark.parametrize("seed", range(40))
def test_the_indexed_matching_answers_as_the_plain_rule(seed):
    rng = random.Random(seed)
    entries = [_entry(rng) for _ in range(rng.randint(0, 30))]
    for _ in range(60):
        raw = _name(rng)
        assert hp.list_matches(raw, entries) == _plain(raw, entries), (raw, entries)


def test_an_entry_list_that_grows_in_place_is_seen():
    entries = [{"name": "WKS01"}]
    assert hp.list_matches("DC01", entries) == []
    entries.append({"name": "DC01"})
    assert hp.list_matches("DC01", entries) == [{"name": "DC01"}]
