"""The report labels a record's stored type from the IOC table, as vhir does.

Every spelling the table accepts, in its own form and in case and separator
variants, is listed under its id's label. A spelling the table refuses is
listed as stored. Records stored before the table keep their bytes.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from report_mcp.server import _extract_all_iocs
from sift_common import ioc_types

from .test_report_ioc_groups import _case_with, _f, _r, _report, _values, case  # noqa: F401

VOCABULARY = Path(__file__).parents[1] / "test_forensic_mcp" / "ioc_vocabulary.json"
DATA = json.loads(VOCABULARY.read_text())
LABEL = {id_: label for _, id_, label in DATA["ids"]}
SPELLINGS = [(id_, id_) for id_ in LABEL]
SPELLINGS += [
    (alias, id_) for id_, aliases in DATA["aliases"].items() for alias in aliases
]


def _forms(s):
    sep = s.replace("-", "_") if "-" in s else s[:1] + "_" + s[1:]
    return {
        "own": s,
        "case": s.upper(),
        "sep": sep,
        "case+sep": " " + s.upper().replace("-", "_") + " ",
    }


ROWS = [
    (form, typed, LABEL[id_])
    for s, id_ in SPELLINGS
    for form, typed in _forms(s).items()
]


def _listed(records):
    return _values(_extract_all_iocs([_f(1)], records, records))


@pytest.mark.parametrize(("form", "typed", "label"), ROWS)
def test_each_accepted_spelling_is_listed_under_its_label(form, typed, label):
    assert _listed([_r(1, "v", typed)]) == {label: ["v"]}


@pytest.mark.parametrize("typed", DATA["refused"])
def test_a_refused_spelling_is_listed_as_stored(typed):
    assert _listed([_r(1, "v", typed)]) == {typed: ["v"]}


@pytest.mark.parametrize("profile", ["full", "ioc"])
def test_the_report_lists_every_spelling_under_its_label(case, profile):  # noqa: F811
    records, want = [], {}
    for n, (s, id_) in enumerate(SPELLINGS):
        for form in ("own", "sep"):
            value = f"value-{form}-{n:03d}"
            records.append(_r(len(records) + 1, value, _forms(s)[form]))
            want.setdefault(LABEL[id_], []).append(value)
    _case_with(case, [_f(1)], records)
    got = _values(_report(case, profile)["iocs"])
    assert got == {k: sorted(want[k]) for k in sorted(want)}


# Records stored before the table, under spellings a case holds: each is
# listed under its id's label, the two the table refuses as stored
OLD = [
    ("file_name", "dropper.dll", "File name"),
    ("account", "CORP\\jdoe", "Account"),
    ("other", "opaque-marker-7", "Unknown"),
    ("url_path", "/admin/shell.aspx", "URL path"),
    ("email-subject", "Invoice overdue", "Email subject"),
    ("imphash", "f34d5f2d4577ed6d9ceec516c1f5a744", "Imphash"),
    ("named-pipe", "\\\\.\\pipe\\msagent_7f", "Named pipe"),
    ("hash", "0123456789abcdef0123456789abcdef", "hash"),
    ("path", "/var/tmp/.x/run", "path"),
]


@pytest.mark.parametrize("profile", ["full", "ioc"])
def test_old_records_are_listed_through_the_table_and_keep_their_bytes(case, profile):  # noqa: F811
    _case_with(
        case,
        [_f(1)],
        [_r(n, value, typed) for n, (typed, value, _) in enumerate(OLD, 1)],
    )
    before = (case / "iocs.json").read_bytes()
    want = {}
    for _, value, label in OLD:
        want.setdefault(label, []).append(value)
    assert _values(_report(case, profile)["iocs"]) == {
        k: sorted(want[k]) for k in sorted(want)
    }
    assert (case / "iocs.json").read_bytes() == before


# One host cited three ways no record holds: bare, with its port, and with its
# port under "unknown". The not-recorded group shows it once, as the bare address.
A, B, C = (
    ("10.20.30.41", None),
    ("10.20.30.41:443", None),
    ("10.20.30.41:443", "unknown"),
)
ORDERS = list(itertools.permutations([A, B, C]))


def _cited(order):
    findings = [_f(n, [{"value": v, "type": t} if t else v], observation="", interpretation="")
                for n, (v, t) in enumerate(order, 1)]  # fmt: skip
    groups = _values(_extract_all_iocs(findings, records=[], all_records=[]))
    return [v for vs in groups.values() for v in vs if v.startswith("10.20.30.41")]


@pytest.mark.parametrize(
    "order", ORDERS, ids=lambda o: " ".join(f"{v}/{t}" for v, t in o)
)
def test_one_host_cited_three_ways_is_listed_once(order):
    assert len(_cited(order)) == 1


@pytest.mark.parametrize(
    "order", ORDERS, ids=lambda o: " ".join(f"{v}/{t}" for v, t in o)
)
def test_the_host_listed_is_the_bare_address(order):
    assert _cited(order) == ["10.20.30.41"]


# Each IOC lists every finding that cites it, however the finding spells it:
# typed or not, with its port or without, or in the finding's text
def test_each_ioc_lists_every_finding_that_cites_it():
    records = [
        {"id": "IOC-tester-001", "value": "10.20.30.51:443", "type": "unknown", "status": "APPROVED"},
        {"id": "IOC-tester-002", "value": "10.20.30.41", "type": "ipv4-addr", "status": "APPROVED"},
    ]  # fmt: skip
    findings = [
        _f(1, [{"value": "10.20.30.51:443", "type": "unknown"}], observation=""),
        _f(2, [{"value": "10.20.30.51:443", "type": "IPv4"}], observation=""),
        _f(3, ["10.20.30.41"], observation=""),
        _f(4, ["10.20.30.41:443"], observation=""),
        _f(5, [], observation="beacon to 10.20.30.41 seen"),
    ]
    groups = _extract_all_iocs(findings, records, records)
    cited = {e["value"]: e["source_findings"] for es in groups.values() for e in es}
    assert cited == {
        "10.20.30.51:443": ["F-tester-001", "F-tester-002"],
        "10.20.30.41": ["F-tester-003", "F-tester-004", "F-tester-005"],
    }


class _Keys(set):
    """A value's keys that count each time they are compared with others."""

    compared = 0

    def __and__(self, other):
        _Keys.compared += 1
        return set(self) & set(other)

    __rand__ = __and__

    def isdisjoint(self, other):
        _Keys.compared += 1
        return set(self).isdisjoint(other)


# The findings an IOC lists are looked up by key, not found by comparing the
# IOC with every citation: twice the IOCs take about twice the comparisons
def test_twice_the_iocs_take_about_twice_the_key_comparisons(monkeypatch):
    keys = ioc_types.keys
    monkeypatch.setattr(ioc_types, "keys", lambda *a: _Keys(keys(*a)))

    def compared(n):
        values = [f"10.20.{i // 200}.{i % 200}" for i in range(n)]
        records = [_r(i, v, "ipv4-addr") for i, v in enumerate(values)]
        findings = [_f(i, [v], observation="") for i, v in enumerate(values)]
        _Keys.compared = 0
        groups = _extract_all_iocs(findings, records, records)
        assert groups == {"IPv4": sorted(
            ({"value": v, "source_findings": [f"F-tester-{i:03d}"]}
             for i, v in enumerate(values)), key=lambda e: e["value"])}  # fmt: skip
        return _Keys.compared

    assert compared(80) <= 2 * compared(40) + 2


# IPv6 addresses typed as IPv4 no record holds are listed whole, as vhir lists them
def test_ipv6_addresses_typed_ipv4_are_listed_whole():
    from vhir_cli.ioc_groups import not_recorded

    pairs = [
        ("2001:db8::1", "IPv4"),
        ("2001:db8::7", "IPv4"),
        ("fe80::1", "ip"),
        ("fe80::2", "ip"),
    ]
    findings = [_f(n, [{"value": v, "type": t}], observation="", interpretation="")
                for n, (v, t) in enumerate(pairs, 1)]  # fmt: skip
    groups = _extract_all_iocs(findings, records=[], all_records=[])
    listed = sorted(e["value"] for es in groups.values() for e in es)
    assert listed == sorted(not_recorded(findings, [])) == sorted(v for v, _ in pairs)
