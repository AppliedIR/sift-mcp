"""A citation joins every IOC record that is the same IOC.

Two values are the same IOC when they share a key: the value as given, the
value refanged, or the value under its type, where an IPv4 address loses its
port. A citation joins each record it matches and keeps that record's type,
status and signed view. The reply says when the type given was not applied,
when every record the citation joined was rejected, and when an address with
a port was kept apart from a record of the bare address.
"""

from __future__ import annotations

import itertools
import json
import os
import stat
from pathlib import Path

import pytest
from vhir_cli.case_io import signed_text

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    _record,
    case,
    home,
)

PATH = "C:\\Windows\\Temp\\dropper.exe"
SHA = "a" * 63 + "1"


def _cite(*iocs, **fields) -> dict:
    result = _record({**FINDING, "iocs": list(iocs), **fields})
    assert result["status"] == "STAGED", result
    return result


def _warnings(result: dict) -> list[str]:
    joined = [w for w in (result.get("warning") or "").split(" | ") if w]
    return joined + list(result.get("warnings") or [])


def _records(case: Path) -> list[dict]:
    path = case / "iocs.json"
    return json.loads(path.read_text()) if path.is_file() else []


def _on(case: Path, prefix: str) -> list[dict]:
    return [r for r in _records(case) if str(r.get("value")).startswith(prefix)]


def _old(rid, value, type_, category, status="DRAFT", **extra) -> dict:
    """A record as an older writer stored it."""
    return {
        "id": rid,
        "value": value,
        "type": type_,
        "category": category,
        "description": "",
        "status": status,
        "confidence": "LOW",
        "source_findings": ["F-old-001"],
        "sightings": [{"host": "WKSTN01", "finding_id": "F-old-001"}],
        "mitre_techniques": [],
        "tags": [],
        "manually_reviewed": False,
        "examiner": "tester",
        "created_at": "2026-01-01T00:00:00+00:00",
        "modified_at": "2026-01-01T00:00:00+00:00",
        **extra,
    }


def _store(case: Path, *records: dict) -> None:
    """Add records to iocs.json as an older writer left them: the case keeps
    the file read-only, so its mode is put back after the write."""
    path = case / "iocs.json"
    mode = stat.S_IMODE(path.stat().st_mode) if path.is_file() else None
    if mode is not None:
        os.chmod(path, mode | stat.S_IWUSR)
    path.write_text(json.dumps([*_records(case), *records], indent=2))
    if mode is not None:
        os.chmod(path, mode)


def _rejected(rid: str, value: str, type_: str, category: str) -> dict:
    return _old(
        rid,
        value,
        type_,
        category,
        status="REJECTED",
        rejected_by="tester",
        rejection_reason="not this host",
        rejected_at="2026-01-02T00:00:00+00:00",
    )


# --- one record for one IOC ------------------------------------------------


def test_an_address_with_its_port_and_without_in_two_findings_is_one_record(case):  # noqa: F811
    first = _cite({"value": "10.20.30.41:443", "type": "IPv4"})
    second = _cite("10.20.30.41")
    (record,) = _on(case, "10.20.30.41")
    assert record["value"] == "10.20.30.41"
    assert sorted(record["source_findings"]) == sorted(
        [first["finding_id"], second["finding_id"]]
    )


def test_an_address_with_its_port_and_without_in_one_finding_is_one_record(case):  # noqa: F811
    _cite({"value": "10.20.30.71:443", "type": "IPv4"}, "10.20.30.71")
    assert len(_on(case, "10.20.30.71")) == 1


def test_one_value_twice_in_one_finding_is_one_record(case):  # noqa: F811
    entry = {"value": "10.20.30.72:443", "type": "unknown"}
    _cite(entry, dict(entry))
    assert len(_on(case, "10.20.30.72")) == 1


def test_two_defangings_of_one_value_in_one_finding_are_one_record(case):  # noqa: F811
    _cite("user[[@]]evilk.example.com", "user[@]evilk.example.com")
    assert len([r for r in _records(case) if "evilk" in r["value"]]) == 1


def test_a_case_folded_and_a_defanged_spelling_in_one_finding_are_one_record(case):  # noqa: F811
    _cite("USER@EVILC.EXAMPLE.COM", "user[@]evilc.example.com")
    assert len([r for r in _records(case) if "evilc" in r["value"].lower()]) == 1


@pytest.mark.parametrize(
    "value",
    [
        "user[[@]]evil6.example.com",
        "10.20.30.77[[:]]443",
        "evil6[[].]example.com",
        "hxxp[[:]]//evil6.example.com/a",
    ],
)
def test_a_double_bracket_defang_cited_twice_is_one_record(case, value):  # noqa: F811
    _cite(value)
    _cite(value)
    assert len(_records(case)) == 1


# Each spelling of one mailbox, and the value it is stored as when it is cited first.
MAILBOX = {
    "user[@]evil7.example.com": "user@evil7.example.com",
    "user[[@]]evil7.example.com": "user@evil7.example.com",
    "USER@EVIL7.EXAMPLE.COM": "USER@EVIL7.EXAMPLE.COM",
}


@pytest.mark.parametrize("order", list(itertools.permutations(MAILBOX)))
def test_three_spellings_of_a_mailbox_in_separate_findings_are_one_record(case, order):  # noqa: F811
    ids = [_cite({"value": v, "type": "email-addr"})["finding_id"] for v in order]
    records = _records(case)
    assert len(records) == 1, records
    assert records[0]["value"] == MAILBOX[order[0]]
    assert sorted(records[0]["source_findings"]) == sorted(ids)


@pytest.mark.parametrize(
    ("spellings", "type_", "live"),
    [
        (
            [
                "user[[[@]]]evil8.example.com",
                "user[@]evil8.example.com",
                "user@evil8.example.com",
            ],
            "email-addr",
            "user@evil8.example.com",
        ),
        (
            ["evil9[[.]]example[.]com", "evil9[.]example[[.]]com", "evil9.example.com"],
            "domain-name",
            "evil9.example.com",
        ),
        (
            [
                "evil11[[[.]]]example[.]com",
                "evil11[.]example[[.]]com",
                "evil11.example.com",
            ],
            "domain-name",
            "evil11.example.com",
        ),
        (
            ["10[[.]]20[.]30[[[.]]]78", "10[.]20[.]30[.]78", "10.20.30.78"],
            "ipv4-addr",
            "10.20.30.78",
        ),
    ],
)
def test_bracket_defangs_of_any_depth_are_one_live_record(case, spellings, type_, live):  # noqa: F811
    ids = [_cite({"value": v, "type": type_})["finding_id"] for v in spellings]
    records = _records(case)
    assert [r["value"] for r in records] == [live]
    assert sorted(records[0]["source_findings"]) == sorted(ids)


@pytest.mark.parametrize(
    ("value", "live"),
    [
        ("user[[@]]evil10.example.com", "user@evil10.example.com"),
        ("user[[[@]]]evil10.example.com", "user@evil10.example.com"),
        ("evil10[[.]]example[[.]]com", "evil10.example.com"),
        ("evil10[[[.]]]example[[.]]com", "evil10.example.com"),
        ("hxxp[[:]]//evil10.example.com/a", "http://evil10.example.com/a"),
    ],
)
def test_a_nested_bracket_defang_is_stored_live(case, value, live):  # noqa: F811
    _cite(value)
    assert [r["value"] for r in _records(case)] == [live]


def test_two_ports_of_one_address_typed_unknown_are_two_records(case):  # noqa: F811
    _cite({"value": "10.20.30.73:443", "type": "unknown"})
    _cite({"value": "10.20.30.73:8080", "type": "unknown"})
    assert len(_on(case, "10.20.30.73")) == 2


def test_an_address_and_its_port_typed_as_a_domain_are_two_records(case):  # noqa: F811
    _cite("10.20.30.74")
    _cite({"value": "10.20.30.74:443", "type": "domain-name"})
    assert len(_on(case, "10.20.30.74")) == 2


def test_an_address_with_its_port_typed_unknown_then_ipv4_is_one_record(case):  # noqa: F811
    _cite({"value": "10.20.30.76:443", "type": "unknown"})
    _cite({"value": "10.20.30.76:443", "type": "IPv4"})
    assert len(_on(case, "10.20.30.76")) == 1


# --- records an older writer stored ----------------------------------------


def test_a_citation_joins_every_old_record_of_its_address(case):  # noqa: F811
    _store(
        case,
        _old("IOC-old-001", "10.20.30.41:443", "IPv4", "network"),
        _old("IOC-old-002", "10.20.30.41", "ipv4-addr", "network"),
    )
    result = _cite({"value": "10.20.30.41", "type": "ipv4-addr"})
    records = _records(case)
    assert [r["id"] for r in records] == ["IOC-old-001", "IOC-old-002"]
    assert all(result["finding_id"] in r["source_findings"] for r in records)


def test_the_bare_address_joins_an_old_record_that_kept_its_port(case):  # noqa: F811
    _store(case, _old("IOC-old-001", "10.20.30.41:443", "IPv4", "network"))
    result = _cite({"value": "10.20.30.41", "type": "ipv4-addr"})
    (record,) = _records(case)
    assert result["finding_id"] in record["source_findings"]


def test_an_old_half_defanged_mailbox_keeps_its_value_and_joins_each_spelling(case):  # noqa: F811
    _store(
        case, _old("IOC-old-008", "user[@]evil12.example.com", "email-addr", "network")
    )
    spellings = [
        "user@evil12.example.com",
        "user[[@]]evil12.example.com",
        "USER@EVIL12.EXAMPLE.COM",
    ]
    ids = [_cite({"value": v, "type": "email-addr"})["finding_id"] for v in spellings]
    (record,) = _records(case)
    assert record["value"] == "user[@]evil12.example.com"
    assert set(ids) <= set(record["source_findings"])


def test_an_old_defanged_url_joins_a_citation_in_upper_case(case):  # noqa: F811
    _store(case, _old("IOC-old-007", "hxxp://evil7.example.com/a", "url", "network"))
    result = _cite({"value": "HXXP://evil7.example.com/a", "type": "url"})
    (record,) = _records(case)
    assert result["finding_id"] in record["source_findings"]


@pytest.mark.parametrize(
    ("old", "cited"),
    [
        (
            _old("IOC-old-008", "10.20.30.41:443", "unknown", "unknown"),
            {"value": "10.20.30.41:443", "type": "IPv4"},
        ),
        (
            _old(
                "IOC-old-009",
                "10.20.30.41:443",
                "IPv4",
                "host",
                status="APPROVED",
                approved_by="tester",
                approved_at="2026-01-02T00:00:00+00:00",
            ),  # fmt: skip
            {"value": "10.20.30.41", "type": "ipv4-addr"},
        ),
    ],
    ids=["port-record-typed-unknown", "approved-port-record"],
)
def test_an_old_port_record_gains_the_citation_and_keeps_its_status_and_view(
    case,  # noqa: F811
    old,
    cited,
):
    _store(case, old)
    (before,) = _records(case)
    result = _cite(cited)
    (after,) = _records(case)
    assert after["id"] == old["id"]
    assert result["finding_id"] in after["source_findings"]
    assert after["status"] == old["status"]
    assert signed_text(after, "ioc") == signed_text(before, "ioc")


OLD_MERGED = [
    _old("IOC-old-001", "10.20.30.93", "IPv4", "host"),
    _old("IOC-old-002", "C:\\Windows\\Temp\\old.exe", "file_path", "host"),
    _rejected("IOC-old-003", "10.20.30.94", "ipv4-addr", "network"),
]
# A merge adds the citation; every other key keeps its stored value
DERIVED = {
    "source_findings",
    "sightings",
    "confidence",
    "mitre_techniques",
    "modified_at",
    "content_hash",
}


def _merge_old(case: Path) -> tuple[dict, dict]:
    _store(case, *OLD_MERGED)
    before = {r["id"]: r for r in _records(case)}
    _cite(
        {"value": "10.20.30.93", "type": "ipv4-addr"},
        {"value": "C:\\Windows\\Temp\\old.exe", "type": "file:path"},
        {"value": "10.20.30.94", "type": "ipv4-addr"},
    )
    after = {r["id"]: r for r in _records(case)}
    assert sorted(after) == sorted(before)
    assert all(len(r["source_findings"]) == 2 for r in after.values())
    return before, after


def test_a_merge_into_an_old_record_keeps_its_signed_view(case):  # noqa: F811
    before, after = _merge_old(case)
    assert {i: signed_text(after[i], "ioc") for i in after} == {
        i: signed_text(before[i], "ioc") for i in before
    }


def test_a_merge_into_an_old_record_keeps_every_key_it_doesnt_derive(case):  # noqa: F811
    before, after = _merge_old(case)
    changed = {
        i: sorted(
            k
            for k in set(before[i]) | set(after[i])
            if k not in DERIVED and before[i].get(k) != after[i].get(k)
        )
        for i in before
    }
    assert changed == {i: [] for i in before}


def test_a_merge_keeps_the_records_status_and_signed_view(case):  # noqa: F811
    _cite({"value": "10.20.30.78", "type": "ipv4-addr"}, host="WKSTN01")
    (before,) = _records(case)
    _cite(
        {"value": "10.20.30.78", "type": "ipv4-addr"},
        host="WKSTN02",
        mitre_ids=["T1071"],
    )
    (after,) = _records(case)
    assert signed_text(after, "ioc") == signed_text(before, "ioc")
    assert after.get("status") == before.get("status")
    assert len(after["sightings"]) == len(before["sightings"]) + 1


# --- what the reply says ---------------------------------------------------


def test_a_type_not_applied_is_named_with_the_record_and_its_type(case):  # noqa: F811
    _cite({"value": PATH, "type": "file_path"})
    result = _cite({"value": PATH, "type": "file:name"})
    (record,) = _records(case)
    named = [
        w
        for w in _warnings(result)
        if record["id"] in w and "file:name" in w and "file:path" in w
    ]
    assert named, _warnings(result)


def test_the_joined_record_keeps_its_type_and_gains_the_finding(case):  # noqa: F811
    _cite({"value": PATH, "type": "file_path"})
    (before,) = _records(case)
    result = _cite({"value": PATH, "type": "file:name"})
    (record,) = _records(case)
    assert record["type"] == before["type"]
    assert result["finding_id"] in record["source_findings"]


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ({"value": SHA, "type": "sha256"}, {"value": SHA, "type": "SHA-256"}),
        (
            {"value": "10.20.30.79:443", "type": "IPv4"},
            {"value": "10.20.30.79", "type": "ipv4-addr"},
        ),
    ],
    ids=["hash alias", "address alias"],
)
def test_another_spelling_of_the_stored_type_carries_no_type_warning(
    case,  # noqa: F811
    first,
    second,
):
    _cite(first)
    result = _cite(second)
    assert not [w for w in _warnings(result) if "type" in w.lower()]


def test_another_spelling_of_an_old_records_type_carries_no_type_warning(case):  # noqa: F811
    _store(case, _old("IOC-old-001", "10.20.30.79:443", "IPv4", "network"))
    result = _cite({"value": "10.20.30.79", "type": "ipv4-addr"})
    (record,) = _records(case)
    assert result["finding_id"] in record["source_findings"]
    assert not [w for w in _warnings(result) if "type" in w.lower()]


def _kept_apart(result: dict, record: dict, type_: str) -> list[str]:
    return [
        w
        for w in _warnings(result)
        if record["id"] in w and str(record["type"]) in w and type_ in w
    ]


@pytest.mark.parametrize(
    ("first", "second", "type_"),
    [
        (
            {"value": "10.20.30.75:443", "type": "IPv4"},
            {"value": "10.20.30.75:443", "type": "unknown"},
            "unknown",
        ),
        (
            {"value": "10.20.30.86", "type": "IPv4"},
            {"value": "10[.]20[.]30[.]86[:]443", "type": "unknown"},
            "unknown",
        ),
        (
            "10.20.30.87",
            {"value": "10.20.30.87:443", "type": "domain-name"},
            "domain-name",
        ),
    ],
    ids=["port typed unknown", "defanged", "typed as a domain"],
)
def test_an_address_kept_apart_from_its_record_is_named(case, first, second, type_):  # noqa: F811
    _cite(first)
    (record,) = _records(case)
    result = _cite(second)
    assert len(_records(case)) == 2
    assert _kept_apart(result, record, type_), _warnings(result)


def test_an_address_kept_apart_in_the_same_finding_is_named(case):  # noqa: F811
    result = _cite(
        {"value": "10.20.30.85", "type": "IPv4"},
        {"value": "10.20.30.85:443", "type": "unknown"},
    )
    records = _records(case)
    assert len(records) == 2
    (bare,) = [r for r in records if r["value"] == "10.20.30.85"]
    assert _kept_apart(result, bare, "unknown"), _warnings(result)


def _rejections(result: dict) -> list[str]:
    return [w for w in _warnings(result) if "REJECT" in w.upper()]


def test_a_citation_that_joins_a_rejected_record_and_another_isnt_warned(case):  # noqa: F811
    _store(
        case,
        _rejected("IOC-old-001", "10.20.30.81:443", "IPv4", "network"),
        _old("IOC-old-002", "10.20.30.81", "ipv4-addr", "network"),
    )
    result = _cite({"value": "10.20.30.81", "type": "ipv4-addr"})
    records = _records(case)
    assert [r["id"] for r in records] == ["IOC-old-001", "IOC-old-002"]
    assert all(result["finding_id"] in r["source_findings"] for r in records)
    assert not _rejections(result)


def test_a_citation_that_joins_only_rejected_records_names_each(case):  # noqa: F811
    _store(
        case,
        _rejected("IOC-old-001", "10.20.30.81:443", "IPv4", "network"),
        _rejected("IOC-old-002", "10.20.30.81", "ipv4-addr", "network"),
    )
    result = _cite({"value": "10.20.30.81", "type": "ipv4-addr"})
    assert [r["id"] for r in _records(case)] == ["IOC-old-001", "IOC-old-002"]
    rejections = _rejections(result)
    assert all(any(i in w for w in rejections) for i in ("IOC-old-001", "IOC-old-002"))


COMPLETENESS = "in text but not in iocs list"


def test_an_address_in_the_text_cited_with_its_port_isnt_called_missing(case):  # noqa: F811
    result = _cite(
        {"value": "10.20.30.41:443", "type": "IPv4"},
        observation="beacon to 10.20.30.41 seen",
    )
    assert not [w for w in _warnings(result) if COMPLETENESS in w]


def test_a_citation_joining_a_port_record_isnt_called_missing(case):  # noqa: F811
    _cite({"value": "10.20.30.51:443", "type": "unknown"})
    result = _cite(
        {"value": "10.20.30.51:443", "type": "IPv4"},
        observation="beacon to 10.20.30.51 seen",
    )
    assert len(_records(case)) == 1
    assert not [w for w in _warnings(result) if COMPLETENESS in w]


# --- the finding's own entries ---------------------------------------------

BLANKS = ("  ", "\t", "\n")  # each read as a left-out type
AS_ENTERED = [
    ({"value": "10.20.30.40", "type": "IPv4"}, "ipv4-addr"),
    ({"value": PATH, "type": "file_path"}, "file:path"),
    ({"value": SHA, "type": "sha256"}, "file:hash:sha256"),
    ({"value": "bad.example.org", "type": "Domain Name"}, "domain-name"),
    ({"value": SHA, "type": "SHA-256"}, "file:hash:sha256"),
    ({"value": "10.20.30.45", "type": "  "}, ""),
    *[
        ({"value": f"10.20.30.46:{port}", "type": blank}, "")
        for blank in BLANKS
        for port in (443, 8080)
    ],
]


@pytest.mark.parametrize(("entry", "type_"), AS_ENTERED, ids=lambda x: json.dumps(x))
def test_the_finding_stores_each_entry_under_its_types_id(case, entry, type_):  # noqa: F811
    result = _cite(entry)
    findings = json.loads((case / "findings.json").read_text())
    (stored,) = [f for f in findings if f["id"] == result["finding_id"]]
    assert stored["iocs"] == [{**entry, "type": type_}]


def test_the_audit_keeps_the_type_as_given(case):  # noqa: F811
    result = _cite({"value": "10.20.30.40", "type": "IPv4"})
    audit = case / "audit" / "forensic-mcp.jsonl"
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    (entry,) = [
        e
        for e in entries
        if e.get("tool") == "record_finding"
        and e.get("result_summary", {}).get("finding_id") == result["finding_id"]
    ]
    assert entry["params"]["finding"]["iocs"] == [
        {"value": "10.20.30.40", "type": "IPv4"}
    ]
