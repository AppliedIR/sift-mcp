"""The report's IOC section lists the case's approved IOC records, each under
its type's label, as vhir's `report` and the Portal list them; a record with
no type takes the text pattern that matches all of its value, else "Unknown";
a type that isn't a string is shown as str(type). Last, in one group, the
values the approved findings name, in their iocs or their text, that no record
of the case holds, whatever its status. Values compare as forensic-mcp keys
them. The shapes and the dry-run case (fixtures/) are the ones vhir's own rows
use, so every view gives the same groups. Approved means verified."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from report_mcp import server as rs
from report_mcp.profiles import PROFILES
from report_mcp.server import _IOC_LABELS, _TEXT_ONLY, _extract_all_iocs, _ioc_key
from vhir_signing import sign_approved

FIXTURE = Path(__file__).parent.parent / "fixtures"
TEXT_ONLY = _TEXT_ONLY
UNC = "\\\\172.16.6.12\\c$\\Users"  # as stored: two leading backslashes
SID = "S-1-5-21-2838623409-1327563992-2591358621-1136"
SHA = "AB" * 32
NOTE = "Seen on the host."


def _f(n, iocs=None, observation=NOTE, interpretation="", **extra):
    f = {"id": f"F-tester-{n:03d}", "status": "APPROVED", "title": f"t{n}",
         "observation": observation, "interpretation": interpretation, **extra}  # fmt: skip
    if iocs is not None:
        f["iocs"] = iocs
    return f


def _r(n, value, type_, status="APPROVED"):
    return {"id": f"IOC-tester-{n:03d}", "value": value, "type": type_,
            "status": status, "source_findings": ["F-tester-001"]}  # fmt: skip


# The examiner's dry-run case: two approved findings and their nine records,
# then a finding that names defanged and host:port values, and their records
DRY_RUN = json.loads((FIXTURE / "ioc_lists_dry_run_case.json").read_text())
DRY_RUN_LIST = {
    "Domain": ["evil.com", "evil2.com"],
    "File": [UNC],
    "IPv4": ["172.16.30.23", "172.16.5.21", "172.16.6.12", "172.16.6.14",
             "172.16.6.18", "172.16.7.15", "203.0.113.7"],
    "Unknown": [SID],
    "user-account": ["tdungan"],
    TEXT_ONLY: ["172.16.6.11", "C:\\Windows\\system32\\cmd.exe"],
}  # fmt: skip

F1 = _f(1, ["172.16.6.12", UNC, {"value": "tdungan", "type": "user-account"}, SID],
        observation="Logon from 172.16.6.12 mapped \\\\172.16.6.12\\c$\\Users as tdungan.",
        interpretation="Admin share access.")  # fmt: skip
F3 = _f(3, [{"value": "203.0.113.7", "type": "ipv4-addr"}],
        observation="Beacon to 203.0.113.7 every 60 s.", interpretation="C2.")  # fmt: skip

# name -> (findings, records, the list the report gives). Every record here is
# APPROVED.
SHAPES = {
    "dry-run-case": (DRY_RUN["findings"], DRY_RUN["records"], DRY_RUN_LIST),
    "no-records": (
        [F1, F3], [],
        {TEXT_ONLY: ["172.16.6.12", "203.0.113.7", SID, UNC, "tdungan"]},
    ),
    "some-records": (
        [F1, F3], [_r(1, UNC, "file:path"), _r(2, "203.0.113.7", "ipv4-addr")],
        {"File": [UNC], "IPv4": ["203.0.113.7"], TEXT_ONLY: ["172.16.6.12", SID, "tdungan"]},
    ),
    # a record's type
    "type-null": ([], [_r(1, "10.1.2.3", None)], {"IPv4": ["10.1.2.3"]}),
    "type-missing": ([], [{"id": "IOC-tester-001", "value": "evil.com", "status": "APPROVED"}],
                     {"Domain": ["evil.com"]}),
    "type-empty": ([], [_r(1, SHA, "")], {"SHA256": [SHA]}),
    "type-blank": ([], [_r(1, "a" * 32, "  ")], {"MD5": ["a" * 32]}),
    "type-none-matches": ([], [_r(1, "hello", None)], {"Unknown": ["hello"]}),
    "type-list": ([], [_r(1, "10.1.2.3", ["ipv4-addr"])], {"['ipv4-addr']": ["10.1.2.3"]}),
    "type-int": ([], [_r(1, "10.1.2.3", 4)], {"4": ["10.1.2.3"]}),
    "type-dict": ([], [_r(1, "x", {"a": 1})], {"{'a': 1}": ["x"]}),
    "type-mapped-any-case": ([], [_r(1, "10.1.2.3", " IPv4-ADDR ")], {"IPv4": ["10.1.2.3"]}),
    "type-shown-as-stored": ([], [_r(1, "svc", "User-Account")], {"User-Account": ["svc"]}),
    "type-control-char": ([], [_r(1, "x", "evil\x1b[2J")], {"evil\x1b[2J": ["x"]}),
    "type-unknown": ([], [_r(1, SID, "unknown")], {"Unknown": [SID]}),
    "patterns": (
        [], [_r(i, v, None) for i, v in enumerate(
            ["10.9.8.7", SHA, "b" * 40, "c" * 32, "C:\\Temp\\x.exe", "bad.ru", "hello"])],
        {"Domain": ["bad.ru"], "File": ["C:\\Temp\\x.exe"], "IPv4": ["10.9.8.7"],
         "MD5": ["c" * 32], "SHA1": ["b" * 40], "SHA256": [SHA], "Unknown": ["hello"]},
    ),
    # a record's value
    "each-record-listed": (
        [], [_r(1, "10.1.2.3", "ipv4-addr"), _r(2, "10.1.2.4", "ipv4-addr")],
        {"IPv4": ["10.1.2.3", "10.1.2.4"]},
    ),
    "value-not-a-string": ([], [_r(1, 445, "port")], {"port": ["445"]}),
    "value-shown-as-stored": ([], [_r(1, "evil[.]com", "domain-name")], {"Domain": ["evil[.]com"]}),
    "empty-values-left-out": (
        [], [_r(1, None, "unknown"), _r(2, "", "unknown"), _r(3, "  ", "unknown"),
             {"id": "IOC-tester-004", "type": "unknown", "status": "APPROVED"}],
        {},
    ),
    # values no record holds
    "recorded-defanged": (
        [_f(1, ["evil[.]com"], observation="Beacon to evil[.]com.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil.com"]},
    ),
    "recorded-ip-port": (
        [_f(1, ["203.0.113.7:8443"], observation="Beacon to 203.0.113.7:8443.")],
        [_r(1, "203.0.113.7", "ipv4-addr")], {"IPv4": ["203.0.113.7"]},
    ),
    "recorded-typed-ip-port": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4-addr"}])],
        [_r(1, "203.0.113.7", "ipv4-addr")], {"IPv4": ["203.0.113.7"]},
    ),
    "recorded-any-case": (
        [_f(1, [SHA.lower(), UNC.upper(), "Evil.COM."])],
        [_r(1, SHA, "sha256"), _r(2, UNC, "file:path"), _r(3, "evil.com", "domain-name")],
        {"Domain": ["evil.com"], "File": [UNC], "SHA256": [SHA]},
    ),
    "ip-port-typed-other-than-ipv4-addr-keeps-it": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4"}], observation="Beacon to 203.0.113.7.")],
        [_r(1, "203.0.113.7", "ipv4-addr")],
        {"IPv4": ["203.0.113.7"], TEXT_ONLY: ["203.0.113.7:8443"]},
    ),
    "domain-keeps-its-port": (
        [_f(1, ["evil.com:443"], observation="Beacon to evil.com:443.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil.com"], TEXT_ONLY: ["evil.com:443"]},
    ),
    "dict-form-keys-untyped": (
        [_f(1, {"IPv4": ["203.0.113.7:8443"], "domain-name": "198.51.100.9:80"})],
        [_r(1, "203.0.113.7", "ipv4-addr"), _r(2, "198.51.100.9", "ipv4-addr")],
        {"IPv4": ["198.51.100.9", "203.0.113.7"]},
    ),
    "dict-form-not-recorded": (
        [_f(1, {"IPv4": ["1.2.3.4"], "": ["evil.com"], "url": "http://x.io/a"})], [],
        {TEXT_ONLY: ["1.2.3.4", "evil.com", "http://x.io/a"]},
    ),
    "record-value-not-a-string-matches": (
        [_f(1, ["445"])], [_r(1, 445, "port")], {"port": ["445"]},
    ),
    "not-recorded-once-as-first-written": (
        [_f(1, ["Evil.com."]), _f(2, ["evil.com", {"value": "EVIL.COM", "type": "url"}])], [],
        {TEXT_ONLY: ["Evil.com."]},
    ),
    "not-recorded-value-not-a-string": (
        [_f(1, [{"value": 445, "type": "port"}])], [], {TEXT_ONLY: ["445"]},
    ),
    "not-recorded-empty-left-out": (
        [_f(1, [None, "", "  ", {"value": None, "type": "ip"}, {"type": "ip"}, 5, ["x"]])], [], {},
    ),
    "text-recorded": (
        [_f(1, observation="Beacon to evil[.]com and 8.8.4.4.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil.com"], TEXT_ONLY: ["8.8.4.4"]},
    ),
    "text-only-once": (
        [_f(1, observation=f"{SHA} then {SHA.lower()}", interpretation="via Bad.com and bad.com")],
        [], {TEXT_ONLY: [SHA.lower(), "bad.com"]},
    ),
    "text-local-addresses-left-out": (
        [_f(1, observation="Bound 0.0.0.0, then 127.0.0.1 and 255.255.255.255; beacon to 10.9.8.7.")],
        [], {TEXT_ONLY: ["10.9.8.7"]},
    ),
    "text-path-sentence-punctuation": (
        [_f(1, ["C:\\Windows\\System32\\SRLUpdate.exe", "C:\\Windows\\System32\\STUN.exe"],
            observation="Removed C:\\Windows\\System32\\SRLUpdate.exe. The task ran "
                        '"C:\\Windows\\System32\\STUN.exe", then (C:\\Temp\\a.exe) and '
                        "'C:\\Temp\\b.exe'; C:\\Temp\\c.exe: done")],
        [_r(1, "C:\\Windows\\System32\\SRLUpdate.exe", "file:path"),
         _r(2, "C:\\Windows\\System32\\STUN.exe", "file:path")],
        {"File": ["C:\\Windows\\System32\\SRLUpdate.exe", "C:\\Windows\\System32\\STUN.exe"],
         TEXT_ONLY: ["C:\\Temp\\a.exe", "C:\\Temp\\b.exe", "C:\\Temp\\c.exe"]},
    ),
    "path-really-ending-in-a-dot": (
        [_f(1, ["C:\\Temp\\odd."], observation="Wrote C:\\Temp\\odd. and left.")],
        [_r(1, "C:\\Temp\\odd.", "file:path")], {"File": ["C:\\Temp\\odd."]},
    ),
    "text-path-closed-parens-kept": (
        [_f(1, observation="Ran C:\\Temp\\copy(1) and (see C:\\Temp\\x(2).exe)")], [],
        {TEXT_ONLY: ["C:\\Temp\\copy(1)", "C:\\Temp\\x(2).exe"]},
    ),
    "stored-type-is-the-text-label": (
        [_f(1, observation="to 8.8.4.4")], [_r(1, "x", TEXT_ONLY)],
        {TEXT_ONLY: ["8.8.4.4", "x"]},
    ),
    "no-iocs": ([_f(1)], [], {}),
}  # fmt: skip


def _values(groups):
    return {label: [e["value"] for e in entries] for label, entries in groups.items()}


# --- the list --------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_report_lists_the_shape(shape):
    findings, records, want = SHAPES[shape]
    got = _values(_extract_all_iocs(findings, records))
    assert got == want
    assert list(got) == list(want)  # labels sorted, the text-only group last


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_report_lists_the_shape_as_vhir_does(shape):
    """Where vhir's own grouper is installed, both give the same groups."""
    vhir = pytest.importorskip("vhir_cli.ioc_groups")
    findings, records, _ = SHAPES[shape]
    got = _values(_extract_all_iocs(findings, records))
    assert got == vhir.ioc_groups(findings, records)
    assert list(got) == list(vhir.ioc_groups(findings, records))


def test_the_label_table_and_patterns_are_vhir_s():
    vhir = pytest.importorskip("vhir_cli.ioc_groups")
    assert _IOC_LABELS == vhir.LABELS
    assert _TEXT_ONLY == vhir.TEXT_ONLY
    assert rs._IOC_PATTERNS == vhir.PATTERNS


@pytest.mark.parametrize("stored", list(_IOC_LABELS))
def test_each_stored_type_reads_as_its_label(stored):
    got = _extract_all_iocs([], [_r(1, "v", stored)])
    assert _values(got) == {_IOC_LABELS[stored]: ["v"]}


@pytest.mark.parametrize(
    "records",
    [[None, "x", 5, ["x"]], [{"id": "IOC-tester-001", "type": "ipv4-addr"}], []],
)
def test_entries_with_no_value_are_left_out(records):
    assert _extract_all_iocs([], records) == {}


@pytest.mark.parametrize("status", ["DRAFT", "REJECTED", None, "", "approved", "OTHER"])
def test_a_value_any_record_holds_is_recorded_whatever_its_status(status):
    """The values the findings name are checked against every record of the
    case, not only the records the report lists."""
    record = {**_r(1, "evil.com", "domain-name"), "status": status}
    finding = _f(1, ["evil[.]com"], observation="Beacon to evil.com.")
    assert _extract_all_iocs([finding], [], [record]) == {}
    assert _values(_extract_all_iocs([finding], [], [])) == {TEXT_ONLY: ["evil[.]com"]}


def test_the_records_listed_are_recorded_when_no_others_are_given():
    finding = _f(1, ["evil[.]com"])
    records = [_r(1, "evil.com", "domain-name")]
    assert _values(_extract_all_iocs([finding], records)) == {"Domain": ["evil.com"]}
    assert _values(_extract_all_iocs([finding], records, records)) == {
        "Domain": ["evil.com"]
    }


# name -> (findings, records, the list the report gives): how a record and a
# finding's value key, beyond the shapes vhir's rows hold
KEYING = {
    "record-typed-other-than-ipv4-addr-keeps-its-port": (
        [_f(1, ["203.0.113.7"])], [_r(1, "203.0.113.7:8443", "ipv4")],
        {"IPv4": ["203.0.113.7:8443"], TEXT_ONLY: ["203.0.113.7"]},
    ),
    "record-typed-ipv4-addr-loses-its-port": (
        [_f(1, ["203.0.113.7"])], [_r(1, "203.0.113.7:8443", "ipv4-addr")],
        {"IPv4": ["203.0.113.7:8443"]},
    ),
    "value-with-an-empty-key-left-out": (
        [_f(1, ["[.]", "..", {"value": ".", "type": "domain-name"}])], [], {},
    ),
}  # fmt: skip


@pytest.mark.parametrize("shape", list(KEYING))
def test_records_and_values_key_as_forensic_mcp_keys_them(shape):
    findings, records, want = KEYING[shape]
    assert _values(_extract_all_iocs(findings, records)) == want


@pytest.mark.parametrize("shape", list(KEYING))
def test_records_and_values_key_as_vhir_keys_them(shape):
    vhir = pytest.importorskip("vhir_cli.ioc_groups")
    findings, records, want = KEYING[shape]
    assert vhir.ioc_groups(findings, records) == want


@pytest.mark.parametrize(
    "value, key",
    [(SHA, SHA.lower()), (" " + "C" * 40 + " ", "c" * 40), ("Evil.COM.", "evil.com"),
     ("10.1.2.3", "10.1.2.3"), (UNC.upper(), UNC.lower()), ("Tdungan", "Tdungan"),
     ("evil[.]com", "evil.com"), ("hxxp://Evil[.]com/a", "http://evil.com/a"),
     ("user[@]evil.com", "user@evil.com"), (" 203.0.113.7:8443 ", "203.0.113.7"),
     ("203[.]0[.]113[.]7:8443", "203.0.113.7"), ("10.0.0.1/24", "10.0.0.1/24"),
     ("300.1.1.1:80", "300.1.1.1:80"), ("evil.com:443", "evil.com:443")],
)  # fmt: skip
def test_values_compare_as_forensic_mcp_records_them(value, key):
    assert _ioc_key(value) == key


@pytest.mark.parametrize(
    "type_, key",
    [("ipv4-addr", "203.0.113.7"), (None, "203.0.113.7"), ("", "203.0.113.7"),
     ("ipv4", "203.0.113.7:8443"), ("domain-name", "203.0.113.7:8443"),
     (["ipv4-addr"], "203.0.113.7:8443")],
)  # fmt: skip
def test_an_ipv4_loses_its_port_as_forensic_mcp_types_it(type_, key):
    assert _ioc_key("203.0.113.7:8443", type_) == key


def test_the_findings_and_records_are_left_as_they_were():
    findings, records, _ = SHAPES["dry-run-case"]
    before = json.dumps([findings, records])
    _extract_all_iocs(findings, records, records)
    assert json.dumps([findings, records]) == before


# --- the findings each value is cross-referenced to ---------------------------------


def test_each_value_names_the_findings_that_hold_or_name_it():
    findings = [
        _f(1, ["203.0.113.7"], observation="Beacon to 203.0.113.7 and 8.8.4.4."),
        _f(2, [{"value": "203.0.113.7:8443", "type": "ipv4-addr"}]),
        _f(3, observation="Then 203[.]0[.]113[.]7 again, and 8.8.4.4."),
        _f(4, ["evil.com"]),
    ]
    records = [_r(1, "203.0.113.7", "ipv4-addr"), _r(2, "10.0.0.1", "ipv4-addr")]
    got = _extract_all_iocs(findings, records)
    assert got == {
        "IPv4": [
            {"value": "10.0.0.1", "source_findings": []},
            {
                "value": "203.0.113.7",
                "source_findings": ["F-tester-001", "F-tester-002", "F-tester-003"],
            },
        ],
        TEXT_ONLY: [
            {"value": "8.8.4.4", "source_findings": ["F-tester-001", "F-tester-003"]},
            {"value": "evil.com", "source_findings": ["F-tester-004"]},
        ],
    }


def test_the_dry_run_case_s_values_name_their_findings():
    findings, records, _ = SHAPES["dry-run-case"]
    got = _extract_all_iocs(findings, records)
    ids = {f["id"] for f in findings}
    for entries in got.values():
        for e in entries:
            assert e["source_findings"] and set(e["source_findings"]) <= ids, e
            assert e["source_findings"] == sorted(e["source_findings"])


def test_a_finding_with_no_id_is_not_named():
    got = _extract_all_iocs([{"iocs": ["8.8.4.4"], "observation": "x"}], [])
    assert got == {TEXT_ONLY: [{"value": "8.8.4.4", "source_findings": []}]}


# --- through generate_report ---------------------------------------------------------


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-IOC-LISTS"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-IOC-LISTS"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


def _case_with(case, findings, records, sign=True):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text(json.dumps(records))
    if sign:
        sign_approved(case)


def _report(case, profile):
    out = rs._generate(profile, case)
    assert out["verification"]["not_verified"] == []
    assert out["verification"]["case_failures"] == []
    return out["report_data"]


@pytest.mark.parametrize("profile", ["full", "ioc"])
@pytest.mark.parametrize("shape", list(SHAPES))
def test_generate_report_lists_the_shape(case, shape, profile):
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    got = _values(_report(case, profile)["iocs"])
    assert got == want
    assert list(got) == list(want)


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_each_profile_counts_each_value_once(case, profile):
    findings, records, want = SHAPES["dry-run-case"]
    _case_with(case, findings, records)
    summary = _report(case, profile)["summary"]
    assert summary["ioc_count"] == sum(len(v) for v in want.values()) == 14


STATUS_RECORDS = [
    _r(1, "10.0.0.1", "ipv4-addr"),
    _r(2, "evil.com", "domain-name", "DRAFT"),
    _r(3, "10.0.0.3", "ipv4-addr", "REJECTED"),
    {**_r(4, "10.0.0.4", "ipv4-addr"), "status": None},
    _r(5, "10.0.0.5", "ipv4-addr", "draft"),
    _r(6, "10.0.0.6", "ipv4-addr", "HELD"),
]
STATUS_FINDINGS = [
    _f(1, ["10.0.0.1"], observation="Beacon to evil[.]com and 10.0.0.9."),
    _f(2, ["10.0.0.3", "10.0.0.8"], status="DRAFT"),
]


@pytest.mark.parametrize("profile", ["full", "ioc"])
def test_generate_report_lists_the_approved_records(case, profile):
    """Only the approved records are listed; a value a draft or rejected
    record holds is recorded, so it is not in the text group, and a draft
    finding's values are not named."""
    _case_with(case, STATUS_FINDINGS, STATUS_RECORDS)
    got = _values(_report(case, profile)["iocs"])
    assert got == {"IPv4": ["10.0.0.1"], TEXT_ONLY: ["10.0.0.9"]}


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_a_value_recorded_from_a_draft_finding_is_never_not_recorded(case, profile):
    findings = [_f(1, observation="Beacon to evil.com."),
                _f(2, ["evil[.]com"], status="DRAFT")]  # fmt: skip
    records = [
        {
            **_r(1, "evil.com", "domain-name", "DRAFT"),
            "source_findings": ["F-tester-002"],
        }
    ]
    _case_with(case, findings, records)
    data = _report(case, profile)
    assert data["summary"]["ioc_count"] == 0
    if "iocs" in data:
        assert data["iocs"] == {}


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_a_case_of_draft_findings_and_records_lists_no_iocs(case, profile):
    findings = [{**f, "status": "DRAFT"} for f in DRY_RUN["findings"]]
    records = [{**r, "status": "DRAFT"} for r in DRY_RUN["records"]]
    _case_with(case, findings, records, sign=False)
    data = rs._generate(profile, case)["report_data"]
    assert data["summary"]["ioc_count"] == 0
    if "iocs" in data:
        assert data["iocs"] == {}


SIGNED = [_r(n, f"10.0.0.{n}", "ipv4-addr") for n in range(1, 6)]
SIGNED += [_r(6, "evil.com", "domain-name")]


def test_the_signed_approved_records_are_listed_and_counted(case):
    _case_with(case, [_f(1)], SIGNED)
    data = _report(case, "ioc")
    ips = [f"10.0.0.{n}" for n in range(1, 6)]
    assert _values(data["iocs"]) == {"Domain": ["evil.com"], "IPv4": ips}
    assert data["summary"]["ioc_count"] == 6


def test_approved_records_no_signature_verifies_are_not_listed(case):
    """Approved in iocs.json but never signed: none verifies, none is listed,
    and their values are still recorded."""
    _case_with(case, [_f(1, observation="Beacon to 10.0.0.1.")], [])
    sign_approved(case)
    (case / "iocs.json").write_text(json.dumps(SIGNED))
    out = rs._generate("ioc", case)
    assert out["report_data"]["iocs"] == {}
    assert out["report_data"]["summary"]["ioc_count"] == 0


UNREADABLE = {
    "a-dict": "{}", "a-number": "7", "a-string": '"x"', "not-json": "not json",
    "a-folder": None,
}  # fmt: skip


def _break_records(case, name):
    target = case / "iocs.json"
    target.unlink()
    if UNREADABLE[name] is None:
        target.mkdir()
    else:
        target.write_text(UNREADABLE[name])


@pytest.mark.parametrize("name", list(UNREADABLE))
def test_records_that_can_t_be_read_are_none(case, name):
    _case_with(case, [F1, F3], [])
    _break_records(case, name)
    assert rs._ioc_records(case) == []


@pytest.mark.parametrize("name", list(UNREADABLE))
def test_a_report_over_unreadable_records_names_the_case_failure(case, name):
    """Verification reads iocs.json first: no finding is verified, none listed."""
    _case_with(case, [F1, F3], [])
    _break_records(case, name)
    out = rs._generate("ioc", case)
    assert out["verification"]["case_failures"]
    assert out["report_data"]["iocs"] == {}
    assert out["report_data"]["summary"]["ioc_count"] == 0
