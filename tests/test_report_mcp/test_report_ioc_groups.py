"""The report's IOC section lists every value a finding's iocs holds, a plain
string too, once, under one label, as vhir's `review --iocs` and `report`
list them: a value with no type takes the type of the case's IOC record for
it, else the pattern that matches all of it, else "Unknown"; a type that isn't
a string is shown as str(type); values only a finding's text names come last,
in one group. The shapes and the dry-run case (fixtures/) are the ones vhir's
own rows use, so every view gives the same groups. Only approved, verified
findings are listed."""

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
    "Domain": ["evil2[.]com", "evil[.]com"],
    "File": [UNC],
    "IPv4": ["172.16.30.23", "172.16.5.21", "172.16.6.12", "172.16.6.14",
             "172.16.6.18", "172.16.7.15", "203.0.113.7:8443"],
    "Unknown": [SID],
    "user-account": ["tdungan"],
    TEXT_ONLY: ["172.16.6.11", "C:\\Windows\\system32\\cmd.exe"],
}  # fmt: skip

F1 = _f(1, ["172.16.6.12", UNC, {"value": "tdungan", "type": "user-account"}, SID],
        observation="Logon from 172.16.6.12 mapped \\\\172.16.6.12\\c$\\Users as tdungan.",
        interpretation="Admin share access.")  # fmt: skip
F3 = _f(3, [{"value": "203.0.113.7", "type": "ipv4-addr"}],
        observation="Beacon to 203.0.113.7 every 60 s.", interpretation="C2.")  # fmt: skip

# name -> (findings, records, the list every view gives)
SHAPES = {
    "dry-run-case": (DRY_RUN["findings"], DRY_RUN["records"], DRY_RUN_LIST),
    "strings-no-records": (
        [F1, F3], [],
        {"IPv4": ["172.16.6.12", "203.0.113.7"], "Unknown": [SID, UNC],
         "user-account": ["tdungan"]},
    ),
    "strings-with-records": (
        [F1, F3], DRY_RUN["records"],
        {"File": [UNC], "IPv4": ["172.16.6.12", "203.0.113.7"], "Unknown": [SID],
         "user-account": ["tdungan"]},
    ),
    "type-null": ([_f(1, [{"value": "10.1.2.3", "type": None}])], [], {"IPv4": ["10.1.2.3"]}),
    "type-missing": ([_f(1, [{"value": "evil.com"}])], [], {"Domain": ["evil.com"]}),
    "type-empty": ([_f(1, [{"value": SHA, "type": ""}])], [], {"SHA256": [SHA]}),
    "type-blank": ([_f(1, [{"value": "a" * 32, "type": "  "}])], [], {"MD5": ["a" * 32]}),
    "type-null-record": (
        [_f(1, [{"value": "tdungan", "type": None}])], [_r(1, "tdungan", "user-account")],
        {"user-account": ["tdungan"]},
    ),
    "type-list": ([_f(1, [{"value": "10.1.2.3", "type": ["ipv4-addr"]}])], [],
                  {"['ipv4-addr']": ["10.1.2.3"]}),
    "type-int": ([_f(1, [{"value": "10.1.2.3", "type": 4}])], [], {"4": ["10.1.2.3"]}),
    "type-dict": ([_f(1, [{"value": "x", "type": {"a": 1}}])], [], {"{'a': 1}": ["x"]}),
    "type-mapped-any-case": ([_f(1, [{"value": "10.1.2.3", "type": " IPv4-ADDR "}])], [],
                             {"IPv4": ["10.1.2.3"]}),
    "type-shown-as-stored": ([_f(1, [{"value": "svc", "type": "User-Account"}])], [],
                             {"User-Account": ["svc"]}),
    "type-control-char": ([_f(1, [{"value": "x", "type": "evil\x1b[2J"}])], [],
                          {"evil\x1b[2J": ["x"]}),
    "string-record-type": ([_f(1, ["evil.com"])], [_r(1, "EVIL.com.", "url")], {"URL": ["evil.com"]}),
    "string-record-draft": ([_f(1, ["evil.com"])], [_r(1, "evil.com", "url", "DRAFT")],
                            {"URL": ["evil.com"]}),
    "string-record-no-type": ([_f(1, ["evil.com"])], [_r(1, "evil.com", "")], {"Domain": ["evil.com"]}),
    "string-record-null-type": ([_f(1, ["evil.com"])], [_r(1, "evil.com", None)],
                                {"Domain": ["evil.com"]}),
    "string-record-list-type": ([_f(1, ["evil.com"])], [_r(1, "evil.com", ["url"])],
                                {"['url']": ["evil.com"]}),
    "string-first-typed-record": (
        [_f(1, ["evil.com"])], [_r(1, "evil.com", ""), _r(2, "evil.com", "domain-name"),
                                _r(3, "evil.com", "url")],
        {"Domain": ["evil.com"]},
    ),
    "string-patterns": (
        [_f(1, ["10.9.8.7", SHA, "b" * 40, "c" * 32, "C:\\Temp\\x.exe", "bad.ru", "hello"])], [],
        {"Domain": ["bad.ru"], "File": ["C:\\Temp\\x.exe"], "IPv4": ["10.9.8.7"],
         "MD5": ["c" * 32], "SHA1": ["b" * 40], "SHA256": [SHA], "Unknown": ["hello"]},
    ),
    "string-defanged-record": (
        [_f(1, ["evil[.]com"], observation="Beacon to evil[.]com.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil[.]com"]},
    ),
    "string-ip-port-record": (
        [_f(1, ["203.0.113.7:8443"], observation="Beacon to 203.0.113.7:8443.")],
        [_r(1, "203.0.113.7", "ipv4-addr")], {"IPv4": ["203.0.113.7:8443"]},
    ),
    "typed-defanged-in-text": (
        [_f(1, [{"value": "evil2[.]com", "type": "domain-name"}], observation="Beacon to evil2.com.")],
        [], {"Domain": ["evil2[.]com"]},
    ),
    "typed-ip-port-in-text": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4-addr"}], observation="Beacon to 203.0.113.7.")],
        [], {"IPv4": ["203.0.113.7:8443"]},
    ),
    "defanged-recorded-and-text-not-recorded": (
        [_f(1, ["evil[.]com"], observation="Beacon to evil[.]com, then bad[.]ru.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil[.]com"], TEXT_ONLY: ["bad.ru"]},
    ),
    "domain-keeps-its-port": (
        [_f(1, ["evil.com:443"], observation="Beacon to evil.com:443.")],
        [_r(1, "evil.com:443", "unknown")], {"Unknown": ["evil.com:443"], TEXT_ONLY: ["evil.com"]},
    ),
    "ip-port-typed-other-than-ipv4-addr-keeps-it": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4"}], observation="Beacon to 203.0.113.7.")],
        [], {"IPv4": ["203.0.113.7:8443"], TEXT_ONLY: ["203.0.113.7"]},
    ),
    "first-label-kept": (
        [_f(1, [{"value": "1.2.3.4", "type": "ipv4-addr"}]),
         _f(2, [{"value": "1.2.3.4", "type": "domain"}])], [],
        {"IPv4": ["1.2.3.4"]},
    ),
    "hash-any-case-once": ([_f(1, [SHA]), _f(2, [SHA.lower()])], [], {"SHA256": [SHA]}),
    "name-trailing-dot-once": ([_f(1, ["Evil.com."]), _f(2, ["evil.com"])], [],
                               {"Unknown": ["Evil.com."]}),
    "path-any-case-once": ([_f(1, [UNC]), _f(2, [UNC.upper()])], [], {"Unknown": [UNC]}),
    "text-only-last": (
        [_f(1, [{"value": "svc", "type": "user-account"}], observation="Beacon to 8.8.4.4.")], [],
        {"user-account": ["svc"], TEXT_ONLY: ["8.8.4.4"]},
    ),
    "text-already-listed": ([_f(1, ["8.8.4.4"], observation="Beacon to 8.8.4.4.")], [],
                            {"IPv4": ["8.8.4.4"]}),
    "text-listed-by-a-later-finding": (
        [_f(1, observation="Beacon to evil.com."),
         _f(2, [{"value": "EVIL.COM", "type": "url"}])], [],
        {"URL": ["EVIL.COM"]},
    ),
    "text-only-once": (
        [_f(1, observation=f"{SHA} then {SHA.lower()}", interpretation="via Bad.com and bad.com")],
        [], {TEXT_ONLY: [SHA.lower(), "bad.com"]},
    ),
    "text-local-addresses-left-out": (
        [_f(1, observation="Bound 0.0.0.0, then 127.0.0.1 and 255.255.255.255; beacon to 10.9.8.7.")],
        [], {TEXT_ONLY: ["10.9.8.7"]},
    ),
    "dict-form": ([_f(1, {"IPv4": ["1.2.3.4"], "": ["evil.com"], "url": "http://x.io/a"})], [],
                  {"Domain": ["evil.com"], "IPv4": ["1.2.3.4"], "URL": ["http://x.io/a"]}),
    "empty-values-left-out": (
        [_f(1, [None, "", "  ", {"value": None, "type": "ip"}, {"type": "ip"}, 5, ["x"]])], [], {},
    ),
    "value-not-a-string": ([_f(1, [{"value": 445, "type": "port"}])], [], {"port": ["445"]}),
    "stored-type-is-the-text-label": (
        [_f(1, [{"value": "x", "type": TEXT_ONLY}], observation="to 8.8.4.4")], [],
        {TEXT_ONLY: ["8.8.4.4", "x"]},
    ),
    "text-path-sentence-punctuation": (
        [_f(1, ["C:\\Windows\\System32\\SRLUpdate.exe", "C:\\Windows\\System32\\STUN.exe"],
            observation="Removed C:\\Windows\\System32\\SRLUpdate.exe. The task ran "
                        '"C:\\Windows\\System32\\STUN.exe", then (C:\\Temp\\a.exe) and '
                        "'C:\\Temp\\b.exe'; C:\\Temp\\c.exe: done")], [],
        {"File": ["C:\\Windows\\System32\\SRLUpdate.exe", "C:\\Windows\\System32\\STUN.exe"],
         TEXT_ONLY: ["C:\\Temp\\a.exe", "C:\\Temp\\b.exe", "C:\\Temp\\c.exe"]},
    ),
    "path-really-ending-in-a-dot": (
        [_f(1, ["C:\\Temp\\odd."], observation="Wrote C:\\Temp\\odd. and left.")], [],
        {"File": ["C:\\Temp\\odd."]},
    ),
    "text-path-closed-parens-kept": (
        [_f(1, observation="Ran C:\\Temp\\copy(1) and (see C:\\Temp\\x(2).exe)")], [],
        {TEXT_ONLY: ["C:\\Temp\\copy(1)", "C:\\Temp\\x(2).exe"]},
    ),
    "no-iocs": ([_f(1)], [], {}),
}  # fmt: skip

# The second dict of each shape below, beside {"value":"203.0.113.7","type":"ipv4-addr"}
ODD_TYPES = {"null": None, "list": ["user-account"], "int": 7}
ODD_SHOWN = {"null": "Unknown", "list": "['user-account']", "int": "7"}


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
    got = _extract_all_iocs([_f(1, [{"value": "v", "type": stored}])], [])
    assert _values(got) == {_IOC_LABELS[stored]: ["v"]}


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
    _extract_all_iocs(findings, records)
    assert json.dumps([findings, records]) == before


# --- the findings each value is cross-referenced to ---------------------------------


def test_each_value_names_the_findings_that_hold_or_name_it():
    findings = [
        _f(1, ["203.0.113.7"], observation="Beacon to 203.0.113.7 and 8.8.4.4."),
        _f(2, [{"value": "203.0.113.7:8443", "type": "ipv4-addr"}]),
        _f(3, observation="Then 203[.]0[.]113[.]7 again, and 8.8.4.4."),
        _f(4, ["evil.com"]),
    ]
    got = _extract_all_iocs(findings, [])
    assert got == {
        "Domain": [{"value": "evil.com", "source_findings": ["F-tester-004"]}],
        "IPv4": [
            {
                "value": "203.0.113.7",
                "source_findings": ["F-tester-001", "F-tester-002", "F-tester-003"],
            }
        ],
        TEXT_ONLY: [
            {"value": "8.8.4.4", "source_findings": ["F-tester-001", "F-tester-003"]}
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
    assert got == {"IPv4": [{"value": "8.8.4.4", "source_findings": []}]}


# --- a type that isn't a string -----------------------------------------------------


@pytest.mark.parametrize("odd", list(ODD_TYPES))
def test_a_type_that_isn_t_a_string_is_shown_as_its_text(odd):
    findings = [
        _f(1, [{"value": "203.0.113.7", "type": "ipv4-addr"}]),
        _f(2, [{"value": "tdungan", "type": ODD_TYPES[odd]}]),
    ]
    got = _values(_extract_all_iocs(findings, []))
    assert got == {"IPv4": ["203.0.113.7"], ODD_SHOWN[odd]: ["tdungan"]}


@pytest.mark.parametrize("odd", ["list", "int"])
def test_a_record_s_type_that_isn_t_a_string_is_shown_as_its_text(odd):
    findings = [_f(1, ["tdungan"])]
    records = [_r(1, "tdungan", ODD_TYPES[odd])]
    assert _values(_extract_all_iocs(findings, records)) == {
        ODD_SHOWN[odd]: ["tdungan"]
    }


def test_string_types_group_as_stored():
    findings = [
        _f(1, [{"value": "203.0.113.7", "type": "ipv4-addr"}]),
        _f(2, [{"value": "tdungan", "type": "user-account"}]),
    ]
    got = _values(_extract_all_iocs(findings, []))
    assert got == {"IPv4": ["203.0.113.7"], "user-account": ["tdungan"]}


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
@pytest.mark.parametrize(
    "shape", ["dry-run-case", "strings-with-records", "string-record-type"]
)
def test_generate_report_lists_the_shape(case, shape, profile):
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    got = _values(_report(case, profile)["iocs"])
    assert got == want
    assert list(got) == list(want)


@pytest.mark.parametrize("odd", list(ODD_TYPES))
def test_generate_report_shows_a_type_that_isn_t_a_string(case, odd):
    findings = [
        _f(1, [{"value": "203.0.113.7", "type": "ipv4-addr"}]),
        _f(2, [{"value": "tdungan", "type": ODD_TYPES[odd]}]),
    ]
    _case_with(case, findings, [])
    got = _report(case, "ioc")["iocs"]
    assert _values(got) == {"IPv4": ["203.0.113.7"], ODD_SHOWN[odd]: ["tdungan"]}


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_each_profile_counts_each_value_once(case, profile):
    findings, records, want = SHAPES["dry-run-case"]
    _case_with(case, findings, records)
    summary = _report(case, profile)["summary"]
    assert summary["ioc_count"] == sum(len(v) for v in want.values()) == 14


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_a_case_of_draft_findings_lists_no_iocs(case, profile):
    findings = [{**f, "status": "DRAFT"} for f in DRY_RUN["findings"]]
    _case_with(case, findings, DRY_RUN["records"], sign=False)
    data = rs._generate(profile, case)["report_data"]
    assert data["summary"]["ioc_count"] == 0
    if "iocs" in data:
        assert data["iocs"] == {}


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
def test_records_that_can_t_be_read_lend_no_type(case, name):
    findings, _, want = SHAPES["strings-no-records"]
    _case_with(case, findings, [])
    _break_records(case, name)
    assert rs._ioc_records(case) == []
    assert _values(_extract_all_iocs(findings, rs._ioc_records(case))) == want


@pytest.mark.parametrize("name", list(UNREADABLE))
def test_a_report_over_unreadable_records_names_the_case_failure(case, name):
    """Verification reads iocs.json first: no finding is verified, none listed."""
    findings, _, _ = SHAPES["strings-no-records"]
    _case_with(case, findings, [])
    _break_records(case, name)
    out = rs._generate("ioc", case)
    assert out["verification"]["case_failures"]
    assert out["report_data"]["iocs"] == {}
    assert out["report_data"]["summary"]["ioc_count"] == 0
