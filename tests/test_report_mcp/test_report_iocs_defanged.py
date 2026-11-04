"""A saved report writes every IOC of the case that is a domain, URL or IPv4
address (evil[.]com, hxxp://bad[.]example[.]com/x, 185[.]220[.]101[.]45) defanged,
in the text and in the server's block, so none is a live link wherever the
report goes. The case's IOCs are its approved findings' IOC fields and the IOC
records they cite; a name a finding's text merely mentions isn't one. Other
URLs and names stay live, a name that is only part of a longer one isn't
touched, and a defanged one isn't twice."""

from __future__ import annotations

import json

import pytest
import yaml
from vhir_signing import sign_approved


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-D-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-D-1", "name": "d"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


def _f(fid, status="APPROVED", **extra):
    return {"id": fid, "title": f"title {fid}", "observation": "o", "interpretation": "i",
            "confidence": "HIGH", "status": status, **extra}  # fmt: skip


def _saved(case, findings, content, iocs=(), filename="r.md", profile="full"):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text(json.dumps(list(iocs)))
    sign_approved(case)
    from report_mcp.server import create_server

    tool = {t.name: t for t in create_server()._tool_manager.list_tools()}[
        "save_report"
    ]
    got = tool.fn(filename=filename, content=content, profile=profile)
    assert got["status"] == "saved", got
    return (case / "reports" / filename).read_text()


APPROVED = _f("F-tester-001", title="C2 at evil.com",
              observation="Beacon to evil.com; the tool came from download.vendor.com",
              iocs=[{"type": "domain-name", "value": "evil.com"}, "185.220.101.45",
                    "http://bad.example.com/x.php", "a.exe",
                    "d41d8cd98f00b204e9800998ecf8427e", "C:\\Tools\\drop.exe"])  # fmt: skip


def test_an_approved_findings_iocs_are_written_defanged_in_the_text(case):
    saved = _saved(case, [APPROVED], (
        "Beacon to evil.com and EVIL.COM from 185.220.101.45; payload "
        "http://bad.example.com/x.php. Hash d41d8cd98f00b204e9800998ecf8427e, "
        "file C:\\Tools\\drop.exe, a.exe."))  # fmt: skip
    text = saved[: saved.index("VERIFICATION")]
    assert "Beacon to evil[.]com and EVIL[.]COM from 185[.]220[.]101[.]45" in text
    assert "payload hxxp://bad[.]example[.]com/x.php." in text
    # hashes, paths and an untyped name like a file aren't indicators to defang
    assert "d41d8cd98f00b204e9800998ecf8427e, file C:\\Tools\\drop.exe, a.exe." in text


def test_the_servers_block_writes_them_defanged_too(case):
    saved = _saved(case, [APPROVED], "# Report")
    block = saved[saved.index("VERIFICATION") :]
    assert "[F-tester-001] C2 at evil[.]com" in block
    assert "evil.com" not in block


def test_a_url_or_name_that_isnt_an_ioc_stays_live(case):
    saved = _saved(case, [APPROVED], (
        "See https://learn.microsoft.com/kb and example.org; notevil.com, "
        "sub.evil.com and evil.com.au are other names; 185.220.101.450 isn't one."))  # fmt: skip
    for live in ("https://learn.microsoft.com/kb", "example.org", "notevil.com",
                 "sub.evil.com", "evil.com.au", "185.220.101.450"):  # fmt: skip
        assert live in saved, live


def test_a_defanged_ioc_isnt_defanged_twice(case):
    saved = _saved(
        case, [APPROVED], "Already evil[.]com and hxxp://bad[.]example[.]com/x.php."
    )
    assert "Already evil[.]com and hxxp://bad[.]example[.]com/x.php." in saved
    assert "[[" not in saved and "hxxxp" not in saved


def test_only_an_approved_findings_iocs_are_defanged(case):
    draft = _f("F-tester-002", status="DRAFT", observation="relay at relay.example.net",
               iocs=["relay.example.net"])  # fmt: skip
    saved = _saved(case, [APPROVED, draft], "evil.com and relay.example.net")
    assert "evil[.]com and relay.example.net" in saved


def test_the_cases_typed_iocs_of_an_approved_finding_are_defanged(case):
    """A domain the finding's IOC field gave as a plain string is typed by the
    case's IOC record: it's defanged, as an address or URL always is."""
    finding = {**APPROVED, "iocs": ["stage.example.net"]}
    record = {"id": "I-tester-001", "type": "domain-name", "value": "stage.example.net",
              "status": "DRAFT", "source_findings": ["F-tester-001"]}  # fmt: skip
    saved = _saved(case, [finding], "Second stage at stage.example.net.", iocs=[record])
    assert "Second stage at stage[.]example[.]net." in saved


def test_a_name_an_approved_finding_only_mentions_stays_live(case):
    """download.vendor.com is in the finding's text, not among its IOCs."""
    saved = _saved(
        case, [APPROVED], "Fetched from download.vendor.com, beaconed to evil.com."
    )
    assert "Fetched from download.vendor.com, beaconed to evil[.]com." in saved
    assert "download[.]vendor" not in saved


def test_a_report_saved_with_a_json_name_is_defanged_too(case):
    """save_report appends its block to any content, so no save is JSON a tool
    reads: a .json name is defanged as any other."""
    content = json.dumps({"iocs": ["evil.com", "http://bad.example.com/x.php"]})
    saved = _saved(case, [APPROVED], content, filename="r.json")
    assert '"evil[.]com"' in saved and "hxxp://bad[.]example[.]com/x.php" in saved


NESTED = _f("F-tester-003", title="C2 at evil13.example.com",
            iocs=[{"type": "domain-name", "value": "evil13[[.]]example.com"},
                  {"type": "url", "value": "hxxp://user[[@]]evil14[[[.]]]example.com/a"},
                  {"type": "email-addr", "value": "user[[@]]evil15.example.com"}])  # fmt: skip


@pytest.mark.parametrize("profile", ["full", "ioc"])
def test_an_ioc_given_in_nested_brackets_is_written_defanged(case, profile):
    """The report names the IOCs live, as stored; each is written defanged,
    and a nested form as given stays as it is."""
    saved = _saved(case, [NESTED], (
        "Beacon to evil13.example.com and http://user@evil14.example.com/a; given "
        "as evil13[[.]]example.com and user[[@]]evil15.example.com."), profile=profile)  # fmt: skip
    assert (
        "Beacon to evil13[.]example[.]com and hxxp://user@evil14[.]example[.]com/a; "
        "given as evil13[[.]]example.com and user[[@]]evil15.example.com." in saved
    )
    assert "[F-tester-003] C2 at evil13[.]example[.]com" in saved
    assert "evil13.example.com" not in saved and "evil14.example.com" not in saved


HXXP_IN_A_NAME = _f("F-tester-004", title="t",
                    iocs=[{"type": "url", "value": "https://safe.example.com/hxxp/payload"},
                          {"type": "domain-name", "value": "hxxp.example.com"}])  # fmt: skip
STORED = [  # the records record_finding stores for them (hxxp made http anywhere)
    {"id": "I-tester-001", "type": "url", "value": "https://safe.example.com/http/payload",
     "status": "DRAFT", "source_findings": ["F-tester-004"]},
    {"id": "I-tester-002", "type": "domain-name", "value": "http.example.com",
     "status": "DRAFT", "source_findings": ["F-tester-004"]},
]  # fmt: skip


@pytest.mark.parametrize("profile", ["full", "ioc"])
def test_an_ioc_with_hxxp_outside_its_scheme_is_written_defanged(case, profile):
    saved = _saved(case, [HXXP_IN_A_NAME], (
        "Payload at https://safe.example.com/hxxp/payload from hxxp.example.com; "
        "stored as https://safe.example.com/http/payload and http.example.com."),
        iocs=STORED, profile=profile)  # fmt: skip
    assert (
        "Payload at hxxps://safe[.]example[.]com/hxxp/payload from hxxp[.]example[.]com; "
        "stored as hxxps://safe[.]example[.]com/http/payload and http[.]example[.]com."
        in saved
    )
