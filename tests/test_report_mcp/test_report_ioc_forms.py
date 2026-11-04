"""An IOC cited in any of its forms is one IOC in every report. For each form
of the corpus (hxxp at the scheme, inside the host and inside the path; [.]
and [@] bracketed to depth 3; upper case), through the full and the IOC
report: a saved report writes none of it live; a signed rejection of its
records keeps it out of the report's IOCs (generate_report's listing and the
IOCs save_report defangs); and the listing holds it once, however many forms
cite it. The records are those record_finding stores for the citations
(tests/test_forensic_mcp/test_ioc_forms_stored.py checks that). vhir-cli's
tests state the same rows against its report."""

from __future__ import annotations

import json
import re

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sift_common import ioc_types
from vhir_cli import keys, ledger
from vhir_cli.case_io import signed_text

FINDING = "F-tester-001"
AT = "2026-10-08T10:00:00+00:00"
CORPUS = {  # each IOC: its type, the live names none of its forms may show, its forms
    "a URL, hxxp at the scheme": ("url", ["evil-s.example.com"], [
        "http://evil-s.example.com/a", "hxxp://evil-s.example.com/a",
        "hxxp[:]//evil-s[.]example[.]com/a", "HXXP://EVIL-S.EXAMPLE.COM/A"]),
    "a domain, hxxp inside the host": ("domain-name", ["hxxp.example.com", "http.example.com"], [
        "hxxp.example.com", "hxxp[.]example[.]com", "hxxp[[.]]example.com",
        "HXXP.EXAMPLE.COM"]),
    "a URL, hxxp inside the path": ("url", ["safe.example.com"], [
        "https://safe.example.com/hxxp/payload", "hxxps://safe[.]example[.]com/hxxp/payload",
        "https://safe[[.]]example.com/hxxp/payload", "HTTPS://SAFE.EXAMPLE.COM/HXXP/PAYLOAD"]),
    "a domain, [.] to depth 3": ("domain-name", ["evil-d.example.org"], [
        "evil-d.example.org", "evil-d[.]example[.]org", "evil-d[[.]]example[[.]]org",
        "evil-d[[[.]]]example[[[.]]]org", "EVIL-D[.]EXAMPLE[.]ORG"]),
    "a URL, [@] to depth 3": ("url", ["evil-u.example.org"], [
        "http://user@evil-u.example.org/x", "hxxp://user[@]evil-u[.]example[.]org/x",
        "hxxp://user[[@]]evil-u.example.org/x", "hxxp://user[[[@]]]evil-u.example.org/x",
        "HXXP://USER[@]EVIL-U.EXAMPLE.ORG/X"]),
}  # fmt: skip
ROWS = [  # (id, the IOC, the forms the finding cites)
    *((f"{name}, cited as {form}", name, [form])
      for name, (_, _, forms) in CORPUS.items() for form in forms),
    *((f"{name}, cited in every form", name, forms)
      for name, (_, _, forms) in CORPUS.items()),
]  # fmt: skip
IDS = [r[0] for r in ROWS]
KNOWN = {  # forms a saved report writes as cited, host live, as public main (0.6.5) does
    "hxxp://evil-s.example.com/a", "HXXP://EVIL-S.EXAMPLE.COM/A",
    "hxxp://user[[@]]evil-u.example.org/x", "hxxp://user[[[@]]]evil-u.example.org/x",
    "HXXP://USER[@]EVIL-U.EXAMPLE.ORG/X",
}  # fmt: skip
WRITTEN_LIVE = pytest.mark.xfail(strict=True, reason=(
    "known issue, as at public main (0.6.5): a URL cited with its host's dots live "
    "(only the scheme defanged, or a nested [@] the defanger doesn't read) is written "
    "as cited; there: AssertionError: assert ['evil-s.example.com'] == []"))  # fmt: skip


def stored(forms: list[str], kind: str) -> list[dict]:
    """The IOC records record_finding stores for a finding citing `forms`
    typed `kind`: each refanged, joined to a record that is the same IOC."""
    records: list[dict] = []
    for form in forms:
        value = ioc_types.refang(form.strip())
        if not any(ioc_types.keys(value, kind) & ioc_types.keys(r["value"], kind)
                   for r in records):  # fmt: skip
            records.append({"id": f"IOC-tester-{len(records) + 1:03d}", "value": value,
                            "type": kind, "status": "DRAFT", "manually_reviewed": False,
                            "source_findings": [FINDING]})  # fmt: skip
    return records


def live(text: str, name: str) -> list[str]:
    """The IOC's live names that `text` shows, in any letter case."""
    return [h for h in CORPUS[name][1] if re.search(re.escape(h), text, re.I)]


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-F-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-F-1", "name": "f"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


def _case(case, name: str, forms: list[str], status: str) -> list[dict]:
    """The case: one approved finding citing `forms`, and its records, each
    set to `status` by the examiner (APPROVED or REJECTED), all signed in the
    ledger as vhir approve and reject sign them. Returns the records."""
    kind = CORPUS[name][0]
    finding = {"id": FINDING, "title": "t", "observation": "o", "interpretation": "i",
               "confidence": "HIGH", "status": "APPROVED", "approved_by": "tester",
               "approved_at": AT, "iocs": [{"value": f, "type": kind} for f in forms]}  # fmt: skip
    records = [{**r, "status": status, "manually_reviewed": True}
               for r in stored(forms, kind)]  # fmt: skip
    for r in records:
        if status == "APPROVED":
            r.update(approved_by="tester", approved_at=AT)
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    decisions = [{"item_id": FINDING, "type": "finding", "decision": "approve",
                  "status_after": "APPROVED", "coupled_from": None,
                  "content_snapshot": signed_text(finding, "finding"),
                  "checks": {"result": "not-applicable", "items": []}}]  # fmt: skip
    decisions += [{"item_id": r["id"], "type": "ioc",
                   "decision": "approve" if status == "APPROVED" else "reject",
                   "status_after": status, "coupled_from": None,
                   "content_snapshot": signed_text(r, "ioc")} for r in records]  # fmt: skip
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    bodies = ledger.prepare(case.name, decisions, "tester", pub, "cli", AT)
    with ledger.case_lock(case.name) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text(json.dumps(records))
    return records


def _listed(case, profile: str) -> list[str]:
    import report_mcp.server as rs

    out = rs._generate(profile, case)
    assert not out["verification"]["case_failures"], out["verification"]
    return [e["value"] for group in out["report_data"]["iocs"].values() for e in group]


def _saved(case, content: str, profile: str) -> str:
    from report_mcp.server import create_server

    tool = {t.name: t for t in create_server()._tool_manager.list_tools()}[
        "save_report"
    ]
    got = tool.fn(filename=f"r-{profile}.md", content=content, profile=profile)
    assert got["status"] == "saved", got
    return (case / "reports" / f"r-{profile}.md").read_text()


@pytest.mark.parametrize(("name", "forms", "profile"), [
    pytest.param(name, forms, profile, id=f"{row}-{profile}",
                 marks=[WRITTEN_LIVE] if KNOWN & set(forms) else [])
    for profile in ["full", "ioc"] for row, name, forms in ROWS
])  # fmt: skip
def test_a_saved_report_writes_no_form_of_an_ioc_live(case, name, forms, profile):
    """The report names it in every form cited, as stored and as listed."""
    records = _case(case, name, forms, "APPROVED")
    named = [*forms, *(r["value"] for r in records), *_listed(case, profile)]
    saved = _saved(case, "Seen: " + "; ".join(named) + ".", profile)
    assert live(saved, name) == []


@pytest.mark.parametrize("profile", ["full", "ioc"])
@pytest.mark.parametrize(("name", "forms"), [r[1:] for r in ROWS], ids=IDS)
def test_a_signed_rejection_keeps_every_form_out_of_the_reports_iocs(
    case, name, forms, profile
):
    from report_mcp.server import _report_iocs
    from vhir_cli.ledger_verify import approved_view

    _case(case, name, forms, "REJECTED")
    assert _listed(case, profile) == []
    assert _report_iocs(case, approved_view(case)) == []


@pytest.mark.parametrize("profile", ["full", "ioc"])
@pytest.mark.parametrize(("name", "forms"), [r[1:] for r in ROWS], ids=IDS)
def test_the_listing_holds_an_ioc_once_however_it_is_cited(case, name, forms, profile):
    _case(case, name, forms, "APPROVED")
    assert len(_listed(case, profile)) == 1
