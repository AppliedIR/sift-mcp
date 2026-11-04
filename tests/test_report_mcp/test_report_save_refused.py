"""save_report writes a report only when every file it reads IOCs from,
findings.json and iocs.json, is absent or parses to a list of records. Any
other file there (empty or blank, not UTF-8, one that won't parse, null, a
number, a boolean, a list holding something other than records, a directory,
a dangling symlink) means the report isn't saved: nothing is raised, a report
already saved under that name is left byte-identical with no new version
beside it (with none there, none is created), and the error names the file
and what the examiner can do, with no command to run. A file that is an empty
list saves. An absent file is
a case with none of them. The IOCs come from the files as they are just before
the write, and each save reads the approved view once. vhir-cli's tests state
the same rows for `vhir report --save`."""

from __future__ import annotations

import hashlib
import json

import pytest
import yaml
from vhir_cli import keys, ledger
from vhir_cli.case_io import signed_text
from vhir_signing import _KEYS, sign_approved

CASE = "INC-2026-REFUSE"
PRIOR = b"PRIOR REPORT, written before the save\n"
DIR, LINK = object(), object()  # in place of the file: a directory, a dangling symlink
VALUE = "c2.example.net"
LATE = "late.example.net"
FINDING = {"id": "F-tester-001", "status": "APPROVED", "title": "Beacon to a C2 host",
           "confidence": "HIGH", "observation": f"beacons to {VALUE}",
           "interpretation": "C2", "iocs": []}  # fmt: skip
IOC = {"id": "IOC-tester-001", "value": VALUE, "type": "domain-name",
       "status": "APPROVED", "manually_reviewed": True, "approved_by": "tester",
       "approved_at": "2026-10-08T12:00:00+00:00",
       "source_findings": [FINDING["id"]]}  # fmt: skip
CONTENT = f"# Report\n\nBeacon to {VALUE}, then {LATE}.\n"


@pytest.fixture
def rs(tmp_path, monkeypatch):
    import report_mcp.server as rs

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


def _case(tmp_path, monkeypatch, field=()):
    """One approved finding naming VALUE; one approved IOC record of VALUE
    citing it, both signed. `field`: the finding's own iocs field."""
    case = tmp_path / CASE
    case.mkdir()
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": CASE, "name": "Refuse"}))
    (case / "findings.json").write_text(json.dumps([dict(FINDING, iocs=list(field))]))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text("[]")
    sign_approved(case)
    key = _KEYS[(str(case), "tester")]
    pub = keys.b64(keys.public_raw(key))
    d = [{"item_id": IOC["id"], "type": "ioc", "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(IOC, "ioc")}]  # fmt: skip
    bodies = ledger.prepare(CASE, d, "tester", pub, "cli", IOC["approved_at"])
    with ledger.case_lock(CASE) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    (case / "iocs.json").write_text(json.dumps([IOC], indent=2))
    return case


def _save(rs, case):
    """(the tool's reply, the saved text or None)."""
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}
    got = tool["save_report"].fn(filename="r.md", content=CONTENT, profile="full")
    path = case / "reports" / "r.md"
    return got, (path.read_text() if path.exists() else None)


BAD = {  # (file, what is written in it, what the error says about it)
    "iocs.json that won't parse (VALUE only in its record)":
        ("iocs.json", None, "couldn't be read"),
    "iocs.json null": ("iocs.json", "null", "holds null, not a list of records"),
    "iocs.json 7": ("iocs.json", "7", "holds a number, not a list of records"),
    "iocs.json true": ("iocs.json", "true", "holds a boolean, not a list of records"),
    "iocs.json a list of strings": ("iocs.json", json.dumps([VALUE]),
                                    "holds a list with an entry that isn't a record"),
    "findings.json that won't parse": ("findings.json", None, "couldn't be read"),
    "findings.json null": ("findings.json", "null", "holds null, not a list of records"),
    "findings.json 7": ("findings.json", "7", "holds a number, not a list of records"),
    "findings.json true": ("findings.json", "true",
                           "holds a boolean, not a list of records"),
    "iocs.json empty": ("iocs.json", "", "is empty, not a list of records"),
    "iocs.json blank": ("iocs.json", " \n\t \n", "is empty, not a list of records"),
    "findings.json empty": ("findings.json", "", "is empty, not a list of records"),
    "findings.json blank": ("findings.json", " \n\t \n",
                            "is empty, not a list of records"),
    "iocs.json not UTF-8": ("iocs.json", b'[{"id": "IOC-x", "value": "\xff"}]',
                            "couldn't be read"),
    "iocs.json a directory": ("iocs.json", DIR, "couldn't be read"),
    "iocs.json a dangling symlink": ("iocs.json", LINK, "couldn't be read"),
    "findings.json not UTF-8": ("findings.json",
                                b'[{"id": "F-x", "observation": "\xff"}]',
                                "couldn't be read"),
    "findings.json a directory": ("findings.json", DIR, "couldn't be read"),
    "findings.json a dangling symlink": ("findings.json", LINK, "couldn't be read"),
}  # fmt: skip
GOOD = {  # (file, what is written in it): a list of records, empty too, saves
    "iocs.json []": ("iocs.json", "[]"),
    "findings.json []": ("findings.json", "[]"),
}  # fmt: skip


def _spoil(path, how):
    """Leave `path` as BAD says: None cuts its closing bracket."""
    if how is None:
        path.write_text(path.read_text().rstrip().rstrip("]"))
    elif how is DIR:
        path.unlink()
        path.mkdir()
    elif how is LINK:
        path.unlink()
        path.symlink_to(path.with_name("no-such-file.json"))
    else:
        path.write_bytes(how if isinstance(how, bytes) else how.encode())


def _sha(path):
    """None when there is no file."""
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


@pytest.mark.parametrize("prior", (False, True), ids=("no-report", "a-report"))
@pytest.mark.parametrize("row", BAD)
def test_a_file_that_is_not_a_list_of_records_refuses_the_save(
    rs, tmp_path, monkeypatch, row, prior
):
    case = _case(tmp_path, monkeypatch)
    name, how, why = BAD[row]
    path = case / name
    _spoil(path, how)
    (case / "reports").mkdir()
    report = case / "reports" / "r.md"
    if prior:
        report.write_bytes(PRIOR)
    before = _sha(report)
    got, saved = _save(rs, case)
    assert [p.name for p in report.parent.iterdir()] == ["r.md"] * prior, got
    assert _sha(report) == before, saved
    assert got["file"] == str(path), got
    assert got["error"].startswith(f"Report not saved. {path} {why}"), got
    assert "`" not in got["error"] and "vhir " not in got["error"], got
    for words in ("Tell the examiner", "restore the file from a backup", "empty list"):
        assert words in got["error"], got


@pytest.mark.parametrize("row", GOOD)
def test_a_file_that_is_an_empty_list_saves(rs, tmp_path, monkeypatch, row):
    case = _case(tmp_path, monkeypatch)
    name, text = GOOD[row]
    (case / name).write_text(text)
    got, saved = _save(rs, case)
    assert got.get("status") == "saved" and saved is not None, got


def test_an_absent_iocs_json_saves(rs, tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, field=[{"value": VALUE, "type": "domain-name"}])
    (case / "iocs.json").unlink()
    got, saved = _save(rs, case)
    assert got.get("status") == "saved" and saved is not None, got
    assert VALUE not in saved and "c2[.]example[.]net" in saved, saved


def test_an_iocs_json_past_the_verify_cap_saves_defanged(rs, tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)  # VALUE only in the IOC record
    path = case / "iocs.json"
    path.write_text(path.read_text() + " " * (17 << 20))
    got, saved = _save(rs, case)
    assert got.get("status") == "saved" and saved is not None, got
    assert VALUE not in saved and "c2[.]example[.]net" in saved, saved


def test_a_record_written_after_the_view_is_read_is_defanged(rs, tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    real = rs.approved_view

    def view_then_record(case_dir):
        view = real(case_dir)
        late = dict(IOC, id="IOC-tester-002", value=LATE, status="DRAFT",
                    manually_reviewed=False)  # fmt: skip
        records = json.loads((case_dir / "iocs.json").read_text())
        (case_dir / "iocs.json").write_text(json.dumps([*records, late]))
        return view

    monkeypatch.setattr(rs, "approved_view", view_then_record)
    got, saved = _save(rs, case)
    assert got.get("status") == "saved" and saved is not None, got
    assert LATE not in saved and "late[.]example[.]net" in saved, saved


def test_each_save_reads_the_approved_view_once(rs, tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    real, calls = rs.approved_view, []

    def counted(case_dir):
        calls.append(case_dir)
        return real(case_dir)

    monkeypatch.setattr(rs, "approved_view", counted)
    got, saved = _save(rs, case)
    assert got.get("status") == "saved" and saved is not None, got
    assert len(calls) == 1, calls
