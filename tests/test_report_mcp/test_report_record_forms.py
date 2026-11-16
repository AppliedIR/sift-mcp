"""Every form of a record file the reader can't read, through report-mcp's
own tool route (call_tool), on a DRAFT case and on a signed one. The forms
restate vhir-cli's table in its tests/test_report_stop_matrix.py.

- generate_report, in every profile, with any one of findings, timeline,
  iocs and todos.json in a form, raises nothing and returns `unreadable`
  naming that file, by full path, with the form's phrase.
- save_report with findings.json or iocs.json in a form refuses: the file
  and its phrase, its remediation line, then "Report not saved: <file> can't
  be read.", never "empty list"; `files` and `file` name it, and a report
  saved earlier under that name is left byte-identical with no new version
  beside it. Two such files are both named, in order.
- save_report with timeline.json or todos.json in a form saves, and its
  PROVENANCE block says what the approved view holds: withheld when verify
  reports a case-level failure, else the approved findings (none on a DRAFT
  case).
- A list nested 500 deep parses, and its one entry isn't a record: in
  findings.json the save refuses with that phrase; in timeline.json it saves,
  with MALFORMED_RECORD in its block and its PROVENANCE withheld.
Mode 000 doesn't refuse root, so that form is skipped under euid 0."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import traceback

import pytest
import yaml
from report_mcp.profiles import PROFILES
from vhir_signing import sign_approved

CASE = "INC-2026-FORMS"
FILES = ("findings.json", "timeline.json", "iocs.json", "todos.json")
VERIFIED = FILES[:3]  # the files verify reads
KINDS = ("draft", "signed")
PRIOR = b"PRIOR REPORT, written before the save\n"
CONTENT = "# Report\n\nBody.\n"
EMPTY = "is empty, not a list of records"
NOT_A_RECORD = "holds a list with an entry that isn't a record"
DIR, LINK, CUT, MIXED, MODE000, TO_VALID, HARD_LINK, FIFO = (object() for _ in range(8))
FORMS = {  # form: (what is written in the file, the phrase the reader gives it)
    "null": ("null", "holds null, not a list of records"),
    "number": ("7", "holds a number, not a list of records"),
    "boolean": ("true", "holds a boolean, not a list of records"),
    "list-of-strings": ('["c2.example.net"]', NOT_A_RECORD),
    "empty": ("", EMPTY),
    "blank": (" \n\t \n", EMPTY),
    "not-utf8": (b'[{"id": "X-1", "note": "\xff"}]', "couldn't be read (not UTF-8 text)"),
    "directory": (DIR, "couldn't be read (it is a folder)"),
    "dangling-symlink": (LINK, "couldn't be read (it is a symbolic link)"),
    "string": ('"records"', "holds a string, not a list of records"),
    "list-of-numbers": ("[1]", NOT_A_RECORD),
    "mixed-list": (MIXED, NOT_A_RECORD),
    "dict": ('{"id": "X-1"}', "holds an object, not a list of records"),
    "unparseable": (CUT, "couldn't be read (not valid JSON)"),
    "permission-denied": (MODE000, "couldn't be read (permission denied)"),
    "symlink-valid": (TO_VALID, "couldn't be read (it is a symbolic link)"),
    "hard-link": (HARD_LINK, "couldn't be read (another name links to it)"),
    "fifo": (FIFO, "couldn't be read (it isn't a regular file)"),
    "nested": ("[" * 100000 + "]" * 100000, "couldn't be read (nested too deeply)"),
}  # fmt: skip
DEEP = "[" * 500 + "]" * 500  # parses: a list whose one entry is a list
RESTORE = "restore the case from a backup (`vhir restore`)"
WITHHELD = "Approved findings: withheld: the case fails verification (see below)"
NONE_SHOWN = "No approved, verified findings."
SHOWN = "[F-tester-001] Beacon"


def _items(status):
    return {
        "findings.json": [{"id": "F-tester-001", "status": status, "title": "Beacon",
                           "confidence": "LOW", "observation": "o", "interpretation": "i",
                           "iocs": []}],
        "timeline.json": [{"id": "T-tester-001", "status": status, "description": "d",
                           "timestamp": "2026-10-08T09:00:00+00:00"}],
        "iocs.json": [{"id": "IOC-tester-001", "status": status, "value": "c2.example.net",
                       "type": "domain-name", "manually_reviewed": True,
                       "source_findings": ["F-tester-001"]}],
        "todos.json": [{"todo_id": "TODO-tester-001", "status": "open",
                        "description": "Pull logs"}],
    }  # fmt: skip


@pytest.fixture
def rs(tmp_path, monkeypatch):
    import report_mcp.server as rs

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


def _case(tmp_path, monkeypatch, kind):
    """A finding, an event, an IOC record and an open todo: all DRAFT, or
    the three verified ones APPROVED and signed."""
    case = tmp_path / CASE
    case.mkdir()
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": CASE, "name": "Forms"}))
    for name, items in _items("APPROVED" if kind == "signed" else "DRAFT").items():
        (case / name).write_text(json.dumps(items, indent=2))
    if kind == "signed":
        sign_approved(case)
    return case


def _spoil(path, form):
    """Leave `path` in `form` (a FORMS key, or the text to write)."""
    how = FORMS[form][0] if form in FORMS else form
    if how is MODE000 and os.geteuid() == 0:
        pytest.skip("mode 000 doesn't refuse root: the form is skipped under euid 0")
    if how in (DIR, LINK, TO_VALID, FIFO):
        if how is TO_VALID:
            real = path.with_name(path.name + ".real")
            real.write_bytes(path.read_bytes())
        path.unlink()
        if how is DIR:
            path.mkdir()
        elif how is LINK:
            path.symlink_to(path.with_name("no-such-file.json"))
        elif how is TO_VALID:
            path.symlink_to(real)
        else:
            os.mkfifo(path)
    elif how is CUT:
        path.write_text(path.read_text().rstrip().rstrip("]"))
    elif how is MIXED:
        path.write_text(json.dumps([*json.loads(path.read_text())[:1], 1]))
    elif how is MODE000:
        path.chmod(0)
    elif how is HARD_LINK:
        os.link(path, path.with_name(path.name + ".2"))
    else:
        path.write_bytes(how if isinstance(how, bytes) else how.encode())


def _remedy(name, form, kind):
    """The remediation line for `name` (findings or iocs.json) in `form` on a
    `kind` case. The signed case's ledger holds an approved item of each
    verified file; the DRAFT case's none. verify passes over a name with
    nothing behind it (a dangling symlink)."""
    if form in ("empty", "blank"):
        if kind == "signed":
            return (f"{name} is empty, but the case's approval records show it held"
                    f" approved items. {RESTORE[0].upper()}{RESTORE[1:]}.")  # fmt: skip
        return (f"{name} holds no records. If the case never held any, write [] to"
                f" it; otherwise {RESTORE}.")  # fmt: skip
    if form != "dangling-symlink":
        return ("Run `vhir review --findings --verify` to see the file's state;"
                f" repair it, or {RESTORE}.")  # fmt: skip
    return f"Repair {name}, or {RESTORE}."


def _call(rs, tool, args):
    """The tool's reply through the server's call_tool, as a dict. Anything
    raised fails the cell, naming the raise and where it came from."""
    try:
        out = asyncio.run(rs.create_server().call_tool(tool, args))
    except Exception as e:  # noqa: BLE001  (the row's property: nothing raises)
        cause = e.__cause__ or e
        pytest.fail(f"{tool} raised {type(e).__name__}: {e} (from "
                    f"{type(cause).__name__} at "
                    f"{traceback.extract_tb(cause.__traceback__)[-1]})")  # fmt: skip
    content = out[0] if isinstance(out, tuple) else out
    return content if isinstance(content, dict) else json.loads(content[0].text)


def _save(rs):
    return _call(rs, "save_report", {"filename": "r.md", "content": CONTENT})


def _listing(case):
    reports = case / "reports"
    if not reports.exists():
        return {}
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(reports.iterdir())}  # fmt: skip


def _refuses(rs, case, names, whys, remedies):
    (case / "reports").mkdir(exist_ok=True)
    (case / "reports" / "r.md").write_bytes(PRIOR)
    before = _listing(case)
    got = _save(rs)
    listed = names[0] if len(names) == 1 else f"{names[0]} and {names[1]}"
    assert got.get("error") == "\n".join([
        *(f"{n} {w}" for n, w in zip(names, whys, strict=True)), *remedies,
        f"Report not saved: {listed} can't be read.",
    ]), got  # fmt: skip
    assert "empty list" not in got["error"]
    assert got.get("files") == [str(case / n) for n in names], got
    assert got.get("file") == str(case / names[0]), got
    assert _listing(case) == before, "reports/ changed"


def _saved_block(rs, case):
    """The save's verification block lines, after checking it saved them."""
    got = _save(rs)
    assert got.get("status") == "saved", got
    saved = (case / "reports" / "r.md").read_text()
    block = got["verification_block"]
    assert "\n".join(block) in saved, "the saved file doesn't end with the block"
    return block


# -- generate_report: every form of every record file, in every profile -----------


@pytest.mark.parametrize("profile", sorted(PROFILES))
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("form", FORMS)
def test_generate_report_names_the_file_in_each_form(
    rs, tmp_path, monkeypatch, form, name, kind, profile
):
    case = _case(tmp_path, monkeypatch, kind)
    _spoil(case / name, form)
    got = _call(rs, "generate_report", {"profile": profile})
    assert "error" not in got, got.get("error")
    assert got.get("unreadable") == [
        {"file": str(case / name), "why": FORMS[form][1]}
    ], got.get("unreadable", f"no `unreadable` in the reply (keys {sorted(got)})")


# -- save_report: findings.json and iocs.json stop it ------------------------------


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("name", ["findings.json", "iocs.json"])
@pytest.mark.parametrize("form", FORMS)
def test_save_report_refuses_on_each_form(rs, tmp_path, monkeypatch, form, name, kind):
    case = _case(tmp_path, monkeypatch, kind)
    _spoil(case / name, form)
    _refuses(rs, case, [name], [FORMS[form][1]], [_remedy(name, form, kind)])


@pytest.mark.parametrize("kind", KINDS)
def test_save_report_names_two_files_in_order(rs, tmp_path, monkeypatch, kind):
    case = _case(tmp_path, monkeypatch, kind)
    _spoil(case / "findings.json", "null")
    _spoil(case / "iocs.json", "unparseable")
    _refuses(
        rs, case, ["findings.json", "iocs.json"],
        [FORMS["null"][1], FORMS["unparseable"][1]],
        [_remedy("findings.json", "null", kind), _remedy("iocs.json", "unparseable", kind)],
    )  # fmt: skip


# -- save_report: timeline.json and todos.json don't stop it -------------------------


def _timeline_failure(form, kind):
    """The case-level line verify gives a timeline.json in `form`, else None."""
    if FORMS[form][1] == NOT_A_RECORD:
        return "Case-level: MALFORMED_RECORD: timeline.json entry "
    if form not in ("empty", "blank", "dangling-symlink"):
        return "Case-level: CASE_FILE_UNREADABLE: timeline.json couldn't be read ("
    if kind == "signed":  # read as no records: the signed event is missing
        return "Case-level: ITEM_MISSING: "
    return None


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("name", ["timeline.json", "todos.json"])
@pytest.mark.parametrize("form", FORMS)
def test_save_report_writes_on_each_form(rs, tmp_path, monkeypatch, form, name, kind):
    case = _case(tmp_path, monkeypatch, kind)
    _spoil(case / name, form)
    block = _saved_block(rs, case)
    failure = _timeline_failure(form, kind) if name == "timeline.json" else None
    case_level = [ln for ln in block if ln.startswith("Case-level: ")]
    if failure:
        assert any(ln.startswith(failure) for ln in case_level), block
        assert WITHHELD in block, block
        assert SHOWN not in block and NONE_SHOWN not in block, block
    else:
        assert case_level == [], block
        assert (SHOWN if kind == "signed" else NONE_SHOWN) in block, block
        assert WITHHELD not in block, block


# -- a list nested 500 deep ----------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_save_report_refuses_a_500_deep_findings_file(rs, tmp_path, monkeypatch, kind):
    case = _case(tmp_path, monkeypatch, kind)
    assert json.loads(DEEP), "the 500-deep list parses"
    _spoil(case / "findings.json", DEEP)
    remedy = ("Run `vhir review --findings --verify` to see the file's state;"
              f" repair it, or {RESTORE}.")  # fmt: skip
    _refuses(rs, case, ["findings.json"], [NOT_A_RECORD], [remedy])


@pytest.mark.parametrize("kind", KINDS)
def test_save_report_writes_with_a_500_deep_timeline_file(
    rs, tmp_path, monkeypatch, kind
):
    case = _case(tmp_path, monkeypatch, kind)
    _spoil(case / "timeline.json", DEEP)
    block = _saved_block(rs, case)
    assert "Case-level: MALFORMED_RECORD: timeline.json entry 1 isn't a record" in block
    assert WITHHELD in block, block
