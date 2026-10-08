"""A portal commit never replaces a findings or timeline file it can't read.

A signed commit rewrites findings.json and timeline.json. One that is
truncated, BOM-prefixed, not UTF-8 or unreadable is refused by name, at the
plan and again at the commit (under the case lock), with nothing signed, the
file left byte-identical and the staged review kept. A 0-byte or blank file
reads as [] and commits, as a [] file does.
"""

from __future__ import annotations

import json
import os

import pytest

from .conftest import enrol, event, finding, reviewed


@pytest.fixture
def case(portal):
    enrol("steve")
    portal.write("findings.json", [finding("F-steve-001")])
    portal.write("timeline.json", [event("T-steve-001", "F-steve-001")])
    return portal


BAD = {
    "truncated": lambda b: b[:-20],
    "a UTF-8 BOM": lambda b: b"\xef\xbb\xbf" + b,
    "not UTF-8": lambda b: b.replace(b"obs", b"\xff", 1).replace(b"ev T", b"\xff", 1),
}


def _spoil(path, shape):
    path.chmod(0o644)
    good = path.read_bytes()
    bad = BAD[shape](good)
    assert bad != good
    path.write_bytes(bad)
    return bad


def _refused(r):
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "CASE_FILE_UNREADABLE"
    assert "couldn't be read as case data; nothing was signed" in r.json()["error"]


@pytest.mark.parametrize("which", ["findings.json", "timeline.json"])
@pytest.mark.parametrize("shape", list(BAD))
def test_a_plan_over_a_file_it_cannot_parse_is_refused_and_changes_nothing(
    case, which, shape
):
    entry = dict(reviewed(case, "T-steve-001", "reject"), staged_by="steve")
    case.stage(entry)
    bad = _spoil(case.dir / which, shape)
    _refused(case.plan([entry]))
    assert (case.dir / which).read_bytes() == bad
    assert case.read("pending-reviews.json")["items"] and case.chain() == []


@pytest.mark.parametrize("which", ["findings.json", "timeline.json"])
def test_a_file_spoiled_after_the_plan_refuses_the_commit(case, which):
    entry = dict(reviewed(case, "T-steve-001", "reject"), staged_by="steve")
    case.stage(entry)
    plan = case.plan([entry]).json()
    sigs = case.sign(plan, case.login(plan).json())
    bad = _spoil(case.dir / which, "truncated")
    _refused(case.commit(plan, sigs))
    assert (case.dir / which).read_bytes() == bad
    assert case.read("pending-reviews.json")["items"] and case.chain() == []


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a mode-000 file, so it can't be made unreadable",
)
def test_a_plan_over_a_findings_file_it_cannot_read_is_refused(case):
    entry = dict(reviewed(case, "T-steve-001", "reject"), staged_by="steve")
    case.stage(entry)
    before = (case.dir / "findings.json").read_bytes()
    os.chmod(case.dir / "findings.json", 0o000)
    try:
        r = case.plan([entry])
    finally:
        os.chmod(case.dir / "findings.json", 0o644)
    _refused(r)
    assert (case.dir / "findings.json").read_bytes() == before


@pytest.mark.parametrize(
    "findings", [b"[]", b"", b"  \n"], ids=["an empty list", "empty", "blank"]
)
def test_a_commit_over_an_empty_or_blank_findings_file_goes_ahead(case, findings):
    entry = dict(reviewed(case, "T-steve-001", "reject"), staged_by="steve")
    case.stage(entry)
    path = case.dir / "findings.json"
    path.chmod(0o644)
    path.write_bytes(findings)
    r = case.sign_all([entry])
    assert r.status_code == 200, r.text
    (event,) = case.read("timeline.json")
    assert event["id"] == "T-steve-001" and event["status"] == "REJECTED"
    assert [ln["item_id"] for ln in case.chain()] == ["T-steve-001"]
    assert (
        json.loads(case.dir.joinpath("findings.json").read_text().strip() or "[]") == []
    )
