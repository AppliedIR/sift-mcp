"""Staged entries: every save and delete is merged under the case lock, keyed
by (id, staged_by). The server stamps who staged an entry; a client's stamp is
never stored, and nobody's save drops another examiner's entry."""

from __future__ import annotations

import json

import pytest
from case_dashboard import signing
from vhir_cli import ledger

from .conftest import entry


@pytest.fixture
def case(portal):
    portal.write("findings.json", [])
    return portal


def _items(case):
    return case.read("pending-reviews.json")["items"]


def _save(case, items, examiner="steve"):
    return case.post("/api/delta", {"case_id": "C-1", "items": items}, examiner)


def test_a_save_is_stamped_by_the_server(case):
    r = _save(case, [dict(entry("F-1"), staged_by="lab2")])
    assert r.status_code == 200 and _items(case) == []  # never stored as lab2's
    _save(case, [dict(entry("F-1"), staged_by="steve", saved_unsigned={"at": "x"})])
    assert _items(case) == [dict(entry("F-1"), staged_by="steve")]


def test_a_copy_carrying_another_examiners_name_is_dropped(case):
    _save(case, [entry("F-1")], examiner="lab2")
    theirs = _items(case)[0]
    r = _save(case, [dict(theirs, action="reject")])
    assert r.json()["dropped"] == [{"id": "F-1", "staged_by": "lab2"}]
    assert _items(case) == [theirs]


def test_one_examiners_save_keeps_the_others_entries(case):
    _save(case, [entry("F-1")], examiner="lab2")
    theirs = json.dumps(_items(case), sort_keys=True)
    _save(case, [entry("F-2")])  # a page loaded before lab2 posted
    stored = _items(case)
    assert [e for e in stored if e["staged_by"] == "lab2"] == json.loads(theirs)
    assert [e["id"] for e in stored if e["staged_by"] == "steve"] == ["F-2"]
    _save(case, [])  # a post never drops an entry it doesn't name: DELETE does
    assert [e["id"] for e in _items(case)] == ["F-1", "F-2"]


def test_an_equal_copy_keeps_its_stamps(case):
    stamped = dict(
        entry("F-1"),
        staged_by="steve",
        saved_unsigned={"at": "t", "reason": "attempts"},
    )
    case.stage(stamped)
    _save(case, [{k: v for k, v in stamped.items() if k != "saved_unsigned"}])
    assert _items(case) == [stamped]
    _save(case, [dict(entry("F-1"), note="changed")])
    assert _items(case) == [dict(entry("F-1"), note="changed", staged_by="steve")]


def test_an_entry_staged_by_unknown_is_kept_and_not_taken_over(case):
    unknown = entry("F-9")
    case.stage(unknown)
    r = _save(case, [unknown, entry("F-1")])
    assert r.json()["dropped"] == [{"id": "F-9", "staged_by": None}]
    assert _items(case) == [unknown, dict(entry("F-1"), staged_by="steve")]


def test_a_delete_removes_only_the_callers_entry(case):
    _save(case, [entry("F-1")], examiner="lab2")
    _save(case, [entry("F-1", "reject")])
    r = case.client.delete("/api/delta/F-1", headers={"x-examiner": "steve"})
    assert r.status_code == 200
    assert _items(case) == [dict(entry("F-1"), staged_by="lab2")]
    r = case.client.delete("/api/delta/F-1", headers={"x-examiner": "steve"})
    assert r.status_code == 404
    assert _items(case) == [dict(entry("F-1"), staged_by="lab2")]


def test_a_delete_can_remove_an_unknown_entry(case):
    case.stage(entry("F-9"))
    r = case.client.delete("/api/delta/F-9", headers={"x-examiner": "steve"})
    assert r.status_code == 200 and _items(case) == []


def test_unknown_fields_are_refused(case):
    r = _save(case, [dict(entry("F-1"), evil=1)])
    assert r.status_code == 400 and "Unknown fields" in r.json()["error"]


def test_a_0_6_processing_file_is_merged_and_kept(case):
    case.stage(entry("F-1"))
    (case.dir / "pending-reviews.processing").write_text(
        json.dumps({"items": [entry("F-1", "reject"), entry("F-2")]})
    )
    _save(case, [entry("F-3")])
    ids = sorted((e["id"], e.get("staged_by")) for e in _items(case))
    assert ids == [("F-1", None), ("F-2", None), ("F-3", "steve")]
    assert not (case.dir / "pending-reviews.processing").exists()
    assert len(list(case.dir.glob("pending-reviews.processing.merged-*"))) == 1


def test_a_corrupt_file_is_set_aside_not_overwritten(case):
    (case.dir / "pending-reviews.json").write_text("{not json")
    _save(case, [entry("F-1")])
    aside = list(case.dir.glob("pending-reviews.json.corrupt-*"))
    assert len(aside) == 1 and aside[0].read_text() == "{not json"


def test_a_busy_lock_is_503(case, monkeypatch):
    monkeypatch.setattr(signing, "LOCK_SECONDS", 0.2)
    with ledger.case_lock("C-1"):
        r = _save(case, [entry("F-1")])
    assert r.status_code == 503 and r.json()["code"] == "LEDGER_BUSY"
    assert not (case.dir / "pending-reviews.json").exists()


def test_a_symlinked_file_is_refused(case, tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    (case.dir / "pending-reviews.json").symlink_to(target)
    r = _save(case, [entry("F-1")])
    assert r.status_code == 403
    assert target.read_text() == "{}"


# --- A page loaded on another case, and entries a post doesn't name ---------


def test_a_save_for_another_case_is_refused_and_nothing_changes(case):
    _save(case, [entry("F-1")])
    before = case.read("pending-reviews.json")
    r = case.post("/api/delta", {"case_id": "C-OTHER", "items": [entry("F-9")]})
    assert r.status_code == 409 and r.json()["code"] == "CASE_CHANGED"
    assert (
        "The active case is now C-1, not C-OTHER. Reload the page" in r.json()["error"]
    )
    assert case.read("pending-reviews.json") == before


def test_a_save_naming_no_case_is_refused(case):
    r = case.post("/api/delta", {"items": [entry("F-1")]})
    assert r.status_code == 409 and r.json()["code"] == "CASE_CHANGED"
    assert case.read("pending-reviews.json") is None


def test_a_save_keeps_the_posters_entries_it_doesnt_name(case):
    _save(case, [entry("F-1"), entry("F-2")])
    _save(case, [dict(entry("F-2"), action="reject")])  # a page that knew of F-2 only
    assert [(e["id"], e["action"]) for e in _items(case)] == [
        ("F-1", "approve"),
        ("F-2", "reject"),
    ]


def test_a_page_left_open_on_x_never_writes_into_y(case, tmp_path, monkeypatch):
    """The active case switches from X to Y while a page is open on X: its
    save is refused, Y keeps its own entry, and X gets nothing."""
    x, y = case.dir, tmp_path / "C-Y"
    y.mkdir()
    (y / "CASE.yaml").write_text("case_id: C-Y\n")
    (y / "findings.json").write_text("[]")
    staged = dict(entry("F-steve-101"), staged_by="steve")
    (y / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-Y", "items": [staged]})
    )
    loaded = case.get("/api/delta").json()  # the page, on X
    loaded.setdefault("case_id", "C-1")
    loaded["items"].append(entry("F-1"))
    monkeypatch.setenv("VHIR_CASE_DIR", str(y))  # the case is switched
    r = case.post("/api/delta", loaded)
    assert r.status_code == 409
    assert json.loads((y / "pending-reviews.json").read_text())["items"] == [staged]
    assert not (x / "pending-reviews.json").exists()
