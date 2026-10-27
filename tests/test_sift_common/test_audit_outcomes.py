"""Each audit write has one outcome, and the writer says which.

recorded (with its id), no case, case gone (the path that is no longer a
case) or write failed (the reason). `log()` still answers the id or None;
`record()` answers the outcome. Nothing is created under a folder that isn't
a case at that moment, and a case moved away between the check and the
creation is not recreated.
"""

from __future__ import annotations

import json
import os
import pathlib
import threading

import pytest
import sift_common
from sift_common import audit as audit_mod
from sift_common.audit import AuditWriter


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    return home


def _case(tmp_path, name="case-a", audit=True):
    case = tmp_path / "cases" / name
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\n")
    if audit:
        (case / "audit").mkdir()
    return case


def _point(home, target):
    (home / ".vhir" / "active_case").write_text(str(target))


def _entries(folder, mcp="test-mcp"):
    log = folder / f"{mcp}.jsonl"
    return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


def _record(writer, **kw):
    return writer.record("t", {}, {}, **kw)


# --- the mapping: one outcome per resolution --------------------------------


def test_explicit_audit_folder_records_with_no_case_check(home, tmp_path):
    folder = tmp_path / "anywhere" / "audit"
    folder.parent.mkdir()
    out = _record(AuditWriter("test-mcp", audit_dir=str(folder)))
    assert out.kind == "recorded" and out.audit_id
    assert [e["audit_id"] for e in _entries(folder)] == [out.audit_id]


def test_audit_folder_from_the_environment_records(home, tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "a" / "b"))
    out = _record(AuditWriter("test-mcp"))
    assert out.kind == "recorded" and _entries(tmp_path / "a" / "b")


def test_a_resolution_taken_earlier_decides_the_outcome(home, tmp_path):
    case = _case(tmp_path)
    writer = AuditWriter("test-mcp")
    _point(home, case)
    res = writer.resolve()
    assert (res.outcome, res.path) == ("case", str(case))
    _point(home, "")
    out = _record(writer, case_dir=res)
    assert out.kind == "recorded" and _entries(case / "audit")
    gone = audit_mod.CaseResolution("case_gone", path="/cases/x")
    assert _record(writer, case_dir=gone) == audit_mod.AuditOutcome(
        kind="case_gone", detail="/cases/x"
    )


def test_an_empty_case_dir_is_no_case(home, tmp_path):
    _point(home, _case(tmp_path))
    assert _record(AuditWriter("test-mcp"), case_dir="").kind == "no_case"


@pytest.mark.parametrize("via", ["case_dir", "resolver", "pointer"])
def test_a_folder_without_case_yaml_is_case_gone_and_left_alone(via, home, tmp_path):
    folder = tmp_path / "cases" / "not-a-case"
    folder.mkdir(parents=True)
    kw = {}
    writer = AuditWriter("test-mcp")
    if via == "case_dir":
        kw["case_dir"] = str(folder)
    elif via == "resolver":
        writer = AuditWriter("test-mcp", case_dir_resolver=lambda: folder)
    else:
        _point(home, folder)
    assert writer.log("t", {}, {}, **kw) is None
    assert list(folder.iterdir()) == []
    out = _record(writer, **kw)
    assert (out.kind, out.detail, out.audit_id) == ("case_gone", str(folder), None)
    assert list(folder.iterdir()) == []


def test_a_resolver_with_nothing_falls_through_to_env_then_pointer(
    home, tmp_path, monkeypatch
):
    env_case, pointed = _case(tmp_path, "env"), _case(tmp_path, "pointed")
    writer = AuditWriter("test-mcp", case_dir_resolver=lambda: None)
    _point(home, pointed)
    monkeypatch.setenv("VHIR_CASE_DIR", str(env_case))
    assert _record(writer).kind == "recorded" and _entries(env_case / "audit")
    monkeypatch.setenv("VHIR_CASE_DIR", str(tmp_path / "nowhere"))
    assert _record(writer).kind == "recorded" and _entries(pointed / "audit")


@pytest.mark.parametrize("pointer", [None, "", "   \n"])
def test_no_pointer_or_an_empty_one_is_no_case(pointer, home):
    if pointer is not None:
        (home / ".vhir" / "active_case").write_text(pointer)
    writer = AuditWriter("test-mcp")
    assert _record(writer) == audit_mod.AuditOutcome(kind="no_case")
    assert writer.log("t", {}, {}) is None


def test_an_unreadable_pointer_is_write_failed_with_its_reason(home):
    (home / ".vhir" / "active_case").mkdir()
    out = _record(AuditWriter("test-mcp"))
    assert out.kind == "write_failed" and "Is a directory" in out.detail


def test_a_fifo_pointer_is_write_failed_and_never_read(home):
    os.mkfifo(home / ".vhir" / "active_case")  # no writer: a read would wait forever
    out = _record(AuditWriter("test-mcp"))
    assert out.kind == "write_failed" and "is not a regular file" in out.detail


@pytest.mark.parametrize("cause", ["mkdir", "write"])
def test_a_failed_creation_or_write_is_write_failed_with_the_os_reason(
    cause, home, tmp_path
):
    case = _case(tmp_path, audit=False)
    _point(home, case)
    if cause == "mkdir":
        (case / "audit").write_text("")
    else:
        (case / "audit").mkdir()
        (case / "audit" / "test-mcp.jsonl").mkdir()
    out = _record(AuditWriter("test-mcp"))
    assert out.kind == "write_failed" and out.detail.startswith("[Errno"), out
    assert out.audit_id is None


def test_log_answers_the_id_or_none(home, tmp_path):
    writer = AuditWriter("test-mcp")
    _point(home, _case(tmp_path))
    aid = writer.log("t", {}, {})
    assert isinstance(aid, str) and aid.startswith("test-tester-")
    _point(home, tmp_path / "cases" / "gone")
    assert writer.log("t", {}, {}) is None


# --- the outcome belongs to the call, never to the writer -------------------


def test_the_writer_keeps_no_outcome_and_threads_get_their_own(home, tmp_path):
    case = _case(tmp_path)
    good = AuditWriter("test-mcp", case_dir_resolver=lambda: case)
    before = dict(vars(good))
    for case_dir in (str(case), "", str(tmp_path / "gone")):
        good.log("t", {}, {}, case_dir=case_dir)
        assert vars(good) == before
    got: dict[str, object] = {}

    def call(key, case_dir):
        got[key] = good.log("t", {}, {}, case_dir=case_dir)

    threads = [
        threading.Thread(target=call, args=(k, d))
        for k, d in (("case", str(case)), ("none", ""))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert isinstance(got["case"], str) and got["none"] is None
    assert vars(good) == before


# --- a pointer that isn't text ----------------------------------------------


def test_an_undecodable_pointer_raises_nothing(home):
    (home / ".vhir" / "active_case").write_bytes(b"/cases/\xff\xfe")
    writer = AuditWriter("test-mcp")
    assert writer.log("t", {}, {}) is None
    assert sift_common.resolve_case_dir() == ""
    out = _record(writer)
    assert out.kind == "write_failed" and "can't decode" in out.detail


# --- a case moved away between its check and the creation -------------------


@pytest.fixture
def move_at_creation(monkeypatch):
    """Renames the case away at the first folder creation under it: just
    after its CASE.yaml check, before anything is created."""
    state = {}
    real = os.mkdir

    def mkdir(path, *args, **kwargs):
        case = state.get("case")
        if case and not state.get("moved") and str(path).startswith(str(case) + "/"):
            os.rename(case, str(case) + "-moved")
            state["moved"] = True
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", mkdir)
    accessor = getattr(pathlib, "_NormalAccessor", None)  # Python 3.10
    if accessor is not None:
        monkeypatch.setattr(accessor, "mkdir", staticmethod(mkdir), raising=False)
    return state


def _writer_for(via, case, home, monkeypatch):
    if via == "explicit":
        return AuditWriter("test-mcp", audit_dir=str(case / "audit"))
    if via == "resolver":
        return AuditWriter("test-mcp", case_dir_resolver=lambda: case)
    if via == "env":
        monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    else:
        _point(home, case)
    return AuditWriter("test-mcp")


@pytest.mark.parametrize("via", ["explicit", "resolver", "env", "pointer"])
def test_a_case_moved_before_creation_is_not_recreated(
    via, home, tmp_path, monkeypatch, move_at_creation
):
    case = _case(tmp_path, audit=False)
    writer = _writer_for(via, case, home, monkeypatch)
    move_at_creation["case"] = case
    assert writer.log("t", {}, {}) is None
    assert move_at_creation.get("moved") and not case.exists()
    os.rename(str(case) + "-moved", case)
    move_at_creation["moved"] = False
    out = _record(writer)
    assert (out.kind, out.detail) == ("case_gone", str(case)) and not case.exists()


# --- a new case records from its first call ---------------------------------


def test_a_new_case_records_from_its_first_call(home, tmp_path, monkeypatch):
    import case_mcp.server as cms

    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setattr(cms, "_ACTIVE_CASE_FILE", home / ".vhir" / "active_case")
    server = cms.create_server()

    def call(tool, **args):
        return server._tool_manager._tools[tool].fn(**args)

    made = call("case_init", name="new", case_id="case-new", share_wintools=False)
    assert "error" not in made, made
    assert call("log_reasoning", text="first")["status"] == "logged"
    bare = _case(tmp_path, "case-bare", audit=False)  # a case with no audit/ yet
    assert "error" not in call("case_activate", case_id="case-bare")
    assert call("log_reasoning", text="second")["status"] == "logged"
    tools = [e["tool"] for e in _entries(tmp_path / "cases" / "case-new" / "audit",
                                          "case-mcp")]  # fmt: skip
    assert {"case_init", "log_reasoning"} <= set(tools)
    tools = [e["tool"] for e in _entries(bare / "audit", "case-mcp")]
    assert {"case_activate", "log_reasoning"} <= set(tools)
