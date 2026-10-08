"""The host-operation journal: one entry per operation id, written whole and
replaced at once, so a reader never sees it in part."""

from __future__ import annotations

import json
import os

import pytest
from sift_common import host_identity as hi


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def test_each_operation_keeps_its_fields_by_id(case):
    hi.record_op(case, "op-1", {"state": "running", "kind": "rename"})
    hi.record_op(case, "op-2", {"state": "done"})
    entry = hi.record_op(case, "op-1", {"state": "incomplete", "reason": "x"})
    assert (
        entry["kind"] == "rename"
        and entry["state"] == "incomplete"
        and entry["updated"]
    )
    ops = hi.read_ops(case)["ops"]
    assert set(ops) == {"op-1", "op-2"} and ops["op-2"]["state"] == "done"
    assert hi.unfinished_op(case)["id"] == "op-1"


def test_a_failed_write_leaves_the_journal_as_it_was_and_no_temporary_file(
    case, monkeypatch
):
    hi.record_op(case, "op-1", {"state": "done"})
    before = (case / hi.OPS).read_bytes()

    def no_space(fd, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "write", no_space)
    with pytest.raises(OSError):
        hi.record_op(case, "op-2", {"state": "running"})
    monkeypatch.undo()
    assert (case / hi.OPS).read_bytes() == before
    assert sorted(p.name for p in case.iterdir() if p.name.endswith(".tmp")) == []
    assert json.loads(before)["ops"].keys() == {"op-1"}


def test_an_operations_decision_line_is_found_by_its_id(case):
    hi.append_decision(case, {"action": "rename", "examiner": "ex1", "op": "op-1",
                              "args": {}}, hi.load(case).obs_offset, door="R")  # fmt: skip
    assert hi.decided_op(case, "op-1") and not hi.decided_op(case, "op-2")


def test_a_torn_decision_line_is_not_a_decision(case):
    with open(case / hi.DECISIONS, "ab") as f:
        f.write(b'{"action": "rename", "op": "op-3", "args": {')  # no newline: torn
    assert not hi.decided_op(case, "op-3")


def _confirm(case, raw="WKS01"):
    return {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": hi.new_machine_key(), "canonical": raw, "pairs": []}]}}  # fmt: skip


@pytest.mark.parametrize("state", ["running", "incomplete"])
def test_a_host_decision_waits_for_an_unfinished_operation(case, state):
    hi.record_op(case, "op-1", {"state": state, "kind": "rename"})
    with pytest.raises(hi.HostOpRunning, match="a host rename/merge is running"):
        hi.append_decision(case, _confirm(case), hi.load(case).obs_offset)
    with pytest.raises(hi.HostOpRunning):
        hi.append_decision_items(case, _confirm(case), hi.load(case).obs_offset)
    # the operation's own decision line goes in
    hi.append_decision(case, {"action": "rename", "examiner": "ex1", "op": "op-1",
                              "args": {}}, hi.load(case).obs_offset, door="R")  # fmt: skip
    hi.record_op(case, "op-1", {"state": "done"})
    hi.append_decision(case, _confirm(case), hi.load(case).obs_offset)


def test_a_check_that_refuses_writes_nothing(case):
    hi.record_op(case, "op-1", {"state": "done"})
    before = (case / hi.OPS).read_bytes()
    seen = []

    def refuse(state):
        seen.append(state)
        raise ValueError("changed since you opened it")

    with pytest.raises(ValueError):
        hi.record_op(case, "op-2", {"state": "running"}, check=refuse)
    assert (case / hi.OPS).read_bytes() == before and isinstance(seen[0], hi.HostState)
