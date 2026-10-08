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
