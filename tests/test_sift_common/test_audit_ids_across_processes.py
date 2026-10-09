"""Audit ids stay unique when several processes write one audit trail.

Each writer kept its sequence in memory and rewrote the shared sidecar from
it after every entry, so two processes with the same name (two sessions on
one project) handed out the same ids. The sequence is now taken under a lock
on the sidecar, which only ever moves forward.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import pytest
from sift_common.audit import AuditWriter

NAME = "test-mcp"


@pytest.fixture
def case(tmp_path, monkeypatch):
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    d = tmp_path / "case-a"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: case-a\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _ids(case: Path) -> list[str]:
    f = case / "audit" / f"{NAME}.jsonl"
    return [json.loads(line)["audit_id"] for line in f.read_text().splitlines() if line]


def test_two_writers_taking_turns_never_share_an_id(case):
    first, second = AuditWriter(NAME), AuditWriter(NAME)  # two sessions' servers
    for writer in (first, second, first, second):
        writer.log(tool="t", params={}, result_summary="x")
    ids = _ids(case)
    assert len(set(ids)) == 4, ids


CHILD = """
import os, sys, time
from sift_common.audit import AuditWriter
while not os.path.exists(sys.argv[1]):
    time.sleep(0.001)
writer = AuditWriter("test-mcp")
for _ in range(int(sys.argv[2])):
    writer.log(tool="t", params={}, result_summary="x")
"""


def test_writers_in_four_processes_at_once_never_share_an_id(case, tmp_path):
    go = tmp_path / "go"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    procs = [
        subprocess.Popen([sys.executable, "-c", CHILD, str(go), "300"], env=env)
        for _ in range(4)
    ]
    time.sleep(0.5)  # every child waiting, so they start together
    go.touch()
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0, 0]
    ids = _ids(case)
    assert len(ids) == 1200
    assert Counter(ids).most_common(1)[0][1] == 1


def test_the_sidecar_never_goes_back(case):
    ahead, behind = AuditWriter(NAME), AuditWriter(NAME)
    behind.log(tool="t", params={}, result_summary="x")
    for _ in range(5):
        ahead.log(tool="t", params={}, result_summary="x")
    behind.log(tool="t", params={}, result_summary="x")
    side = json.loads((case / "audit" / f"{NAME}.seq").read_text())
    assert side["seq"] == 7
    assert len(set(_ids(case))) == 7


# A writer given no resolver keeps its old choice of case


def _point(tmp_path: Path, case: Path) -> None:
    (tmp_path / "home" / ".vhir").mkdir(parents=True, exist_ok=True)
    (tmp_path / "home" / ".vhir" / "active_case").write_text(str(case))


def test_a_writer_without_a_resolver_still_follows_vhir_case_dir(case, tmp_path):
    other = tmp_path / "case-b"
    other.mkdir()
    (other / "CASE.yaml").write_text("case_id: case-b\n")
    _point(tmp_path, other)
    AuditWriter(NAME).log(tool="t", params={}, result_summary="x")
    assert len(_ids(case)) == 1
    assert not (other / "audit").exists()


def test_a_writer_without_a_resolver_in_a_project_folder_uses_the_pointer(
    case, tmp_path, monkeypatch
):
    project = tmp_path / "project"  # a lite project: no CASE.yaml
    project.mkdir()
    monkeypatch.setenv("VHIR_CASE_DIR", str(project))
    _point(tmp_path, case)
    AuditWriter(NAME).log(tool="t", params={}, result_summary="x")
    assert len(_ids(case)) == 1
    assert not (project / "audit").exists()


def test_a_resolver_names_the_case_and_none_falls_back(case, tmp_path):
    other = tmp_path / "case-b"
    other.mkdir()
    (other / "CASE.yaml").write_text("case_id: case-b\n")
    AuditWriter(NAME, case_dir_resolver=lambda: other).log(
        tool="t", params={}, result_summary="x"
    )
    AuditWriter(NAME, case_dir_resolver=lambda: None).log(
        tool="t", params={}, result_summary="x"
    )
    assert (len(_ids(other)), len(_ids(case))) == (1, 1)


def test_a_case_switch_between_minting_and_writing_cannot_move_the_id(
    case, tmp_path, monkeypatch
):
    other = tmp_path / "case-b"
    (other / "audit").mkdir(parents=True)
    (other / "CASE.yaml").write_text("case_id: case-b\n")
    writer = AuditWriter(NAME)
    own = writer._next_audit_id(other / "audit")  # case B's own first entry
    (other / "audit" / f"{NAME}.jsonl").write_text(json.dumps({"audit_id": own}) + "\n")
    writer = AuditWriter(NAME)
    mint = AuditWriter._next_audit_id

    def mint_then_switch(self, *a, **k):
        minted = mint(self, *a, **k)
        monkeypatch.setenv("VHIR_CASE_DIR", str(other))  # the examiner switches cases
        return minted

    monkeypatch.setattr(AuditWriter, "_next_audit_id", mint_then_switch)
    logged = writer.log(tool="t", params={}, result_summary="x")
    assert _ids(other) == [own]
    assert _ids(case) == [logged]


def test_an_emptied_sidecar_does_not_bring_back_a_used_id(case):
    writer = AuditWriter(NAME)
    writer.log(tool="t", params={}, result_summary="x")
    # another process logs, and leaves the sidecar truncated
    AuditWriter(NAME).log(tool="t", params={}, result_summary="x")
    (case / "audit" / f"{NAME}.seq").write_text("")
    writer.log(tool="t", params={}, result_summary="x")
    ids = _ids(case)
    assert len(ids) == 3 and len(set(ids)) == 3, ids


def test_an_entry_gets_its_id_from_the_case_it_is_written_to(
    case, tmp_path, monkeypatch
):
    other = tmp_path / "case-b"
    other.mkdir()
    (other / "CASE.yaml").write_text("case_id: case-b\n")
    for target, n in ((case, 2), (other, 1)):
        monkeypatch.setenv("VHIR_CASE_DIR", str(target))
        for _ in range(n):
            AuditWriter(NAME).log(tool="t", params={}, result_summary="x")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    resolve = AuditWriter._get_audit_dir

    def resolve_then_switch(self, *args):
        found = resolve(self, *args)
        monkeypatch.setenv("VHIR_CASE_DIR", str(other))  # a switch right after
        return found

    monkeypatch.setattr(AuditWriter, "_get_audit_dir", resolve_then_switch)
    AuditWriter(NAME).log(tool="t", params={}, result_summary="x")
    ids = _ids(case)
    assert len(ids) == 3 and len(set(ids)) == 3, ids
