"""Audit IDs are never issued twice within one audit directory.

The writer kept one sequence per process and resumed it only when the date
changed, so after a case switch it handed out IDs the other case already held.
It now resumes on a switch too, never below where it was: an ID minted in one
case can still be logged into the other after the switch.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path

import pytest
from sift_common import audit
from sift_common.audit import AuditWriter

DAY1 = dt.datetime(2026, 10, 1, 12, tzinfo=dt.timezone.utc)
DAY2 = dt.datetime(2026, 10, 2, 12, tzinfo=dt.timezone.utc)
NAME = "test-mcp"


@pytest.fixture(autouse=True)
def clock(monkeypatch, tmp_path):
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ANALYST", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # no active_case pointer
    now = [DAY1]

    class FixedClock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return now[0]

    monkeypatch.setattr(audit, "datetime", FixedClock)
    return now


def _case(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    (path / "audit").mkdir(parents=True)
    (path / "CASE.yaml").write_text("case_id: x\n")
    return path


def _use(monkeypatch, case: Path | None) -> None:
    if case is None:
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    else:
        monkeypatch.setenv("VHIR_CASE_DIR", str(case))


def _log(writer: AuditWriter, n: int) -> list[str]:
    return [writer.log(tool="t", params={}, result_summary="ok") for _ in range(n)]


def _ids(case: Path) -> list[str]:
    log = case / "audit" / f"{NAME}.jsonl"
    return [
        json.loads(line)["audit_id"] for line in log.read_text().splitlines() if line
    ]


def _dups(case: Path) -> list[str]:
    return [i for i, n in Counter(_ids(case)).items() if n > 1]


def _sidecar(case: Path) -> dict:
    return json.loads((case / "audit" / f"{NAME}.seq").read_text())


@pytest.fixture
def a_with_32(tmp_path, monkeypatch):
    """Case A already holds today's IDs 001-032, written by an earlier process."""
    a = _case(tmp_path, "A")
    _use(monkeypatch, a)
    _log(AuditWriter(NAME), 32)
    return a


def test_a_switch_away_and_back_continues_the_case(tmp_path, monkeypatch, a_with_32):
    b = _case(tmp_path, "B")
    writer = AuditWriter(NAME)
    _use(monkeypatch, b)
    _log(writer, 8)
    _use(monkeypatch, a_with_32)
    got = _log(writer, 2)
    assert [i[-3:] for i in got] == ["033", "034"]
    assert _sidecar(a_with_32)["seq"] == 34 and not _dups(a_with_32)


def test_alternating_cases_across_a_date_change(
    tmp_path, monkeypatch, clock, a_with_32
):
    b = _case(tmp_path, "B")
    writer = AuditWriter(NAME)
    _use(monkeypatch, b)
    _log(writer, 2)
    _use(monkeypatch, a_with_32)
    _log(writer, 2)
    _use(monkeypatch, b)
    _log(writer, 1)
    clock[0] = DAY2
    _log(AuditWriter(NAME), 10)  # another writer, B, day 2
    _use(monkeypatch, a_with_32)
    _log(writer, 1)
    _use(monkeypatch, b)
    _log(writer, 1)
    assert (_dups(a_with_32), _dups(b)) == ([], [])


def test_starting_in_the_case_with_fewer_ids(tmp_path, monkeypatch):
    """Case B holds more IDs than A; the writer starts in A."""
    a, b = _case(tmp_path, "A"), _case(tmp_path, "B")
    _use(monkeypatch, a)
    _log(AuditWriter(NAME), 3)
    _use(monkeypatch, b)
    _log(AuditWriter(NAME), 20)
    writer = AuditWriter(NAME)
    for case in (a, b, a):
        _use(monkeypatch, case)
        _log(writer, 2)
    assert (_dups(a), _dups(b)) == ([], [])


def test_a_corrupt_sidecar_after_a_switch_resumes_from_the_log(
    tmp_path, monkeypatch, a_with_32
):
    (a_with_32 / "audit" / f"{NAME}.seq").write_text("{garbage")
    b = _case(tmp_path, "B")
    writer = AuditWriter(NAME)
    _use(monkeypatch, b)
    _log(writer, 3)
    _use(monkeypatch, a_with_32)
    assert _log(writer, 1)[0].endswith("-033")


@pytest.mark.parametrize(
    "restart", [True, False], ids=["after a restart", "same process"]
)
def test_an_id_minted_elsewhere_then_one_minted_here(
    tmp_path, monkeypatch, a_with_32, restart
):
    """forensic-mcp logs shell IDs with log(audit_id=...); that write records
    the writer's counter from another case in this case's sidecar."""
    b = _case(tmp_path, "B")
    writer = AuditWriter(NAME)
    _use(monkeypatch, b)
    _log(writer, 8)
    _use(monkeypatch, a_with_32)
    writer.log(
        tool="cmd", params={}, result_summary="x", audit_id="shell-tester-20261001-001"
    )
    got = _log(AuditWriter(NAME) if restart else writer, 1)
    assert got[0].endswith("-033") and not _dups(a_with_32)


def test_minting_with_no_case_then_a_case(monkeypatch, a_with_32):
    _use(monkeypatch, None)
    writer = AuditWriter(NAME)
    writer._next_audit_id()
    writer._next_audit_id()
    _use(monkeypatch, a_with_32)
    assert _log(writer, 1)[0].endswith("-033")


@pytest.fixture
def a_and_b_with_8(tmp_path, monkeypatch):
    cases = []
    for name in ("A", "B"):
        case = _case(tmp_path, name)
        _use(monkeypatch, case)
        _log(AuditWriter(NAME), 8)
        cases.append(case)
    return cases


@pytest.mark.parametrize(
    "restart", [False, True], ids=["same writer", "after a restart"]
)
def test_an_id_minted_before_a_switch_and_logged_after_it(
    monkeypatch, a_and_b_with_8, restart
):
    """A tool call mints in A; the case switches to B before it logs."""
    a, b = a_and_b_with_8
    writer = AuditWriter(NAME)
    _use(monkeypatch, a)
    minted = writer._next_audit_id()
    _use(monkeypatch, b)
    writer.log(tool="run_command", params={}, result_summary="x", audit_id=minted)
    _log(AuditWriter(NAME) if restart else writer, 1)
    assert (_dups(a), _dups(b)) == ([], [])


@pytest.mark.parametrize(
    "restart", [False, True], ids=["same writer", "after a restart"]
)
def test_overlapping_calls_across_a_switch(monkeypatch, a_and_b_with_8, restart):
    """Call 1 mints in A; the case switches; call 2 mints and logs in B; call
    1 then logs, into B."""
    a, b = a_and_b_with_8
    writer = AuditWriter(NAME)
    _use(monkeypatch, a)
    first = writer._next_audit_id()
    _use(monkeypatch, b)
    second = writer._next_audit_id()
    writer.log(tool="call2", params={}, result_summary="x", audit_id=second)
    writer.log(tool="call1", params={}, result_summary="x", audit_id=first)
    _log(AuditWriter(NAME) if restart else writer, 1)
    assert (_dups(a), _dups(b)) == ([], [])


def test_a_foreign_id_logged_into_a_case_then_a_restart(tmp_path, monkeypatch):
    """A shell ID from another component, logged into A, then a restart in A."""
    a, b = _case(tmp_path, "A"), _case(tmp_path, "B")
    _use(monkeypatch, a)
    _log(AuditWriter(NAME), 9)
    _use(monkeypatch, b)
    _log(AuditWriter(NAME), 8)
    writer = AuditWriter(NAME)
    for _ in range(8):
        writer._next_audit_id()
    _use(monkeypatch, a)
    writer.log(
        tool="shell",
        params={},
        result_summary="x",
        audit_id="shell-tester-20261001-099",
    )
    got = _log(AuditWriter(NAME), 1)
    assert not _dups(a), got  # may skip numbers; never repeats
