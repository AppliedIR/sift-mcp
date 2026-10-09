"""Audit IDs are never issued twice, whatever the case switches.

The writer kept one sequence per process and resumed it from each case's
sidecar and log, so a case switch could hand out IDs the other case already
held. Each ID now ends in a ULID: no per-case sequence, sidecar or log scan,
so a switch, a restart, a date change or an unreadable log line can't repeat
one, and an ID minted in one case can still be logged into another.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

import pytest
from sift_common import audit
from sift_common.audit import AuditWriter

DAY1 = dt.datetime(2026, 10, 1, 12, tzinfo=dt.timezone.utc)
DAY2 = dt.datetime(2026, 10, 2, 12, tzinfo=dt.timezone.utc)
NAME = "test-mcp"
ULID_TAIL = re.compile(r"-[0-9]{8}-[0-9a-hjkmnp-tv-z]{26}\Z")


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
    lines = [json.loads(x) for x in log.read_text().splitlines() if x]
    return [e["audit_id"] for e in lines if isinstance(e, dict) and "audit_id" in e]


def _dups(case: Path) -> list[str]:
    return [i for i, n in Counter(_ids(case)).items() if n > 1]


def _no_sidecar(*cases: Path) -> bool:
    return not any((c / "audit" / f"{NAME}.seq").exists() for c in cases)


@pytest.fixture
def a_with_32(tmp_path, monkeypatch):
    """Case A already holds 32 of today's IDs, written by an earlier process."""
    a = _case(tmp_path, "A")
    _use(monkeypatch, a)
    _log(AuditWriter(NAME), 32)
    return a


def test_a_switch_away_and_back_never_repeats_an_id(tmp_path, monkeypatch, a_with_32):
    b = _case(tmp_path, "B")
    writer = AuditWriter(NAME)
    _use(monkeypatch, b)
    _log(writer, 8)
    _use(monkeypatch, a_with_32)
    got = _log(writer, 2)
    assert all(ULID_TAIL.search(i) for i in got), got
    assert not _dups(a_with_32) and _no_sidecar(a_with_32, b)


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


@pytest.mark.parametrize(
    "restart", [True, False], ids=["after a restart", "same process"]
)
def test_an_id_minted_elsewhere_then_one_minted_here(
    tmp_path, monkeypatch, a_with_32, restart
):
    """forensic-mcp logs shell IDs with log(audit_id=...) into this case."""
    b = _case(tmp_path, "B")
    writer = AuditWriter(NAME)
    _use(monkeypatch, b)
    _log(writer, 8)
    _use(monkeypatch, a_with_32)
    writer.log(
        tool="cmd", params={}, result_summary="x", audit_id="shell-tester-20261001-001"
    )
    got = _log(AuditWriter(NAME) if restart else writer, 1)
    assert ULID_TAIL.search(got[0]) and not _dups(a_with_32)


def test_minting_with_no_case_then_a_case(monkeypatch, a_with_32):
    _use(monkeypatch, None)
    writer = AuditWriter(NAME)
    writer._next_audit_id()
    writer._next_audit_id()
    _use(monkeypatch, a_with_32)
    assert ULID_TAIL.search(_log(writer, 1)[0]) and not _dups(a_with_32)


def test_an_id_carries_the_day_it_was_minted(monkeypatch, clock, a_with_32):
    writer = AuditWriter(NAME)
    first = writer._next_audit_id()
    clock[0] = DAY2
    assert "-20261001-" in first and "-20261002-" in _log(writer, 1)[0]


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


@pytest.mark.parametrize(
    "line",
    [
        '["20261001"]',
        '{"audit_id": null, "d": "20261001"}',
        '{"audit_id": 5, "d": "20261001"}',
    ],
    ids=["a list", "a null audit_id", "an int audit_id"],
)
def test_a_log_line_of_another_shape_is_skipped_on_a_switch(
    tmp_path, monkeypatch, line
):
    """Valid JSON that isn't an audit entry: nothing reads the log to mint."""
    x, y = _case(tmp_path, "X"), _case(tmp_path, "Y")
    _use(monkeypatch, y)
    _log(AuditWriter(NAME), 7)
    with open(y / "audit" / f"{NAME}.jsonl", "a") as f:
        f.write(line + "\n")
    writer = AuditWriter(NAME)
    _use(monkeypatch, x)
    _log(writer, 3)
    _use(monkeypatch, y)
    assert ULID_TAIL.search(_log(writer, 1)[0]) and not _dups(y)


_DEEP = 100_000
BAD_LINES = {
    "invalid utf-8": b'{"d": "20261001", "x": "\xff\xfe"}\n',
    "deep nesting": ("[" * _DEEP + '"20261001"' + "]" * _DEEP + "\n").encode(),
    "a 5000-digit int": ('{"d": "20261001", "n": ' + "1" * 5000 + "}\n").encode(),
}


@pytest.mark.parametrize("bad", sorted(BAD_LINES))
def test_a_log_line_that_cannot_be_read(monkeypatch, a_with_32, bad):
    """Each aborted the old scan, and with it the next log()."""
    with open(a_with_32 / "audit" / f"{NAME}.jsonl", "ab") as f:
        f.write(BAD_LINES[bad])
    assert ULID_TAIL.search(_log(AuditWriter(NAME), 1)[0])


def test_no_sidecar_is_read_or_written(tmp_path, monkeypatch, a_with_32):
    """A sidecar an older version left, of any shape, changes nothing."""
    for text in ("[32]", "{garbage", json.dumps({"date": "20261001", "seq": 99})):
        (a_with_32 / "audit" / f"{NAME}.seq").write_text(text)
        writer = AuditWriter(NAME)
        _use(monkeypatch, _case(tmp_path, f"B{len(text)}"))
        _log(writer, 2)
        _use(monkeypatch, a_with_32)
        assert ULID_TAIL.search(_log(writer, 1)[0]) and not _dups(a_with_32)
        assert (a_with_32 / "audit" / f"{NAME}.seq").read_text() == text
