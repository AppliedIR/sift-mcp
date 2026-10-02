"""get_timeline's start/end compare instants, not text.

A −05:00 event inside a Z window was omitted (and a +05:30 event outside it
included), and a same-second fractional event fell outside a Z bound,
because the bounds were compared as strings. When either side doesn't parse,
the comparison stays textual, as it was.
"""

from __future__ import annotations

import json

import forensic_mcp.case.manager as manager_module
import pytest
from forensic_mcp.case.manager import CaseManager


@pytest.fixture
def window(tmp_path, monkeypatch):
    # The manager re-reads the active-case pointer on every call: point it here.
    pointer = tmp_path / "active_case"
    monkeypatch.setattr(manager_module, "_ACTIVE_CASE_FILE", pointer)

    def run(events, **kw):
        case = tmp_path / "case-utc"
        case.mkdir(exist_ok=True)
        (case / "CASE.yaml").write_text("case_id: case-utc\nstatus: open\n")
        (case / "timeline.json").write_text(json.dumps(events))
        pointer.write_text(str(case))
        return sorted(e["id"] for e in CaseManager().get_timeline(**kw))

    return run


def test_offset_events_are_placed_by_their_instant(window):
    events = [
        {"id": "in-0500", "timestamp": "2026-10-02T10:00:00-05:00"},  # 15:00Z
        {"id": "out-0530", "timestamp": "2026-10-02T15:00:00+05:30"},  # 09:30Z
        {"id": "in-Z", "timestamp": "2026-10-02T14:30:00Z"},
    ]
    got = window(
        events, start_date="2026-10-02T14:00:00Z", end_date="2026-10-02T16:00:00Z"
    )
    assert got == ["in-0500", "in-Z"]


def test_a_same_second_fractional_event_is_inside_a_z_bound(window):
    events = [
        {"id": "a", "timestamp": "2023-01-20T10:00:00Z"},
        {"id": "b", "timestamp": "2023-01-20T10:00:00.500000Z"},
        {"id": "c", "timestamp": "2023-01-21"},
    ]
    got = window(
        events, start_date="2023-01-20T10:00:00Z", end_date="2023-01-21T00:00:00Z"
    )
    assert got == ["a", "b", "c"]


EVENTS = [
    {"id": "a", "timestamp": "2023-01-20T10:00:00Z"},
    {"id": "b", "timestamp": "2023-01-20T10:00:00.500000Z"},
    {"id": "c", "timestamp": "2023-01-21"},
    {"id": "d", "timestamp": "2023-02-01T00:00:00Z"},
]


@pytest.mark.parametrize(
    "kw,want",
    [
        (
            {"start_date": "2023-01-20T09:00:00Z", "end_date": "2023-01-21T00:00:00Z"},
            ["a", "b", "c"],
        ),
        ({"start_date": "2023-01-20", "end_date": "2023-01-21"}, ["a", "b", "c"]),
        ({"start_date": "2023-02"}, ["d"]),  # a partial date: compared as text
        ({"end_date": "2023-01-20"}, []),
    ],
    ids=["z window", "date-only window", "partial-date bound", "date-only end"],
)
def test_stored_format_windows_are_unchanged(window, kw, want):
    assert window(EVENTS, **kw) == want


def test_an_unparseable_stored_value_compares_as_text(window):
    events = [{"id": "junk", "timestamp": "yesterday-ish"}]
    assert window(events, start_date="2026-01-01T00:00:00Z") == ["junk"]  # "y" > "2"
    assert window(events, end_date="2026-01-01T00:00:00Z") == []
