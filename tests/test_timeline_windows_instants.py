"""report-mcp's timeline window compares instants, and a date-only end
includes its whole day there and in get_timeline.

report-mcp compared timestamps as text: an event at 20:00-05:00 (01:00 the
next day, UTC) passed an end of 21:00Z, an event at 08:00+05:30 passed a
start of 03:00Z, and an end of 2023-01-29 dropped every event on the 29th.
get_timeline already compared instants, but its date-only end dropped the
day too. A value that doesn't parse still compares as text, as before.
"""

from __future__ import annotations

import json

import forensic_mcp.case.manager as manager_module
import pytest
import yaml
from forensic_mcp.case.manager import CaseManager
from report_mcp.server import _generate
from vhir_signing import sign_approved

EVENTS = {
    "E1": "2023-01-29T00:00:00Z",
    "E2": "2023-01-29T10:00:00Z",
    "E3": "2023-01-29T23:59:59.5Z",
    "E4": "2023-01-30T00:00:00Z",
    "E5": "2023-01-29T20:00:00-05:00",  # 30th 01:00Z
    "E6": "2023-01-29T08:00:00+05:30",  # 29th 02:30Z
    "E7": "2023-01-28T23:00:00Z",
    "E8": "2023-01-29T23:30:00-0500",  # ±HHMM: 30th 04:30Z
}
ALL = sorted(EVENTS)


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    (d / "timeline.json").write_text(
        json.dumps(
            [
                {"id": name, "timestamp": ts, "status": "APPROVED"}
                for name, ts in EVENTS.items()
            ]
        )
    )
    sign_approved(d)  # a report shows only approvals that verify
    pointer = tmp_path / "active_case"
    pointer.write_text(str(d))
    monkeypatch.setattr(manager_module, "_ACTIVE_CASE_FILE", pointer)
    return d


def _report(case, start, end):
    data = _generate("timeline", case, start_date=start or "", end_date=end or "")
    return sorted(t["id"] for t in data["report_data"]["timeline"])


def _get_timeline(case, start, end):
    kw = {k: v for k, v in (("start_date", start), ("end_date", end)) if v}
    return sorted(e["id"] for e in CaseManager().get_timeline(**kw))


SITES = pytest.mark.parametrize(
    "site", [_report, _get_timeline], ids=["report-mcp", "get_timeline"]
)


@SITES
@pytest.mark.parametrize(
    "start, end, expected",
    [
        (None, "2023-01-29", ["E1", "E2", "E3", "E6", "E7"]),
        (None, "2023-01-29T21:00:00Z", ["E1", "E2", "E6", "E7"]),
        ("2023-01-29T03:00:00Z", None, ["E2", "E3", "E4", "E5", "E8"]),
        ("2023-01-29T23:59:59Z", None, ["E3", "E4", "E5", "E8"]),
        ("2023-01-30T04:00:00Z", "2023-01-30T05:00:00Z", ["E8"]),
    ],
    ids=["date-only end", "end instant", "start instant", "late start", "+-HHMM"],
)
def test_a_window_compares_instants(case, site, start, end, expected):
    assert site(case, start, end) == expected


@SITES
@pytest.mark.parametrize(
    "start, end, expected",
    [
        ("2023-01-29T00:00:00Z", "2023-01-29T10:00:00Z", ["E1", "E2", "E6"]),
        ("2023-01-29", None, ["E1", "E2", "E3", "E4", "E5", "E6", "E8"]),
        (None, "9999-12-31", ALL),
    ],
    ids=["instant window", "date-only start", "the last day"],
)
def test_anchor_windows_that_were_already_right(case, site, start, end, expected):
    assert site(case, start, end) == expected


@SITES
def test_anchor_a_value_that_doesn_t_parse_compares_as_text(case, site):
    timeline = json.loads((case / "timeline.json").read_text())
    timeline.append(
        {"id": "E9", "timestamp": "2023-01-29 sometime", "status": "APPROVED"}
    )
    (case / "timeline.json").write_text(json.dumps(timeline))
    sign_approved(case)  # E9's approval too
    assert "E9" in site(case, "2023-01-29", None)
    assert "E9" not in site(case, None, "2023-01-28")
