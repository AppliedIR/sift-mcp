"""The Timeline tab lists events in time order: by the instant to the second,
a time with no zone read as UTC, and the stored text when the second ties."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)


def _fn(page, name):
    m = re.search(r"\nfunction " + name + r"\(", page)
    if not m:
        return ""
    return page[m.start() + 1 : page.index("\n}\n", m.start()) + 3]


def _order(stamps):
    """Run the page's getFilteredTimelineEvents in Tokyo: the ids in listed order."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()
    fns = "".join(
        _fn(page, n)
        for n in ("timelineOrder", "timelineKey", "getFilteredTimelineEvents")
    )
    events = [{"id": i, "timestamp": ts, "status": "DRAFT"} for i, ts in stamps.items()]
    script = (
        "var timelineFilter = 'all', timelineTypeFilter = '';"
        " function getDeltaEntry() { return null; }\n"
        + fns
        + f"\nvar timelineEvents = {json.dumps(events)};"
        " process.stdout.write(JSON.stringify("
        "getFilteredTimelineEvents().map(function(e) { return e.id; })));"
    )
    out = subprocess.run(
        [node, "-e", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "TZ": "Asia/Tokyo"},  # east of UTC: local != UTC
    )
    assert out.returncode == 0, out.stderr[-800:]
    return json.loads(out.stdout)


def test_offset_and_naive_times_list_by_instant():
    # B is 14:02:11Z; C has no zone, so it is 15:00Z, not 15:00 Tokyo time
    stamps = {
        "A": "2026-03-31T20:00:00Z",
        "B": "2026-03-31T23:02:11+09:00",
        "C": "2026-03-31T15:00:00",
    }
    assert _order(stamps) == ["B", "C", "A"]


def test_same_second_and_unparsed_times_keep_their_order():
    stamps = {
        "Z1": "2026-03-31T14:02:12Z",
        "Z2": "2026-03-31T14:02:11Z",
        "Z3": "2026-03-31T14:02:11.9Z",
        "Z4": "2026-03-31T14:02:11.123456789Z",
        "Z5": "２０２６-03-31T14:02:11Z",
        "Z6": "2026-03-31",
    }
    assert _order(stamps) == ["Z6", "Z4", "Z3", "Z2", "Z5", "Z1"]
