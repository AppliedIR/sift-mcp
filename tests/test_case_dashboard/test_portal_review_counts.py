"""The Portal's review counts read stored decisions as the Pending filter does.

The sidebar stats, the progress text, the timeline summary and the tab badges
count a finding or event as reviewed when it holds a stored APPROVED or
REJECTED status, or when this examiner staged a decision on it. Another
examiner's staged entries and a staged edit leave it pending. The page's own
functions run in node against a minimal DOM.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)

FUNCTIONS = (
    "me",
    "isOwn",
    "getDeltaEntry",
    "isPendingReview",
    "timelineOrder",
    "timelineKey",
    "getFilteredFindings",
    "getFilteredTimelineEvents",
    "updateSidebarStats",
    "updateProgress",
    "updateTimelineSummary",
    "updateTabBadges",
    "showEmptyOrFirst",
)


def _fn(page, name):
    """The page's function `name`, or "" when the page has none."""
    m = re.search(r"\nfunction " + name + r"\(", page)
    if not m:
        return ""
    return page[m.start() + 1 : page.index("\n}\n", m.start()) + 3]


HARNESS = r"""
const vm = require('vm');
const els = {};
const badges = {};
let activeTab = 'findings';
let selected = null;
const ctx = vm.createContext({
  console, JSON, Math, Date, Set, Object, Array, String,
  CONF_ORDER: { HIGH: 1, MEDIUM: 2, LOW: 3, SPECULATIVE: 4 },
  findings: [], timelineEvents: [], delta: { items: [] }, caseMeta: {},
  currentFilter: 'pending', timelineFilter: 'pending', timelineTypeFilter: '',
  currentSort: 'conf-desc', searchQuery: '', filterConf: '', filterType: '',
  filterExaminer: '', filterHost: '', filterAccount: '',
  evidenceData: [], todosData: [], iocsData: [],
  document: {
    getElementById: (id) => (els[id] = els[id] || { id, style: {}, innerHTML: '', textContent: '' }),
    querySelector: (sel) => (sel === '.tab.active' ? { dataset: { tab: activeTab } } : null),
  },
  setBadge: (tab, n) => { badges[tab] = n; },
  selectFinding: (id) => { selected = id; },
  formatTimeShort: (ts) => ts,
});
vm.runInContext(SOURCE, ctx);
const S = JSON.parse(SCENARIO);
ctx.findings = S.findings;
ctx.timelineEvents = S.timeline;
ctx.delta = { version: 1, items: S.staged };
ctx.caseMeta = { you: 'alice', signing: { examiner: 'alice' } };
const out = {};
vm.runInContext('updateSidebarStats()', ctx);
out.sidebar = els.sidebarStats.innerHTML;
activeTab = 'findings';
vm.runInContext('updateProgress()', ctx);
out.progress_findings = els.progressText.textContent;
out.bar_findings = els.progressFill.style.width;
activeTab = 'timeline';
vm.runInContext('updateProgress()', ctx);
out.progress_timeline = els.progressText.textContent;
out.bar_timeline = els.progressFill.style.width;
vm.runInContext('updateTimelineSummary()', ctx);
out.summary = els.timelineSummary.textContent.split(' · ').pop();
vm.runInContext('updateTabBadges()', ctx);
out.badge_findings = badges['tab-findings'];
out.badge_timeline = badges['tab-timeline'];
out.filter_findings = vm.runInContext('getFilteredFindings().length', ctx);
out.filter_timeline = vm.runInContext('getFilteredTimelineEvents().length', ctx);
vm.runInContext('showEmptyOrFirst()', ctx);
out.empty = selected === null ? (els.emptyState || {}).innerHTML : null;
process.stdout.write(JSON.stringify(out));
"""


def _counts(findings, timeline, staged):
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()
    source = "".join(_fn(page, n) for n in FUNCTIONS)
    scenario = {"findings": findings, "timeline": timeline, "staged": staged}
    script = HARNESS.replace("SOURCE", json.dumps(source), 1).replace(
        "SCENARIO", json.dumps(json.dumps(scenario)), 1
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr[-800:]
    return json.loads(out.stdout)


def _finding(n, status):
    return {"id": f"F-alice-{n:03d}", "title": f"finding {n}", "status": status}


def _event(n, status):
    return {
        "id": f"T-alice-{n:03d}",
        "description": f"event {n}",
        "status": status,
        "timestamp": f"2026-03-31T1{n}:00:00Z",
    }


def _staged(item_id, action, who="alice"):
    return {"id": item_id, "action": action, "staged_by": who}


STORED_FINDINGS = [
    _finding(n, s)
    for n, s in enumerate(["APPROVED"] * 4 + ["REJECTED"] * 2 + ["DRAFT"] * 3, start=1)
]
STORED_EVENTS = [
    _event(n, s)
    for n, s in enumerate(["APPROVED"] * 3 + ["REJECTED"] + ["DRAFT"] * 2, start=1)
]


def test_stored_and_staged_decisions_each_count_once():
    staged = [
        _staged("F-alice-007", "approve"),  # a draft, approved here
        _staged("F-alice-008", "edit"),  # an edit leaves it pending
        _staged("F-alice-001", "edit"),
        _staged("F-alice-002", "reject"),  # already approved: counted once
        _staged("T-alice-005", "reject"),
        _staged("T-alice-001", "edit"),
        _staged("F-alice-009", "approve", who="bob"),  # not this examiner's
        _staged("T-alice-006", "approve", who="bob"),
    ]
    got = _counts(STORED_FINDINGS, STORED_EVENTS, staged)
    assert got == {
        "sidebar": "<div>9 total · 2 pending</div>",
        "progress_findings": "7 of 9 findings reviewed",
        "bar_findings": "78%",
        "progress_timeline": "5 of 6 events reviewed",
        "bar_timeline": "83%",
        "summary": "5 of 6 reviewed",
        "badge_findings": 2,
        "badge_timeline": 1,
        "filter_findings": 2,
        "filter_timeline": 1,
        "empty": None,
    }


def test_a_case_with_every_item_decided_reads_nothing_pending():
    findings = [
        _finding(1, "APPROVED"),
        _finding(2, "APPROVED"),
        _finding(3, "REJECTED"),
    ]
    events = [_event(1, "APPROVED"), _event(2, "REJECTED")]
    got = _counts(findings, events, [])
    empty = got.pop("empty")
    assert got == {
        "sidebar": "<div>3 total · 0 pending</div>",
        "progress_findings": "3 of 3 findings reviewed",
        "bar_findings": "100%",
        "progress_timeline": "2 of 2 events reviewed",
        "bar_timeline": "100%",
        "summary": "2 of 2 reviewed",
        "badge_findings": 0,
        "badge_timeline": 0,
        "filter_findings": 0,
        "filter_timeline": 0,
    }
    assert "No pending findings remaining" in empty


def test_a_case_with_nothing_decided_reads_all_pending():
    findings = [_finding(n, "DRAFT") for n in range(1, 6)]
    events = [_event(n, "DRAFT") for n in range(1, 4)]
    got = _counts(findings, events, [])
    assert got == {
        "sidebar": "<div>5 total · 5 pending</div>",
        "progress_findings": "0 of 5 findings reviewed",
        "bar_findings": "0%",
        "progress_timeline": "0 of 3 events reviewed",
        "bar_timeline": "0%",
        "summary": "0 of 3 reviewed",
        "badge_findings": 5,
        "badge_timeline": 3,
        "filter_findings": 5,
        "filter_timeline": 3,
        "empty": None,
    }
