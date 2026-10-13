"""The Portal tells the examiner about approve and reject attempts refused
for want of a terminal, as `vhir approve` and `vhir review` do.

An attempt with no examiner at a terminal (an AI's run) saves nothing and
writes one audit line; the summary counts them, and the page shows one amber
line beside the withdrawn line, as text.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import case_dashboard.routes as D
import pytest

PAGE = Path(D.__file__).parent / "static" / "v2" / "index.html"


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _refused(case, ts, action, ids):
    with open(case / "audit" / "cli-approve.jsonl", "a") as f:
        f.write(json.dumps({"ts": ts, "mcp": "cli-approve", "tool": action, "examiner": "steve",
                            "source": "cli", "params": {"ids": ids},
                            "result_summary": {"status": "NO_TERMINAL",
                                               "reason": "no terminal"}}) + "\n")  # fmt: skip


def _summary():
    return json.loads(asyncio.run(D.get_summary(None)).body)


def test_the_summary_counts_the_refused_attempts(case):
    _refused(case, "2026-10-13T09:00:00+00:00", "approve", ["F-steve-001"])
    _refused(
        case, "2026-10-13T09:05:00+00:00", "reject", ["F-steve-002", "T-steve-001"]
    )
    assert _summary()["no_terminal"] == {
        "total": 2, "latest": "2026-10-13T09:05:00+00:00", "ids": ["F-steve-002", "T-steve-001"]}  # fmt: skip


def test_anchor_a_case_without_refused_attempts_counts_none(case):
    assert _summary()["no_terminal"] == {"total": 0}


def _js_function(name: str) -> str:
    page = PAGE.read_text()
    start = page.index(f"function {name}(")
    return page[start : page.index("\n}\n", start) + 3]


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
@pytest.mark.parametrize("total", [0, 1], ids=["none", "one"])
def test_the_page_shows_the_line_as_text(total):
    summary = {"no_terminal": {"total": total, "latest": "2026-10-13T09:00:00+00:00",
                               "ids": ["F-<img src=x onerror=alert(1)>"]}}  # fmt: skip
    script = (
        "var el = {style: {}, textContent: '', innerHTML: 'untouched'};"
        "var document = {getElementById: function(id) { return id === 'noTerminalLine' ? el : null; }};"
        f"var summaryData = {json.dumps(summary)};\n"
        + _js_function("renderNoTerminalLine")
        + "renderNoTerminalLine(); process.stdout.write(JSON.stringify(el));"
    )
    el = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True,
                                   check=True).stdout)  # fmt: skip
    assert el["innerHTML"] == "untouched"  # set as text, never as HTML
    if total:
        assert el["style"]["display"] == ""
        assert el["textContent"] == (
            "1 approve/reject attempt(s) refused: no terminal (latest 2026-10-13T09:00:00+00:00, "
            "F-<img src=x onerror=alert(1)>) — not you? see `vhir audit`"
        )
    else:
        assert el["style"]["display"] == "none" and el["textContent"] == ""


def test_the_line_sits_beside_the_withdrawn_line():
    page = PAGE.read_text()
    assert (
        '<div class="withdrawn-line" id="noTerminalLine" style="display:none"></div>'
        in page
    )
    assert page.count("renderNoTerminalLine();") == 2
