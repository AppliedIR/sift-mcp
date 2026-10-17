"""The timeline ruler's marker title survives a description that is not a
string, and a string description's title is unchanged."""

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

DESC = (
    'svchost.exe started "x" & <y> by jdoe 日本,'
    " a description longer than sixty characters in total"
)


def _fn(page, name):
    m = re.search(r"\n(async )?function " + name + r"\(", page)
    if not m:
        return ""
    return page[m.start() + 1 : page.index("\n}\n", m.start()) + 3]


def _title(description):
    """Run the page's renderTimelineRuler: the first marker's title, or THROW."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()
    fns = "".join(
        _fn(page, n)
        for n in (
            "safeStr",
            "escapeHtml",
            "escapeJsString",
            "timelineOrder",  # the ruler's sort, when the page has it
            "timelineKey",
            "renderTimelineRuler",
        )
    )
    events = [
        {"id": "T-1", "timestamp": "2026-03-31T14:00:00Z", "description": description},
        {"id": "T-2", "timestamp": "2026-03-31T20:00:00Z", "description": "other"},
    ]
    script = (
        "var els = {}; var document = {"
        " getElementById: function(id) { return els[id] || (els[id] = {style: {}, innerHTML: ''}); },"
        " createElement: function() { var t = ''; return {"
        " set textContent(v) { t = String(v); },"
        " get innerHTML() { return t.replace(/&/g, '&amp;').replace(/</g, '&lt;')"
        ".replace(/>/g, '&gt;').replace(/\\u00a0/g, '&nbsp;'); } }; } };\n"
        + fns
        + f"\nvar timelineEvents = {json.dumps(events)};"
        " try { renderTimelineRuler();"
        ' var m = / title="([^"]*)" onclick=/.exec(els.timelineRulerMarkers.innerHTML);'
        " process.stdout.write(JSON.stringify(m ? m[1] : null));"
        " } catch (e) { process.stdout.write(JSON.stringify('THROW: ' + e.name)); }"
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr[-800:]
    return json.loads(out.stdout)


def test_ruler_title_any_description_shape():
    shapes = {
        "int": 12345,
        "dict": {"a": 1},
        "toStringNull": {"toString": None},
        "string": DESC,
    }
    got = {k: _title(v) for k, v in shapes.items()}
    assert got == {
        "int": "12345",
        "dict": "[object Object]",
        "toStringNull": "[unprintable]",
        "string": DESC[:60]
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;"),
    }
