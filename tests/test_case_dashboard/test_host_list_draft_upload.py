"""A draft that fills the host-list text box is what Upload sends, even after
an earlier file choice; a file chosen after the draft is sent, and the
examiner's edits to the draft stay. Names are synthetic."""

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

# Each step: ("file", text) chooses a file, ("draft", key, text) has the server
# hold a draft, ("render",) runs renderHosts, ("type", text) edits the text box
STEPS = {
    "file_then_draft": [("file", "OLDHOST\n"), ("draft", 1, "NEWHOST\n"), ("render",)],
    "file_then_draft_then_edit": [
        ("file", "OLDHOST\n"),
        ("draft", 1, "NEWHOST\n"),
        ("render",),
        ("type", "EDITEDHOST\n"),
    ],
    "file_no_draft": [("file", "OLDHOST\n"), ("render",)],
    "draft_only": [("draft", 1, "NEWHOST\n"), ("render",)],
    "same_draft_rerendered_keeps_edit": [
        ("draft", 1, "NEWHOST\n"),
        ("render",),
        ("type", "EDITEDHOST\n"),
        ("render",),
    ],
    "file_after_draft": [
        ("draft", 1, "NEWHOST\n"),
        ("render",),
        ("file", "OLDHOST\n"),
        ("render",),
    ],
}


def _fn(page, name):
    m = re.search(r"\n(async )?function " + name + r"\(", page)
    return page[m.start() + 1 : page.index("\n}\n", m.start()) + 3]


def _sent(steps):
    """Run the page's renderHosts and Upload click: the text the list carries."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()
    start = page.index("document.addEventListener('click', async function(ev) {")
    click = page[start : page.index("\n});\n", start) + 5]
    assert "data-host-act" in click and "'list'" in click
    fns = "".join(_fn(page, n) for n in ("hostDraftHtml", "renderHosts", "hostDecide"))
    script = (
        "var server = {draft: null}, sent = [], listeners = {};\n"
        "var file = {files: [], set value(v) { if (v === '' || v === null)"
        " this.files = []; else throw new Error('InvalidStateError'); }};\n"
        "var els = {hostsPanel: {contains: function() { return false; }},"
        " hostListText: {value: ''}, hostListPanel: {open: false},"
        " hostListFile: file};\n"
        "var document = {activeElement: null,"
        " getElementById: function(id) { return els[id] || (els[id] = {}); },"
        " addEventListener: function(t, f) { listeners[t] = f; }};\n"
        "var hostsView = {page: 1, ppage: 1, lpage: 1, state: '', q: '', data: null,"
        " runs: [], result: null};\n"
        "var HOST_DECISION_ACTS = ['list'];\n"
        "function hostOpUnfinished() { return false; }\n"
        "function escapeHtml(s) { return String(s); }\n"
        "function hostsHeaderHtml() { return ''; }"
        " function hostRunsHtml() { return ''; }"
        " function hostProposedHtml() { return ''; }"
        " function hostRowsHtml() { return ''; }"
        " function hostPagerHtml() { return ''; }"
        " function hostListSubText() { return ''; }"
        " function hostListRowsHtml() { return ''; }"
        " function hostListPagerHtml() { return ''; }"
        " function setBadge() {} function hostDecisionsFixed() {}"
        " function renderHostOps() {} function showToast() {}\n"
        "async function apiFetch(path, opts) {"
        " if (path.indexOf('/api/hosts?') === 0) return {draft: server.draft,"
        " machines: [], proposed: [], proposed_total: 0, obs_offset: 0};"
        " if (path === '/api/hosts/runs') return {runs: []};"
        " var b = JSON.parse(opts.body); sent.push(b);"
        " if (b.action === 'list') server.draft = null; return {summary: 'ok'}; }\n"
        + fns
        + click
        + f"\nvar steps = {json.dumps(steps)};\n"
        "(async function() {"
        " for (var s of steps) {"
        "  if (s[0] === 'file') { let t = s[1];"
        "   file.files = [{name: 'old.csv', text: async function() { return t; }}]; }"
        "  else if (s[0] === 'draft') server.draft = {t: s[1], source: 'inventory.pdf',"
        " text: s[2], entries: 1};"
        "  else if (s[0] === 'render') await renderHosts();"
        "  else els.hostListText.value = s[1]; }"
        " var target = {closest: function() { return {getAttribute: function(a) {"
        " return a === 'data-host-act' ? 'list' : null; }}; }};"
        " await listeners.click({target: target, preventDefault: function() {}});"
        " var lists = sent.filter(function(b) { return b.action === 'list'; });"
        " process.stdout.write(JSON.stringify(lists.map(function(b) {"
        " return b.args.text; })));"
        "})().catch(function(e) { process.stdout.write(JSON.stringify("
        "'THROW: ' + e.name + ': ' + e.message)); });"
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr[-800:]
    return json.loads(out.stdout)


def test_a_draft_that_fills_the_box_after_a_file_choice_is_what_upload_sends():
    got = {k: _sent(STEPS[k]) for k in ("file_then_draft", "file_then_draft_then_edit")}
    assert got == {
        "file_then_draft": ["NEWHOST\n"],
        "file_then_draft_then_edit": ["EDITEDHOST\n"],
    }


def test_a_file_alone_a_draft_alone_and_a_later_file_send_as_before():
    keys = ("file_no_draft", "draft_only", "same_draft_rerendered_keeps_edit",
            "file_after_draft")  # fmt: skip
    got = {k: _sent(STEPS[k]) for k in keys}
    assert got == {
        "file_no_draft": ["OLDHOST\n"],
        "draft_only": ["NEWHOST\n"],
        "same_draft_rerendered_keeps_edit": ["EDITEDHOST\n"],
        "file_after_draft": ["OLDHOST\n"],
    }
