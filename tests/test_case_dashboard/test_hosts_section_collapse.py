"""The Hosts tab's three sections each collapse from a button in their header,
run under node: all start open, a click closes only its own section and a
second click opens it again, and nothing is kept across reloads."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
).read_text()
PANEL = PAGE[PAGE.index('id="panel-hosts"') : PAGE.index('data-panel="accounts"')]
SECTIONS = {
    "Host list": (
        "hostsSecList",
        ["hostsListTable", "hostsListPager", "hostListPanel"],
    ),
    "Impacted hosts": ("hostsSecImpacted", ["impactedHostsTable"]),
    "Machines in evidence": (
        "hostsSecMachines",
        ["hostsTable", "hostsPager", "hostDetail"],
    ),
}


def _button(name):
    m = re.search(r"<h4[^>]*>\s*<button ([^>]*)>" + name + r"</button>", PANEL)
    assert m, name + " has no button in its header"
    return dict(re.findall(r'([\w-]+)="([^"]*)"', m.group(1)))


def _body(sid):
    start = PANEL.index('<div id="' + sid + '"')
    depth, at = 0, start
    for tag in re.finditer(r"<(/?)div\b", PANEL[start:]):
        depth += -1 if tag.group(1) else 1
        if depth == 0:
            at = start + tag.start()
            break
    return PANEL[start:at]


@pytest.mark.parametrize("name", SECTIONS)
def test_each_section_header_is_a_button_that_starts_open(name):
    sid, parts = SECTIONS[name]
    attrs = _button(name)
    assert attrs["aria-expanded"] == "true" and attrs["aria-controls"] == sid
    assert attrs["data-host-act"] == "section" and attrs["type"] == "button"
    body = _body(sid)
    assert "hidden" not in body[: body.index(">")]
    for part in parts:
        assert 'id="' + part + '"' in body


def test_the_search_runs_and_proposals_stay_outside_the_sections():
    for outside in (
        "hostsQuery",
        "hostsOps",
        "hostsRuns",
        "hostsProposed",
        "hostsStateFilter",
    ):
        assert all('id="' + outside + '"' not in _body(s) for s, _ in SECTIONS.values())


def _run(body):
    node = shutil.which("node") or pytest.skip("node isn't installed")
    fn = PAGE[PAGE.index("\nfunction toggleHostSection(") + 1 :]
    fn = fn[: fn.index("\n}\n") + 3]
    start = PAGE.index(
        "document.addEventListener('click', async function(ev) {\n  var el = ev.target.closest"
    )
    listener = PAGE[start : PAGE.index("\n});\n", start) + 5]
    script = (
        "var listeners = {}, calls = [];\n"
        "function el(attrs) { return {hidden: false, attrs: attrs,"
        " getAttribute: function(a) { return a in this.attrs ? this.attrs[a] : null; },"
        " setAttribute: function(a, v) { this.attrs[a] = String(v); }}; }\n"
        "var els = {}, buttons = {};\n"
        "['hostsSecList', 'hostsSecImpacted', 'hostsSecMachines'].forEach(function(id) {"
        " els[id] = el({}); buttons[id] = el({'data-host-act': 'section',"
        " 'aria-expanded': 'true', 'aria-controls': id}); });\n"
        "var document = {getElementById: function(id) { return els[id]; },"
        " addEventListener: function(t, f) { listeners[t] = f; }};\n"
        "var hostsView = {data: null};\n"
        "var HOST_DECISION_ACTS = ['list'];\n"
        "function hostOpUnfinished() { calls.push('hostOpUnfinished'); return false; }\n"
        "function renderHosts() { calls.push('renderHosts'); }\n"
        "function hostDecide() { calls.push('hostDecide'); }\n"
        "var store = {get: function() { calls.push('storage'); return null; }};\n"
        "var localStorage = store, sessionStorage = store;\n"
        "function click(id) { return listeners.click({target: {closest: function() {"
        " return buttons[id]; }}, preventDefault: function() { calls.push('prevent'); }}); }\n"
        "function state() { return Object.keys(els).map(function(id) {"
        " return [buttons[id].getAttribute('aria-expanded'), els[id].hidden]; }); }\n"
        + fn
        + listener
        + "\n(async function() {\n"
        + body
        + "\n})().catch(function(e) { process.stdout.write(JSON.stringify('THROW: ' + e.message)); });"
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=30, check=False
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_a_click_closes_only_its_own_section_and_a_second_opens_it():
    got = _run(
        "var seen = [state()];"
        " await click('hostsSecMachines'); seen.push(state());"
        " await click('hostsSecList'); seen.push(state());"
        " await click('hostsSecMachines'); seen.push(state());"
        " process.stdout.write(JSON.stringify([seen, calls]));"
    )
    seen, calls = got
    open_, shut = ["true", False], ["false", True]
    assert seen == [
        [open_, open_, open_],
        [open_, open_, shut],
        [shut, open_, shut],
        [shut, open_, open_],
    ]
    assert calls == ["prevent"] * 3  # no render, no request, nothing stored


def test_the_toggle_keeps_nothing_across_reloads():
    fn = PAGE[PAGE.index("\nfunction toggleHostSection(") :]
    fn = fn[: fn.index("\n}\n")]
    assert "Storage" not in fn and "cookie" not in fn and "location" not in fn
