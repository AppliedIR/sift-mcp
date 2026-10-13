"""The Portal renders an audit line's values and a timeline status as text.

A result summary's exit_code and stdout_bytes are escaped. A compact timeline
row keeps a status inside its class. An audit line's output_sha256,
output_file or inputs given as an object, or a lone value instead of a list,
render instead of throwing and blanking the evidence panel or the chain
tooltip.

String level, as the page builds them: the page's own top-level state and
functions run under Node with a small DOM stand-in (its escapeHtml kept; the
stand-in's text node escapes as a browser's does), and every tag of the HTML
they return is parsed for the attributes it really has. The payloads have no
digits, which formatTime would read as a date. The browser leg is test's.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import case_dashboard.routes as D
import pytest

STATIC = Path(D.__file__).parent / "static"
V2 = STATIC / "v2" / "index.html"
TAG = "<svg onload=window.__pwn=true>"  # digit-free: never read as a date
ATTR = 'x" onmouseover="window.__pwn=true'  # breaks out of a quoted attribute
SHOWN_TAG = "&lt;svg onload=window.__pwn=true&gt;"

pytestmark = pytest.mark.skipif(
    not shutil.which("node"), reason="node is not installed"
)

RENDER_JS = r"""
// render.js <index.html> <scenario.json>: load the page's top-level state and functions
// into one scope with a small DOM stand-in, run the scenario's render calls, and print
// {element id or call: html} as JSON. Not the browser: the HTML strings the page builds.
'use strict';
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const scen = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const lines = src.split('\n');
const decls = lines.filter(l => /^(let|const|var) [\w$]+ = [^;]*;\s*(\/\/.*)?$/.test(l)).join('\n');
const fns = [];
const re = /^(async )?function ([\w$]+)\(/gm;
let m;
while ((m = re.exec(src))) {
  const end = src.indexOf('\n}\n', m.index);
  fns.push(src.slice(m.index, end + 2));
}
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function el(id) {
  const e = {
    id, children: [], style: {}, dataset: {}, className: '', _html: '',
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    set textContent(s) { this._html = esc(s); }, get textContent() { return this._html; },
    set innerHTML(s) { this._html = String(s); this.children = []; },
    get innerHTML() { return this._html + this.children.map(c => c.outer()).join(''); },
    outer() { return '<div class="' + this.className + '">' + this.innerHTML + '</div>'; },
    setAttribute() {}, getAttribute() { return null; }, addEventListener() {},
    appendChild(c) { this.children.push(c); return c; }, insertBefore(c) { this.children.push(c); return c; },
    querySelector() { return el('q'); }, querySelectorAll() { return []; }, remove() {},
    scrollIntoView() {}, focus() {}, closest() { return null; },
  };
  return e;
}
const byId = {};
const document = {
  createElement: () => el(''),
  getElementById: id => (byId[id] = byId[id] || el(id)),
  querySelector: () => el('q'), querySelectorAll: () => [], addEventListener() {},
  body: el('body'),
};
const window = { location: { pathname: '/portal/', search: '', hash: '', origin: 'http://x' } }; const localStorage = { getItem() { return null; }, setItem() {} };
const out = {};
const body = decls + '\n' + fns.join('\n') + '\n' +
  'return function(scen, out) {' +
  '  if (scen.findings) findings = scen.findings;' +
  '  if (scen.timeline) timelineEvents = scen.timeline;' +
  '  if (scen.delta) delta = scen.delta;' +
  '  if (scen.filter) currentFilter = scen.filter;' +
  '  if (scen.timelineFilter) timelineFilter = scen.timelineFilter;' +
  '  for (const c of scen.calls) {' +
  '    try { const r = eval(c); out[c] = typeof r === "string" ? r : null; }' +
  '    catch (e) { out[c] = "THREW " + e.constructor.name + ": " + e.message; }' +
  '  }' +
  '};';
new Function('document', 'window', 'localStorage', 'fetch', 'setTimeout', 'esc', body)(
  document, window, localStorage, () => Promise.reject(new Error('no fetch')), () => 0, esc
)(scen, out);
for (const [id, e] of Object.entries(byId)) out['#' + id] = e.innerHTML;
process.stdout.write(JSON.stringify(out));
"""

_ATTRS = re.compile(r"""\s([^\s=>"'/]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>"']+))?""")


def _injected(html: str) -> list[str]:
    """Each tag the payload made, or gave an event handler: as a browser parses it."""
    bad = []
    for tag in re.findall(r"<[a-zA-Z][^>]*>", html):
        name = re.match(r"<([a-zA-Z0-9]+)", tag).group(1).lower()
        attrs = {a.lower() for a, _ in _ATTRS.findall(tag[len(name) + 1 :])}
        if name in ("svg", "img") or attrs & {"onerror", "onload", "onmouseover"}:
            bad.append(tag)
    return bad


def _render(tmp_path, page: Path, scenario: dict) -> dict:
    script = tmp_path / "render.js"
    script.write_text(RENDER_JS)
    scen = tmp_path / "scenario.json"
    scen.write_text(json.dumps(scenario))
    run = subprocess.run(["node", str(script), str(page), str(scen)],
                         capture_output=True, text=True, timeout=60)  # fmt: skip
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


@pytest.mark.parametrize(
    "summary,shown",
    [({"exit_code": TAG}, SHOWN_TAG), ({"stdout_bytes": TAG}, SHOWN_TAG),
     ({"output_sha256": {}}, "[object Object]")],
    ids=["exit_code", "stdout_bytes", "output_sha256-object"],
)  # fmt: skip
def test_an_audit_lines_result_summary_renders_as_text(tmp_path, summary, shown):
    call = f"renderResultSummary({json.dumps(summary)})"
    html = _render(tmp_path, V2, {"calls": [call]})[call]
    assert not html.startswith("THREW"), html  # an object threw and blanked the panel
    assert _injected(html) == [] and shown in html, html


def test_a_timeline_row_keeps_a_status_inside_its_class(tmp_path):
    ev = {
        "id": "T-a-001",
        "timestamp": "2026-01-02T03:04:05Z",
        "status": ATTR,
        "verification": "draft",
        "description": "d",
        "event_type": "other",
    }
    call = "renderTimelineCompactRow(timelineEvents[0], null, false)"
    html = _render(tmp_path, V2, {"timeline": [ev], "calls": [call]})[call]
    assert _injected(html) == [], html
    assert 'class="tl-row status-x&quot; onmouseover=&quot;window.__pwn=true' in html


@pytest.mark.parametrize(
    "call",
    [
        "renderResultSummary({output_sha256: {}})",
        "_buildTooltipHtml({tool: 't', result_summary: {output_sha256: {}, output_file: {}},"
        " input_files: [5], input_sha256s: [{}]}, {})",
    ],
    ids=["v2-panel", "v2-chain-tooltip"],
)
def test_an_audit_lines_non_text_fields_render(tmp_path, call):
    """v2's evidence panel and chain tooltip took output_sha256 (and the tooltip
    output_file and each input) as text: an object threw and blanked them."""
    html = _render(tmp_path, V2, {"calls": [call]})[call]
    assert not html.startswith("THREW"), html
    assert "[object Object]" in html and _injected(html) == [], html


@pytest.mark.parametrize(
    "inputs",
    ["input_files: 'C:/evidence/a.evtx', input_sha256s: 'ab'.repeat(32)",
     "input_files: {x: 1}, input_sha256s: {y: 2}"],
    ids=["one-string-each", "an-object-each"],
)  # fmt: skip
def test_the_chain_tooltip_takes_inputs_given_alone(tmp_path, inputs):
    """input_files and input_sha256s given as one value (not a list) threw at
    .map and blanked the tooltip; now each is shown as a list of one."""
    call = f"_buildTooltipHtml({{tool: 't', {inputs}}}, {{}})"
    html = _render(tmp_path, V2, {"calls": [call]})[call]
    assert not html.startswith("THREW"), html
    assert "Input files:" in html and "Input SHA-256:" in html, html
    assert _injected(html) == [], html
