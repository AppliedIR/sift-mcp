"""When a finding's card can't be shown, the selection stays on the record the
card does show, and one message names the record and the error. The 'a' key
then approves the record the examiner sees, never the one clicked.

The page's own script runs under node with a stand-in `document`. Each row
clicks findings through selectFinding, presses 'a' through the page's own key
handler, and reads back the selection, the card, the messages and what is
staged."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)

DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const I = JSON.parse(fs.readFileSync(0, 'utf8'));
const src = fs.readFileSync(I.page, 'utf8').match(/<script>([\s\S]*?)<\/script>\s*<div id="chainTooltip"/)[1];
function el(id) {
  return { id, innerHTML: '', textContent: '', value: '', style: {}, dataset: {}, checked: false,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {}, removeEventListener() {}, setAttribute() {}, getAttribute() { return ''; },
    appendChild() {}, prepend() {}, remove() {}, focus() {}, scrollIntoView() {},
    querySelector() { return el('q'); }, querySelectorAll() { return []; }, closest() { return null; },
    getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0 }; },
    parentElement: null, children: [], offsetHeight: 0 };
}
const els = {}, toasts = [];
const body = el('body');
body.appendChild = function (t) { toasts.push(t.text); };
const keys = [];
const document = {
  getElementById(id) { return els[id] || (els[id] = el(id)); },
  querySelector(sel) {
    if (sel === '.tab.active') return Object.assign(el('tab'), { dataset: { tab: 'findings' } });
    return sel === '.dialog-overlay.visible' ? null : el('q');
  },
  querySelectorAll() { return []; },
  addEventListener(type, fn) { if (type === 'keydown') keys.push(fn); },
  createElement(t) {
    const e = el(t);
    Object.defineProperty(e, 'textContent', {
      set(v) {
        e.text = String(v == null ? '' : v);
        e.innerHTML = e.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      }, get() { return e.text; } });
    return e;
  }, body, documentElement: el('html'), cookie: '', title: '' };
const storage = { getItem() { return null; }, setItem() {}, removeItem() {} };
const ctx = { document, console, JSON, Math, Date, Promise, Object, Array, String, Number, Set, Map,
  RegExp, Error, encodeURIComponent, decodeURIComponent, parseInt, parseFloat, isNaN,
  setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {},
  fetch() { return new Promise(() => {}); }, localStorage: storage, sessionStorage: storage,
  navigator: { clipboard: {} }, crypto: require('crypto').webcrypto, TextEncoder, TextDecoder,
  atob, btoa, Uint8Array, history: { replaceState() {}, pushState() {} }, alert() {},
  confirm() { return false; }, location: { pathname: '/portal/', hash: '', search: '', href: 'http://x/portal/' } };
ctx.window = ctx; ctx.window.addEventListener = function () {};
ctx.window.innerWidth = 1200; ctx.window.innerHeight = 800;
process.on('unhandledRejection', () => {});
vm.createContext(ctx);
ctx.__I = I; ctx.__toasts = toasts; ctx.__keys = keys;
try {
  vm.runInContext(src + `
;(function(){
  findings = __I.findings; caseMeta = {signing: {examiner: 'steve'}};
  delta = {version: 1, case_id: 'C-1', items: []}; timelineEvents = __I.timeline;
  var out = [];
  __I.steps.forEach(function (step) {
    __toasts.length = 0;
    var thrown = null;
    try {
      if (step === 'a') __keys.forEach(function (fn) {
        fn({key: 'a', target: {tagName: 'BODY'}, preventDefault: function () {}});
      });
      else selectFinding(step);
    } catch (e) { thrown = 'THROW: ' + e.message; }
    var m = /title of (F-steve-[0-9]+)/.exec(document.getElementById('findingCard').innerHTML);
    out.push({step: step, selected: selectedId, card: m ? m[1] : null, thrown: thrown,
              toasts: __toasts.slice(), staged: delta.items.filter(function (i) {
                return i.action === 'approve'; }).map(function (i) { return i.id; })});
  });
  globalThis.__OUT = out;
})();`, ctx);
} catch (e) { ctx.__ERR = String(e && e.stack || e); }
if (ctx.__ERR) { process.stderr.write(ctx.__ERR); process.exit(3); }
process.stdout.write(JSON.stringify(ctx.__OUT));
"""


def _finding(fid, **extra):
    return {"id": fid, "title": "title of " + fid, "observation": "o",
            "interpretation": "i", "confidence": "LOW", "status": "DRAFT", **extra}  # fmt: skip


def _steps(findings, steps, timeline=()):
    """Each step is a finding id to click, or "a" for the approve key."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    r = subprocess.run(
        [node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
        input=json.dumps({"page": str(PAGE), "findings": findings,
                          "timeline": list(timeline), "steps": steps}),
    )  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout)


GOOD = [_finding("F-steve-001"), _finding("F-steve-002")]


def test_a_card_that_cant_be_shown_leaves_the_shown_record_selected():
    """F-steve-009's related_findings is a string, so its card throws before
    it is written: the card stays on F-steve-001, and so does the selection."""
    bad = _finding("F-steve-009", related_findings="F-steve-001")
    _, click, key = _steps([*GOOD, bad], ["F-steve-001", "F-steve-009", "a"])
    assert click == {
        "step": "F-steve-009", "selected": "F-steve-001", "card": "F-steve-001",
        "thrown": None, "staged": [],
        "toasts": ["F-steve-009 can't be shown: f.related_findings.map is not a function"],
    }  # fmt: skip
    assert key["staged"] == ["F-steve-001"]


def test_a_well_formed_record_clicked_is_selected_and_shown():
    got = _steps(GOOD, ["F-steve-001", "F-steve-002"])
    assert [(c["selected"], c["card"], c["thrown"], c["toasts"]) for c in got] == [
        ("F-steve-001", "F-steve-001", None, []),
        ("F-steve-002", "F-steve-002", None, []),
    ]


def test_a_throw_after_the_card_is_written_selects_the_clicked_record():
    """An event whose related_findings is a number throws in the timeline
    context, after the clicked record's card is written. That record is the
    one shown, so it is selected and approved, the error propagates as before,
    and no message is shown. A rule that went back to the record before the
    click would fail here."""
    timeline = [{"id": "T-steve-001", "timestamp": "2026-01-01T00:00:00Z",
                 "description": "d", "related_findings": 5}]  # fmt: skip
    findings = [*GOOD, _finding("F-steve-010")]
    _, click, key = _steps(findings, ["F-steve-001", "F-steve-010", "a"], timeline)
    thrown = "THROW: ev.related_findings.indexOf is not a function"
    assert click == {"step": "F-steve-010", "selected": "F-steve-010",
                     "card": "F-steve-010", "thrown": thrown, "toasts": [],
                     "staged": []}  # fmt: skip
    assert key["staged"] == ["F-steve-010"]
