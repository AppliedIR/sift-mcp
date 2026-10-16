"""The portal shows a finding's IOCs read-only, as the finding stores them:
structured `{value, type}` IOCs render their values (comma-joined), and a
legacy plain-string IOC passes through. When a stale pending delta carries a
`modifications.iocs`, both the original and the modified sides render their
values too. In no case does the page print "[object Object]".

The page's own script runs under node with a stand-in `document`; each row
renders a finding's card and the card's IOCs section is read back."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import finding

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)

# [{value, type}] — the shape forensic-mcp stores; values are IP and domain.
STRUCT = finding(
    "F-steve-001",
    iocs=[{"value": "203.0.113.7", "type": "ipv4"},
          {"value": "evil.example.com", "type": "domain"}],
)  # fmt: skip
# Legacy plain-string IOCs recorded before the structured shape.
LEGACY = finding("F-steve-002", iocs=["198.51.100.9", "bad.example.org"])
# A finding whose own iocs are structured; a stale pending delta would replace
# them. Display must show both sides' values, never "[object Object]".
STALE = finding("F-steve-003", iocs=[{"value": "203.0.113.7", "type": "ipv4"}])

FINDINGS = [STRUCT, LEGACY, STALE]
CASE_META = {"signing": {"examiner": "steve"}}
DELTA = {
    "version": 1,
    "case_id": "C-1",
    "items": [{
        "id": "F-steve-003",
        "action": "edit",
        "staged_by": "steve",
        "modifications": {"iocs": {
            "original": [{"value": "203.0.113.7", "type": "ipv4"}],
            "modified": [{"value": "9.9.9.9", "type": "ipv4"}],
        }},
    }],
}  # fmt: skip

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
const els = {};
const document = {
  getElementById(id) { return els[id] || (els[id] = el(id)); },
  querySelector() { return el('q'); }, querySelectorAll() { return []; }, addEventListener() {},
  createElement(t) {
    const e = el(t);
    Object.defineProperty(e, 'textContent', {
      set(v) { e.innerHTML = String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); },
      get() { return e.innerHTML; } });
    return e;
  }, body: el('body'), documentElement: el('html'), cookie: '', title: '' };
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
ctx.__F = I.findings; ctx.__CM = I.caseMeta; ctx.__D = I.delta;
try {
  vm.runInContext(src + `
;(function(){
  findings = __F; caseMeta = __CM; delta = __D; var out = {};
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    renderFinding(f.id);
    out[f.id] = document.getElementById('findingCard').innerHTML;
  }
  globalThis.__OUT = out;
})();`, ctx);
} catch (e) { ctx.__ERR = String(e && e.stack || e); }
if (ctx.__ERR) { process.stderr.write(ctx.__ERR); process.exit(3); }
process.stdout.write(JSON.stringify(ctx.__OUT));
"""


@pytest.fixture(scope="module")
def cards() -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    r = subprocess.run(
        [node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
        input=json.dumps({"page": str(PAGE), "findings": FINDINGS,
                          "caseMeta": CASE_META, "delta": DELTA}),
    )  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout)


def test_structured_iocs_render_their_values_not_object_object(cards):
    card = cards["F-steve-001"]
    assert ">IOCs<" in card
    assert "203.0.113.7, evil.example.com" in card
    assert "[object Object]" not in card


def test_a_legacy_plain_string_ioc_passes_through(cards):
    card = cards["F-steve-002"]
    assert ">IOCs<" in card
    assert "198.51.100.9" in card and "bad.example.org" in card
    assert "[object Object]" not in card


def test_a_stale_iocs_delta_shows_both_sides_values_not_object_object(cards):
    card = cards["F-steve-003"]
    assert ">IOCs<" in card
    assert "203.0.113.7" in card and "9.9.9.9" in card
    assert "[object Object]" not in card


def test_no_card_ever_prints_object_object(cards):
    assert "[object Object]" not in "".join(cards.values())
