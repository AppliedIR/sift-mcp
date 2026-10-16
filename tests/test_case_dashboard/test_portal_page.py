"""The whole v2 page, run in Node against a live portal.

The page's own script runs with a small DOM stand-in, and its fetch reaches a
real portal (uvicorn on 127.0.0.1, the gateway's auth middleware) on a scratch
case. These rows drive the commit dialog as an examiner does: what the dialog
freezes, what a retry may sign, and whose entries it includes.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from .conftest import PASSWORD, enrol, finding, reviewed

uvicorn = pytest.importorskip("uvicorn")

V2 = Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
TOKEN = "vhir_gw_" + "s" * 24

SHIM = r"""
const ORIGIN = process.env.ORIGIN;
const out = { toasts: [], posts: [], banners: [] };
function makeEl(id) {
  const classes = new Set();
  const el = {
    id, innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
    style: {}, dataset: {}, title: '', href: '', children: [], offsetWidth: 300,
    classList: { add: c => classes.add(c), remove: c => classes.delete(c),
                 contains: c => classes.has(c), toggle: c => classes.has(c) ? classes.delete(c) : classes.add(c) },
    querySelectorAll(sel) {
      if (sel === 'input[data-other]') {
        return [...this.innerHTML.matchAll(/data-other="(\d+)"/g)].map(m => {
          const box = makeEl('other-' + m[1]); box.dataset.other = m[1]; others[m[1]] = box; return box;
        });
      }
      if (sel === 'textarea[data-reason]') {  // each failed item's reason, as typed
        return [...this.innerHTML.matchAll(/data-reason="([^"]+)"/g)].map(m => {
          const box = makeEl('reason'); box.dataset.reason = m[1];
          box.value = globalThis.typedReason || ''; return box;
        });
      }
      return [];
    },
  };
  return new Proxy(el, { get(t, k) {
    if (k in t) return t[k];
    if (k === 'then' || typeof k === 'symbol') return undefined;
    return () => makeEl('anon');
  }, set(t, k, v) { t[k] = v; return true; } });
}
const els = {}; const others = {};
const document = {
  getElementById: id => (els[id] = els[id] || makeEl(id)),
  querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  createElement: () => { const d = makeEl('new');  // textContent in, escaped innerHTML out
    return new Proxy(d, { set(t, k, v) { if (k === 'textContent') t.innerHTML = String(v ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); else t[k] = v; return true; } }); },
  body: makeEl('body'), documentElement: makeEl('html'),
  title: '',
  get activeElement() { return this.body; },  // a browser's, with nothing focused
};
document.body.tagName = 'BODY';
const store = () => { const m = {}; return { getItem: k => m[k] ?? null, setItem: (k, v) => { m[k] = String(v); }, removeItem: k => { delete m[k]; } }; };
const window = globalThis;
window.location = { hash: '#token=' + process.env.TOKEN, pathname: '/portal/', search: '' };
window.history = { replaceState() {} };
window.isSecureContext = true;
window.matchMedia = () => ({ matches: false, addEventListener() {} });
window.addEventListener = () => {};
window.sessionStorage = store(); window.localStorage = store();
window.document = document;
const _fetch = globalThis.fetch;
globalThis.fetch = async (url, opts = {}) => {
  if (url.endsWith('/api/commit') && globalThis.beforeCommit) await globalThis.beforeCommit();
  if ((opts.method || 'GET') === 'POST') out.posts.push(url.replace(/^\/portal/, ''));
  return _fetch(ORIGIN + url, opts);
};
globalThis.setInterval = () => 0;
function alert() {} function confirm() { return true; } function prompt() { return ''; }
"""

DRIVER = r"""
showToast = (m) => out.toasts.push(m);
showErrorBanner = (m) => out.banners.push(m);
const el = id => document.getElementById(id);
// loadAll() returns at once while another load (the page's own start-up) is
// in flight: wait until the page holds the case and its signing state
async function ready() {
  for (let i = 0; i < 400 && (isLoading || !caseMeta.signing); i++) {
    await new Promise(r => setTimeout(r, 25));
  }
  if (isLoading || !caseMeta.signing) throw new Error('the page never finished loading the case');
}
async function test() {
  await new Promise(r => setTimeout(r, 50));
  await loadAll();
  await ready();
  const steps = JSON.parse(process.env.STEPS);
  for (const s of steps) {
    if (s.do === 'open') await VHIR_SIGN.open();
    if (s.do === 'tick') { const box = others[s.i]; box.checked = true; await box.onchange(); }
    if (s.do === 'server') await _fetch(ORIGIN + '/test/' + s.what, { method: 'POST' });
    if (s.do === 'move_before_commit') {
      let n = 0;
      globalThis.beforeCommit = async () => { if (n++ < s.times) await _fetch(ORIGIN + '/test/' + s.what, { method: 'POST' }); };
    }
    if (s.do === 'reload') { await loadAll(); await ready(); }
    if (s.do === 'replan') { globalThis.typedReason = s.reason; await el('commitReplan').onclick(); }
    if (s.do === 'sign') { el('commitPassword').value = process.env.PASSWORD; await VHIR_SIGN.submit(); }
    if (s.do === 'move_and_reopen_before_commit') {
      // the ledger moves, and the examiner closes and reopens, while the commit is in flight
      let n = 0;
      globalThis.beforeCommit = async () => {
        if (n++ > 0) return;
        await _fetch(ORIGIN + '/test/move', { method: 'POST' });
        VHIR_SIGN.close();
        await VHIR_SIGN.open();
      };
    }
    if (s.do === 'sign_then_tick') {
      // the examiner ticks another examiner's entry while the key is being derived
      el('commitPassword').value = process.env.PASSWORD;
      const box = others[s.i];  // the box the dialog drew, with its handler
      const first = VHIR_SIGN.submit();
      box.checked = true; await box.onchange();
      out.tickedBox = { checked: box.checked, disabledNow: others[s.i].disabled };
      await first;
    }
    if (s.do === 'sign_then_reopen') {
      // the examiner cancels while the key is being derived, and opens a new dialog
      el('commitPassword').value = process.env.PASSWORD;
      const first = VHIR_SIGN.submit();
      VHIR_SIGN.close();
      await VHIR_SIGN.open();
      await first;
    }
    if (s.do === 'snap') out[s.as] = { findings: findings.map(f => [f.id, f.observation, f.status]),
      list: el('commitList').innerHTML, error: el('commitError').textContent,
      signButton: el('commitSubmitBtn').textContent, signDisabled: el('commitSubmitBtn').disabled,
      signShown: el('commitSubmitBtn').style.display !== 'none',
      boxShown: el('commitPasswordRow').style.display !== 'none',
      summary: el('commitSummary').textContent,
      open: VHIR_SIGN.isOpen(), delta: delta.items.map(e => [e.id, e.staged_by || null]) };
  }
}
test().then(() => { process.stdout.write(JSON.stringify(out)); process.exit(0); })
      .catch(e => { process.stderr.write(String(e.stack || e)); process.exit(1); });
"""


def _page_script() -> str:
    import re

    return "\n".join(re.findall(r"<script>(.*?)</script>", V2.read_text(), re.S))


@pytest.fixture
def live(portal, monkeypatch, tmp_path):
    """The portal served on 127.0.0.1 behind the gateway's auth middleware,
    with test routes that move the ledger or change an item meanwhile."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    from case_dashboard.routes import create_dashboard_v2_app
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sift_gateway.auth import AuthMiddleware
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from vhir_cli import keys, ledger
    from vhir_cli.case_io import signed_text

    other = Ed25519PrivateKey.generate()

    def move(request):
        """Another examiner signs an approval of F-steve-002: the head moves."""
        item = portal.item("F-steve-002")
        pub = keys.b64(keys.public_raw(other))
        bodies = ledger.prepare("C-1", [{"item_id": item["id"], "type": "finding",
                                         "decision": "edit", "status_after": "DRAFT",
                                         "coupled_from": None,
                                         "content_snapshot": signed_text(item, "finding")}],
                                "lab2", pub, "cli", "2026-10-08T10:00:00+00:00")  # fmt: skip
        with ledger.case_lock("C-1") as lock:
            ledger.commit(
                lock, bodies, [ledger.sign_body(b, other) for b in bodies], pub
            )
        return JSONResponse({})

    def uncite(request):
        """F-steve-002 stops citing the IOC, so approving F-steve-001 now
        cascades to it: a decision that wasn't shown."""
        findings = portal.read("findings.json")
        findings[1]["iocs"] = []
        portal.write("findings.json", findings)
        return JSONResponse({})

    def change(request):
        findings = portal.read("findings.json")
        findings[0]["observation"] = "changed while the dialog was open"
        portal.write("findings.json", findings)
        return JSONResponse({})

    keys_ = {TOKEN: {"examiner": "steve", "role": "examiner"}}
    app = Starlette(
        routes=[
            Route("/test/move", move, methods=["POST"]),
            Route("/test/change", change, methods=["POST"]),
            Route("/test/uncite", uncite, methods=["POST"]),
            Mount("/portal", app=create_dashboard_v2_app()),
        ]
    )
    app.add_middleware(AuthMiddleware, api_keys=keys_)
    from sift_gateway import auth

    monkeypatch.setattr(
        auth,
        "_PUBLIC_PATHS",
        auth._PUBLIC_PATHS | {"/test/move", "/test/change", "/test/uncite"},
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.02)

    def run(steps):
        script = tmp_path / "page.js"
        script.write_text(SHIM + _page_script() + DRIVER)
        r = subprocess.run(
            [node, str(script)],
            env={"PATH": "/usr/bin:/bin", "ORIGIN": f"http://127.0.0.1:{port}",
                 "TOKEN": TOKEN, "STEPS": json.dumps(steps), "PASSWORD": PASSWORD},
            capture_output=True, text=True, timeout=120,
        )  # fmt: skip
        assert r.returncode == 0, r.stderr[-3000:]
        return json.loads(r.stdout)

    yield run
    server.should_exit = True
    t.join(5)


@pytest.fixture
def case(portal):
    enrol("steve")
    portal.write("findings.json", [finding("F-steve-001"), finding("F-steve-002")])
    portal.write("timeline.json", [])
    portal.write("iocs.json", [])
    portal.stage(dict(reviewed(portal, "F-steve-001"), staged_by="steve"))
    return portal


def test_the_dialog_lists_then_signs_with_one_passphrase(case, live):
    out = live([{"do": "open"}, {"do": "snap", "as": "shown"}, {"do": "sign"},
                {"do": "snap", "as": "after"}])  # fmt: skip
    assert (
        "F-steve-001" in out["shown"]["list"]
        and out["shown"]["signButton"] == "Sign 1 decision"
    )
    assert out["shown"]["signDisabled"] is False
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-001"]
    assert out["after"]["open"] is False and out["after"]["delta"] == []
    assert any(t.startswith("Signed: 1 approved") for t in out["toasts"])
    assert out["posts"].count("/api/commit") == 1


def test_a_load_while_the_dialog_is_open_changes_nothing(case, live):
    out = live([{"do": "open"}, {"do": "server", "what": "change"}, {"do": "reload"},
                {"do": "snap", "as": "s"}])  # fmt: skip
    assert ["F-steve-001", "obs", "DRAFT"] in out["s"][
        "findings"
    ]  # still the frozen copy


def test_a_moved_ledger_is_retried_once_with_no_second_passphrase(case, live):
    out = live([{"do": "open"}, {"do": "move_before_commit", "what": "move", "times": 1},
                {"do": "sign"}, {"do": "snap", "as": "s"}])  # fmt: skip
    assert out["s"]["open"] is False, out["s"]["error"]
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-002", "F-steve-001"]
    assert (
        out["posts"].count("/api/commit/plan") == 2
        and out["posts"].count("/api/commit") == 2
    )


def test_a_retry_that_would_sign_something_else_signs_nothing(case, live):
    out = live([{"do": "open"}, {"do": "server", "what": "change"},
                {"do": "move_before_commit", "what": "move", "times": 1},
                {"do": "sign"}, {"do": "snap", "as": "s"}])  # fmt: skip
    assert out["s"]["open"] is True and "PLAN_CHANGED" in out["s"]["error"]
    assert out["posts"].count("/api/commit") == 1  # the first, refused as moved
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-002"]


def test_a_second_move_is_shown_not_retried(case, live):
    out = live([{"do": "open"}, {"do": "move_before_commit", "what": "move", "times": 2},
                {"do": "sign"}, {"do": "snap", "as": "s"}])  # fmt: skip
    assert out["s"]["open"] is True and out["s"]["error"]
    assert out["posts"].count("/api/commit") == 2
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-002", "F-steve-002"]


def test_another_examiners_entry_is_left_out_until_ticked(case, live):
    case.stage(
        dict(reviewed(case, "F-steve-001"), staged_by="steve"),
        dict(reviewed(case, "F-steve-002"), staged_by="lab2"),
    )
    out = live([{"do": "open"}, {"do": "snap", "as": "before"}, {"do": "tick", "i": "0"},
                {"do": "snap", "as": "ticked"}, {"do": "sign"}])  # fmt: skip
    assert "F-steve-002" not in out["before"]["list"]
    assert out["before"]["signButton"] == "Sign 1 decision"
    assert "F-steve-002" in out["ticked"]["list"]
    assert out["ticked"]["signButton"] == "Sign 2 decisions"
    assert {(ln["item_id"], ln["examiner"]) for ln in case.chain()} == {
        ("F-steve-001", "steve"), ("F-steve-002", "steve")}  # fmt: skip


def test_a_box_ticked_while_signing_changes_nothing_that_is_signed(case, live):
    """The Sign click confirmed one entry: an entry ticked while the key is
    being derived is neither planned nor signed under that click."""
    case.stage(
        dict(reviewed(case, "F-steve-001"), staged_by="steve"),
        dict(reviewed(case, "F-steve-002"), staged_by="lab2"),
    )
    out = live([{"do": "open"}, {"do": "sign_then_tick", "i": "0"}])
    # the boxes are disabled while signing; a change that reaches the handler
    # anyway is undone
    assert out["tickedBox"] == {"checked": False, "disabledNow": True}
    assert out["posts"].count("/api/commit/plan") == 1
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-001"]


def test_an_item_changed_before_the_dialog_opened_is_refused_by_the_page(case, live):
    """The page loaded F-steve-001, then it changed on disk. The staged entry
    has no review hash, so the gateway plans the new text; the page compares
    it with what it showed the examiner and refuses before any passphrase."""
    case.stage({"id": "F-steve-001", "type": "finding", "action": "approve",
                "modifications": {}, "staged_by": "steve"})  # fmt: skip
    out = live([{"do": "server", "what": "change"}, {"do": "open"},
                {"do": "snap", "as": "s"}, {"do": "sign"}])  # fmt: skip
    assert (
        "PLAN_CHANGED" in out["s"]["error"]
        and "observation differ" in out["s"]["error"]
    )
    assert out["s"]["signDisabled"] is True
    assert "/api/commit/key" not in out["posts"] and "/api/commit" not in out["posts"]
    assert case.chain() == []


def test_a_retry_that_adds_a_cascade_signs_nothing(portal, live):
    """An IOC cited by two findings doesn't cascade from one of them. While
    the dialog is open the other stops citing it, and the ledger moves: the
    retry would add the IOC, which wasn't shown, so nothing is signed."""
    enrol("steve")
    portal.write("findings.json", [finding("F-steve-001", iocs=["198.51.100.7"]),
                                   finding("F-steve-002", iocs=["198.51.100.7"])])  # fmt: skip
    portal.write("timeline.json", [])
    portal.write("iocs.json", [{"id": "IOC-steve-001", "value": "198.51.100.7",
                                "type": "ipv4-addr", "status": "DRAFT",
                                "source_findings": ["F-steve-001", "F-steve-002"]}])  # fmt: skip
    portal.stage(dict(reviewed(portal, "F-steve-001"), staged_by="steve"))
    out = live([{"do": "open"}, {"do": "snap", "as": "shown"},
                {"do": "server", "what": "uncite"},
                {"do": "move_before_commit", "what": "move", "times": 1},
                {"do": "sign"}, {"do": "snap", "as": "s"}])  # fmt: skip
    # shown as held for its own decision, never as an entry to sign
    assert "<strong>IOC-steve-001</strong>" not in out["shown"]["list"]
    assert (
        "IOC-steve-001 stays DRAFT: cited by F-steve-001 (APPROVED) and "
        "F-steve-002 (DRAFT). It is approved only when every finding that cites it "
        "is approved. To reject it now: vhir reject IOC-steve-001"
    ) in out["shown"]["list"]
    assert "IOCs tab" not in out["shown"]["list"]
    assert (
        "What would be signed changed after you reviewed it: IOC-steve-001"
        in out["s"]["error"]
    )
    assert out["posts"].count("/api/commit") == 1
    assert [ln["item_id"] for ln in portal.chain()] == ["F-steve-002"]


def test_a_dialog_closed_while_signing_signs_nothing(case, live):
    """Cancel while the key is being derived, then open the dialog again: the
    first passphrase entry stops; it never signs or posts the new dialog's
    plan, which nobody has signed for."""
    out = live([{"do": "open"}, {"do": "sign_then_reopen"}, {"do": "snap", "as": "s"}])
    assert "/api/commit/key" not in out["posts"] and "/api/commit" not in out["posts"]
    assert out["posts"].count("/api/commit/plan") == 2
    assert out["s"]["open"] is True and out["s"]["signDisabled"] is False
    assert case.chain() == []


def test_a_dialog_closed_during_the_commit_keeps_the_new_dialog_s_retry(case, live):
    """The ledger moves and the dialog is closed and reopened while a commit is
    in flight: the old run stops at the refusal; it doesn't plan again on the
    new dialog, whose one retry and error line stay its own."""
    out = live([{"do": "open"}, {"do": "move_and_reopen_before_commit"}, {"do": "sign"},
                {"do": "snap", "as": "s"}])  # fmt: skip
    # the old dialog's plan and key, the new dialog's plan (posted while the
    # old commit waited), the old commit (refused: the ledger moved); then nothing
    assert out["posts"] == ["/api/commit/plan", "/api/commit/key", "/api/commit/plan",
                            "/api/commit"]  # fmt: skip
    assert out["s"]["open"] is True and out["s"]["error"] == ""
    assert out["s"]["signDisabled"] is False
