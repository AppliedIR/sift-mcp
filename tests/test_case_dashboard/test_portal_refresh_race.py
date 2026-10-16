"""A decision pressed while the portal refreshes is never lost.

The 15 s refresh (`loadAll`) fetches the staged delta. It takes the server's
copy only when nothing here is unsaved: no local change since it started, no
save waiting or out, and the last save didn't fail. Saves go one at a time, and
the status reads saved only in that state; closing the page in any other
state sends the delta. The page's own functions run in node, with the
fetches and the save timer driven by the test.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from case_dashboard import signing

PAGE = (Path(signing.__file__).parent / "static" / "v2" / "index.html").read_text()


def _fn(name: str) -> str:
    start = PAGE.index(f"function {name}(")
    return PAGE[PAGE.rindex("\n", 0, start) + 1 : PAGE.index("\n}\n", start) + 3]


def _unload() -> str:
    """The page's beforeunload handler, as the page adds it."""
    start = PAGE.index("window.addEventListener('beforeunload'")
    return PAGE[start : PAGE.index("\n});\n", start) + 5]


def _state() -> str:
    """The page's own state declarations, from `let token` to its first function."""
    start = PAGE.index("let token = null;")
    return PAGE[start : PAGE.index("\nfunction ", start) + 1]


# The page's functions under test run in a context where every other name is
# a no-op (renderers, toolbars), and fetches and timers are the test's.
HARNESS = r"""
const vm = require('vm');
const noop = function() { return noop; };
const pending = [];   // [url, opts, resolve, reject]
const timers = [];    // [fn]
const posts = [];
const statuses = [];
let maxPostsOut = 0;   // POSTs out at once
const unloadHandlers = [];
const unloads = [];    // what closing the page sent
const base = {
  console, JSON, Math, Date, Promise, Set, Object, Array, String, Error,
  isLoading: false, batchSelected: new Set(), batchTimelineSelected: new Set(),
  previousFindingIds: new Set(), VHIR_SIGN: { isOpen: () => false },
  document: { getElementById: () => ({ style: {}, classList: { add: noop, remove: noop } }),
              querySelectorAll: () => [] },
  setSaveStatus: (s) => { statuses.push(s); },
  window: { addEventListener: (ev, fn) => { if (ev === 'beforeunload') unloadHandlers.push(fn); } },
  API_BASE: '', apiHeaders: () => ({}),
  fetch: (url, opts) => { unloads.push({ url, method: opts.method, keepalive: opts.keepalive,
                                         items: JSON.parse(opts.body).items }); },
  setTimeout: (fn) => { timers.push(fn); return timers.length; },
  clearTimeout: (n) => { if (n) timers[n - 1] = null; },
  apiFetch: (url, opts) => new Promise((resolve, reject) => {
    if (opts && opts.method === 'POST') posts.push(JSON.parse(opts.body));
    pending.push([url, opts, resolve, reject]);
    maxPostsOut = Math.max(maxPostsOut, pending.filter(p => p[1] && p[1].method === 'POST').length);
  }),
};
const ctx = vm.createContext(new Proxy(base, {
  has: () => true,
  get: (t, k) => (k in t ? t[k] : (typeof k === 'string' ? noop : undefined)),
  set: (t, k, v) => { t[k] = v; return true; },
}));
vm.runInContext(SOURCE + `
var T = {
  get delta() { return delta; },
  set caseMeta(v) { caseMeta = v; },
  set selectedId(v) { selectedId = v; },
  loadAll, setDeltaEntry, saveDelta, doSkip, doTimelineSkip, doTimelineApprove,
};`, ctx);
const T = ctx.T;
const SERVER = { version: 1, case_id: 'C-1', items: [] };
function answer(url) {   // the server's copy, as JSON brings it
  const body = { '/api/findings': [{ id: 'F-1' }, { id: 'F-2' }], '/api/delta': SERVER,
                 '/api/timeline': [{ id: 'T-1' }, { id: 'T-2' }],
                 '/api/case': { case_id: 'C-1', signing: { examiner: 'steve' } } }[url] || [];
  return JSON.parse(JSON.stringify(body));
}
async function settle() { for (let i = 0; i < 20; i++) await Promise.resolve(); }
async function answerAll() {
  while (pending.length) { const [u, , r] = pending.shift(); r(answer(u)); await settle(); }
}
function unload() { for (const f of unloadHandlers) f(); }   // the page closes
async function fire() {
  const fns = timers.splice(0).filter(Boolean);
  for (const f of fns) { f(); await settle(); }
}
"""


def _run(steps: str) -> dict:
    node = shutil.which("node") or pytest.skip("node isn't installed")
    source = _state() + "".join(
        _fn(n) for n in ("me", "isOwn", "getDeltaEntry", "setDeltaEntry", "loadAll",
                         "scheduleSave", "deltaForSave", "saveDelta", "doSkip",
                         "doTimelineSkip", "doTimelineApprove", "noteRemoved",
                         "isClean") if f"function {n}(" in PAGE
    ) + _unload()  # fmt: skip
    script = (
        f"const SOURCE = {json.dumps(source)};\n" + HARNESS
        + "(async () => {\n" + steps
        + "\nprocess.stdout.write(JSON.stringify({posts, delta: T.delta.items, statuses, maxPostsOut, unloads}));\n})();"
    )  # fmt: skip
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


START = """
T.caseMeta = { case_id: 'C-1', signing: { examiner: 'steve' } };
T.loadAll(); await settle(); await answerAll();   // the page as it opened
"""


def _ids(items) -> list:
    return sorted(i["id"] for i in items)


def test_a_decision_pressed_while_a_refresh_is_out_is_saved():
    out = _run(
        START
        + """
T.loadAll(); await settle();                        // the 15 s refresh: fetches out
T.setDeltaEntry({ id: 'F-1', action: 'approve' });  // pressed meanwhile
await answerAll();                                   // the refresh lands
await fire(); await answerAll();                     // the save, 1 s later
"""
    )
    assert _ids(out["delta"]) == ["F-1"]
    assert _ids(out["posts"][-1]["items"]) == ["F-1"]


def test_a_decision_whose_save_is_still_out_survives_a_refresh():
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire();                                        // its save is posted, unanswered
T.loadAll(); await settle();
const [save] = pending.splice(0, 1);                 // the refresh answers first
await answerAll();
save[2]({}); await settle();                         // then the save is confirmed
T.setDeltaEntry({ id: 'F-2', action: 'reject' });   // the next press saves both
await fire(); await answerAll();
"""
    )
    assert _ids(out["posts"][-1]["items"]) == ["F-1", "F-2"]


def test_with_nothing_unsaved_a_refresh_takes_the_servers_delta():
    """Another examiner's staged entry arrives by refresh, as before."""
    out = _run(
        START
        + """
SERVER.items = [{ id: 'F-2', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();
"""
    )
    assert out["delta"] == [{"id": "F-2", "action": "approve", "staged_by": "ann"}]
    assert out["posts"] == []


def test_once_its_save_is_confirmed_a_refresh_takes_the_servers_delta_again():
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire(); await answerAll();                     // saved
SERVER.items = [{ id: 'F-1', action: 'approve', staged_by: 'steve' },
                { id: 'F-2', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();
"""
    )
    assert _ids(out["delta"]) == ["F-1", "F-2"]


def test_an_unstaged_decision_stays_gone_when_a_refresh_fetched_before_it_lands():
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire(); await answerAll();                     // staged and saved
SERVER.items = [{ id: 'F-1', action: 'approve', staged_by: 'steve' }];
T.loadAll(); await settle();                         // a refresh: the server still has F-1
T.selectedId = 'F-1'; T.doSkip(); await settle();    // un-staged: its DELETE goes out
const del = pending.pop(); del[2]({}); await settle();   // the DELETE is answered first
await answerAll();                                   // then the refresh lands, with F-1
T.setDeltaEntry({ id: 'F-2', action: 'reject' });   // the next press saves
await fire(); await answerAll();
"""
    )
    assert _ids(out["delta"]) == ["F-2"]
    assert _ids(out["posts"][-1]["items"]) == ["F-2"]  # F-1 never posted again


def test_a_save_confirmed_while_a_refresh_is_out_never_lets_its_stale_copy_in():
    """The refresh's fetch read the delta before the save reached it."""
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire();                                        // its save is posted
T.loadAll(); await settle();                         // a refresh goes out
const save = pending.shift(); save[2]({}); await settle();   // the save confirms first
await answerAll();                                   // the refresh lands, without F-1
"""
    )
    assert _ids(out["delta"]) == ["F-1"]


def test_an_unstage_while_a_save_is_out_is_saved_and_refreshes_again():
    """Its DELETE lands before the save: the undo's own save follows, and then
    the next refresh brings another examiner's entry."""
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-2', action: 'reject' });
await fire(); await answerAll();                     // F-2 staged and saved
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire();                                        // F-1's save is out
T.selectedId = 'F-2'; T.doSkip(); await settle();
const del = pending.pop(); del[2]({}); await settle();   // the DELETE lands first
const save = pending.shift(); save[2]({}); await settle();   // then the save
await fire(); await answerAll();                     // the undo's save
SERVER.items = [{ id: 'F-1', action: 'approve', staged_by: 'steve' },
                { id: 'F-3', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();
"""
    )
    assert _ids(out["posts"][-1]["items"]) == ["F-1"]
    assert _ids(out["delta"]) == ["F-1", "F-3"]
    assert out["statuses"][-1] == "saved"


def test_decisions_signed_elsewhere_leave_the_page_and_are_never_posted_again():
    """Staged here, signed with `vhir approve` (it signs the portal's staged
    decisions and removes them from pending-reviews.json)."""
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire(); await answerAll();                     // staged and saved
SERVER.items = [];                                   // signed from the CLI
T.loadAll(); await settle(); await answerAll();      // the next refresh
T.setDeltaEntry({ id: 'F-2', action: 'reject' });
await fire(); await answerAll();
"""
    )
    assert _ids(out["delta"]) == ["F-2"]
    assert _ids(out["posts"][-1]["items"]) == ["F-2"]  # F-1 never staged again


FAILED_SAVE = """
await fire(); pending.shift()[3](new Error('save failed')); await settle();
"""


def test_an_undo_after_a_failed_save_saves_what_is_left_and_refreshes_again():
    """F-1's change didn't save, then F-1 is undone: what is left is saved, and
    the next refresh brings another examiner's entry."""
    out = _run(
        "SERVER.items = [{ id: 'F-1', action: 'approve', staged_by: 'steve' }];"
        + START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'reject' });"""
        + FAILED_SAVE
        + """
T.selectedId = 'F-1'; T.doSkip(); await settle();
const del = pending.pop(); del[2]({}); await settle();   // the undo is taken
await fire(); await answerAll();                     // what is left is saved
SERVER.items = [{ id: 'F-2', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();
"""
    )
    assert out["posts"][-1]["items"] == []
    assert out["delta"] == [{"id": "F-2", "action": "approve", "staged_by": "ann"}]


def _undo_after_failed_save(delete_answer: str) -> dict:
    """F-1 and F-3 never saved; F-1 is undone; its DELETE is answered as given."""
    return _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
T.setDeltaEntry({ id: 'F-3', action: 'reject' });"""
        + FAILED_SAVE
        + """
T.selectedId = 'F-1'; T.doSkip(); await settle();
const del = pending.pop(); """
        + delete_answer
        + """; await settle();
await fire(); await answerAll();
"""
    )


def test_an_undo_after_a_failed_save_keeps_and_saves_the_other_change():
    out = _undo_after_failed_save("del[2]({})")
    assert _ids(out["delta"]) == ["F-3"]
    assert _ids(out["posts"][-1]["items"]) == ["F-3"]
    assert out["statuses"][-1] == "saved"


def test_an_undo_refused_404_after_a_failed_save_still_retries_the_save():
    """The server never had F-1, so its DELETE is a 404: the undo doesn't take,
    F-1 stays on the page, and both decisions are saved."""
    out = _undo_after_failed_save("del[3](new Error('Not found'))")
    assert _ids(out["delta"]) == ["F-1", "F-3"]
    assert _ids(out["posts"][-1]["items"]) == ["F-1", "F-3"]
    assert out["statuses"][-1] == "saved"


def test_an_undo_of_a_decision_not_yet_saved_is_saved_either_way():
    """Pressed and undone inside the 1 s save wait: a 200 removes it, a 404
    leaves it, and either way the page and the next save agree."""
    for answer, ids in (
        ("del[2]({})", []),
        ("del[3](new Error('Not found'))", ["F-1"]),
    ):
        out = _run(
            START
            + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
T.selectedId = 'F-1'; T.doSkip(); await settle();
const del = pending.pop(); """
            + answer
            + """; await settle();
await fire(); await answerAll();
"""
        )
        assert _ids(out["delta"]) == ids
        assert _ids(out["posts"][-1]["items"]) == ids
        assert out["statuses"][-1] == "saved"


def test_a_timeline_undo_after_a_failed_save_saves_what_is_left():
    out = _run(
        "SERVER.items = [{ id: 'T-1', type: 'timeline', action: 'approve', staged_by: 'steve' }];"
        + START
        + """
T.setDeltaEntry({ id: 'T-1', type: 'timeline', action: 'reject' });"""
        + FAILED_SAVE
        + """
T.doTimelineSkip('T-1'); await settle();
const del = pending.pop(); del[2]({}); await settle();
await fire(); await answerAll();
SERVER.items = [{ id: 'F-2', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();
"""
    )
    assert out["posts"][-1]["items"] == []
    assert out["delta"] == [{"id": "F-2", "action": "approve", "staged_by": "ann"}]


def test_decisions_pressed_just_before_a_refresh_are_kept_and_saved():
    """The refresh lands while the 1 s save is still waiting, not yet posted."""
    out = _run(
        START
        + """
T.doTimelineApprove('T-1'); T.doTimelineApprove('T-2');
T.setDeltaEntry({ id: 'F-1', action: 'approve', note: 'edited' });
const before = posts.length;
T.loadAll(); await settle(); await answerAll();      // the refresh, save not posted
posts.push({ before });
await fire(); await answerAll();                     // the save, 1 s later
"""
    )
    assert out["posts"][0] == {"before": 0}
    assert _ids(out["delta"]) == ["F-1", "T-1", "T-2"]
    assert _ids(out["posts"][-1]["items"]) == ["F-1", "T-1", "T-2"]


def test_saves_go_one_at_a_time_and_a_failed_later_save_stays_failed():
    """A second save asked for while one is out waits for it; when that later
    save fails, the page says so and a refresh keeps the unsaved decisions."""
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire();                                        // save A is out
T.setDeltaEntry({ id: 'F-2', action: 'reject' });
await fire();                                        // asked again while A is out
pending.shift()[2]({}); await settle();              // A succeeds: B posts both
pending.shift()[3](new Error('save failed')); await settle();   // B fails
SERVER.items = [{ id: 'F-1', action: 'approve', staged_by: 'steve' },
                { id: 'F-3', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();      // a refresh
posts.push({ failedStatus: statuses[statuses.length - 1] });
T.setDeltaEntry({ id: 'F-4', action: 'approve' });  // the next press retries
await fire(); await answerAll();
"""
    )
    assert out["maxPostsOut"] == 1
    assert _ids(out["posts"][1]["items"]) == ["F-1", "F-2"]
    assert out["posts"][2] == {"failedStatus": "error"}
    assert "saved" not in out["statuses"][:-1]
    assert _ids(out["delta"]) == ["F-1", "F-2", "F-4"]
    assert _ids(out["posts"][-1]["items"]) == ["F-1", "F-2", "F-4"]
    assert out["statuses"][-1] == "saved"


def test_an_undo_that_lands_while_its_save_is_out_and_fails_is_saved_after():
    """F-1's save is out; its undo's DELETE lands; then the save fails. The
    status never reads saved until the undo's own save succeeds, and later
    refreshes bring another examiner's entry."""
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire();                                        // F-1's save is out
T.selectedId = 'F-1'; T.doSkip(); await settle();
const del = pending.pop(); del[2]({}); await settle();   // the undo lands
pending.shift()[3](new Error('save failed')); await settle();   // the save fails
SERVER.items = [{ id: 'F-1', action: 'approve', staged_by: 'steve' }];
T.loadAll(); await settle(); await answerAll();      // a refresh before the retry
await fire(); await answerAll();                     // the undo's save
SERVER.items = [{ id: 'F-2', action: 'approve', staged_by: 'ann' }];
T.loadAll(); await settle(); await answerAll();
T.loadAll(); await settle(); await answerAll();
"""
    )
    assert out["statuses"] == ["saving", "saving", "error", "saved"]
    assert out["posts"][-1]["items"] == []
    assert out["delta"] == [{"id": "F-2", "action": "approve", "staged_by": "ann"}]


# -- Closing the page sends the delta unless nothing here is unsaved


def test_closing_the_page_with_a_save_waiting_sends_it():
    out = _run(START + "T.setDeltaEntry({ id: 'F-1', action: 'approve' }); unload();")
    assert [(u["url"], u["method"], u["keepalive"]) for u in out["unloads"]] == [
        ("/api/delta", "POST", True)
    ]
    assert _ids(out["unloads"][0]["items"]) == ["F-1"]


def test_closing_the_page_while_a_save_is_out_and_another_is_asked_sends_both():
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire();                                        // save A out, unanswered
T.setDeltaEntry({ id: 'F-2', action: 'reject' });
await fire();                                        // B's timer: asked again
unload();
"""
    )
    assert [_ids(u["items"]) for u in out["unloads"]] == [["F-1", "F-2"]]


def test_closing_the_page_while_its_only_save_is_out_sends_it():
    out = _run(
        START
        + "T.setDeltaEntry({ id: 'F-1', action: 'approve' }); await fire(); unload();"
    )
    assert [_ids(u["items"]) for u in out["unloads"]] == [["F-1"]]


def test_closing_the_page_after_a_failed_save_sends_it_again():
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire(); pending.shift()[3](new Error('save failed')); await settle();
unload();
"""
    )
    assert out["statuses"][-1] == "error"
    assert [_ids(u["items"]) for u in out["unloads"]] == [["F-1"]]


def test_closing_the_page_with_everything_saved_sends_nothing():
    out = _run(
        START
        + """
T.setDeltaEntry({ id: 'F-1', action: 'approve' });
await fire(); await answerAll();                     // the server took it
unload();
"""
    )
    assert out["statuses"][-1] == "saved" and out["unloads"] == []
