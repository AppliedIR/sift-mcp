"""The Hosts tab's banner says why the last host request from the page failed,
and only that: a success clears it, a later refusal replaces it, and an older
operation's refusal never outlives the requests after it. Names are synthetic."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from .test_hosts_tab import _DOCUMENT, PORTAL, _js_function

pytestmark = pytest.mark.skipif(
    not shutil.which("node"), reason="node is not installed"
)

_NAMES = ["safeStr", "escapeHtml", "escapeAttr", "hostOpsHtml", "renderHostOps", "hostOp",
          "hostDecide", "hostOpEnded"]  # fmt: skip

_PAGE = """
const panes = {hostsOps: {innerHTML: ''}, hostDetail: {innerHTML: ''}};
document.getElementById = (id) => panes[id];
const API_BASE = '';
function apiHeaders() { return {}; }
function showToast() {}
function hostDecisionsFixed() {}
function renderHosts() { return renderHostOps(); }
global.setTimeout = () => 0; global.clearTimeout = () => 0;
var hostsView = {data: {obs_offset: 0}, ops: null, wasRunning: false, failed: '', launched: false};
let server = {unfinished: null, last: null, launch: null};
let answer = null;  // what the next POST answers
async function fetch() {
  if (answer.net) throw new Error(answer.net);
  return {status: answer.status, ok: answer.status < 300, json: async () => answer.body};
}
async function apiFetch(path) {
  if (path === '/api/hosts/ops') return JSON.parse(JSON.stringify(server));
  if (answer.status >= 300) throw new Error(answer.body.error);
  return answer.body;
}
const settle = () => new Promise((r) => setImmediate(r));
const shown = [];
async function step(s) {
  const [kind, x] = s;
  if (kind === 'op') {
    answer = x;
    if (x.status === 202) server = {...server, unfinished: {state: 'running', id: 'op-1'},
                                    launch: {state: 'running'}};
    else if (x.body && x.body.state) server = {...server, launch: {state: x.body.state, result: x.body}};
    await hostOp({op: {}});
  } else if (kind === 'decide') {
    answer = x;
    await hostDecide('confirm', {});
  } else if (kind === 'serve') {
    server = x;
    await renderHostOps();
  } else if (kind === 'end') {  // the operation ends; the next poll reads it
    server = {...server, unfinished: null, launch: x && {state: x.state, result: x}};
    await renderHostOps();
  }
  await settle(); await settle();
  const m = panes.hostsOps.innerHTML.match(/The last request failed: (.*?)<\\/div>/g) || [];
  shown.push(m.map((t) => t.slice(25, -6)));
}
"""

REFUSED_A = ["op", {"status": 409, "body": {"state": "refused", "reason": "runs are writing into the case: 9b735f0a"}}]  # fmt: skip
REFUSED_B = ["op", {"status": 409, "body": {"state": "refused", "reason": "the machine changed"}}]  # fmt: skip
DONE = ["op", {"status": 200, "body": {"state": "done", "id": "op-2"}}]
RUNNING = ["op", {"status": 202, "body": {"state": "running"}}]
BAD = ["op", {"status": 400, "body": {"error": "no such machine"}}]
NET = ["op", {"net": "Failed to fetch"}]
DEC_REFUSED = ["decide", {"status": 409, "body": {"error": "the name joins no machine"}}]  # fmt: skip
DEC_OK = ["decide", {"status": 200, "body": {"summary": "Confirmed 1 group"}}]
A, B = "runs are writing into the case: 9b735f0a", "the machine changed"


def _run(steps) -> list:
    script = (
        _DOCUMENT
        + "".join(
            ("async " if f"async function {n}(" in PORTAL else "") + _js_function(n)
            for n in _NAMES
        )
        + _PAGE
        + f"(async () => {{ for (const s of {json.dumps(steps)}) await step(s);"
        + " process.stdout.write(JSON.stringify(shown)); })();"
    )
    out = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout
    return json.loads(out)


@pytest.mark.parametrize(
    "steps,banners",
    [
        ([REFUSED_A, REFUSED_B], [[A], [B]]),  # B's reason only
        ([REFUSED_A, DONE], [[A], []]),  # a success clears it
        ([DONE], [[]]),  # twin: no earlier banner, none
        ([REFUSED_A, DEC_REFUSED], [[A], ["the name joins no machine"]]),
        ([REFUSED_A, DEC_OK], [[A], []]),
        ([DEC_REFUSED, DEC_OK], [["the name joins no machine"], []]),
        ([REFUSED_A, BAD], [[A], ["no such machine"]]),
        ([REFUSED_A, NET], [[A], ["Failed to fetch"]]),
        # launched, then answered by the poll: its own answer
        ([REFUSED_A, RUNNING, ["end", {"state": "refused", "reason": "busy"}]],
         [[A], [], ["busy"]]),
        ([REFUSED_A, RUNNING, ["end", {"state": "failed", "reason": None}]],
         [[A], [], ["failed"]]),
        ([REFUSED_A, RUNNING, ["end", {"state": "done"}]], [[A], [], []]),
        ([RUNNING, ["end", None]], [[], []]),
    ],
)  # fmt: skip
def test_the_banner_shows_the_last_requests_refusal_only(steps, banners):
    assert _run(steps) == banners


def test_an_operation_this_page_did_not_launch_leaves_the_banner_alone():
    # the gateway's last launch was refused before this page loaded, and an
    # operation started elsewhere runs and ends: neither is this page's request
    elsewhere = [
        "serve",
        {
            "unfinished": {"state": "running", "id": "op-9"},
            "last": None,
            "launch": {
                "state": "refused",
                "result": {"state": "refused", "reason": "older"},
            },
        },
    ]
    ended = ["end", {"state": "refused", "reason": "older"}]
    assert _run([elsewhere, ended]) == [[], []]
    assert _run([REFUSED_A, elsewhere, ended]) == [[A], [A], [A]]


def test_the_reason_is_escaped():
    evil = "<img src=x onerror=alert(1)>"
    out = _run([["op", {"status": 409, "body": {"state": "refused", "reason": evil}}]])
    assert out == [["&lt;img src=x onerror=alert(1)&gt;"]]
