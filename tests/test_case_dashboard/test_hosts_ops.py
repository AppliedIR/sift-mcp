"""The Hosts tab launches the examiner's host operations and follows them.

Rename, merge and split run in opensearch-mcp's job, a process of its own
that takes the case lock, keeps its journal in host-ops.json and writes the
decision line itself. The portal launches it with the request's examiner,
answers at once when the job ends at once (a refusal, a quick op), else 202,
and serves the journal: an unfinished operation's progress, and the
incomplete banner with Re-run, which resumes it. A stand-in job replays the
real job's journal and command line here (no cluster).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from case_dashboard import hosts as H
from sift_common import host_identity as hi

from .test_hosts_tab import _audit, _render, case, client  # noqa: F401

FAKE = """
import json, os, sys, time
from sift_common import host_identity as hi
args = sys.argv[1:]
case = args[args.index("--case-dir") + 1]
examiner = args[args.index("--examiner") + 1]
mode = os.environ.get("FAKE_R", "done")
with open(os.path.join(case, "r-calls.jsonl"), "a") as f:
    f.write(json.dumps(args) + "\\n")
if mode == "refused":
    print(json.dumps({"state": "refused", "reason": "a process holds the case lock"}))
    sys.exit(2)
if "--resume" in args:
    op_id = args[args.index("--resume") + 1]
    entry = hi.record_op(case, op_id, {"state": "done", "finished": "t2"})
    print(json.dumps({"id": op_id, **entry}))
    sys.exit(0)
op = json.loads(args[args.index("--op") + 1])
if "--expect" in args:  # R checks these under the case lock it holds
    expect = json.loads(args[args.index("--expect") + 1])
    state = hi.load(case)
    if not isinstance(expect, dict) or any(
        (state.machine_of_key(k) is None or state.machine_of_key(k).canonical != v)
        for k, v in expect.items()
    ):
        print(json.dumps({"state": "refused", "reason": "refused: changed since you opened it"}))
        sys.exit(2)
op_id = "op-fake-1"
hi.record_op(case, op_id, {"op": op, "kind": op["kind"], "canonical": op.get("canonical"),
             "before": {"keys": {"k1": 1200}, "v1": {"i|n": 34}}, "examiner": examiner,
             "state": "running", "reason": "", "started": "t0"})
if mode == "slow":
    time.sleep(float(os.environ.get("FAKE_R_SECONDS", "4")))
if mode == "incomplete":
    entry = hi.record_op(case, op_id, {"state": "incomplete", "reason": "<img src=x> 3 doc(s) still without the name"})
    print(json.dumps({"id": op_id, **entry}))
    sys.exit(1)
size = os.path.getsize(os.path.join(case, hi.OBSERVATIONS))
hi.append_decision(case, {"action": op["kind"], "examiner": examiner,
                   "args": {k: v for k, v in op.items() if k != "kind"}}, size, door="R")
entry = hi.record_op(case, op_id, {"state": "done", "relabelled": 1234, "finished": "t1"})
print(json.dumps({"id": op_id, **entry}))
"""


@pytest.fixture
def launch(tmp_path, monkeypatch):
    """The stand-in job, started with the real command line's arguments."""
    script = tmp_path / "fake_r.py"
    script.write_text(FAKE)

    def command(case_dir, examiner, op, resume, expect=None):
        real = command.__wrapped__(case_dir, examiner, op, resume, expect)
        return [sys.executable, str(script), *real[3:]]

    command.__wrapped__ = H.r_command
    monkeypatch.setattr(H, "r_command", command)
    monkeypatch.setattr(H, "_r_available", lambda: True)
    monkeypatch.setattr(H, "_launches", {})
    return command


def _calls(case):
    path = case / "r-calls.jsonl"
    return (
        [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
    )


RENAME = {"kind": "rename", "machine": "m" * 16, "canonical": "WKS99"}


def machines(case, *names) -> dict[str, str]:
    """Confirmed machines named `names`; their ids by name."""
    recs, items = [], []
    for name in names:
        u = hi.unit_key(f"evidence/{name}")
        recs += [{"kind": "unit", "unit": u, "locator": f"evidence/{name}"},
                 {"kind": "name", "unit": u, "raw": name, "evidence": "SYSTEM",
                  "origin": "artifact"}]  # fmt: skip
        items.append({"key": hi.new_machine_key(), "canonical": name,
                      "pairs": [[u, name]]})  # fmt: skip
    size = hi.append_observations(case, recs)
    hi.append_decision(
        case, {"action": "confirm", "examiner": "t", "args": {"machines": items}}, size
    )
    return {i["canonical"]: i["key"] for i in items}


def _as_r_writes(case, action, args):
    size = (case / hi.OBSERVATIONS).stat().st_size
    hi.append_decision(case, {"action": action, "examiner": "t", "args": args}, size, door="R")  # fmt: skip


@pytest.fixture
def wks(case):
    return machines(case, "WKS01", "WKS02", "WKS03")


def rename(ids, name="WKS01", to="WKS99", seen=None):
    op = {"kind": "rename", "machine": ids[name], "canonical": to}
    return {"op": op, "seen": {ids[name]: seen or name}}


def test_the_job_is_started_as_the_examiner_and_its_journal_served(
    case, client, launch, wks
):  # noqa: F811
    r = client.post("/api/hosts/ops", json=rename(wks))
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "done" and r.json()["last"]["relabelled"] == 1234
    (call,) = _calls(case)
    assert call[call.index("--examiner") + 1] == "tester"
    assert json.loads(call[call.index("--op") + 1]) == rename(wks)["op"]
    assert [(e["tool"], e["examiner"], e["origin"]) for e in _audit(case)] == [
        ("host_op", "tester", "portal"), ("host_op", "tester", "portal")]  # fmt: skip
    view = client.get("/api/hosts/ops").json()
    assert view["unfinished"] is None and view["last"]["state"] == "done"


def test_a_refusal_is_answered_and_changes_nothing(
    case, client, launch, wks, monkeypatch
):  # noqa: F811
    monkeypatch.setenv("FAKE_R", "refused")
    r = client.post("/api/hosts/ops", json=rename(wks))
    assert (
        r.status_code == 409 and r.json()["reason"] == "a process holds the case lock"
    )
    assert hi.read_ops(case)["ops"] == {}
    assert client.get("/api/hosts/ops").json()["launch"]["state"] == "refused"


def test_a_long_op_answers_202_and_shows_its_progress(
    case, client, launch, wks, monkeypatch
):  # noqa: F811
    monkeypatch.setenv("FAKE_R", "slow")
    with client:  # one event loop for the whole row, as the gateway has
        r = client.post("/api/hosts/ops", json=rename(wks))
        assert r.status_code == 202 and r.json()["state"] == "running"
        view = client.get("/api/hosts/ops").json()
        running = view["unfinished"]
        assert running["state"] == "running" and running["to_relabel"] == 1234
        assert running["examiner"] == "tester" and view["launch"]["state"] == "running"
        again = client.post("/api/hosts/ops", json=rename(wks, "WKS02"))
        assert again.status_code == 409  # one launch at a time from the portal
        deadline = time.time() + 15
        while (
            time.time() < deadline
            and client.get("/api/hosts/ops").json()["launch"]["state"] == "running"
        ):
            time.sleep(0.2)
        view = client.get("/api/hosts/ops").json()
    assert view["launch"]["state"] == "done" and view["unfinished"] is None
    assert view["last"]["relabelled"] == 1234
    assert _audit(case)[-1]["result_summary"] == {"value": "done: op-fake-1"}


def test_an_incomplete_op_shows_the_banner_and_re_run_resumes_it(
    case, client, launch, wks, monkeypatch
):  # noqa: F811
    monkeypatch.setenv("FAKE_R", "incomplete")
    r = client.post("/api/hosts/ops", json=rename(wks))
    assert r.status_code == 200 and r.json()["state"] == "incomplete"
    view = client.get("/api/hosts/ops").json()
    assert view["unfinished"]["state"] == "incomplete"
    monkeypatch.setenv("FAKE_R", "done")
    r = client.post("/api/hosts/ops", json={"resume": "op-fake-1"})
    assert r.status_code == 200 and r.json()["state"] == "done"
    assert _calls(case)[-1][-2:] == ["--resume", "op-fake-1"]
    assert client.get("/api/hosts/ops").json()["unfinished"] is None


def test_without_an_examiner_nothing_is_started(case, client, launch, wks, monkeypatch):  # noqa: F811
    monkeypatch.delenv("VHIR_EXAMINER")
    assert client.post("/api/hosts/ops", json=rename(wks)).status_code == 401
    assert _calls(case) == [] and _audit(case) == []


@pytest.mark.parametrize(
    "body",
    [{}, {"op": RENAME, "resume": "op-1", "seen": {}}, {"op": {"kind": "delete"}, "seen": {}},
     {"resume": ""}, {"op": "rename", "seen": {}}, {"op": RENAME}],
)  # fmt: skip
def test_a_malformed_request_starts_nothing(case, client, launch, body):  # noqa: F811
    assert client.post("/api/hosts/ops", json=body).status_code == 400
    assert _calls(case) == []


def test_without_opensearch_mcp_it_says_so(case, client, wks, monkeypatch):  # noqa: F811
    monkeypatch.setattr(H, "_r_available", lambda: False)
    r = client.post("/api/hosts/ops", json=rename(wks))
    assert r.status_code == 503 and "opensearch-mcp" in r.json()["error"]


class TestAnOpActsOnTheMachineTheExaminerSaw:
    """The request carries each machine's name as the page showed it; the
    job is given them as `expect` and checks them under the case lock it
    holds while it works, so a change made any time before (by another tab,
    a CLI job, a host decision) refuses it, with nothing written."""

    REFUSED = "refused: changed since you opened it"

    def test_a_form_opened_before_a_split_gave_its_id_away_is_refused(
        self, case, client, launch, wks
    ):  # noqa: F811
        a, b = wks["WKS01"], wks["WKS02"]
        _as_r_writes(case, "merge", {"into": a, "from": [b]})
        page = client.get("/api/hosts?q=WKS01").json()
        (seen,) = [m for m in page["machines"] if m["id"] == a]
        assert seen["keys"] == [a, b]  # the detail the examiner opened
        # the split takes a's own key out: that id is now the split-out machine
        _as_r_writes(
            case, "split", {"machine": a, "keys": [a], "canonical": "SPLITOUT"}
        )
        assert hi.load(case).machine_of_key(a).canonical == "SPLITOUT"
        r = client.post(
            "/api/hosts/ops", json=rename(wks, to="WKS77", seen=seen["canonical"])
        )
        assert r.status_code == 409, r.text
        assert r.json()["reason"] == self.REFUSED
        (call,) = _calls(case)
        assert json.loads(call[call.index("--expect") + 1]) == {a: "WKS01"}
        assert hi.read_ops(case)["ops"] == {}  # refused before its journal entry
        # the same request with what the page shows now goes ahead
        fresh = rename(wks, to="WKS77", seen="SPLITOUT")
        assert client.post("/api/hosts/ops", json=fresh).status_code == 200

    def test_a_second_tab_s_request_after_the_first_tab_renamed_is_refused(
        self, case, client, launch, wks
    ):  # noqa: F811
        tab1 = client.get("/api/hosts").json()
        tab2 = client.get("/api/hosts").json()
        assert tab1["machines"] == tab2["machines"]
        first = client.post("/api/hosts/ops", json=rename(wks, to="WKS50"))
        assert first.status_code == 200, first.text
        assert hi.load(case).machine_of_key(wks["WKS01"]).canonical == "WKS50"
        stale = {"op": {"kind": "split", "machine": wks["WKS01"], "keys": ["x"],
                        "canonical": "OTHER"}, "seen": {wks["WKS01"]: "WKS01"}}  # fmt: skip
        r = client.post("/api/hosts/ops", json=stale)
        assert r.status_code == 409 and r.json()["reason"] == self.REFUSED
        assert hi.load(case).machine_of_key(wks["WKS01"]).canonical == "WKS50"

    def test_a_merge_names_both_machines_as_seen(self, case, client, launch, wks):  # noqa: F811
        op = {"kind": "merge", "into": wks["WKS01"], "from": [wks["WKS02"]]}
        stale = {"op": op, "seen": {wks["WKS01"]: "WKS01", wks["WKS02"]: "OLD"}}
        assert client.post("/api/hosts/ops", json=stale).status_code == 409
        call = _calls(case)[-1]
        assert json.loads(call[call.index("--expect") + 1]) == {
            wks["WKS01"]: "WKS01", wks["WKS02"]: "OLD"}  # fmt: skip
        ok = {"op": op, "seen": {wks["WKS01"]: "WKS01", wks["WKS02"]: "WKS02"}}
        assert client.post("/api/hosts/ops", json=ok).status_code == 200

    def test_a_change_after_the_gateway_read_the_case_is_caught_by_the_job(
        self, case, client, launch, wks, monkeypatch
    ):  # noqa: F811
        """A race: the gateway resolves the request, then a split
        moves the key before the job takes the lock. The job's own check
        refuses it."""
        real = H.r_command

        def split_first(*a, **k):
            _as_r_writes(case, "merge", {"into": wks["WKS01"], "from": [wks["WKS02"]]})
            _as_r_writes(case, "split", {"machine": wks["WKS01"], "keys": [wks["WKS01"]],
                                         "canonical": "SPLITOUT"})  # fmt: skip
            return real(*a, **k)

        monkeypatch.setattr(H, "r_command", split_first)
        r = client.post("/api/hosts/ops", json=rename(wks, to="WKS77"))
        assert r.status_code == 409 and r.json()["reason"] == self.REFUSED
        assert hi.load(case).machine_of_key(wks["WKS01"]).canonical == "SPLITOUT"
        assert hi.read_ops(case)["ops"] == {}

    def test_a_host_decision_while_an_operation_runs_is_refused(
        self, case, client, wks
    ):  # noqa: F811
        hi.record_op(case, "op-x", {"kind": "rename", "state": "running",
                                    "examiner": "tester", "started": "t0"})  # fmt: skip
        page = client.get("/api/hosts").json()
        (m,) = [x for x in page["machines"] if x["id"] == wks["WKS02"]]
        group = {"machine": m["id"], "canonical": m["canonical"]}  # as confirm_machine
        r = client.post(
            "/api/hosts/decisions",
            json={"action": "confirm", "seen_offset": page["obs_offset"],
                  "args": {"groups": [group]}},
        )  # fmt: skip
        assert (
            r.status_code == 409 and "host rename/merge is running" in r.json()["error"]
        )

    def test_a_list_upload_while_an_operation_is_unfinished_writes_nothing(
        self, case, client, wks
    ):  # noqa: F811
        """The portal's `list` action reaches the host list's binds; the
        shared guard refuses it, and the tab shows the message."""
        hi.record_op(case, "op-x", {"kind": "rename", "state": "incomplete",
                                    "examiner": "tester", "started": "t0"})  # fmt: skip
        before = (
            (case / hi.OBSERVATIONS).read_bytes(),
            (case / hi.DECISIONS).read_bytes(),
        )
        page = client.get("/api/hosts").json()
        r = client.post(
            "/api/hosts/decisions",
            json={"action": "list", "seen_offset": page["obs_offset"],
                  "args": {"text": "WKS01\nFIN-1\n"}},
        )  # fmt: skip
        assert r.status_code == 409
        assert (
            r.json()["error"]
            == "a host rename/merge is running; try again when it ends"
        )
        assert (
            (case / hi.OBSERVATIONS).read_bytes(),
            (case / hi.DECISIONS).read_bytes(),
        ) == before


class TestMergeAcrossPages:
    def test_a_machine_on_another_page_is_merged_by_its_typed_name(
        self, case, client, launch, wks
    ):  # noqa: F811
        page = client.get("/api/hosts?per_page=1").json()
        assert page["total"] == 3 and [m["canonical"] for m in page["machines"]] == [
            "WKS01"
        ]
        body = {"op": {"kind": "merge", "into": wks["WKS01"], "from_name": "wks03"},
                "seen": {wks["WKS01"]: "WKS01"}}  # fmt: skip
        r = client.post("/api/hosts/ops", json=body)
        assert r.status_code == 200, r.text
        (call,) = _calls(case)
        sent = json.loads(call[call.index("--op") + 1])
        assert sent == {"kind": "merge", "into": wks["WKS01"], "from": [wks["WKS03"]]}
        assert json.loads(call[call.index("--expect") + 1]) == {
            wks["WKS03"]: "WKS03",
            wks["WKS01"]: "WKS01",
        }  # the name resolved, as found
        assert hi.load(case).machine_of_key(wks["WKS03"]).canonical == "WKS01"

    def test_a_name_no_machine_has_starts_nothing(self, case, client, launch, wks):  # noqa: F811
        body = {"op": {"kind": "merge", "into": wks["WKS01"], "from_name": "NOPE"},
                "seen": {wks["WKS01"]: "WKS01"}}  # fmt: skip
        r = client.post("/api/hosts/ops", json=body)
        assert (
            r.status_code == 400 and "no machine is named 'NOPE'" in r.json()["error"]
        )
        assert _calls(case) == []


def test_the_job_s_command_line():
    cmd = H.r_command(Path("/c"), "tester", RENAME, None)
    assert cmd[1:3] == ["-m", "opensearch_mcp.host_ops"]
    assert cmd[3:7] == ["--case-dir", "/c", "--examiner", "tester"]
    assert json.loads(cmd[cmd.index("--op") + 1]) == RENAME
    assert H.r_command(Path("/c"), "tester", None, "op-1")[-2:] == ["--resume", "op-1"]
    cmd = H.r_command(Path("/c"), "tester", RENAME, None, {"m1": "WKS01"})
    assert json.loads(cmd[cmd.index("--expect") + 1]) == {"m1": "WKS01"}
    assert "--expect" not in H.r_command(Path("/c"), "t", None, "op-1", {"m1": "x"})


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
class TestTheTabShowsTheOperation:
    def test_an_incomplete_op_shows_the_banner_with_re_run(self):
        view = {"unfinished": {"id": "op-1", "state": "incomplete", "kind": "merge",
                               "canonical": "WKS01", "reason": "<img src=x onerror=alert(1)>"},
                "last": None, "launch": None}  # fmt: skip
        out = _render("hostOpsHtml(data)", view)
        assert (
            "Host rename incomplete" in out
            and 'data-host-act="op_resume" data-op="op-1"' in out
        )
        assert "<img" not in out and "&lt;img src=x onerror=alert(1)&gt;" in out

    def test_a_running_op_shows_its_progress(self):
        view = {"unfinished": {"id": "op-1", "state": "running", "kind": "rename",
                               "canonical": "WKS99", "to_relabel": 1234, "started": "t0",
                               "examiner": "tester"},
                "launch": {"state": "running"}, "last": None}  # fmt: skip
        out = _render("hostOpsHtml(data)", view)
        assert "1234 indexed records to relabel" in out and "op_resume" not in out

    def test_a_running_op_this_gateway_isn_t_running_can_be_resumed(self):
        view = {"unfinished": {"id": "op-1", "state": "running", "kind": "rename"},
                "launch": None, "last": None}  # fmt: skip
        assert "Resume if it stopped" in _render("hostOpsHtml(data)", view)

    def test_corrections_offer_rename_merge_and_split(self):
        m = {"id": "m1", "canonical": "WKS01", "keys": ["k1", "k2"], "history": []}
        out = _render("hostCorrectionsHtml(data)", m)
        for act in ("op_rename", "op_merge", "op_split"):
            assert f'data-host-act="{act}"' in out
        assert 'data-op-key="k1"' in out and " disabled" not in out
        assert 'data-seen="WKS01"' in out  # the name it was opened with
        # the merge picker takes any machine's name, not only this page's
        assert 'data-op-field="merge_name" list="hostMergeNames"' in out
        assert "<select" not in out


def _run_js(names, body: str) -> str:
    from .test_hosts_tab import PORTAL, _js_function

    def source(name):  # an async function keeps its keyword
        text = _js_function(name)
        return "async " + text if f"async function {name}(" in PORTAL else text

    return subprocess.run(
        ["node", "-e", "".join(source(n) for n in names) + body],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip


_PAGE = """
const panes = {hostDetail: {innerHTML: 'WKS01 detail'}, hostsOps: {innerHTML: ''}};
const document = {getElementById: (id) => panes[id]};
const calls = [];
function renderHosts() { calls.push('renderHosts'); }
function showToast(m) { calls.push('toast ' + m); }
function hostOpsHtml() { return ''; }
function hostDecisionsFixed() {}
function apiHeaders() { return {}; }
const API_BASE = '';
var hostsView = {ops: null, wasRunning: false};
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
class TestTheTabSendsWhatItShowedAndClosesTheDetail:
    def test_each_correction_carries_the_name_the_page_showed(self):
        body = """
        const fields = {rename_canonical: 'NEW', merge_name: 'wks03', split_canonical: 'S'};
        const box = {
          getAttribute: (a) => ({'data-machine': 'm1', 'data-seen': 'WKS01'})[a],
          querySelector: (q) => ({value: fields[q.match(/"(.*)"/)[1]]}),
          querySelectorAll: () => [{checked: true, getAttribute: () => 'k2'},
                                   {checked: false, getAttribute: () => 'k1'}],
        };
        const el = {closest: () => box};
        process.stdout.write(JSON.stringify(['op_rename', 'op_merge', 'op_split']
          .map((a) => hostOpFrom(el, a))));
        """
        rename, merge, split = json.loads(_run_js(["hostOpFrom"], body))
        seen = {"m1": "WKS01"}
        assert rename == {"op": {"kind": "rename", "machine": "m1", "canonical": "NEW"},
                          "seen": seen}  # fmt: skip
        assert merge == {"op": {"kind": "merge", "into": "m1", "from_name": "wks03"},
                         "seen": seen}  # fmt: skip
        assert split == {"op": {"kind": "split", "machine": "m1", "keys": ["k2"],
                                "canonical": "S"}, "seen": seen}  # fmt: skip

    @pytest.mark.parametrize(
        "status,launch,closed",
        [(200, "done", True), (409, "refused", True), (400, None, False),
         (202, "running", False),  # still running: the poll closes it when it ends
         (202, "done", True)],  # ended before the first poll
    )  # fmt: skip
    def test_an_op_that_answers_at_once_closes_the_detail(self, status, launch, closed):
        served = json.dumps(
            {"unfinished": None, "launch": launch and {"state": launch}}
        )
        body = (
            _PAGE
            + f"""
        global.setTimeout = () => 0; global.clearTimeout = () => 0;
        async function fetch() {{
          return {{status: {status}, ok: {str(status < 300).lower()},
                   json: async () => ({{state: 'done'}})}};
        }}
        async function apiFetch() {{ return {served}; }}
        hostOp({{op: {{}}}}).then(() => process.stdout.write(
          JSON.stringify([panes.hostDetail.innerHTML, calls])));
        """
        )
        detail, calls = json.loads(
            _run_js(["hostOpEnded", "hostOp", "renderHostOps"], body)
        )
        assert (detail != "WKS01 detail") == closed
        assert ("renderHosts" in calls) == closed
        if closed:
            assert "open a machine again" in detail

    def test_a_running_op_that_ends_closes_the_detail(self):
        body = (
            _PAGE
            + """
        let answers = [{unfinished: {state: 'running', id: 'op-1'}}, {unfinished: null}];
        async function apiFetch() { return answers.shift(); }
        global.setTimeout = () => 0; global.clearTimeout = () => 0;
        (async () => {
          await renderHostOps();
          const during = panes.hostDetail.innerHTML;
          await renderHostOps();  // the poll after it ended
          process.stdout.write(JSON.stringify([during, panes.hostDetail.innerHTML, calls]));
        })();
        """
        )
        during, after, calls = json.loads(
            _run_js(["hostOpEnded", "renderHostOps"], body)
        )
        assert during == "WKS01 detail"
        assert "open a machine again" in after and calls == ["renderHosts"]


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
class TestHostDecisionsWaitWhileAnOperationIsUnfinished:
    SCRIPT = """
    const made = {};
    function control(act) { return made[act] = made[act] || {disabled: false, title: ''}; }
    const panel = {querySelectorAll: (q) => [control(q.match(/"(.*)"/)[1])]};
    const fields = {hostListText: {disabled: false}, hostListFile: {disabled: false}};
    const document = {getElementById: (id) => id === 'hostsPanel' ? panel : fields[id]};
    var hostsView = {ops: OPS};
    hostDecisionsFixed();
    process.stdout.write(JSON.stringify({made, fields}));
    """

    def _run(self, ops):
        body = "var HOST_DECISION_ACTS = " + json.dumps(
            ["list", "start_now", "cancel_run", "confirm_all", "confirm", "not_a_host",
             "confirm_machine"]
        ) + ";\n" + self.SCRIPT.replace("OPS", json.dumps(ops))  # fmt: skip
        return json.loads(_run_js(["hostOpUnfinished", "hostDecisionsFixed"], body))

    @pytest.mark.parametrize("state", ["running", "incomplete"])
    def test_every_decision_control_is_disabled(self, state):
        out = self._run({"unfinished": {"state": state}})
        assert out["made"] and all(c["disabled"] for c in out["made"].values())
        assert set(out["made"]) == {"list", "start_now", "cancel_run", "confirm_all",
                                    "confirm", "not_a_host", "confirm_machine"}  # fmt: skip
        assert out["fields"]["hostListText"]["disabled"] is True
        assert "unfinished" in out["made"]["list"]["title"]

    def test_with_none_unfinished_they_are_enabled(self):
        out = self._run({"unfinished": None})
        assert not any(c["disabled"] for c in out["made"].values())
        assert out["fields"]["hostListFile"]["disabled"] is False

    def test_reading_the_operations_sets_the_controls(self):
        """The table is drawn before the operations are read: reading them
        (each poll included) sets the controls again."""
        body = (
            _PAGE.replace("function hostDecisionsFixed() {}\n", "")
            + """
        function hostDecisionsFixed() { calls.push('fixed ' + !!hostsView.ops.unfinished); }
        global.setTimeout = () => 0; global.clearTimeout = () => 0;
        let answers = [{unfinished: {state: 'incomplete', id: 'op-1'}}, {unfinished: null}];
        async function apiFetch() { return answers.shift(); }
        (async () => { await renderHostOps(); await renderHostOps();
          process.stdout.write(JSON.stringify(calls)); })();
        """
        )
        calls = json.loads(_run_js(["renderHostOps"], body))
        assert calls == ["fixed true", "fixed false"]

    def test_the_page_lists_each_decision_act_it_disables(self):
        from .test_hosts_tab import PORTAL

        listed = re.search(r"var HOST_DECISION_ACTS = (\[[^\]]*\]);", PORTAL).group(1)
        acts = set(json.loads(listed.replace("'", '"')))
        drawn = set(re.findall(r'data-host-act="(\w+)"', PORTAL))
        corrections = {"page", "ppage", "detail", "op_resume", "op_rename", "op_merge",
                       "op_split", "draft_dismiss"}  # fmt: skip
        assert drawn - corrections == acts  # every decision control the tab draws


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
class TestEveryJournalFieldIsText:
    """host-ops.json is case data another process can write: every field the
    banner shows renders as text."""

    EVIL = "<img src=x onerror=alert(1)>"

    def _clean(self, out):
        assert "<img" not in out, out
        assert "&lt;img src=x onerror=alert(1)&gt;" in out

    def _op(self, state):
        e = self.EVIL
        return {"id": e, "state": state, "kind": e, "canonical": e, "reason": e,
                "started": e, "examiner": e, "to_relabel": e, "relabelled": e}  # fmt: skip

    @pytest.mark.parametrize("state", ["incomplete", "running"])
    def test_an_unfinished_op(self, state):
        out = _render("hostOpsHtml(data)", {"unfinished": self._op(state), "last": None,
                                             "launch": None})  # fmt: skip
        self._clean(out)

    def test_the_last_op_and_launch(self):
        out = _render("hostOpsHtml(data)", {"unfinished": None, "last": self._op("done"),
                      "launch": {"state": "refused", "result": {"reason": self.EVIL}}})  # fmt: skip
        self._clean(out)
        assert (
            out.count("&lt;img") >= 4
        )  # id, kind, name and relabelled, plus the reason
