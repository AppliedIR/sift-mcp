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
import shutil
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
entry = hi.record_op(case, op_id, {"state": "done", "relabelled": 1234, "finished": "t1"})
print(json.dumps({"id": op_id, **entry}))
"""


@pytest.fixture
def launch(tmp_path, monkeypatch):
    """The stand-in job, started with the real command line's arguments."""
    script = tmp_path / "fake_r.py"
    script.write_text(FAKE)

    def command(case_dir, examiner, op, resume):
        real = command.__wrapped__(case_dir, examiner, op, resume)
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


def test_the_job_is_started_as_the_examiner_and_its_journal_served(
    case, client, launch
):  # noqa: F811
    r = client.post("/api/hosts/ops", json={"op": RENAME})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "done" and r.json()["last"]["relabelled"] == 1234
    (call,) = _calls(case)
    assert call[call.index("--examiner") + 1] == "tester"
    assert json.loads(call[call.index("--op") + 1]) == RENAME
    assert [(e["tool"], e["examiner"], e["origin"]) for e in _audit(case)] == [
        ("host_op", "tester", "portal"), ("host_op", "tester", "portal")]  # fmt: skip
    view = client.get("/api/hosts/ops").json()
    assert view["unfinished"] is None and view["last"]["state"] == "done"


def test_a_refusal_is_answered_and_changes_nothing(case, client, launch, monkeypatch):  # noqa: F811
    monkeypatch.setenv("FAKE_R", "refused")
    r = client.post("/api/hosts/ops", json={"op": RENAME})
    assert (
        r.status_code == 409 and r.json()["reason"] == "a process holds the case lock"
    )
    assert hi.read_ops(case)["ops"] == {}
    assert client.get("/api/hosts/ops").json()["launch"]["state"] == "refused"


def test_a_long_op_answers_202_and_shows_its_progress(
    case, client, launch, monkeypatch
):  # noqa: F811
    monkeypatch.setenv("FAKE_R", "slow")
    with client:  # one event loop for the whole row, as the gateway has
        r = client.post("/api/hosts/ops", json={"op": RENAME})
        assert r.status_code == 202 and r.json()["state"] == "running"
        view = client.get("/api/hosts/ops").json()
        running = view["unfinished"]
        assert running["state"] == "running" and running["to_relabel"] == 1234
        assert running["examiner"] == "tester" and view["launch"]["state"] == "running"
        again = client.post("/api/hosts/ops", json={"op": RENAME})
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
    case, client, launch, monkeypatch
):  # noqa: F811
    monkeypatch.setenv("FAKE_R", "incomplete")
    r = client.post("/api/hosts/ops", json={"op": RENAME})
    assert r.status_code == 200 and r.json()["state"] == "incomplete"
    view = client.get("/api/hosts/ops").json()
    assert view["unfinished"]["state"] == "incomplete"
    monkeypatch.setenv("FAKE_R", "done")
    r = client.post("/api/hosts/ops", json={"resume": "op-fake-1"})
    assert r.status_code == 200 and r.json()["state"] == "done"
    assert _calls(case)[-1][-2:] == ["--resume", "op-fake-1"]
    assert client.get("/api/hosts/ops").json()["unfinished"] is None


def test_without_an_examiner_nothing_is_started(case, client, launch, monkeypatch):  # noqa: F811
    monkeypatch.delenv("VHIR_EXAMINER")
    assert client.post("/api/hosts/ops", json={"op": RENAME}).status_code == 401
    assert _calls(case) == [] and _audit(case) == []


@pytest.mark.parametrize(
    "body",
    [{}, {"op": RENAME, "resume": "op-1"}, {"op": {"kind": "delete"}}, {"resume": ""},
     {"op": "rename"}],
)  # fmt: skip
def test_a_malformed_request_starts_nothing(case, client, launch, body):  # noqa: F811
    assert client.post("/api/hosts/ops", json=body).status_code == 400
    assert _calls(case) == []


def test_without_opensearch_mcp_it_says_so(case, client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(H, "_r_available", lambda: False)
    r = client.post("/api/hosts/ops", json={"op": RENAME})
    assert r.status_code == 503 and "opensearch-mcp" in r.json()["error"]


def test_the_job_s_command_line():
    cmd = H.r_command(Path("/c"), "tester", RENAME, None)
    assert cmd[1:3] == ["-m", "opensearch_mcp.host_ops"]
    assert cmd[3:7] == ["--case-dir", "/c", "--examiner", "tester"]
    assert json.loads(cmd[cmd.index("--op") + 1]) == RENAME
    assert H.r_command(Path("/c"), "tester", None, "op-1")[-2:] == ["--resume", "op-1"]


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
        for act in ("op_rename", "op_split"):
            assert f'data-host-act="{act}"' in out
        assert 'data-op-key="k1"' in out and " disabled" not in out


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
