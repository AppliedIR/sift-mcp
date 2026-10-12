"""The portal (in the gateway, so every backend's loop) refuses a case file it
can't read safely with a 409 naming it, never hangs, never says "0 evidence",
and answers the next request. Each case runs in a forked child with an alarm
and a capped address space."""

from __future__ import annotations

import json
import os
import pickle
import resource
import signal
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")


def _child(fn, secs=8):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            with open("/proc/self/statm") as f:
                size = int(f.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
            resource.setrlimit(resource.RLIMIT_AS, (size + (1 << 30),) * 2)
            signal.alarm(secs)
            out = ("ok", fn())
        except BaseException as e:  # noqa: BLE001
            out = ("raised", f"{type(e).__name__}: {e}")
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    data = b""
    while chunk := os.read(r, 65536):
        data += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return pickle.loads(data) if data else ("killed",)


@pytest.fixture
def cases(tmp_path, monkeypatch):
    # the portal's single-user examiner, for the POST routes
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    out = {}
    for name in ("bad", "good"):
        d = tmp_path / name
        (d / "audit").mkdir(parents=True)
        (d / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\n")
        for f in ("findings.json", "timeline.json", "todos.json", "iocs.json"):
            (d / f).write_text("[]")
        (d / "evidence.json").write_text(json.dumps({"files": []}))
        (d / "pending-reviews.json").write_text('{"items": []}')
        for f in ("host-observations.jsonl", "host-decisions.jsonl"):
            (d / f).write_text("")
        out[name] = d
    return out


def _get(cases, monkeypatch, route, method="GET", body=None):
    from case_dashboard import routes
    from starlette.testclient import TestClient

    def run():
        with TestClient(routes.create_dashboard_app()) as c:
            monkeypatch.setenv("VHIR_CASE_DIR", str(cases["bad"]))
            r1 = (
                c.request(method, route, json=body)
                if body is not None
                else c.get(route)
            )
            monkeypatch.setenv("VHIR_CASE_DIR", str(cases["good"]))
            return r1.status_code, r1.json(), c.get("/api/todos").status_code

    return _child(run)


@pytest.mark.parametrize("name,route", [
    ("evidence.json", "/api/evidence"), ("findings.json", "/api/summary"),
    ("CASE.yaml", "/api/case"), ("host-decisions.jsonl", "/api/hosts"),
    ("audit/wintools-mcp.jsonl", "/api/summary")])  # fmt: skip
def test_a_fifo_is_a_409_naming_it_and_the_loop_answers_next(
    cases, monkeypatch, name, route
):
    p = cases["bad"] / name
    p.unlink(missing_ok=True)
    os.mkfifo(p)
    kind, (code, body, next_code) = _get(cases, monkeypatch, route)
    assert (kind, code, next_code) == ("ok", 409, 200)
    assert p.name in body["error"] and "isn't a regular file" in body["error"]


def test_host_ops_fifo_is_named_by_get_ops_and_never_blocks(cases, monkeypatch):
    os.mkfifo(cases["bad"] / "host-ops.json")
    kind, (code, body, next_code) = _get(cases, monkeypatch, "/api/hosts/ops")
    assert (kind, code, next_code) == ("ok", 500, 200)  # get_ops' own answer
    assert body["error"].startswith("host-ops.json: unreadable: ")


@pytest.mark.parametrize("size", [(16 << 20) + 64, 64 << 20])
def test_an_over_cap_document_is_a_409_never_0_evidence(cases, monkeypatch, size):
    """Sparse: refused from its size, before any read or parse."""
    with open(cases["bad"] / "evidence.json", "wb") as f:
        f.truncate(size)
    kind, (code, body, _) = _get(cases, monkeypatch, "/api/evidence")
    assert (kind, code) == ("ok", 409)
    assert body["error"] == (f"{cases['bad'] / 'evidence.json'} is larger than 16 MiB, "
                             "so it wasn't read. It holds the case's evidence records: "
                             "keep a copy of it before you move it out of the case, then "
                             "try again.")  # fmt: skip


def test_a_folder_says_so(cases, monkeypatch):
    p = cases["bad"] / "findings.json"
    p.unlink()
    p.mkdir()
    kind, (code, body, _) = _get(cases, monkeypatch, "/api/summary")
    assert (kind, code) == ("ok", 409)
    assert (
        body["error"]
        == f"{p} is a folder, not a file. Put the case's own file back, then try again."
    )


def test_a_fifo_swapped_in_after_the_host_load_is_refused_by_the_lock(
    cases, monkeypatch
):
    from sift_common import host_identity as hi

    real = hi.load

    def load_then_swap(case_dir):
        state = real(case_dir)
        p = cases["bad"] / hi.OBSERVATIONS
        if not p.is_fifo():
            p.unlink()
            os.mkfifo(p)
        return state

    monkeypatch.setattr(hi, "load", load_then_swap)
    kind, (code, body, next_code) = _get(cases, monkeypatch, "/api/hosts/decisions", "POST",
                                         {"action": "list", "args": {"text": "wkstn05\n"}})  # fmt: skip
    assert (kind, code, next_code) == ("ok", 409, 200)
    assert (
        body["error"]
        == "host-observations.jsonl: not a regular file with a single link; refused"
    )


def test_a_route_that_answers_a_host_log_error_itself_is_unchanged(cases, monkeypatch):
    kind, (code, body, _) = _get(cases, monkeypatch, "/api/hosts/decisions", "POST",
                                 {"action": "cancel_run", "args": {"run_id": "nope"}})  # fmt: skip
    assert (kind, code, body) == (
        "ok",
        409,
        {"error": "no run 'nope' is waiting for host confirmation"},
    )


GETS = ["/api/evidence", "/api/audit/F-x-001", "/api/delta", "/api/case", "/api/todos",
        "/api/summary", "/api/hosts", "/api/hosts/runs", "/api/hosts/0123456789abcdef",
        "/api/hosts/ops"]  # fmt: skip


@pytest.mark.parametrize("route", GETS)
def test_a_route_held_by_a_slow_read_never_holds_the_loop(cases, monkeypatch, route):
    """The route's first read (the case it serves) is held; another route on
    the same loop, sent once the read is held, answers within 1 s."""
    import threading
    import time

    def run():
        from case_dashboard import routes
        from starlette.testclient import TestClient

        real, held, release, calls = (
            routes._resolve_case_dir,
            threading.Event(),
            threading.Event(),
            [],
        )

        def slow():
            calls.append(1)
            if len(calls) == 1:  # the target's
                held.set()
                release.wait(6)
            return real()

        monkeypatch.setattr(routes, "_resolve_case_dir", slow)
        monkeypatch.setenv("VHIR_CASE_DIR", str(cases["good"]))
        got = {}
        with TestClient(routes.create_dashboard_app()) as c:
            target = threading.Thread(
                target=lambda: got.setdefault("target", c.get(route))
            )
            target.start()
            held.wait(5)
            other = threading.Thread(
                target=lambda: got.setdefault("other", c.get("/api/todos"))
            )
            t0 = time.monotonic()
            other.start()
            other.join(1.0)
            answered, waited = "other" in got, time.monotonic() - t0  # at the 1 s mark
            release.set()
            target.join(5)
            other.join(5)
        return (
            answered and waited < 1.0,
            got["other"].status_code,
            got["target"].status_code,
        )

    kind, (fast, other_code, target_code) = _get_raw(run)
    assert (kind, fast, other_code) == ("ok", True, 200), (target_code,)


def _get_raw(fn):
    return _child(fn, secs=15)
