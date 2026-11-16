"""Every route that reads a case file reads it whatever its size: a findings.json
over 20 MiB, an audit or host log line over 20 MiB and a log over 256 MiB, each
made of lines shaped as real ones are. Nothing is refused for its size. A file
that isn't a regular file is still refused by name, never waited on. Each row
runs in a forked child, which reports its own peak memory growth (printed
with -s)."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import select
import signal

import pytest
import yaml

POSIX = pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.geteuid() == 0, reason="posix"
)
MIB = 1 << 20
SHA = hashlib.sha256(b"output").hexdigest()


def _in_child(fn, timeout):
    """("ok", fn()) or ("raised", text), from a forked child, with the child's
    peak memory growth in MiB; ("blocked",) if it didn't end within `timeout`."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            with open("/proc/self/clear_refs", "w") as f:
                f.write("5")  # the peak starts from here
            before = _hwm()
            try:
                out = ("ok", fn())
            except BaseException as e:  # noqa: BLE001 - reported to the parent
                out = ("raised", f"{type(e).__name__}: {e}"[:2000])
            out = (*out, (_hwm() - before) >> 10)
        except BaseException as e:  # noqa: BLE001
            out = ("raised", repr(e)[:2000], 0)
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    try:
        ready, _, _ = select.select([r], [], [], timeout)
        if not ready:
            os.kill(pid, signal.SIGKILL)
            return ("blocked", "", 0)
        data = b""
        while chunk := os.read(r, 65536):
            data += chunk
        return pickle.loads(data)
    finally:
        os.close(r)
        os.waitpid(pid, 0)


def _hwm() -> int:
    """This process's peak resident memory, KiB."""
    with open("/proc/self/status") as f:
        return next(int(x.split()[1]) for x in f if x.startswith("VmHWM:"))


# --- inputs, shaped as real case files are --------------------------------------


def _audit_entry(n: int, pad: int = 0) -> dict:
    """A run_command entry as the MCP servers write one (about 900 bytes);
    `pad` adds that many bytes of tool output to its result."""
    return {
        "ts": f"2026-11-16T{n // 3600 % 24:02d}:{n // 60 % 60:02d}:{n % 60:02d}.123456Z",
        "tool": "run_command",
        "audit_id": f"forensic-tester-{n:06d}",
        "examiner": "tester",
        "case_id": "SZ-1",
        "source": "mcp_server",
        "params": {
            "command": "vol -f /cases/SZ-1/evidence/rd01.mem windows.pslist",
            "purpose": "list the processes running at capture",
            "save_output": True,
        },  # fmt: skip
        "result_summary": {
            "exit_code": 0,
            "lines": 412,
            "stdout": "x" * pad,
            "output_file": f"/cases/SZ-1/extractions/out-{n:06d}.txt",
            "sha256": SHA,
        },  # fmt: skip
        "input_files": ["/cases/SZ-1/evidence/rd01.mem"],
        "elapsed_ms": 4123.5,
        "data_provenance": "tool output, untrusted",
    }


def _withdrawn(n: int, pad: int = 0) -> dict:
    """A record_finding entry whose result is WITHDRAWN, as forensic-mcp writes
    one; `pad` adds that many bytes of artifact content."""
    entry = _audit_entry(n)
    entry["tool"] = "record_finding"
    entry["params"] = {"title": "Run key persistence", "artifacts": [
        {"source": "/cases/SZ-1/extractions/reg.csv", "content": "c" * pad}]}  # fmt: skip
    entry["result_summary"] = {"status": "WITHDRAWN", "finding_id": f"F-tester-{n:03d}"}
    return entry


def _write_log(path, size: int) -> str:
    """A log of real-shaped lines whose last line is a withdrawal; `size` is
    the least it holds. Under 64 MiB it is two lines, the second holding
    `size` bytes. The last line's audit id is returned."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        if size < 64 * MIB:
            f.write(json.dumps(_audit_entry(1)).encode() + b"\n")
            f.write(json.dumps(_withdrawn(2, size)).encode() + b"\n")
            return f"forensic-tester-{2:06d}"
        n, written, batch = 0, 0, []
        while written < size:
            n += 1
            line = json.dumps(_audit_entry(n)).encode() + b"\n"
            batch.append(line)
            written += len(line)
            if len(batch) == 4096:
                f.write(b"".join(batch))
                batch.clear()
        n += 1
        f.write(b"".join(batch) + json.dumps(_withdrawn(n)).encode() + b"\n")
        return f"forensic-tester-{n:06d}"


def _findings(size: int) -> list[dict]:
    """Real-shaped findings (about 10 KB each, as the case writes them) whose
    file passes `size` bytes; the last one is titled by its id."""
    one = {"status": "DRAFT", "title": "Prefetch shows svc-upd.exe run from Temp",
           "observation": "o" * 3000, "interpretation": "i" * 1500,
           "confidence": "MEDIUM", "examiner": "tester", "host": "rd01",
           "artifacts": [{"source": "/cases/SZ-1/extractions/pf.csv", "extraction":
                          "PECmd -d ...", "content": "c" * 4000,
                          "audit_id": "sift-tester-000001"}]}  # fmt: skip
    found = [{"id": f"F-tester-{i:04d}", **one} for i in range(1, size // 8000 + 2)]
    found[-1]["title"] = found[-1]["id"]
    return found


def _write_findings(path, size: int) -> str:
    found = _findings(size)
    data = json.dumps(found, indent=2).encode()
    assert len(data) > size
    path.write_bytes(data)
    return found[-1]["id"]


def _write_ops(path, size: int) -> str:
    """host-ops.json, as the journal writes it, past `size` bytes."""
    op = {"kind": "rename", "state": "done", "unit": "u-0123456789abcdef",
          "to": "WKSTN05", "examiner": "tester", "t": "2026-11-16T05:00:00Z",
          "note": "n" * 600}  # fmt: skip
    ops = {
        f"op-{i:07d}": dict(op, updated=f"2026-11-16T05:00:00.{i:07d}Z")
        for i in range(1, size // 700 + 2)
    }  # the last is the latest
    data = json.dumps({"ops": ops}, indent=2).encode()
    assert len(data) > size
    path.write_bytes(data)
    return f"op-{len(ops):07d}"


def _write_draft(path, size: int) -> str:
    """host-list-draft.json past `size` bytes: one line per host, as pasted."""
    lines = [f"wkstn{i:06d}.corp.example 10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}"
             for i in range(1, size // 36 + 2)]  # fmt: skip
    data = json.dumps({"text": "\n".join(lines) + "\n", "source": "pasted",
                       "entries": len(lines), "t": "2026-11-16T05:00:00Z"}).encode()  # fmt: skip
    assert len(data) > size
    path.write_bytes(data)
    return lines[-1]


@pytest.fixture
def case(tmp_path, monkeypatch):
    c = tmp_path / "SZ-1"
    (c / "audit").mkdir(parents=True)
    (c / "CASE.yaml").write_text(yaml.dump({"case_id": "SZ-1", "status": "open"}))
    for f in ("findings.json", "timeline.json", "todos.json", "iocs.json"):
        (c / f).write_text("[]")
    (c / "evidence.json").write_text(json.dumps({"files": []}))
    (c / "pending-reviews.json").write_text('{"items": []}')
    monkeypatch.setenv("VHIR_CASE_DIR", str(c))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    from report_mcp import server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    yield c
    for big in [*c.iterdir(), *(c / "audit").iterdir()]:  # never left for the next run
        if big.is_file():
            big.chmod(0o644)
            big.unlink()


# --- the routes ------------------------------------------------------------------
# route -> (the file it reads, relative to the case; write(path, size) -> marker;
#           call(case, marker) -> what it read; read(got, marker) -> True when the
#           marker's record was read)


def _portal(case, route):
    from case_dashboard import routes
    from starlette.testclient import TestClient

    with TestClient(routes.create_dashboard_v2_app()) as c:
        r = c.get(route)
    return r.status_code, r.json()


def _portal_audit(case, marker):
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-tester-001", "audit_ids": [marker]}])
    )
    return _portal(case, "/api/audit/F-tester-001")


def _withdrawals(case, marker):
    from case_dashboard import routes

    entries, _, unread = routes._withdrawals(case)
    return [e.get("audit_id") for e in entries], unread


def _host_log(case, name):
    from sift_common import host_identity as hi

    (_, size), data = hi._read(case / name)
    return size, json.loads(data.rstrip(b"\n").rsplit(b"\n", 1)[-1])["audit_id"]


def _decisions(case, name):
    """Each line as the Portal host page reads host-decisions.jsonl, by the
    reader it calls (named capped_lines before this fix)."""
    from sift_common import file_identity as fi

    lines = getattr(fi, "case_lines", None) or fi.capped_lines
    n = last = 0
    for raw in lines(case / name, follow=False):
        n, last = n + 1, raw
    return n, json.loads(last)["audit_id"]


def _save_finding(case, size):
    from forensic_mcp.case.manager import CaseManager

    found = _findings(size)
    CaseManager()._save_findings(case, found)
    back = json.loads((case / "findings.json").read_bytes())
    return len(back), back[-1]["id"], found[-1]["id"]


def _approved_view(case):
    from vhir_cli.ledger_verify import approved_view

    return [d for _, d in approved_view(case)["result"].failures]


def _generate(case):
    from report_mcp import server as rs

    out = rs._generate("full", case)
    return out.get("unreadable", []), out.get("error", "")


LOG = "audit/forensic-mcp.jsonl"
LOG_ROUTES = {
    "Portal audit (/api/audit)": (LOG, _write_log, _portal_audit,
                                  lambda got, m: got[0] == 200 and [e["audit_id"] for e in got[1]] == [m]),
    "Portal withdrawals (/api/summary)": (LOG, _write_log, _withdrawals,
                                          lambda got, m: got == ([m], [])),
    "host log (host-observations.jsonl)": ("host-observations.jsonl", _write_log,
                                           lambda c, m: _host_log(c, "host-observations.jsonl"),
                                           lambda got, m: got[1] == m),
    "host decisions (Portal host page's reader)": ("host-decisions.jsonl", _write_log,
                                                   lambda c, m: _decisions(c, "host-decisions.jsonl"),
                                                   lambda got, m: got[1] == m),
}  # fmt: skip
DOC_ROUTES = {
    "Portal findings (/api/findings)": ("findings.json", _write_findings,
                                        lambda c, m: _portal(c, "/api/findings"),
                                        lambda got, m: got[0] == 200 and got[1][-1]["id"] == m),
    "Portal record load (/api/summary)": ("findings.json", _write_findings,
                                          lambda c, m: _portal(c, "/api/summary"),
                                          lambda got, m: got[0] == 200),
    "verification (approved_view)": ("findings.json", _write_findings, lambda c, m: _approved_view(c),
                                     lambda got, m: not any("findings.json" in d for d in got)),
    "report-mcp generate": ("findings.json", _write_findings, lambda c, m: _generate(c),
                            lambda got, m: got == ([], "")),
    "host-ops (/api/hosts/ops)": ("host-ops.json", _write_ops,
                                  lambda c, m: _portal(c, "/api/hosts/ops"),
                                  lambda got, m: got[0] == 200 and got[1]["last"]["id"] == m),
    "host-list draft": ("host-list-draft.json", _write_draft,
                        lambda c, m: __import__("sift_common.host_proposal", fromlist=["x"]).read_host_list_draft(c)["text"][-200:],
                        lambda got, m: m in got),
}  # fmt: skip
SIZES = {"20 MiB line": 20 * MIB, "log over 256 MiB": 257 * MIB}


def _report(route, what, got):
    status, value, grew = got
    print(f"\nPEAK {route} | {what} | grew {grew} MiB | {status}")
    return status, value


@pytest.mark.parametrize("what", sorted(SIZES))
@pytest.mark.parametrize("route", sorted(LOG_ROUTES))
def test_a_case_log_of_any_size_is_read(case, route, what):
    rel, write, call, read = LOG_ROUTES[route]
    marker = write(case / rel, SIZES[what])
    status, got = _report(
        route, what, _in_child(lambda: call(case, marker), timeout=900)
    )
    assert status == "ok", got
    assert read(got, marker), str(got)[:2000]


@pytest.mark.parametrize("route", sorted(DOC_ROUTES))
def test_a_case_document_over_20_mib_is_read(case, route):
    rel, write, call, read = DOC_ROUTES[route]
    marker = write(case / rel, 20 * MIB)
    status, got = _report(
        route, f"{rel} over 20 MiB", _in_child(lambda: call(case, marker), timeout=300)
    )
    assert status == "ok", got
    assert read(got, marker), str(got)[-2000:]


def test_a_finding_that_takes_findings_json_past_20_mib_is_saved(case):
    status, got = _report("save finding", "findings.json over 20 MiB",
                          _in_child(lambda: _save_finding(case, 20 * MIB), timeout=300))  # fmt: skip
    assert status == "ok", got
    n, last, want = got
    assert last == want and n == int(want.rsplit("-", 1)[1]), got


@POSIX
@pytest.mark.parametrize(
    "route", sorted(LOG_ROUTES) + sorted(f"doc:{r}" for r in DOC_ROUTES)
)
def test_a_case_file_that_isnt_regular_is_refused_by_name(case, route):
    """A FIFO no one writes to, in the file's place: named, never waited on."""
    rel, _, call, _ = (
        DOC_ROUTES[route[4:]] if route.startswith("doc:") else LOG_ROUTES[route]
    )
    path = case / rel
    path.unlink(missing_ok=True)
    os.mkfifo(path)
    status, got, _ = _in_child(lambda: str(call(case, "none")), timeout=20)
    assert status in ("ok", "raised"), status
    assert "regular file" in got, got[:2000]
