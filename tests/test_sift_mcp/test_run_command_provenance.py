"""A finding citing a run_command run traces through the run's recorded
inputs to the registered evidence, with the hash the run read it at: a file
re-registered with other bytes since breaks the trace, the same bytes don't."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys

import pytest
from sift_common import provenance as pv
from sift_mcp.server import create_server

READ = "import sys\nprint(open(sys.argv[1]).read())"


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    d = tmp_path / "cases" / "case-a"
    (d / "evidence").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: case-a\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(d))
    return d


def _register(case, path, data: bytes) -> None:
    path.write_bytes(data)
    row = {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest()}
    (case / "evidence.json").write_text(json.dumps({"files": [row]}))


def _cited_run(case, src) -> str:
    r = asyncio.run(
        create_server().call_tool(
            "run_command",
            {"command": [sys.executable, "-c", READ, str(src)], "purpose": "t"},
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)["audit_id"]


def test_a_run_on_evidence_re_registered_with_other_bytes_breaks(case):
    src = case / "evidence" / "mem.raw"
    _register(case, src, b"MEMORY")
    aid = _cited_run(case, src)
    _register(case, src, b"OTHER BYTES")  # replaced and registered again
    t = pv.trace_artifact(pv.load_case(case), aid, "MEMORY")
    assert t.grade == "BROKEN" and t.break_["kind"] == "hash-mismatch", t


def test_a_run_on_evidence_registered_again_with_the_same_bytes_is_full(case):
    src = case / "evidence" / "mem.raw"
    _register(case, src, b"MEMORY")
    aid = _cited_run(case, src)
    _register(case, src, b"MEMORY")
    t = pv.trace_artifact(pv.load_case(case), aid, "MEMORY")
    assert t.grade == "FULL", t
    assert t.root["sha256"] == hashlib.sha256(b"MEMORY").hexdigest()


WRITE_ONE = (
    "import sys, time\n"
    "time.sleep(0.5)\n"
    "open(sys.argv[3] + '/' + sys.argv[4], 'w').write(sys.argv[4] + ' rows')\n"
    "time.sleep(1)\n"
)


def test_parallel_runs_writing_one_folder_leave_its_files_ambiguous(case):
    import threading

    src = case / "evidence" / "mem.raw"
    _register(case, src, b"MEMORY")
    shared = case / "extractions" / "shared"
    shared.mkdir(parents=True)
    ids = {}

    def go(name):
        cmd = [sys.executable, "-c", WRITE_ONE, str(src), "--csv", str(shared), name]
        r = asyncio.run(
            create_server().call_tool("run_command", {"command": cmd, "purpose": "t"})
        )
        r = r[0] if isinstance(r, tuple) else r
        ids[name] = json.loads(r[0].text)["audit_id"]

    threads = [threading.Thread(target=go, args=(n,)) for n in ("a.csv", "b.csv")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    pc = pv.load_case(case)
    for name in ("a.csv", "b.csv"):
        f = shared / name
        t = pv.trace_file(pc, f, hashlib.sha256(f.read_bytes()).hexdigest())
        assert t.grade == "AMBIGUOUS", t  # never FULL to one of them
        assert sorted(x["audit_id"] for x in t.candidates) == sorted(ids.values())
    # a finding citing a later run that read one of them
    aid = _cited_run(case, shared / "a.csv")
    t = pv.trace_artifact(pv.load_case(case), aid, "a.csv rows")
    assert t.grade == "AMBIGUOUS", t
    assert sorted(x["audit_id"] for x in t.candidates) == sorted(ids.values())


def test_the_tool_says_to_give_parallel_runs_distinct_output_folders():
    doc = create_server()._tool_manager._tools["run_command"].fn.__doc__
    assert "Give parallel runs distinct output folders" in doc
