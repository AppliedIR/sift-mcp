"""run_command records what a run read and wrote, from the command itself.

The inputs are the files and folders the command names (bare, or as a
--flag=value; never an output flag's value), each with where it is (realpath,
st_dev, mount id) and its hash. The real run_command runs in-process on a
scratch case under a scratch HOME.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from sift_mcp.server import create_server

PY = sys.executable


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
    (d / "extractions").mkdir()
    (d / "CASE.yaml").write_text("case_id: case-a\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(d))
    return d


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(case: Path, command: list[str], **kw) -> tuple[dict, dict]:
    """(the response, the run's entry)."""
    r = asyncio.run(
        create_server().call_tool(
            "run_command", {"command": command, "purpose": "t", **kw}
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    resp = json.loads(r[0].text)
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    entries = [json.loads(x) for x in lines if x.strip()]
    return resp, [e for e in entries if e["tool"] == "run_command"][-1]


def _register(case: Path, *files: Path) -> None:
    rows = [{"path": str(f.resolve()), "sha256": _sha(f)} for f in files]
    (case / "evidence.json").write_text(json.dumps({"files": rows}))


def _by_real(entry: dict) -> dict:
    return {i["realpath"]: i for i in entry["inputs"]}


def test_the_input_is_the_file_the_command_names_not_the_ais_list(case):
    s1 = case / "extractions" / "sample1.raw"
    s1.write_bytes(b"S1")
    s2 = case / "extractions" / "sample2.raw"
    s2.write_bytes(b"S2")
    _, e = run(case, [PY, "-c", "pass", "-f", str(s2)], input_files=[str(s1)])
    assert e["input_files"] == [str(s2.resolve())]
    assert e["input_sha256s"] == [_sha(s2)]
    assert _by_real(e)[str(s2.resolve())]["sha256"] == _sha(s2)


def test_each_input_records_where_it_is(case):
    f = case / "evidence" / "a.raw"
    f.write_bytes(b"A")
    _, e = run(case, [PY, "-c", "pass", str(f)])
    (i,) = e["inputs"]
    st = os.stat(f)
    assert i["path"] == str(f) and i["realpath"] == str(f.resolve())
    assert i["st_dev"] == st.st_dev and isinstance(i["mnt_id"], int)
    assert i["sha256"] == _sha(f)


def test_a_flag_value_is_an_input_and_an_output_flags_value_is_not(case):
    a = case / "evidence" / "a.evtx"
    a.write_bytes(b"A")
    out = case / "extractions" / "out"
    out.mkdir()
    (out / "earlier.csv").write_text("x")
    _, e = run(case, [PY, "-c", "pass", f"--file={a}", "--csv", str(out)])
    assert list(_by_real(e)) == [str(a.resolve())]


def test_a_registered_input_links_by_its_path_and_a_folder_is_unhashed(case):
    img = case / "evidence" / "disk.E01"
    img.write_bytes(b"E01")
    _register(case, img)
    folder = case / "evidence" / "logs"
    folder.mkdir()
    _, e = run(case, [PY, "-c", "pass", str(img), str(folder)])
    ins = _by_real(e)
    assert "sha256" not in ins[str(img.resolve())]
    assert e["input_registered"] == [str(img.resolve())]
    assert "sha256" not in ins[str(folder.resolve())]
    assert e["input_sha256s"] == [_sha(img), ""]


def test_dd_style_operands_read_if_and_never_of(case):
    src = case / "evidence" / "src.raw"
    src.write_bytes(b"SRC")
    dst = case / "extractions" / "old.dd"
    dst.write_bytes(b"OLD")
    _, e = run(case, [PY, "-c", "pass", f"if={src}", f"of={dst}"])
    assert list(_by_real(e)) == [str(src.resolve())]


def test_a_file_only_the_ai_listed_is_recorded_as_declared(case):
    s1 = case / "extractions" / "sample1.raw"
    s1.write_bytes(b"S1")
    s2 = case / "extractions" / "sample2.raw"
    s2.write_bytes(b"S2")
    _, e = run(case, [PY, "-c", "pass", "-f", str(s2)], input_files=[str(s1), str(s2)])
    ins = _by_real(e)
    assert ins[str(s1.resolve())]["found"] == "declared"
    assert ins[str(s1.resolve())]["sha256"] == _sha(s1)
    assert "found" not in ins[str(s2.resolve())]  # the command names it
    assert e["input_files"] == [str(s2.resolve())]


def test_the_tool_doesnt_ask_for_files_the_command_already_names(case):
    doc = create_server()._tool_manager._tools["run_command"].fn.__doc__
    assert "Pass the paths you" not in doc and "declared" in doc
    _, e = run(case, [PY, "-c", "pass"])
    resp, _ = run(case, ["ls", "-1"])  # names nothing that exists
    assert "pass input_files" not in json.dumps(resp)
    resp, _ = run(case, [PY, "-c", "pass"], input_files=["/nonexistent/x.raw"])
    assert "/nonexistent/x.raw" in resp["input_files_warning"]


def test_the_shared_guidance_doesnt_ask_for_input_files_on_every_call():
    root = Path(__file__).resolve().parents[2]
    agents = (root / "AGENTS.md").read_text()
    assert "Pass `input_files` on every" not in agents
    assert "recorded as declared" in agents


def test_a_run_works_in_its_own_empty_folder_named_by_its_audit_id(case):
    code = "import os\nprint(sorted(os.listdir('.')))\nopen('made.txt', 'w').write('x')"
    resp, e = run(case, [PY, "-c", code])
    folder = case / "extractions" / e["audit_id"]
    assert resp["audit_id"] == e["audit_id"]
    assert (folder / "made.txt").read_text() == "x"
    assert e["result_summary"]["stdout_head"].strip() == "[]"


def test_without_a_case_a_run_keeps_the_process_folder(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    r = asyncio.run(
        create_server().call_tool(
            "run_command",
            {"command": [PY, "-c", "import os\nprint(os.getcwd())"], "purpose": "t"},
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    assert str(tmp_path) in r[0].text


def test_a_relative_path_names_a_file_in_the_runs_folder(case):
    code = "import sys\nprint(open(sys.argv[1]).read())"
    resp, e = run(case, [PY, "-c", code, "../earlier/a.raw"])
    assert not e.get("inputs")  # nothing there yet
    earlier = case / "extractions" / "earlier"
    earlier.mkdir()
    (earlier / "a.raw").write_text("A")
    resp, e = run(case, [PY, "-c", code, "../earlier/a.raw"])
    (i,) = e["inputs"]
    assert i["realpath"] == str((earlier / "a.raw").resolve())
    assert resp["success"] is True


def test_a_relative_path_reaching_the_audit_is_refused(case):
    log = case / "audit" / "sift-mcp.jsonl"
    run(case, [PY, "-c", "pass"])  # the audit exists
    resp, _ = run(case, ["rm", "../../audit/sift-mcp.jsonl"])
    assert resp["success"] is False and "Blocked" in resp["error"]
    assert log.exists()
    resp, _ = run(case, ["cp", "/etc/hostname", "../../evidence.json"])
    assert resp["success"] is False and "Blocked" in resp["error"]


def test_a_relative_output_path_is_checked_where_the_run_writes(case):
    code = "import sys\nopen(sys.argv[2], 'w').write('csv')"
    resp, _ = run(case, [PY, "-c", code, "--csv", "../mine.csv"])
    assert resp["success"] is True, resp.get("error")
    assert (case / "extractions" / "mine.csv").read_text() == "csv"


def test_an_attached_output_flag_is_checked_as_an_output(case, tmp_path):
    resp, _ = run(case, [PY, "-c", "pass", f"-o{tmp_path / 'outside'}"])
    assert resp["success"] is False and "outside the case" in resp["error"]
    resp, _ = run(case, [PY, "-c", "pass", "-o../mine"])
    assert resp["success"] is True, resp.get("error")


def test_an_attached_output_flags_path_is_where_the_command_writes():
    from sift_mcp import command_files

    reads, writes = command_files.named(
        ["7z", "x", "/c/a.7z", "-o/c/out", "-ofoo"], frozenset({"-o"}), "/c/op"
    )
    assert reads == ["/c/op/x", "/c/a.7z"]
    assert writes == ["/c/out", "/c/op/foo"]
