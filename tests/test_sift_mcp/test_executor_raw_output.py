"""A tool's output is kept as the bytes it wrote.

The executor decoded stdout as UTF-8 (bad bytes replaced) and saved and
hashed that re-encoded text, so the saved file and its hash weren't the
tool's output. The decoded text is now only for the response; what is saved
and hashed is the raw bytes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest
from sift_mcp.executor import execute

OUT = b"PID\tName\n1337\tevil\xe9.exe\n\xff\xfe"  # not UTF-8
ERR = b"warning: \x80 bad byte\n"


@pytest.fixture
def no_case(monkeypatch, tmp_path):
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.setattr("sift_mcp.executor.resolve_case_dir", lambda: "")
    monkeypatch.delenv("SIFT_MAX_OUTPUT", raising=False)
    return tmp_path


def _writes(out: bytes, err: bytes = b"") -> list[str]:
    code = f"import sys; sys.stdout.buffer.write({out!r}); sys.stderr.buffer.write({err!r})"
    return [sys.executable, "-c", code]


def test_saved_stdout_and_stderr_are_the_bytes_the_tool_wrote(no_case):
    r = execute(_writes(OUT, ERR), save_output=True, save_dir=str(no_case / "out"))
    assert Path(r["output_file"]).read_bytes() == OUT
    assert r["output_sha256"] == hashlib.sha256(OUT).hexdigest()
    assert Path(r["stderr_file"]).read_bytes() == ERR
    assert r["stderr_sha256"] == hashlib.sha256(ERR).hexdigest()
    assert r["stdout"] == OUT.decode("utf-8", errors="replace")  # the response's text


def test_the_output_hash_is_there_when_nothing_was_saved(no_case):
    r = execute(_writes(OUT))
    assert "output_file" not in r
    assert r["output_sha256"] == hashlib.sha256(OUT).hexdigest()
    assert execute(_writes(b""))["output_sha256"] == hashlib.sha256(b"").hexdigest()


def test_run_command_reports_and_records_the_output_hash(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in (
        "VHIR_CASE_DIR",
        "VHIR_AUDIT_DIR",
        "VHIR_ACTIVE_CASE",
        "SIFT_MAX_OUTPUT",
    ):
        monkeypatch.delenv(var, raising=False)
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: case\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(case))
    from sift_mcp.server import create_server

    script = tmp_path / "tool.py"  # run_command refuses ";" in an argument
    script.write_text(_writes(OUT)[2].replace("; ", "\n"))
    r = asyncio.run(
        create_server().call_tool(
            "run_command", {"command": [sys.executable, str(script)], "purpose": "t"}
        )
    )
    r = json.loads((r[0] if isinstance(r, tuple) else r)[0].text)
    entry = json.loads((case / "audit" / "sift-mcp.jsonl").read_text().splitlines()[-1])
    assert r["output_sha256"] == hashlib.sha256(OUT).hexdigest()
    assert entry["result_summary"]["output_sha256"] == hashlib.sha256(OUT).hexdigest()
