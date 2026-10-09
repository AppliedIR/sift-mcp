"""run_command records a hash for every input, however large.

An input over 1 GB was recorded as "skipped:too_large", so a memory sample or
a registered archive had no hash to link by. Now a registered file links to
the registry by its path (it isn't read again), and any other input is hashed:
in the call up to 1 GB, else in the background, recorded as `pending:<job>`
until its `hash_complete` entry. The real run_command runs in-process on a
scratch case under a scratch HOME.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest
from sift_common import file_identity as fi
from sift_mcp.server import create_server


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


def _run_on(case: Path, path: Path) -> dict:
    r = asyncio.run(
        create_server().call_tool(
            "run_command",
            {"command": [sys.executable, "-c", "pass", str(path)], "purpose": "t"},
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    json.loads(r[0].text)
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    return json.loads(lines[-1])


def _input(entry: dict, path: Path) -> str:
    return entry["input_sha256s"][entry["input_files"].index(str(path.resolve()))]


def test_a_registered_input_takes_the_registry_hash_without_being_read(
    case, monkeypatch
):
    z = case / "evidence" / "samples.7z"
    z.write_bytes(b"7z archive")
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(z.resolve()), "sha256": "ab" * 32}]})
    )

    def never(path):
        raise AssertionError(f"{path} was read")

    monkeypatch.setattr(fi, "hash_file", never)
    e = _run_on(case, z)
    assert _input(e, z) == "ab" * 32
    assert e["input_registered"] == [str(z.resolve())]


def test_an_input_that_isnt_registered_is_hashed(case):
    f = case / "evidence" / "notes.txt"
    f.write_bytes(b"not registered")
    e = _run_on(case, f)
    assert _input(e, f) == hashlib.sha256(b"not registered").hexdigest()
    assert "input_registered" not in e


def test_an_input_over_the_limit_is_pending_until_its_hash_completes(case, monkeypatch):
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    s2 = case / "extractions" / "x1" / "sample2.raw"
    s2.parent.mkdir(parents=True)
    s2.write_bytes(b"m" * 4096)
    pending = _input(_run_on(case, s2), s2)
    assert pending.startswith("pending:"), pending
    job = pending.split(":", 1)[1]
    log = case / "audit" / "file-identity.jsonl"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and job not in (
        log.read_text() if log.exists() else ""
    ):
        time.sleep(0.05)
    (done,) = [e for e in map(json.loads, log.read_text().splitlines())
               if e["job_id"] == job]  # fmt: skip
    assert done["tool"] == "hash_complete" and done["path"] == str(s2.resolve())
    assert done["sha256"] == hashlib.sha256(b"m" * 4096).hexdigest()
    assert done["requested_by"] == "run_command"
