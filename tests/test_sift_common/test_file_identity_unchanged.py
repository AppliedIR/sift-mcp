"""A background hash records a file's hash only for the bytes the call saw.

The job hashes later than the call. A file changed between the call and the
job, or while the job reads it, gets no hash under the call's identity: its
row is a failure, "changed since the call: <fields>". The file's
(st_dev, st_ino, size, mtime_ns, ctime_ns) must agree at the call, when the
job opens it, and after the job read it to EOF, with the bytes read equal to
its size. hash_file's own check (open versus after the read) raises an
OSError, so its other callers (opensearch-mcp's manifest, vhir's register)
see an error instead of a mixed hash.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import time

import pytest
from sift_common import file_identity as fi


@pytest.fixture
def case(tmp_path, monkeypatch):
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    d = tmp_path / "case"
    (d / "audit").mkdir(parents=True)
    return d


def _closed(case, job_id, timeout=30.0):
    log = case / "audit" / "file-identity.jsonl"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            for line in log.read_text().splitlines():
                e = json.loads(line)
                if e.get("job_id") == job_id:
                    return e
        time.sleep(0.05)
    raise AssertionError(f"{job_id} never closed")


def _held(monkeypatch, only=None):
    """The job waits for the returned Event before it hashes (`only` that
    file, if given)."""
    go, real = threading.Event(), fi.hash_file
    held = lambda p: only is None or os.path.realpath(p) == os.path.realpath(only)  # noqa: E731
    monkeypatch.setattr(
        fi, "hash_file", lambda p: (not held(p) or go.wait(10)) and real(p)
    )
    return go


def _append(path, data=b"+"):
    with open(path, "ab") as f:
        f.write(data)


def _appending_during_read(monkeypatch, path):
    """hash_file's reader appends to the file after its first chunk: a writer
    still writing while the job reads."""
    monkeypatch.setattr(fi, "_CHUNK", 64)
    real_sha256 = hashlib.sha256

    class Hook:
        def __init__(self):
            self.h, self.n = real_sha256(), 0

        def update(self, chunk):
            self.n += 1
            if self.n == 1:
                _append(path, b"written during the read")
            self.h.update(chunk)

        def hexdigest(self):
            return self.h.hexdigest()

    monkeypatch.setattr(fi.hashlib, "sha256", Hook)


# (a) changed between the call and the job
def test_a_file_changed_after_the_call_gets_a_failure_not_a_hash(case, monkeypatch):
    f = case / "acq.img"
    f.write_bytes(b"a" * 4096)
    go = _held(monkeypatch)
    p = fi.hash_for_call(f, case_dir=case, requested_by="run_command", inline_limit=100)
    _append(f)  # the run changes its input in place
    go.set()
    row = _closed(case, p.job_id)
    assert row["tool"] == "hash_failed" and "sha256" not in row, row
    assert row["error"].startswith("changed since the call: "), row["error"]
    assert "size" in row["error"]
    assert row["size"] == 4097  # the file as it is now, as failure rows carry


# (b) changed while the job reads it
def test_a_file_appended_during_the_read_gets_a_failure(case, monkeypatch):
    f = case / "acq.img"
    f.write_bytes(b"b" * 4096)
    _appending_during_read(monkeypatch, f)
    p = fi.hash_for_call(f, case_dir=case, requested_by="run_command", inline_limit=100)
    row = _closed(case, p.job_id)
    assert row["tool"] == "hash_failed" and "sha256" not in row, row
    assert row["error"].startswith("changed since the call: "), row["error"]


# (c) a list job: only the changed file fails
def test_a_list_job_fails_only_the_file_that_changed(case, monkeypatch):
    kept, moved = case / "kept.bin", case / "moved.bin"
    kept.write_bytes(b"k" * 300)
    moved.write_bytes(b"m" * 300)
    go = _held(monkeypatch)
    batch = fi.hash_files_for_call([kept, moved], case_dir=case, requested_by="t",
                                   inline_limit=0)  # fmt: skip
    _append(moved)
    go.set()
    rows = {r["path"]: r for r in _closed(case, batch.job_id)["files"]}
    assert rows[str(kept)]["sha256"] == hashlib.sha256(b"k" * 300).hexdigest()
    assert "sha256" not in rows[str(moved)]
    assert rows[str(moved)]["error"].startswith("changed since the call: ")


# (d) the control: an unchanged file still records its hash, with its own fields
def test_an_unchanged_file_still_records_its_hash_alone_and_in_a_list(
    case, monkeypatch
):
    f, g = case / "same.bin", case / "same2.bin"
    f.write_bytes(b"s" * 4096)
    g.write_bytes(b"t" * 300)
    go = _held(monkeypatch)
    one = fi.hash_for_call(f, case_dir=case, requested_by="t", inline_limit=100)
    many = fi.hash_files_for_call([g], case_dir=case, requested_by="t", inline_limit=0)
    go.set()
    row, (lrow,) = _closed(case, one.job_id), _closed(case, many.job_id)["files"]
    for r, path, data in ((row, f, b"s" * 4096), (lrow, g, b"t" * 300)):
        st = os.stat(path)
        assert r["sha256"] == hashlib.sha256(data).hexdigest()
        assert (r["size"], r["st_ino"], r["mtime_ns"], r["ctime_ns"]) == (
            st.st_size, st.st_ino, st.st_mtime_ns, st.st_ctime_ns)  # fmt: skip


def test_hash_file_says_which_fields_changed_during_the_read(tmp_path, monkeypatch):
    f = tmp_path / "x.bin"
    f.write_bytes(b"c" * 4096)
    _appending_during_read(monkeypatch, f)
    with pytest.raises(fi.FileChanged) as e:
        fi.hash_file(f)
    assert isinstance(e.value, OSError) and "size" in e.value.fields


def test_the_byte_count_catches_a_change_the_stat_did_not_show(tmp_path, monkeypatch):
    """A filesystem whose stat lags its writes (a cached network share): the
    bytes read, not the size the stat gave, show the file grew."""
    f = tmp_path / "x.bin"
    f.write_bytes(b"d" * 4096)
    _appending_during_read(monkeypatch, f)
    real_fstat, first = os.fstat, []
    monkeypatch.setattr(fi.os, "fstat", lambda fd: first[0] if first
                        else first.append(real_fstat(fd)) or first[0])  # fmt: skip
    with pytest.raises(fi.FileChanged) as e:
        fi.hash_file(f)
    assert e.value.fields == ["size"]


# (e) end to end through run_command, the route the UAT used
@pytest.fixture
def run_case(tmp_path, monkeypatch):
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


def test_a_run_that_changes_its_input_in_place_closes_with_a_failure(
    run_case, monkeypatch
):
    """The job is held until the run returns, so it reads the file the run
    left (the UAT's ordering: its truncate finished before the job read)."""
    from sift_mcp.server import create_server

    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    img = run_case / "extractions" / "x1" / "acq.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"i" * 4096)
    go = _held(monkeypatch, only=img)  # the script, also an input, hashes in the call
    grow = run_case.parent / "grow.py"  # a tool that writes to the file it reads
    grow.write_text("import sys\nopen(sys.argv[1], 'ab').write(b'grown by the run')\n")
    r = asyncio.run(create_server().call_tool(
        "run_command", {"command": [sys.executable, str(grow), str(img)], "purpose": "t"}))  # fmt: skip
    json.loads((r[0] if isinstance(r, tuple) else r)[0].text)
    assert img.read_bytes().endswith(b"grown by the run")  # the run did change it
    go.set()  # the run has returned: now the job reads the file
    entry = json.loads(
        (run_case / "audit" / "sift-mcp.jsonl").read_text().splitlines()[-1]
    )
    recorded = entry["input_sha256s"][entry["input_files"].index(str(img.resolve()))]
    assert recorded.startswith("pending:"), recorded
    row = _closed(run_case, recorded.split(":", 1)[1])
    assert row["tool"] == "hash_failed" and "sha256" not in row, row
    assert row["error"].startswith("changed since the call: "), row["error"]


# (f) hash_file's other callers get an error through their OSError handling
def test_vhirs_register_reports_a_file_changed_while_it_was_read(tmp_path, monkeypatch):
    evidence = pytest.importorskip("vhir_cli.commands.evidence")
    f = tmp_path / "img.bin"
    f.write_bytes(b"v" * 4096)
    _appending_during_read(monkeypatch, f)
    hashes, _, errors = evidence._hash_each(tmp_path, [str(f)])
    assert hashes == {} and "changed while it was hashed" in errors[str(f)], (
        hashes,
        errors,
    )


def test_opensearchs_manifest_hash_raises_for_a_file_changed_while_it_was_read(
    tmp_path, monkeypatch
):
    manifest = pytest.importorskip("opensearch_mcp.manifest")
    f = tmp_path / "img.bin"
    f.write_bytes(b"o" * 4096)
    _appending_during_read(monkeypatch, f)
    with pytest.raises(OSError, match="changed while it was hashed"):
        manifest.sha256_file(f)
