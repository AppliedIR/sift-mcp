"""File identity: one SHA-256 of a regular file, with no size cap.

Inputs over 1 GB were recorded as "skipped:too_large", which breaks the hash
link for every memory or disk image. A FIFO, device or directory is refused
without being read, so it never blocks the caller.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

import pytest
from sift_common import file_identity as fi

GiB = 1 << 30


def _zeros_sha(size: int) -> str:
    h, block = hashlib.sha256(), bytes(1 << 20)
    while size:
        n = min(size, len(block))
        h.update(block[:n])
        size -= n
    return h.hexdigest()


def test_a_file_is_hashed_whole_with_its_stat_fields(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x00\xffevidence" * 1000)
    r = fi.hash_file(f)
    st = os.stat(f)
    assert r.sha256 == hashlib.sha256(f.read_bytes()).hexdigest()
    assert (r.path, r.size, r.st_dev, r.st_ino, r.mtime_ns) == (
        str(f), st.st_size, st.st_dev, st.st_ino, st.st_mtime_ns,
    )  # fmt: skip


def test_a_file_over_the_old_1_gb_cap_is_hashed_whole(tmp_path):
    big = tmp_path / "mem.raw"
    with open(big, "wb") as f:
        f.truncate(GiB + 4096)  # sparse
    assert fi.hash_file(big).sha256 == _zeros_sha(GiB + 4096)


def test_a_fifo_a_device_and_a_directory_are_refused_unread(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)  # nothing writes it: a blocking read would hang the test
    for p in (fifo, "/dev/null", tmp_path):
        with pytest.raises(fi.NotRegularFile, match="not a regular file"):
            fi.hash_file(p)
    assert issubclass(fi.NotRegularFile, ValueError)


def _registry(case, *entries):
    (case / "evidence.json").write_text(json.dumps({"files": list(entries)}))


def test_a_registered_file_links_by_its_path_without_being_read(tmp_path):
    case = tmp_path / "case"
    z = case / "evidence" / "samples.7z"
    z.parent.mkdir(parents=True)
    z.write_bytes(b"7z")
    _registry(case, {"path": str(z.resolve()), "sha256": "ab" * 32})
    z.chmod(0)  # unreadable: the registry's hash is used, the file isn't opened
    link = tmp_path / "link.7z"
    link.symlink_to(z)
    assert fi.registered_hash(case, z) == "ab" * 32
    assert fi.registered_hash(case, link) == "ab" * 32  # the same file, by realpath
    z.chmod(0o644)


def test_a_file_that_isnt_registered_has_no_registered_hash(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    other = tmp_path / "copy.7z"
    other.write_bytes(b"7z")
    assert fi.registered_hash(case, other) is None  # no registry
    _registry(case, {"path": str(tmp_path / "samples.7z"), "sha256": "ab" * 32})
    assert fi.registered_hash(case, other) is None
    (case / "evidence.json").write_text("{not json")
    assert fi.registered_hash(case, other) is None


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
    """The entry that closes a pending hash, once its thread has written it."""
    log = case / "audit" / "file-identity.jsonl"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            for line in log.read_text().splitlines():
                e = json.loads(line)
                if e.get("job_id") == job_id:
                    return e
        time.sleep(0.05)
    return None


def test_a_file_within_the_limit_is_hashed_in_the_call(case):
    f = case / "small.bin"
    f.write_bytes(b"x" * 100)
    r = fi.hash_for_call(f, case_dir=case, requested_by="run_command", inline_limit=100)
    assert (
        isinstance(r, fi.HashResult)
        and r.sha256 == hashlib.sha256(b"x" * 100).hexdigest()
    )
    assert fi.INLINE_LIMIT == 1_000_000_000


def test_a_larger_file_is_hashed_once_in_the_background_for_every_caller(
    case, monkeypatch
):
    f = case / "sample2.raw"
    f.write_bytes(b"m" * 4096)
    go, real = threading.Event(), fi.hash_file
    monkeypatch.setattr(fi, "hash_file", lambda p: go.wait(10) and real(p))
    p1 = fi.hash_for_call(f, case_dir=case, requested_by="op-1", inline_limit=100)
    p2 = fi.hash_for_call(f, case_dir=case, requested_by="op-2", inline_limit=100)
    go.set()  # the first job is still running when the second request comes
    assert isinstance(p1, fi.Pending) and p1.job_id == p2.job_id  # one job, one result
    done = _closed(case, p1.job_id)
    st = os.stat(f)
    assert done["tool"] == "hash_complete"
    assert done["sha256"] == hashlib.sha256(b"m" * 4096).hexdigest()
    assert (done["path"], done["size"], done["st_ino"], done["mtime_ns"]) == (
        str(f), 4096, st.st_ino, st.st_mtime_ns,
    )  # fmt: skip
    assert done["requested_by"] == "op-1" and done["started"] <= done["finished"]
    assert [e for e in _entries(case) if e.get("job_id") == p1.job_id] == [done]


def test_a_background_hash_that_cant_read_its_file_says_so(case, monkeypatch):
    f = case / "sample2.raw"
    f.write_bytes(b"m" * 4096)

    def unreadable(path):
        raise OSError("unreadable")

    monkeypatch.setattr(fi, "hash_file", unreadable)
    p = fi.hash_for_call(f, case_dir=case, requested_by="op-3", inline_limit=100)
    failed = _closed(case, p.job_id)
    assert failed["tool"] == "hash_failed" and "unreadable" in failed["error"]
    assert "sha256" not in failed


def test_without_a_case_a_larger_file_starts_nothing(tmp_path):
    f = tmp_path / "sample2.raw"
    f.write_bytes(b"m" * 4096)
    before = threading.active_count()
    assert fi.hash_for_call(f, case_dir="", requested_by="op", inline_limit=100) is None
    assert threading.active_count() == before


def test_a_fifo_is_refused_before_any_hashing(case):
    fifo = case / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(fi.NotRegularFile):
        fi.hash_for_call(fifo, case_dir=case, requested_by="op", inline_limit=0)


def _entries(case):
    log = case / "audit" / "file-identity.jsonl"
    return [json.loads(x) for x in log.read_text().splitlines()]
