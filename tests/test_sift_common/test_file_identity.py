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


def test_a_folders_files_hash_inline_within_the_limit_and_the_rest_in_one_job(case):
    kape = case / "evidence" / "kape"
    kape.mkdir(parents=True)
    small = kape / "Security.evtx"
    small.write_bytes(b"A" * 40)
    big = [kape / "pagefile0.sys", kape / "pagefile1.sys"]
    for f in big:
        f.write_bytes(b"P" * 400)
    fifo = kape / "pipe"
    os.mkfifo(fifo)
    b = fi.hash_files_for_call([small, *big, fifo], case_dir=case,
                               requested_by="evidence_register", inline_limit=100)  # fmt: skip
    assert set(b.done) == {str(small)}
    assert b.done[str(small)].sha256 == hashlib.sha256(b"A" * 40).hexdigest()
    assert b.not_regular == [str(fifo)] and b.pending == [str(p) for p in big]
    done = _closed(case, b.job_id)
    assert (
        done["tool"] == "hash_complete" and done["requested_by"] == "evidence_register"
    )
    assert [(f["path"], f["sha256"]) for f in done["files"]] == [
        (str(p), hashlib.sha256(b"P" * 400).hexdigest()) for p in big
    ]
    assert "sha256" not in done  # a list's hashes are per file


def test_the_inline_bytes_of_a_folder_never_pass_the_limit(case):
    files = []
    for i, n in enumerate((60, 60, 30)):
        files.append(case / f"f{i}")
        files[-1].write_bytes(b"x" * n)
    b = fi.hash_files_for_call(files, case_dir=case, requested_by="t", inline_limit=100)
    assert sum(r.size for r in b.done.values()) <= 100
    assert set(b.done) | set(b.pending) == {str(f) for f in files}
    _closed(case, b.job_id)


def test_a_folder_job_that_reads_nothing_fails_and_one_that_reads_some_completes(
    case, monkeypatch
):
    a, c = case / "a.bin", case / "c.bin"
    a.write_bytes(b"a" * 400)
    c.write_bytes(b"c" * 400)
    real = fi.hash_file

    def some(path):
        if str(path).endswith("a.bin"):
            raise OSError("unreadable")
        return real(path)

    monkeypatch.setattr(fi, "hash_file", some)
    b = fi.hash_files_for_call([a, c], case_dir=case, requested_by="t", inline_limit=10)
    done = _closed(case, b.job_id)
    assert done["tool"] == "hash_complete"
    assert "unreadable" in done["files"][0]["error"] and "sha256" in done["files"][1]
    monkeypatch.setattr(
        fi, "hash_file", lambda p: (_ for _ in ()).throw(OSError("gone"))
    )
    os.utime(a, ns=(1, 1))  # a new list key: a new job
    b2 = fi.hash_files_for_call([a], case_dir=case, requested_by="t", inline_limit=10)
    failed = _closed(case, b2.job_id)
    assert failed["tool"] == "hash_failed" and "gone" in failed["files"][0]["error"]


def test_without_a_case_a_folders_large_files_stay_unhashed(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"b" * 400)
    b = fi.hash_files_for_call([f], case_dir="", requested_by="t", inline_limit=100)
    assert (b.done, b.job_id, b.pending, b.not_regular) == ({}, "", [str(f)], [])


@pytest.mark.parametrize("batch", [False, True], ids=["one file", "a folder"])
def test_one_file_pending_in_two_cases_closes_in_each(
    case, tmp_path, monkeypatch, batch
):
    """The active case switched while a large file hashed: each case's pending
    hash gets its own job, and its own closing entry."""
    other = tmp_path / "case-b"
    (other / "audit").mkdir(parents=True)
    f = case / "pagefile.sys"
    f.write_bytes(b"P" * 400)
    go, real = threading.Event(), fi.hash_file
    monkeypatch.setattr(fi, "hash_file", lambda p: go.wait(10) and real(p))

    def ask(c):
        if batch:
            return fi.hash_files_for_call(
                [f], case_dir=c, requested_by="t", inline_limit=10
            ).job_id
        return fi.hash_for_call(f, case_dir=c, requested_by="t", inline_limit=10).job_id

    a, b = ask(case), ask(other)
    go.set()
    assert a != b
    for c, job in ((case, a), (other, b)):
        assert _closed(c, job)["tool"] == "hash_complete"


def test_a_completed_background_hash_is_taken_for_the_unchanged_file(case):
    f = case / "pagefile.sys"
    f.write_bytes(b"P" * 400)
    b = fi.hash_files_for_call([f], case_dir=case, requested_by="t", inline_limit=10)
    done = _closed(case, b.job_id)
    st = os.stat(f)
    (row,) = done["files"]
    assert (row["st_dev"], row["st_ino"], row["ctime_ns"]) == (
        st.st_dev, st.st_ino, st.st_ctime_ns,
    )  # fmt: skip
    assert fi.completed_hash(case, f) == hashlib.sha256(b"P" * 400).hexdigest()
    assert fi.completed_hash(case, case / "other.sys") is None


def test_a_one_file_job_is_taken_too(case):
    f = case / "sample2.raw"
    f.write_bytes(b"m" * 400)
    p = fi.hash_for_call(f, case_dir=case, requested_by="t", inline_limit=10)
    _closed(case, p.job_id)
    assert fi.completed_hash(case, f) == hashlib.sha256(b"m" * 400).hexdigest()


def test_a_rewrite_backdated_to_the_same_size_and_mtime_is_not_taken(case):
    f = case / "pagefile.sys"
    f.write_bytes(b"P" * 400)
    b = fi.hash_files_for_call([f], case_dir=case, requested_by="t", inline_limit=10)
    _closed(case, b.job_id)
    st = os.stat(f)
    time.sleep(0.01)
    f.write_bytes(b"Q" * 400)  # same size
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))  # mtime set back, as touch -d does
    assert os.stat(f).st_mtime_ns == st.st_mtime_ns and os.stat(f).st_size == 400
    assert fi.completed_hash(case, f) is None  # ctime moved: the record isn't this file


def test_a_failed_background_hash_is_taken_until_the_file_changes(case, monkeypatch):
    f = case / "locked.sys"
    f.write_bytes(b"L" * 400)
    os.chmod(f, 0o644)  # whatever the umask, the fix below changes the mode

    def unreadable(path):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(fi, "hash_file", unreadable)
    b = fi.hash_files_for_call([f], case_dir=case, requested_by="t", inline_limit=10)
    _closed(case, b.job_id)
    got = fi.completed_hashes(case, [f])
    assert "Permission denied" in got[str(f)]["error"] and "sha256" not in got[str(f)]
    os.chmod(f, 0o600)  # fixing it changes its mode (and ctime): hashed again
    assert fi.completed_hashes(case, [f]) == {}


def test_a_recorded_failure_no_longer_applies_once_the_permissions_change(
    case, monkeypatch
):
    """Permissions fixed within one ctime tick (a coarse filesystem clock):
    every other stat field is as recorded, and the failure is still dropped."""
    f = case / "locked.sys"
    f.write_bytes(b"L" * 400)
    os.chmod(f, 0o000)

    def unreadable(path):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(fi, "hash_file", unreadable)
    b = fi.hash_files_for_call([f], case_dir=case, requested_by="t", inline_limit=10)
    _closed(case, b.job_id)
    assert "Permission denied" in fi.completed_hashes(case, [f])[str(f)]["error"]
    real, then = os.stat, os.stat(f)

    class Fixed:  # the recorded stat, with only the mode changed
        def __getattr__(self, name):
            return 0o100600 if name == "st_mode" else getattr(then, name)

    monkeypatch.setattr(
        fi.os,
        "stat",
        lambda p, *a, **k: Fixed() if str(p) == str(f) else real(p, *a, **k),
    )
    assert fi.completed_hashes(case, [f]) == {}


def test_completed_hashes_read_the_log_once_for_many_files(case, monkeypatch):
    files = []
    for n in range(50):
        files.append(case / f"f{n}.bin")
        files[-1].write_bytes(b"x" * (100 + n))
    b = fi.hash_files_for_call(files, case_dir=case, requested_by="t", inline_limit=10)
    _closed(case, b.job_id)
    reads, real = [], fi._completed_rows
    monkeypatch.setattr(fi, "_completed_rows", lambda c: reads.append(c) or real(c))
    got = fi.completed_hashes(case, files)
    assert len(reads) == 1 and len(got) == 50
    assert got[str(files[7])]["sha256"] == hashlib.sha256(b"x" * 107).hexdigest()
    assert fi.completed_hash(case, files[7]) == got[str(files[7])]["sha256"]
