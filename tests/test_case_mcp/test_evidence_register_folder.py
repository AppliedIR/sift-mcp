"""The AI registers a folder (a KAPE collection) without running past the call's
time limit.

Small files are hashed in the call. A large one is hashed in the background:
the call answers {"status": "hashing", "job_id": …} and registers nothing, and
a repeat call takes the job's recorded hash, as long as the file is unchanged
(same device, inode, size, mtime and ctime), and registers the folder.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

import pytest
from sift_common import file_identity as fi

from .test_server import _clean_env, _parse, case_dir, server  # noqa: F401


@pytest.fixture
def kape(case_dir):  # noqa: F811
    d = case_dir["path"] / "evidence" / "kape"
    d.mkdir()
    (d / "Security.evtx").write_bytes(b"E" * 40)
    (d / "pagefile.sys").write_bytes(b"P" * 400)
    return d


def _registry(case_dir):  # noqa: F811
    return json.loads((case_dir["path"] / "evidence.json").read_text())["files"]


def _wait(case_dir, job_id):  # noqa: F811
    log = case_dir["path"] / "audit" / "file-identity.jsonl"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if log.exists() and job_id in log.read_text():
            return [json.loads(x) for x in log.read_text().splitlines()]
        time.sleep(0.05)
    raise AssertionError(f"{job_id} never closed")


def test_a_small_folder_registers_in_one_call(server, case_dir, kape):  # noqa: F811
    r = _parse(server["evidence_register"](path=str(kape)))
    assert r["kind"] == "folder" and r["file_count"] == 2, r
    assert _registry(case_dir)[0]["registered_via"] == "mcp"


def test_a_large_file_is_hashed_in_the_background_and_a_repeat_call_registers(
    server,
    case_dir,
    kape,
    monkeypatch,  # noqa: F811
):
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    first = _parse(server["evidence_register"](path=str(kape)))
    assert first["status"] == "hashing" and first["files_hashing"] == 1, first
    assert (
        _registry(case_dir) == []
        and not (case_dir["path"] / "evidence-manifests").exists()
    )
    entries = _wait(case_dir, first["job_id"])
    second = _parse(server["evidence_register"](path=str(kape)))
    assert second["kind"] == "folder", second
    rows = json.loads((case_dir["path"] / second["manifest_path"]).read_text())["files"]
    assert {r["path"].rsplit("/", 1)[1]: r["sha256"] for r in rows} == {
        "Security.evtx": hashlib.sha256(b"E" * 40).hexdigest(),
        "pagefile.sys": hashlib.sha256(b"P" * 400).hexdigest(),
    }
    log = case_dir["path"] / "audit" / "file-identity.jsonl"
    assert len(log.read_text().splitlines()) == len(entries)  # no second job


def test_a_file_changed_after_its_job_is_hashed_again(
    server, case_dir, kape, monkeypatch
):  # noqa: F811
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    first = _parse(server["evidence_register"](path=str(kape)))
    _wait(case_dir, first["job_id"])
    big = kape / "pagefile.sys"
    st = os.stat(big)
    time.sleep(0.01)
    big.write_bytes(b"Q" * 400)
    os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))  # same size and mtime
    again = _parse(server["evidence_register"](path=str(kape)))
    assert again["status"] == "hashing" and again["job_id"] != first["job_id"], again
    assert _registry(case_dir) == []


def test_the_ais_verify_of_a_folder_is_pending_then_ok(
    server, case_dir, kape, monkeypatch
):  # noqa: F811
    _parse(server["evidence_register"](path=str(kape)))  # all small: in the call
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    first = _parse(server["evidence_verify"]())
    by = {r["path"].rsplit("/", 1)[1]: r for r in first["results"]}
    assert by["Security.evtx"]["status"] == "OK"
    assert by["pagefile.sys"]["status"] == "PENDING" and first["pending"] == 1
    _wait(case_dir, by["pagefile.sys"]["job_id"])
    second = _parse(server["evidence_verify"]())
    assert [r["status"] for r in second["results"]] == ["OK", "OK"], second
    assert "pending" not in second


def test_a_large_member_that_cant_be_read_is_listed_not_hashed_forever(
    server,
    case_dir,
    kape,
    monkeypatch,  # noqa: F811
):
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    big = kape / "pagefile.sys"
    big.chmod(0)
    try:
        first = _parse(server["evidence_register"](path=str(kape)))
        _wait(case_dir, first["job_id"])
        second = _parse(server["evidence_register"](path=str(kape)))  # no new job
        assert second.get("kind") == "folder", second
        m = json.loads((case_dir["path"] / second["manifest_path"]).read_text())
        assert [u["path"].rsplit("/", 1)[1] for u in m["unreadable"]] == [
            "pagefile.sys"
        ]
    finally:
        big.chmod(0o644)


def test_verify_of_a_member_that_turned_unreadable_ends_as_an_error(
    server,
    case_dir,
    kape,
    monkeypatch,  # noqa: F811
):
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    first = _parse(server["evidence_register"](path=str(kape)))
    _wait(case_dir, first["job_id"])
    assert _parse(server["evidence_register"](path=str(kape)))["kind"] == "folder"
    big = kape / "pagefile.sys"
    big.chmod(0)
    try:
        v = _parse(server["evidence_verify"]())
        (pending,) = [r for r in v["results"] if r["status"] == "PENDING"]
        _wait(case_dir, pending["job_id"])
        v = _parse(server["evidence_verify"]())  # the failure is taken: no new job
        by = {r["path"].rsplit("/", 1)[1]: r for r in v["results"]}
        assert by["pagefile.sys"]["status"] == "ERROR", by
        assert "Permission" in by["pagefile.sys"]["error"] and "pending" not in v
    finally:
        big.chmod(0o644)


def test_a_failure_is_taken_once_then_the_next_request_hashes_again(
    server,
    case_dir,
    kape,
    monkeypatch,  # noqa: F811
):
    """A transient read error (EIO) stops the automatic retry, once: the
    registration it belongs to lists the file as unreadable. The examiner's
    next request hashes it again, and the file, readable now, clears it."""
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    real, failed = fi.hash_file, []

    def flaky(path):
        if str(path).endswith("pagefile.sys") and not failed:
            failed.append(path)
            raise OSError(5, "Input/output error", str(path))
        return real(path)

    monkeypatch.setattr(fi, "hash_file", flaky)
    first = _parse(server["evidence_register"](path=str(kape)))
    _wait(case_dir, first["job_id"])
    second = _parse(server["evidence_register"](path=str(kape)))  # takes the failure
    m = json.loads((case_dir["path"] / second["manifest_path"]).read_text())
    assert [u["path"].rsplit("/", 1)[1] for u in m["unreadable"]] == ["pagefile.sys"]
    third = _parse(server["evidence_register"](path=str(kape)))  # asked again
    assert third.get("status") == "hashing" and third["job_id"] != first["job_id"], (
        third
    )
    _wait(case_dir, third["job_id"])
    big = str(kape / "pagefile.sys")
    assert fi.completed_hashes(case_dir["path"], [big]) == {
        big: {"sha256": hashlib.sha256(b"P" * 400).hexdigest()}
    }
