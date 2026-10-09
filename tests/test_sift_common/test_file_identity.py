"""File identity: one SHA-256 of a regular file, with no size cap.

Inputs over 1 GB were recorded as "skipped:too_large", which breaks the hash
link for every memory or disk image. A FIFO, device or directory is refused
without being read, so it never blocks the caller.
"""

from __future__ import annotations

import hashlib
import json
import os

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
