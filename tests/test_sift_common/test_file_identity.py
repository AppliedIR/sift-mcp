"""File identity: one SHA-256 of a regular file, with no size cap.

Inputs over 1 GB were recorded as "skipped:too_large", which breaks the hash
link for every memory or disk image. A FIFO, device or directory is refused
without being read, so it never blocks the caller.
"""

from __future__ import annotations

import hashlib
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
