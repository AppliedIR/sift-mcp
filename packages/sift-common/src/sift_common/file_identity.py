"""File identity: the SHA-256 of a regular file, with no size cap.

Every place that records what a file is hashes it here, so a hash in one
entry can be compared with a hash in another.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass

_CHUNK = 1 << 20


class NotRegularFile(ValueError):
    """Only a regular file has an identity hash: a FIFO, device, socket or
    directory is refused without being read."""


@dataclass(frozen=True)
class HashResult:
    path: str
    sha256: str
    size: int
    st_dev: int
    st_ino: int
    mtime_ns: int


def hash_file(path) -> HashResult:
    """The SHA-256 of the whole file, however large. The file is opened
    non-blocking and checked before any read, so a FIFO never blocks."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise NotRegularFile(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        h = hashlib.sha256()
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return HashResult(
        str(path), h.hexdigest(), st.st_size, st.st_dev, st.st_ino, st.st_mtime_ns
    )
