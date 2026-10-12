"""provenance.load_case reads a registry that isn't a regular file as none.

`evidence.json` linked to /dev/zero, or a FIFO another process holds open
with a registry in it: no roots, at once, without reading without end or
taking a registry out of a pipe. Each call runs in a forked child with a hard
join timeout and its address space capped.
"""

from __future__ import annotations

import hashlib
import json
import os

from sift_common import provenance as pv

from .test_registry_not_regular import _within


def _case(tmp_path):
    x = tmp_path / "evidence" / "x.bin"
    x.parent.mkdir()
    x.write_bytes(b"registered evidence bytes\n")
    sha = hashlib.sha256(x.read_bytes()).hexdigest()
    body = json.dumps(
        {"files": [{"path": os.path.realpath(x), "sha256": sha}]}
    ).encode()
    (tmp_path / "audit").mkdir()
    (tmp_path / "evidence.json").write_bytes(body)
    return body


def _roots(d):
    return len(pv.load_case(d).roots)


def test_a_regular_registry_gives_its_roots(tmp_path):
    _case(tmp_path)
    assert _within(lambda: _roots(tmp_path)) == ("ok", 1)


def test_a_registry_linked_to_dev_zero_gives_no_roots(tmp_path):
    _case(tmp_path)
    (tmp_path / "evidence.json").unlink()
    (tmp_path / "evidence.json").symlink_to("/dev/zero")
    assert _within(lambda: _roots(tmp_path)) == ("ok", 0)


def test_a_held_fifo_registry_gives_no_roots(tmp_path):
    body = _case(tmp_path)
    (tmp_path / "evidence.json").unlink()
    os.mkfifo(tmp_path / "evidence.json")
    fd = os.open(tmp_path / "evidence.json", os.O_RDWR)
    try:
        os.write(fd, body)
        assert _within(lambda: _roots(tmp_path)) == ("ok", 0)
    finally:
        os.close(fd)
