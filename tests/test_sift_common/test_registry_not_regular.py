"""A registry that isn't a regular file reads as no registry, and never blocks.

`evidence.json` as a FIFO (idle, held open by another process, or holding
the registry's bytes) or a link to a device: `registered_hash` returns None,
as with no registry, without waiting for a writer or reading without end.
Each call runs in a forked child with a hard join timeout, so a blocking read
fails the test instead of hanging it.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import resource

import pytest
from sift_common import file_identity as fi

CTX = mp.get_context("fork")


def _child(fn, q):
    # a read from a device fails, rather than taking the box's memory
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    try:
        q.put(("ok", fn()))
    except BaseException as e:  # noqa: BLE001 - reported to the parent
        q.put(("raised", f"{type(e).__name__}: {e}"))


def _within(fn, timeout=5.0):
    """What `fn` returns in a forked child, or 'blocked' if it doesn't within
    `timeout` (the child is then killed)."""
    q = CTX.Queue()
    p = CTX.Process(target=_child, args=(fn, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.kill()
        p.join()
        return ("blocked",)
    return q.get(timeout=5)


@pytest.fixture
def case(tmp_path):
    x = tmp_path / "evidence" / "x.bin"
    x.parent.mkdir()
    x.write_bytes(b"registered evidence bytes\n")
    sha = hashlib.sha256(x.read_bytes()).hexdigest()
    body = json.dumps(
        {"files": [{"path": os.path.realpath(x), "sha256": sha}]}
    ).encode()
    (tmp_path / "evidence.json").write_bytes(body)
    return tmp_path, x, sha, body


def _fifo(path):
    path.unlink()
    os.mkfifo(path)


def test_a_regular_registry_gives_the_registered_hash(case):
    d, x, sha, _ = case
    assert _within(lambda: fi.registered_hash(d, x)) == ("ok", sha)


def test_no_registry_gives_none(case):
    d, x, _, _ = case
    (d / "evidence.json").unlink()
    assert _within(lambda: fi.registered_hash(d, x)) == ("ok", None)


def test_a_fifo_registry_gives_none_without_waiting(case):
    d, x, _, _ = case
    _fifo(d / "evidence.json")
    assert _within(lambda: fi.registered_hash(d, x)) == ("ok", None)


@pytest.mark.parametrize("fed", [False, True], ids=["idle", "holding the registry"])
def test_a_fifo_registry_another_process_holds_open_gives_none(case, fed):
    """A writer holds it open, so an open succeeds: only the type check
    keeps the read from waiting, or from taking a hash out of a pipe."""
    d, x, _, body = case
    _fifo(d / "evidence.json")
    wfd = os.open(d / "evidence.json", os.O_RDWR)
    try:
        if fed:
            os.write(wfd, body)
        assert _within(lambda: fi.registered_hash(d, x)) == ("ok", None)
    finally:
        os.close(wfd)


def test_a_registry_linked_to_a_device_gives_none(case):
    d, x, _, _ = case
    (d / "evidence.json").unlink()
    (d / "evidence.json").symlink_to("/dev/zero")
    assert _within(lambda: fi.registered_hash(d, x)) == ("ok", None)


def test_read_regular_reads_a_regular_file_and_refuses_anything_else(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"bytes")
    assert _within(lambda: fi.read_regular(f)) == ("ok", b"bytes")
    os.mkfifo(tmp_path / "p")
    for path in (tmp_path / "p", tmp_path, "/dev/null"):
        kind, *why = _within(lambda p=path: fi.read_regular(p))
        assert kind == "raised" and why[0].startswith("NotRegularFile"), (
            path,
            kind,
            why,
        )
