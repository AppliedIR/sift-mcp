"""sift-common's case-file reader: a FIFO, device or folder is refused unread,
by name; a line or a document of any size is read whole. Each read that could
block runs in a forked child with an alarm and its address space capped, so a
regression fails the test, not the box.
"""

from __future__ import annotations

import os
import pickle
import resource
import signal
import sys

import pytest
from sift_common import file_identity as fi

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")
NOT_REGULAR = ("{p} isn't a regular file (a named pipe, socket or device). Put the "
               "case's own file back, then try again.")  # fmt: skip
FOLDER = "{p} is a folder, not a file. Put the case's own file back, then try again."
MIB_16 = 16 << 20  # the most a case file's line or document could once hold


def _child(fn, secs=5):
    """("ok", value) or ("raised", "Class: text") from fn in a forked child with
    a `secs` alarm and 1 GiB more address space than it starts with."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            with open("/proc/self/statm") as f:
                size = int(f.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
            resource.setrlimit(resource.RLIMIT_AS, (size + (1 << 30),) * 2)
            signal.alarm(secs)
            out = ("ok", fn())
        except BaseException as e:  # noqa: BLE001
            out = ("raised", f"{type(e).__name__}: {e}")
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    data = b""
    while chunk := os.read(r, 65536):
        data += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return pickle.loads(data) if data else ("killed",)


@pytest.mark.parametrize("how", ["fifo", "devzero", "folder"])
def test_a_fifo_device_or_folder_is_refused_unread_by_name(tmp_path, how):
    p = tmp_path / "wintools-mcp.jsonl"
    if how == "fifo":
        os.mkfifo(p)
    elif how == "devzero":
        p.symlink_to("/dev/zero")
    else:
        p.mkdir()
    text = (FOLDER if how == "folder" else NOT_REGULAR).format(p=p)
    assert _child(lambda: list(fi.case_lines(p))) == (
        "raised",
        f"NotRegularFile: {text}",
    )
    assert _child(lambda: fi.read_document(p)) == ("raised", f"NotRegularFile: {text}")


def test_the_refusal_is_not_an_oserror():
    """A reader that passes over an unreadable file (except OSError) must not
    pass over this one: it reaches the portal's 409."""
    assert not issubclass(fi.NotRegularFile, OSError)


@pytest.mark.parametrize("end", [b"\n", b"\r\n", b""], ids=["LF", "CRLF", "last-line"])
def test_a_line_over_16_mib_is_read_whole_with_its_line_end(tmp_path, end):
    """Case logs written on Windows end their lines in CRLF: a line of any
    length is one record with either end, or none."""
    p = tmp_path / "wintools-mcp.jsonl"
    p.write_bytes(b"x" * (MIB_16 + 1) + end)
    assert [len(raw) for raw in fi.case_lines(p)] == [MIB_16 + 1 + len(end)]


def test_long_lines_are_each_read_whole(tmp_path):
    p = tmp_path / "a.jsonl"
    with open(p, "wb") as f:
        f.write(b"x" * MIB_16 + b"\n")
        f.write(b"y" * (64 << 20) + b"\n")
        f.write(b"z\n")
    got = _child(lambda: [len(raw) for raw in fi.case_lines(p)], secs=30)
    assert got == ("ok", [MIB_16 + 1, (64 << 20) + 1, 2])


def test_a_document_over_16_mib_is_read(tmp_path):
    p = tmp_path / "evidence.json"
    with open(p, "wb") as f:
        f.truncate(MIB_16 + 1)
    assert _child(lambda: len(fi.read_document(p))) == ("ok", MIB_16 + 1)


def test_a_fifo_swapped_in_after_any_path_check_is_still_refused(tmp_path, monkeypatch):
    p = tmp_path / "wintools-mcp.jsonl"
    p.write_text('{"audit_id": "x"}\n')
    real = os.open

    def swap_then_open(path, *a, **k):
        if os.fspath(path) == str(p) and not p.is_fifo():
            p.unlink()
            os.mkfifo(p)
        return real(path, *a, **k)

    monkeypatch.setattr(os, "open", swap_then_open)
    assert _child(lambda: list(fi.case_lines(p))) == (
        "raised", "NotRegularFile: " + NOT_REGULAR.format(p=p))  # fmt: skip
