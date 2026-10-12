"""sift-common's case-file reader: a FIFO, device or folder is refused unread,
by name; a line over LINE_CAP or a document over DOC_CAP is refused by name,
never held whole. Each read that could block runs in a forked child with an
alarm and its address space capped, so a regression fails the test, not the box.
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
LONG = ("{p} line {n} is longer than 16 MiB, so the file wasn't read past it. It holds "
        "the case's {what}: keep a copy of it before you move it out of the case, then "
        "try again.")  # fmt: skip
LARGE = ("{p} is larger than 16 MiB, so it wasn't read. It holds the case's {what}: keep "
         "a copy of it before you move it out of the case, then try again.")  # fmt: skip


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
    assert _child(lambda: list(fi.capped_lines(p))) == (
        "raised",
        f"NotRegularFile: {text}",
    )
    assert _child(lambda: fi.read_document(p)) == ("raised", f"NotRegularFile: {text}")


@pytest.mark.parametrize("rel,what", [
    ("findings.json", "findings"), ("todos.json", "TODOs"), ("CASE.yaml", "case details"),
    ("audit/wintools-mcp.jsonl", "audit entries"), ("host-ops.json", "host-operation records"),
    ("other.json", "case records")])  # fmt: skip
def test_an_over_cap_text_says_what_the_file_holds(tmp_path, rel, what):
    p = tmp_path / rel
    p.parent.mkdir(exist_ok=True)
    with open(p, "wb") as f:
        f.truncate(fi.DOC_CAP + 1)
    assert _child(lambda: fi.read_document(p))[1] == (
        f"CaseFileTooBig: {LARGE.format(p=p, what=what)}")  # fmt: skip


def test_the_refusals_are_not_oserrors():
    """A reader that passes over an unreadable file (except OSError) must not
    pass over these: they reach the portal's 409."""
    assert not issubclass(fi.CaseFileTooBig, OSError)
    assert not issubclass(fi.NotRegularFile, OSError)


def test_the_cap_boundary_and_a_long_line_named_never_held(tmp_path):
    p = tmp_path / "a.jsonl"
    with open(p, "wb") as f:
        f.write(b"x" * fi.LINE_CAP + b"\n")  # exactly the cap: read
        f.write(b"y" * (128 << 20) + b"\n")  # 128 MiB: refused at line 2

    def read():
        import tracemalloc

        tracemalloc.start()
        got = []
        try:
            for raw in fi.capped_lines(p):
                got.append(len(raw))
        except fi.CaseFileTooBig as e:
            return got, e.line, str(e), tracemalloc.get_traced_memory()[1]

    kind, (got, line, text, peak) = _child(read, secs=30)
    assert (kind, got, line) == ("ok", [fi.LINE_CAP + 1], 2)
    assert text == LONG.format(p=p, n=2, what="case records")
    # the line before, the read buffer and its join: never the 128 MiB line whole
    assert peak <= 3 * fi.LINE_CAP + (8 << 20)


def test_a_document_over_the_cap_is_refused_from_its_size(tmp_path):
    p = tmp_path / "evidence.json"
    with open(p, "wb") as f:
        f.truncate(fi.DOC_CAP + 1)
    assert _child(lambda: fi.read_document(p)) == (
        "raised", f"CaseFileTooBig: {LARGE.format(p=p, what='evidence records')}")  # fmt: skip
    with open(p, "wb") as f:
        f.truncate(fi.DOC_CAP)  # exactly the cap: read
    assert _child(lambda: len(fi.read_document(p))) == ("ok", fi.DOC_CAP)


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
    assert _child(lambda: list(fi.capped_lines(p))) == (
        "raised", "NotRegularFile: " + NOT_REGULAR.format(p=p))  # fmt: skip
