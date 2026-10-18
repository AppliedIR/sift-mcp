"""folder_record with ``known``: the caller's own hashes of files it wrote
in this run give the digest when they cover every member, with nothing
hashed and neither the place nor the size bounds in force; otherwise the walk
is the usual one."""

from __future__ import annotations

import hashlib
import os

import pytest
from sift_common import file_identity as fi
from sift_common import file_place

MEMBERS = {"a.pf": b"alpha", "sub/b.pf": b"b" * 400, ".hidden": b"dot"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _folder(root, members=MEMBERS):
    for rel, data in members.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def _known(root, members=MEMBERS) -> dict:
    real = os.path.realpath(root)
    return {os.path.join(real, rel): _sha(data) for rel, data in members.items()}


def _digest(members=MEMBERS) -> str:
    return fi.folder_digest([(rel, _sha(data)) for rel, data in members.items()])


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    return d


def _no_hashing(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("a known member was hashed")

    monkeypatch.setattr(fi, "hash_file", refuse)


def test_known_members_outside_the_case_and_over_the_bounds_get_the_digest(
    case, tmp_path, monkeypatch
):
    folder = _folder(tmp_path / "x" / "Prefetch")
    _no_hashing(monkeypatch)
    monkeypatch.setattr(fi, "FOLDER_FILES", 2)
    monkeypatch.setattr(fi, "FOLDER_BYTES", 10)
    got = file_place.folder_record(case, file_place.place(folder), _known(folder))
    assert got == {"files": 3, "bytes": 408, "sha256": _digest()}


def test_input_record_passes_known_through(case, tmp_path, monkeypatch):
    folder = _folder(tmp_path / "x" / "Prefetch")
    _no_hashing(monkeypatch)
    rec, reg = file_place.input_record(
        case, folder, "t", folder=True, known=_known(folder)
    )
    assert reg is None and "sha256" not in rec
    assert rec["folder"] == {"files": 3, "bytes": 408, "sha256": _digest()}


def test_one_unknown_member_outside_the_case_is_no_record_and_hashes_nothing(
    case, tmp_path, monkeypatch
):
    folder = _folder(tmp_path / "x" / "Prefetch")
    known = _known(folder)
    known.pop(os.path.join(os.path.realpath(folder), "sub/b.pf"))
    _no_hashing(monkeypatch)
    assert file_place.folder_record(case, file_place.place(folder), known) is None


def test_one_unknown_member_in_the_case_is_the_usual_walk(case, monkeypatch):
    folder = _folder(case / "extractions" / "Prefetch")
    known = _known(folder)
    known.pop(os.path.join(os.path.realpath(folder), "a.pf"))
    known[os.path.join(os.path.realpath(folder), ".hidden")] = "0" * 64  # never used
    got = file_place.folder_record(case, file_place.place(folder), known)
    assert got == file_place.folder_record(case, file_place.place(folder))
    assert got == {"files": 3, "bytes": 408, "sha256": _digest()}
    monkeypatch.setattr(fi, "FOLDER_FILES", 2)  # the usual walk keeps its bounds
    assert file_place.folder_record(case, file_place.place(folder), known) is None


@pytest.mark.parametrize("shape", ["file symlink", "folder symlink", "fifo"])
def test_known_members_never_lift_the_refusals(case, tmp_path, monkeypatch, shape):
    folder = _folder(tmp_path / "x" / "Prefetch")
    known = _known(folder)
    if shape == "file symlink":
        os.symlink(folder / "a.pf", folder / "link.pf")
    elif shape == "folder symlink":
        os.symlink(folder / "sub", folder / "linkdir")
    else:
        os.mkfifo(folder / "pipe")
    _no_hashing(monkeypatch)
    assert file_place.folder_record(case, file_place.place(folder), known) is None


@pytest.mark.parametrize("known", [None, {}], ids=["None", "empty"])
def test_without_known_nothing_changes(case, tmp_path, known):
    inside = _folder(case / "extractions" / "Prefetch")
    outside = _folder(tmp_path / "x" / "Prefetch")
    assert file_place.folder_record(case, file_place.place(inside), known) == {
        "files": 3, "bytes": 408, "sha256": _digest()}  # fmt: skip
    assert file_place.folder_record(case, file_place.place(outside), known) is None
