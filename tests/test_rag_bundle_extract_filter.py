"""The RAG index bundle can't write outside its destination when it's unpacked.

tarfile's "data" filter refuses a member that leaves the destination. It was
applied only on Python 3.12, so on 3.10 and 3.11, which have it too, a bundle
member such as ../x was written beside the index with no error. Synthetic
bundles only. The module is loaded from its file: CI doesn't install
forensic-rag, and this module needs only the standard library and zstandard.
"""

from __future__ import annotations

import importlib.util
import io
import os
import tarfile
from pathlib import Path

import pytest

zstd = pytest.importorskip("zstandard")

MODULE = (
    Path(__file__).resolve().parents[1]
    / "packages/forensic-rag/src/rag_mcp/scripts/download_index.py"
)

pytestmark = pytest.mark.skipif(
    not hasattr(tarfile, "data_filter"),
    reason="this Python's tarfile has no extraction filter",
)


def _module():
    spec = importlib.util.spec_from_file_location("download_index_under_test", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bundle(path: Path, members: list[tarfile.TarInfo | tuple[str, bytes]]) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for m in members:
            if isinstance(m, tarfile.TarInfo):
                tar.addfile(m)
            else:
                name, data = m
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    path.write_bytes(zstd.ZstdCompressor().compress(buf.getvalue()))
    return path


def test_a_member_that_climbs_out_of_the_destination_is_refused(tmp_path):
    dest = tmp_path / "index"
    dest.mkdir()
    src = _bundle(
        tmp_path / "evil.tar.zst",
        [("metadata.json", b"{}"), ("../escaped.txt", b"written outside\n")],
    )
    with pytest.raises(tarfile.FilterError):
        _module()._extract_bundle(src, dest)
    assert not (tmp_path / "escaped.txt").exists()


def test_a_link_that_points_out_of_the_destination_is_refused(tmp_path):
    dest = tmp_path / "index"
    dest.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tarfile.TarInfo("chroma")
    link.type = tarfile.SYMTYPE
    link.linkname = "../outside"
    src = _bundle(tmp_path / "evil.tar.zst", [link, ("chroma/x.bin", b"x")])
    with pytest.raises(tarfile.FilterError):
        _module()._extract_bundle(src, dest)
    assert list(outside.iterdir()) == []


def test_a_link_to_an_absolute_path_is_refused(tmp_path):
    dest = tmp_path / "index"
    dest.mkdir()
    link = tarfile.TarInfo("link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    src = _bundle(tmp_path / "evil.tar.zst", [link])
    with pytest.raises(tarfile.FilterError):
        _module()._extract_bundle(src, dest)
    assert not os.path.lexists(dest / "link")


def test_a_well_formed_bundle_still_unpacks(tmp_path):
    dest = tmp_path / "index"
    dest.mkdir()
    src = _bundle(
        tmp_path / "good.tar.zst",
        [("metadata.json", b'{"records": 2}'), ("chroma/data.bin", b"\x00\x01")],
    )
    _module()._extract_bundle(src, dest)
    assert (dest / "metadata.json").read_bytes() == b'{"records": 2}'
    assert (dest / "chroma/data.bin").read_bytes() == b"\x00\x01"
