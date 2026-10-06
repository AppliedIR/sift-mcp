"""Downloading the RAG index again keeps the user's own documents.

The download replaces the index, and the bundle's user_state.json lists what
the new index holds. Writing the pre-download state back over it told the
refresh that the user's documents were already embedded, so they were dropped
from the index with no error. Synthetic bundles only: GitHub, the index check
and the refresh are stubbed. The module is loaded from its file, because CI
doesn't install forensic-rag.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import types
from pathlib import Path

import pytest

zstd = pytest.importorskip("zstandard")

MODULE = (
    Path(__file__).resolve().parents[1]
    / "packages/forensic-rag/src/rag_mcp/scripts/download_index.py"
)
PKG = "_rag_redownload_under_test"

SHIPPED = {"AppliedIR/ref.jsonl": {"hash": "1" * 64, "record_ids": ["user_ref_0"]}}
MINE = {"mine.md": {"hash": "2" * 64, "record_ids": ["user_mine_0"]}}


def _state(files: dict) -> bytes:
    return json.dumps({"version": 1, "files": files}).encode()


def _release(tmp_path: Path) -> Path:
    rel = tmp_path / "release"
    rel.mkdir()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in (
            ("metadata.json", b"{}"),
            ("chroma/chroma.sqlite3", b"the new index"),
            ("user_state.json", _state(SHIPPED)),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    bundle = rel / "rag-index.tar.zst"
    bundle.write_bytes(zstd.ZstdCompressor().compress(buf.getvalue()))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (rel / "rag-checksums.sha256").write_text(f"{digest} rag-index.tar.zst\n")
    return rel


@pytest.fixture
def download(tmp_path, monkeypatch):
    """Run download_index against a local release; return the states the refresh saw."""
    seen: list = []

    def refresh(**kwargs):
        state = Path(kwargs["data_dir"]) / "user_state.json"
        seen.append(json.loads(state.read_text()) if state.exists() else None)
        return types.SimpleNamespace(status="success", errors=[])

    fake = types.ModuleType(f"{PKG}.refresh")
    fake.refresh = refresh
    monkeypatch.setitem(sys.modules, f"{PKG}.refresh", fake)
    spec = importlib.util.spec_from_file_location(f"{PKG}.scripts.dl", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    rel = _release(tmp_path)
    assets = [{"name": n, "url": str(rel / n)} for n in mod.ASSETS]
    monkeypatch.setattr(mod, "_fetch_release", lambda tag="latest": {"assets": assets})
    monkeypatch.setattr(
        mod,
        "_download_asset",
        lambda url, d: Path(d).write_bytes(Path(url).read_bytes()),
    )
    monkeypatch.setattr(mod, "_verify_index", lambda data_dir: True)

    def run(dest: Path) -> list:
        assert mod.download_index(dest) is True
        return seen

    return run


def test_the_refresh_after_a_redownload_sees_the_users_documents_as_new(
    tmp_path, download
):
    dest = tmp_path / "data"
    (dest / "chroma").mkdir(parents=True)
    (dest / "chroma/chroma.sqlite3").write_bytes(b"the old index, with mine.md")
    (dest / "user_state.json").write_bytes(_state({**SHIPPED, **MINE}))

    seen = download(dest)

    assert len(seen) == 1, "the user's documents must be re-embedded"
    assert seen[0]["files"] == SHIPPED
    assert json.loads((dest / "user_state.json").read_text())["files"] == SHIPPED


def test_a_first_download_installs_the_bundles_state_and_skips_the_refresh(
    tmp_path, download
):
    dest = tmp_path / "data"

    seen = download(dest)

    assert seen == []
    assert json.loads((dest / "user_state.json").read_text())["files"] == SHIPPED


def test_a_redownload_without_user_documents_installs_the_bundles_state_and_skips_the_refresh(
    tmp_path, download, capsys
):
    dest = tmp_path / "data"
    (dest / "chroma").mkdir(parents=True)
    (dest / "chroma/chroma.sqlite3").write_bytes(b"the old index")
    (dest / "user_state.json").write_bytes(_state({}))

    seen = download(dest)

    assert seen == []
    assert json.loads((dest / "user_state.json").read_text())["files"] == SHIPPED
    assert "Restored user_state.json" not in capsys.readouterr().out
