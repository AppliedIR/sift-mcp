"""The RAG server sees a refreshed index without a restart, and a manual
re-download keeps one Chroma setting for the whole process.

A loaded index kept answering from what it loaded, while its stats showed the
new count, until the server restarted: Chroma keeps one system per path, so
only closing the client and opening it again reads the change. And
download_index opened its first client before setting ANONYMIZED_TELEMETRY,
so the refresh's later client was refused ("already exists ... with
different settings") and the examiner's documents were not put back.

The store rows use the real chromadb (skipped where it isn't installed) with
a stand-in embedding model; another process changes the store, as a refresh
or download does.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "packages/forensic-rag/src"
DIM = 8


def _vector(text: str) -> list[float]:
    digest = hashlib.sha256(text.encode()).digest()
    return [b / 255 + 0.01 for b in digest[:DIM]]


class _Embedded(list):
    def tolist(self):
        return list(self)


class FakeModel:
    """A deterministic stand-in for the sentence-transformers model."""

    def __init__(self, name: str = "") -> None:
        self.name = name

    def encode(self, texts):
        if isinstance(texts, str):
            return _Embedded(_vector(texts))
        return _Embedded(_Embedded(_vector(t)) for t in texts)


# --- the telemetry setting is the same for every client in a download ------


def test_every_chroma_client_in_a_download_sees_the_same_telemetry_setting(
    tmp_path, monkeypatch
):
    """Run with an examiner document on disk, so the refresh opens its client
    after the index check opened one."""
    zstd = pytest.importorskip("zstandard")
    import io
    import tarfile

    monkeypatch.delenv("ANONYMIZED_TELEMETRY", raising=False)
    seen: list = []

    class Client:
        def __init__(self, path: str, **kwargs) -> None:
            seen.append(os.environ.get("ANONYMIZED_TELEMETRY"))

        def get_collection(self, name):
            return types.SimpleNamespace(
                count=lambda: 30000,
                query=lambda **kw: {"ids": [["x"]]},
            )

    chroma = types.ModuleType("chromadb")
    chroma.PersistentClient = Client
    st = types.ModuleType("sentence_transformers")
    st.SentenceTransformer = FakeModel
    monkeypatch.setitem(sys.modules, "chromadb", chroma)
    monkeypatch.setitem(sys.modules, "sentence_transformers", st)

    pkg = "_rag_telemetry_under_test"
    for name, rel in ((pkg, "__init__.py"), (f"{pkg}.scripts", "scripts/__init__.py")):
        spec = importlib.util.spec_from_file_location(
            name, SRC / "rag_mcp" / rel, submodule_search_locations=[]
        )
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, mod)
    utils = types.ModuleType(f"{pkg}.utils")
    utils.DEFAULT_MODEL_NAME = "BAAI/bge-base-en-v1.5"
    monkeypatch.setitem(sys.modules, f"{pkg}.utils", utils)
    refresh_mod = types.ModuleType(f"{pkg}.refresh")

    def refresh(**kwargs):
        Client(path=str(kwargs["data_dir"] / "chroma"))
        return types.SimpleNamespace(status="success", errors=[])

    refresh_mod.refresh = refresh
    monkeypatch.setitem(sys.modules, f"{pkg}.refresh", refresh_mod)
    spec = importlib.util.spec_from_file_location(
        f"{pkg}.scripts.download_index",
        SRC / "rag_mcp/scripts/download_index.py",
    )
    dl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dl)

    rel = tmp_path / "release"
    rel.mkdir()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in (
            ("metadata.json", b'{"model": "BAAI/bge-base-en-v1.5"}'),
            ("chroma/chroma.sqlite3", b"index"),
            ("user_state.json", b'{"version": 1, "files": {}}'),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    (rel / "rag-index.tar.zst").write_bytes(
        zstd.ZstdCompressor().compress(buf.getvalue())
    )
    assets = [{"name": n, "url": str(rel / n)} for n in ("rag-index.tar.zst",)]
    monkeypatch.setattr(dl, "ASSETS", ("rag-index.tar.zst",))
    monkeypatch.setattr(dl, "_fetch_release", lambda tag="latest": {"assets": assets})
    monkeypatch.setattr(
        dl,
        "_download_asset",
        lambda url, d: Path(d).write_bytes(Path(url).read_bytes()),
    )
    # the examiner store's client comes first, then the index check's, then,
    # with bundled files to update, the refresh's
    monkeypatch.setattr(
        dl,
        "_sync_examiner_store",
        lambda dest: Client(path=str(dest / "user" / "chroma")) and 0,
    )
    monkeypatch.setattr(dl, "_bundled_drift", lambda dest: True)
    monkeypatch.setattr(dl, "_verify_index", lambda data_dir: Client(path="x") and True)
    dest = tmp_path / "data"
    (dest / "chroma").mkdir(parents=True)
    (dest / "user_state.json").write_text(
        json.dumps(
            {"version": 1, "files": {"mine.md": {"record_ids": ["user_mine_0"]}}}
        )
    )

    assert dl.download_index(dest) is True
    assert len(seen) == 3, seen
    assert set(seen) == {"False"}, seen


# --- the reader reopens a store another process changed --------------------


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A small real index, and a RAGIndex over it with the stand-in model."""
    pytest.importorskip("chromadb")
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "False")
    monkeypatch.syspath_prepend(str(SRC))
    index_mod = importlib.import_module("rag_mcp.index")
    monkeypatch.setattr(index_mod, "SentenceTransformer", FakeModel)
    data = tmp_path / "data"
    _write(data, {"a_0": "first record", "b_0": "second record"}, create=True)
    return data, index_mod.RAGIndex(index_dir=data)


_WRITER = r"""
import json, sys, chromadb
from pathlib import Path
data, records, create = Path(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3] == "1"
client = chromadb.PersistentClient(path=str(data / "chroma"))
if create:
    col = client.create_collection("ir_knowledge", metadata={"hnsw:space": "cosine"})
else:
    col = client.get_collection("ir_knowledge")
col.add(
    ids=list(records),
    documents=list(records.values()),
    embeddings=[v["vector"] for v in json.loads(sys.argv[4])],
    metadatas=[{"source": "probe"} for _ in records],
)
(data / "metadata.json").write_text(json.dumps({"record_count": col.count(), "sources": ["probe"]}))
"""


def _write(data: Path, records: dict, create: bool = False, keep_mtime=None) -> None:
    """Add records from a separate process, as a refresh or download does."""
    data.mkdir(parents=True, exist_ok=True)
    vectors = [{"vector": _vector(text)} for text in records.values()]
    subprocess.run(
        [
            sys.executable,
            "-c",
            _WRITER,
            str(data),
            json.dumps(records),
            "1" if create else "0",
            json.dumps(vectors),
        ],
        check=True,
        env={**os.environ, "ANONYMIZED_TELEMETRY": "False"},
        timeout=120,
    )
    if keep_mtime is not None:  # an extraction keeps the archive's mtime
        os.utime(data / "metadata.json", ns=keep_mtime)


def _top(index, query: str) -> list[str]:
    return [r["text"] for r in index.search(query, top_k=3)["results"]]


def test_a_loaded_index_sees_another_process_s_refresh(store):
    data, index = store
    assert "a note about lateral movement" not in _top(index, "x")
    _write(data, {"note_0": "a note about lateral movement"})
    assert _top(index, "a note about lateral movement")[0] == (
        "a note about lateral movement"
    )
    assert index.get_stats()["document_count"] == 3


def test_a_change_that_keeps_the_mtime_still_reloads(store):
    """Extracting the same bundle again keeps metadata.json's mtime."""
    data, index = store
    _top(index, "x")
    mtime = (data / "metadata.json").stat().st_mtime_ns
    _write(data, {"note_0": "a note about lateral movement"}, keep_mtime=(mtime, mtime))
    assert (data / "metadata.json").stat().st_mtime_ns == mtime
    assert _top(index, "a note about lateral movement")[0] == (
        "a note about lateral movement"
    )


def test_an_unchanged_index_is_not_reopened(store):
    data, index = store
    _top(index, "x")
    client = index._client
    _top(index, "y")
    index.get_stats()
    index.sources()
    assert index._client is client


def test_the_process_holds_one_client_per_store(store, monkeypatch):
    data, index = store
    import chromadb

    opened: list = []
    real = chromadb.PersistentClient

    def counting(*args, **kwargs):
        opened.append(kwargs.get("path") or args[0])
        return real(*args, **kwargs)

    index_mod = sys.modules["rag_mcp.index"]
    monkeypatch.setattr(index_mod.chromadb, "PersistentClient", counting)
    _top(index, "x")
    index.get_stats()
    index.sources()
    assert len(opened) == 1
    _write(data, {"note_0": "a note"})
    index.get_stats()
    index.sources()
    _top(index, "x")
    assert len(opened) == 2  # one reopen, shared by every call


def test_a_search_during_a_reload_waits_for_it(store):
    data, index = store
    _top(index, "x")
    real_open = index._open_stores

    def slow_open():
        time.sleep(0.3)
        real_open()

    index._open_stores = slow_open
    _write(data, {"note_0": "a note about lateral movement"})
    results: dict = {}

    def search(name):
        try:
            results[name] = _top(index, "a note about lateral movement")
        except Exception as e:  # noqa: BLE001 (the row is that none is raised)
            results[name] = e

    first = threading.Thread(target=search, args=("first",))
    first.start()
    time.sleep(0.1)  # the first search is reopening the store
    second = threading.Thread(target=search, args=("second",))
    second.start()
    first.join(10)
    second.join(10)
    for name in ("first", "second"):
        assert isinstance(results[name], list), results[name]
        assert results[name][0] == "a note about lateral movement"


def test_a_reload_waits_for_a_search_already_running(store):
    """A search reading the store holds it until it finishes, so another
    thread's reload can't close the store under it."""
    data, index = store
    _top(index, "x")
    real_nearest, real_close = index._nearest, index._close_stores
    started, go, closed = threading.Event(), threading.Event(), threading.Event()

    def held_nearest(*args):
        started.set()
        go.wait(10)
        return real_nearest(*args)

    def noted_close():
        real_close()
        closed.set()

    index._nearest = held_nearest
    index._close_stores = noted_close
    results: dict = {}

    def search(name):
        try:
            results[name] = _top(index, "x")
        except Exception as e:  # noqa: BLE001 (the row is that none is raised)
            results[name] = e

    first = threading.Thread(target=search, args=("first",))
    first.start()
    assert started.wait(10)
    _write(data, {"note_0": "a note"})
    index._nearest = real_nearest
    second = threading.Thread(target=search, args=("second",))
    second.start()
    closed.wait(2)  # without the lock, the reload closes the store now
    go.set()
    first.join(10)
    second.join(10)
    for name in ("first", "second"):
        assert isinstance(results[name], list), results[name]
