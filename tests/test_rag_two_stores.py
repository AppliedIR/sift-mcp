"""The examiner's knowledge-folder documents live in their own store.

One collection held the shipped knowledge and the examiner's documents. A
re-download replaced it and dropped the examiner's records; lite's state files
sat in the package directory whatever the data directory was, so a document
lost there was never embedded again; a release build bundled the builder's
own documents; and the examiner's best match was missed in the 22k-record
graph. Now user/ holds the examiner store, built from the folder and
committed by its metadata.json; writers commit it before they remove the old
copies from the shipped store; and search merges both, marked by origin.

Real chromadb (skipped where it isn't installed) with a stand-in embedding
model; the package's data directory is redirected to scratch, so no test
writes into the source tree.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "packages/forensic-rag/src"
DIM = 8
MODEL = "BAAI/bge-base-en-v1.5"
OTHER_MODEL = "BAAI/bge-small-en-v1.5"
NOTE = "Lateral movement used PsExec from the jump host at 03:12."
EDITED = "Lateral movement used WMI from the jump host at 03:53."
REF = "Bundled reference: event 4624 logon types."


def _vector(text: str) -> list[float]:
    digest = hashlib.sha256(text.encode()).digest()
    return [b / 255 + 0.01 for b in digest[:DIM]]


class _Embedded(list):
    def tolist(self):
        return list(self)


class FakeModel:
    def __init__(self, name: str = "") -> None:
        self.name = name

    def encode(self, texts):
        if isinstance(texts, str):
            return _Embedded(_vector(texts))
        return _Embedded(_Embedded(_vector(t)) for t in texts)


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """The rag_mcp modules with the stand-in model, the package data dir in
    scratch, and an install: a shipped store, a bundled knowledge file and
    the examiner's note."""
    pytest.importorskip("chromadb")
    st = pytest.importorskip("sentence_transformers")
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "False")
    for var in ("RAG_INDEX_DIR", "RAG_MODEL_NAME", "RAG_KNOWLEDGE_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.syspath_prepend(str(SRC))
    monkeypatch.setattr(st, "SentenceTransformer", FakeModel)
    mods = {
        n: importlib.import_module(f"rag_mcp.{n}")
        for n in ("utils", "ingest", "stores", "refresh", "build", "index", "status")
    }
    mods["download"] = importlib.import_module("rag_mcp.scripts.download_index")
    for n in ("refresh", "build", "index"):
        monkeypatch.setattr(mods[n], "SentenceTransformer", FakeModel)
    pkg = tmp_path / "pkg" / "data"
    pkg.mkdir(parents=True)
    for n in ("utils", "stores"):
        monkeypatch.setattr(mods[n], "PACKAGE_DATA_DIR", pkg)
    monkeypatch.setattr(mods["build"], "SOURCES_DIR", tmp_path / "sources")

    know = tmp_path / "knowledge"
    (know / "AppliedIR").mkdir(parents=True)
    (know / "AppliedIR" / ".bundled").touch()
    (know / "AppliedIR" / "ref.md").write_text(REF)
    (know / "notes").mkdir()
    (know / "notes" / "probe-note.md").write_text(NOTE)
    monkeypatch.setenv("RAG_KNOWLEDGE_DIR", str(know))
    data = tmp_path / "data"

    class Rig:
        pass

    rig = Rig()
    rig.__dict__.update(mods)
    rig.pkg, rig.know, rig.data, rig.tmp = pkg, know, data, tmp_path
    return rig


def _client(path: Path):
    import chromadb

    return chromadb.PersistentClient(path=str(path))


def _legacy_install(rig, examiner: bool = True) -> None:
    """The layout before this change: one store, one state file; with
    examiner=True the note was refreshed into the shipped store."""
    data = rig.data
    (data / "chroma").mkdir(parents=True)
    client = _client(data / "chroma")
    col = client.create_collection("ir_knowledge", metadata={"hnsw:space": "cosine"})
    records = {
        "sigma_0": ("Sigma rule for PsExec service install.", {"source": "sigma"}),
        "user_ref_0": (REF, {"source": "user_ref", "file": "AppliedIR/ref.md"}),
    }
    files = {
        "AppliedIR/ref.md": {
            "hash": rig.utils.compute_file_hash(rig.know / "AppliedIR" / "ref.md"),
            "record_ids": ["user_ref_0"],
        }
    }
    if examiner:
        path = rig.know / "notes" / "probe-note.md"
        records["user_probe-note_0"] = (
            NOTE,
            {"source": "user_probe-note", "file": str(path)},
        )
        files["notes/probe-note.md"] = {
            "hash": rig.utils.compute_file_hash(path),
            "record_ids": ["user_probe-note_0"],
        }
    col.add(
        ids=list(records),
        documents=[d for d, _ in records.values()],
        metadatas=[m for _, m in records.values()],
        embeddings=[_vector(d) for d, _ in records.values()],
    )
    client.close()
    (data / "metadata.json").write_text(
        json.dumps({"model": MODEL, "record_count": len(records), "sources": ["sigma"]})
    )
    (data / "user_state.json").write_text(json.dumps({"version": 1, "files": files}))


def _new_process() -> None:
    """Chroma caches one system per path in a process; refresh and build run
    as separate processes in use, so drop the cache between them here."""
    from chromadb.api.client import SharedSystemClient

    SharedSystemClient.clear_system_cache()


def _ids(path: Path, collection: str) -> dict[str, str]:
    client = _client(path)
    try:
        got = client.get_collection(collection).get(include=["documents"])
        return dict(zip(got["ids"], got["documents"], strict=True))
    finally:
        client.close()


def _shipped(rig) -> dict[str, str]:
    return _ids(rig.data / "chroma", "ir_knowledge")


def _user(rig) -> dict[str, str]:
    return _ids(rig.data / "user" / "chroma", "user_knowledge")


def _refresh(rig, **kw):
    return rig.refresh.refresh(skip_online=True, data_dir=rig.data, **kw)


def _search(rig, query: str, top_k: int = 5) -> dict:
    index = rig.index.RAGIndex(index_dir=rig.data)
    try:
        return index.search(query, top_k=top_k)
    finally:
        index._close_stores()


def _user_unchanged(rig):
    """user/'s state and commit files byte for byte, and its records.

    Chroma rewrites chroma.sqlite3 on every open, even one that only reads
    (measured), so the store's own files can't be compared byte for byte.
    """
    files = {
        f: (rig.data / "user" / f).read_bytes()
        for f in ("user_state.json", "metadata.json")
    }
    return files, _user(rig)


def _snapshot(rig) -> dict[str, str]:
    return {
        str(p.relative_to(rig.data)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(rig.data.rglob("*"))
        if p.is_file()
    }


# --- the one-time build and the commit ------------------------------------


def test_the_first_refresh_builds_the_examiner_store_from_the_folder(rig):
    _legacy_install(rig)
    result = _refresh(rig)
    assert result.status == "success", result.errors
    assert _user(rig) == {"user_probe-note_0": NOTE}
    assert _shipped(rig) == {
        "sigma_0": "Sigma rule for PsExec service install.",
        "user_ref_0": REF,
    }
    state = json.loads((rig.data / "user_state.json").read_text())
    assert list(state["files"]) == ["AppliedIR/ref.md"]
    meta = json.loads((rig.data / "user" / "metadata.json").read_text())
    assert (meta["model"], meta["hnsw:space"], meta["record_count"]) == (
        MODEL,
        "cosine",
        1,
    )
    found = _search(rig, NOTE)["results"]
    assert (found[0]["text"], found[0]["origin"]) == (NOTE, "user")


def test_a_second_run_with_no_change_rewrites_nothing(rig):
    _legacy_install(rig)
    _refresh(rig)
    files = ("user_state.json", "user/user_state.json", "user/metadata.json")
    before = {f: (rig.data / f).read_bytes() for f in files}
    ids = (_shipped(rig), _user(rig))
    _refresh(rig)
    assert {f: (rig.data / f).read_bytes() for f in files} == before
    assert (_shipped(rig), _user(rig)) == ids


def test_a_crash_before_the_commit_keeps_every_record_reachable(rig, monkeypatch):
    _legacy_install(rig)
    real = rig.stores.atomic_write_json

    def crash(path, data, *a, **k):
        if Path(path).name == "metadata.json" and Path(path).parent.name == "user":
            raise OSError("killed before the commit")
        return real(path, data, *a, **k)

    monkeypatch.setattr(rig.stores, "atomic_write_json", crash)
    assert _refresh(rig).status == "error"
    assert rig.stores.layout(rig.data) == "uncommitted"
    assert _shipped(rig)["user_probe-note_0"] == NOTE  # still reachable
    result = _search(rig, NOTE)
    assert "origin" not in result["results"][0] and "notice" in result
    assert result["results"][0]["text"] == NOTE

    monkeypatch.setattr(rig.stores, "atomic_write_json", real)
    (rig.know / "notes" / "probe-note.md").write_text(EDITED)
    assert _refresh(rig).status == "success"
    assert _user(rig) == {"user_probe-note_0": EDITED}
    assert "user_probe-note_0" not in _shipped(rig)


def test_a_crash_after_the_commit_shows_no_duplicate_and_converges(rig, monkeypatch):
    _legacy_install(rig)
    real = rig.refresh.cleanup_shipped

    def crash(*a, **k):
        raise OSError("killed before the cleanup")

    monkeypatch.setattr(rig.refresh, "cleanup_shipped", crash)
    with pytest.raises(OSError):
        _refresh(rig)
    assert _shipped(rig)["user_probe-note_0"] == NOTE
    assert _user(rig)["user_probe-note_0"] == NOTE
    texts = [r["text"] for r in _search(rig, NOTE, top_k=10)["results"]]
    assert texts.count(NOTE) == 1

    monkeypatch.setattr(rig.refresh, "cleanup_shipped", real)
    _refresh(rig)
    assert "user_probe-note_0" not in _shipped(rig)


def test_a_record_sharing_a_bundled_id_is_still_found(rig):
    """An examiner file named like a bundled file shares its record ids."""
    _legacy_install(rig, examiner=False)
    (rig.know / "notes" / "ref.md").write_text("My own notes on logon type 10.")
    _refresh(rig)
    assert _user(rig)["user_ref_0"] == "My own notes on logon type 10."
    origins = {(r["text"], r["origin"]) for r in _search(rig, REF, top_k=10)["results"]}
    assert (REF, "shipped") in origins
    assert ("My own notes on logon type 10.", "user") in origins


def test_a_lost_state_entry_still_replaces_the_file_s_old_records(rig):
    _legacy_install(rig, examiner=False)
    note = rig.know / "notes" / "probe-note.md"
    note.write_text("## one\n" + "a" * 900 + "\n## two\n" + "b" * 900)
    _refresh(rig)
    assert len([i for i in _user(rig) if i.startswith("user_probe-note_")]) == 2
    state_path = rig.data / "user" / "user_state.json"
    state = json.loads(state_path.read_text())
    state["files"].pop("notes/probe-note.md")
    state_path.write_text(json.dumps(state))
    note.write_text(EDITED)
    _refresh(rig)
    assert {i: d for i, d in _user(rig).items() if "probe-note" in i} == {
        "user_probe-note_0": EDITED
    }


def test_a_store_missing_a_listed_record_gets_the_file_again(rig):
    _legacy_install(rig)
    _refresh(rig)
    client = _client(rig.data / "user" / "chroma")
    client.get_collection("user_knowledge").delete(ids=["user_probe-note_0"])
    client.close()
    _refresh(rig)
    assert _user(rig) == {"user_probe-note_0": NOTE}


# --- lite: the state follows the data directory ---------------------------


def test_lite_a_new_document_is_one_document_and_one_record(rig, monkeypatch):
    _legacy_install(rig, examiner=False)
    monkeypatch.setenv("RAG_INDEX_DIR", str(rig.data))
    (rig.know / "notes" / "probe-note.md").unlink()
    rig.refresh.refresh(skip_online=True)
    (rig.know / "notes" / "probe-note.md").write_text(NOTE)
    result = rig.refresh.refresh(skip_online=True)
    assert (result.documents_added, result.records_added) == (1, 1)
    assert not (rig.pkg / "user_state.json").exists()


def test_lite_a_document_lost_before_the_upgrade_comes_back(rig, monkeypatch):
    """The package-dir state listed it; the index never held it."""
    _legacy_install(rig, examiner=False)
    monkeypatch.setenv("RAG_INDEX_DIR", str(rig.data))
    lost = {
        "notes/probe-note.md": {
            "hash": rig.utils.compute_file_hash(rig.know / "notes" / "probe-note.md"),
            "record_ids": ["user_probe-note_0"],
        }
    }
    (rig.pkg / "user_state.json").write_text(json.dumps({"version": 1, "files": lost}))
    rig.refresh.refresh(skip_online=True)
    assert _user(rig) == {"user_probe-note_0": NOTE}
    assert not (rig.pkg / "user_state.json").exists()
    assert (rig.pkg / "user_state.json.migrated").exists()


# --- build ----------------------------------------------------------------


def test_a_build_bundles_no_examiner_record_and_leaves_user_alone(rig):
    _legacy_install(rig)
    _refresh(rig)
    user_before = _user_unchanged(rig)
    _new_process()
    result = rig.build.build(skip_online=True, data_dir=rig.data)
    assert result.status == "success", result.errors
    assert _shipped(rig) == {"user_ref_0": REF}
    state = json.loads((rig.data / "user_state.json").read_text())
    assert list(state["files"]) == ["AppliedIR/ref.md"]
    assert _user_unchanged(rig) == user_before


# --- download -------------------------------------------------------------


def _bundle(rig, extra: list[tuple[str, bytes]] = ()) -> Path:
    """A bundle made from a pristine shipped store, plus any extra members."""
    zstd = pytest.importorskip("zstandard")
    import io
    import tarfile

    src = rig.tmp / "bundle-src"
    _legacy_install_into(rig, src)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in ("chroma", "metadata.json", "user_state.json"):
            tar.add(src / name, arcname=name)
        for name, data in extra:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    rel = rig.tmp / "release"
    rel.mkdir(exist_ok=True)
    (rel / "rag-index.tar.zst").write_bytes(
        zstd.ZstdCompressor().compress(buf.getvalue())
    )
    return rel


def _legacy_install_into(rig, path: Path) -> None:
    saved = rig.data
    rig.data = path
    try:
        _legacy_install(rig, examiner=False)
    finally:
        rig.data = saved


def _download(rig, monkeypatch, rel: Path) -> bool:
    dl = rig.download
    assets = [{"name": "rag-index.tar.zst", "url": str(rel / "rag-index.tar.zst")}]
    monkeypatch.setattr(dl, "ASSETS", ("rag-index.tar.zst",))
    monkeypatch.setattr(dl, "_fetch_release", lambda tag="latest": {"assets": assets})
    monkeypatch.setattr(
        dl,
        "_download_asset",
        lambda url, d: Path(d).write_bytes(Path(url).read_bytes()),
    )
    monkeypatch.setattr(dl, "_verify_index", lambda data_dir: True)
    return dl.download_index(rig.data)


def test_a_redownload_keeps_the_examiner_s_documents(rig, monkeypatch, capsys):
    _legacy_install(rig)
    assert _download(rig, monkeypatch, _bundle(rig)) is True
    assert _user(rig) == {"user_probe-note_0": NOTE}
    assert "user_probe-note_0" not in _shipped(rig)
    assert "1 record(s) kept" in capsys.readouterr().out
    found = _search(rig, NOTE)["results"]
    assert (found[0]["text"], found[0]["origin"]) == (NOTE, "user")


def test_a_bundle_s_user_members_are_skipped_and_named(rig, monkeypatch, capsys):
    _legacy_install(rig)
    _refresh(rig)
    before = _user_unchanged(rig)
    rel = _bundle(rig, [("user/user_state.json", b"{}"), ("notes.txt", b"x")])
    assert _download(rig, monkeypatch, rel) is True
    out = capsys.readouterr().out
    assert "Skipped (not part of the shipped index): user/user_state.json" in out
    assert "Skipped (not part of the shipped index): notes.txt" in out
    assert not (rig.data / "notes.txt").exists()
    assert _user_unchanged(rig) == before


def test_a_download_whose_examiner_sync_fails_extracts_nothing(
    rig, monkeypatch, capsys
):
    _legacy_install(rig)
    before = _snapshot(rig)

    def fail(*a, **k):
        raise RuntimeError("the model can't load")

    monkeypatch.setattr(rig.stores, "sync_examiner_store", fail)
    assert _download(rig, monkeypatch, _bundle(rig)) is False
    out = capsys.readouterr().out
    assert "python -m rag_mcp.refresh --skip-online" in out
    after = _snapshot(rig)
    assert {k: v for k, v in after.items() if not k.startswith("user/")} == {
        k: v for k, v in before.items() if not k.startswith("user/")
    }


# --- the model guard ------------------------------------------------------


@pytest.mark.parametrize("writer", ["refresh", "build", "download"])
def test_another_model_is_refused_before_anything_is_written(rig, monkeypatch, writer):
    _legacy_install(rig)
    before = _snapshot(rig)
    monkeypatch.setenv("RAG_MODEL_NAME", OTHER_MODEL)
    if writer == "refresh":
        result = _refresh(rig)
        ok, errors = result.status != "error", " ".join(result.errors)
    elif writer == "build":
        result = rig.build.build(skip_online=True, data_dir=rig.data)
        ok, errors = result.status != "error", " ".join(result.errors)
    else:
        ok, errors = _download(rig, monkeypatch, _bundle(rig)), ""
    assert not ok
    if errors:
        assert OTHER_MODEL in errors and MODEL in errors
    assert _snapshot(rig) == before
    assert not (rig.data / "user").exists()


# --- the reader -----------------------------------------------------------


def test_an_uncommitted_or_absent_examiner_store_searches_as_before(rig):
    _legacy_install(rig)
    before = _search(rig, NOTE)
    assert "origin" not in before["results"][0]
    assert "refresh --skip-online" in before["notice"]
    (rig.data / "user").mkdir()
    after = _search(rig, NOTE)
    assert after["results"] == before["results"]


@pytest.mark.parametrize("field, value", [("hnsw:space", "l2"), ("model", OTHER_MODEL)])
def test_an_examiner_store_embedded_differently_is_left_out(rig, field, value):
    _legacy_install(rig)
    _refresh(rig)
    meta_path = rig.data / "user" / "metadata.json"
    meta = json.loads(meta_path.read_text())
    meta[field] = value
    meta_path.write_text(json.dumps(meta))
    result = _search(rig, NOTE)
    assert all("origin" not in r for r in result["results"])
    assert NOTE not in [r["text"] for r in result["results"]]
    assert value in result["warning"]


def test_stats_and_sources_cover_both_stores(rig):
    _legacy_install(rig)
    _refresh(rig)
    index = rig.index.RAGIndex(index_dir=rig.data)
    try:
        stats = index.get_stats()
        assert (stats["document_count"], stats["user_document_count"]) == (2, 1)
        assert (stats["model"], stats["user_model"]) == (MODEL, MODEL)
        assert stats["layout"] == "two-store"
        assert "user_probe-note" in index.sources()
        assert stats["user_sources"] == ["user_probe-note"]
    finally:
        index._close_stores()


def test_the_search_caveats_say_what_origin_user_means(rig):
    caveats = rig.__dict__.get("tool_metadata") or importlib.import_module(
        "rag_mcp.tool_metadata"
    )
    text = " ".join(caveats.TOOL_METADATA["search_knowledge"]["caveats"])
    assert "origin 'user'" in text


# --- status ---------------------------------------------------------------


def test_status_counts_the_shipped_store_and_reports_the_examiner_s(rig):
    _legacy_install(rig)
    _refresh(rig)
    status = rig.status.get_status(data_dir=rig.data, check_updates=False)
    assert status.document_count == 2
    assert (status.user_document_count, status.user_model, status.layout) == (
        1,
        MODEL,
        "two-store",
    )
    stores = {(d["file"], d["store"]) for d in status.watched_documents}
    assert stores == {("AppliedIR/ref.md", "shipped"), ("notes/probe-note.md", "user")}


def test_status_of_an_empty_shipped_store_beside_a_populated_examiner_store(rig):
    _legacy_install(rig)
    _refresh(rig)
    client = _client(rig.data / "chroma")
    col = client.get_collection("ir_knowledge")
    col.delete(ids=col.get(include=[])["ids"])
    client.close()
    status = rig.status.get_status(data_dir=rig.data, check_updates=False)
    assert (status.document_count, status.user_document_count) == (0, 1)


def test_with_no_bundled_the_shipped_store_still_drops_the_examiner_s_copies(rig):
    """The bundled pass is skipped, so the cleanup alone must do it."""
    _legacy_install(rig)
    assert _refresh(rig, no_bundled=True).status == "success"
    assert "user_probe-note_0" not in _shipped(rig)
    state = json.loads((rig.data / "user_state.json").read_text())
    assert list(state["files"]) == ["AppliedIR/ref.md"]


def test_a_build_whose_examiner_sync_fails_still_holds_no_examiner_record(
    rig, monkeypatch
):
    def fail(*a, **k):
        raise RuntimeError("the examiner store can't be written")

    monkeypatch.setattr(rig.build, "sync_examiner_store", fail)
    result = rig.build.build(skip_online=True, data_dir=rig.data)
    assert result.status == "error"
    assert _shipped(rig) == {"user_ref_0": REF}
    state = json.loads((rig.data / "user_state.json").read_text())
    assert list(state["files"]) == ["AppliedIR/ref.md"]
