"""The shipped store and the examiner's store, under one data directory.

    <data>/chroma         ir_knowledge: online sources and bundled knowledge
    <data>/metadata.json  the shipped store's model and counts
    <data>/user_state.json   the bundled knowledge files it holds
    <data>/user/chroma    user_knowledge: the examiner's knowledge-folder files
    <data>/user/user_state.json  the files it holds
    <data>/user/metadata.json    the commit point: model, space, counts

A download replaces the shipped store and never writes user/; a build
rebuilds chroma/ and never touches user/. Readers use user/ only once its
metadata.json exists (committed). Every writer brings the examiner store in
line with the knowledge folder, commits it, and only then removes the
examiner's old copies from the shipped store, so a crash at any point leaves
every examiner record reachable in one store or the other.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ingest import (
    _is_in_bundled_dir,
    _sanitize_id,
    get_document_records,
    scan_knowledge_folder,
)
from .utils import (
    DEFAULT_MODEL_NAME,
    PACKAGE_DATA_DIR,
    atomic_write_json,
    compute_file_hash,
    sanitize_metadata,
)

logger = logging.getLogger(__name__)

SHIPPED_COLLECTION = "ir_knowledge"
USER_COLLECTION = "user_knowledge"
USER_DIR = "user"
DEFAULT_SPACE = "cosine"
_EXAMINER_ID = re.compile(r"^(user|ingested)_")


def user_dir(data_dir: Path) -> Path:
    return data_dir / USER_DIR


def is_committed(data_dir: Path) -> bool:
    return (user_dir(data_dir) / "metadata.json").is_file()


def read_json(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def read_state(path: Path) -> dict[str, Any]:
    state = read_json(path)
    if not isinstance(state.get("files"), dict):
        state = _empty_state()
    return state


def _empty_state() -> dict[str, Any]:
    return {"version": 1, "files": {}}


def layout(data_dir: Path) -> str:
    """two-store (committed), uncommitted (user/ without its commit point),
    or legacy (no user/)."""
    if is_committed(data_dir):
        return "two-store"
    return "uncommitted" if user_dir(data_dir).exists() else "legacy"


# --- the model guard ---------------------------------------------------------


class ModelMismatchError(RuntimeError):
    """RAG_MODEL_NAME names a model other than the index's."""


def guard_model(data_dir: Path, requested: str | None = None) -> str:
    """The model both stores are embedded with: the shipped store's recorded
    model (DEFAULT_MODEL_NAME before there is one). A different requested
    model is refused before anything is written."""
    model = read_json(data_dir / "metadata.json").get("model") or DEFAULT_MODEL_NAME
    requested = requested or os.environ.get("RAG_MODEL_NAME")
    if requested and requested != model:
        raise ModelMismatchError(
            f"RAG_MODEL_NAME is {requested}, but the index is embedded with "
            f"{model}. Nothing was changed. Unset RAG_MODEL_NAME (or set it to "
            f"{model}); a different model needs both stores re-embedded."
        )
    return model


# --- the examiner store: sync, then commit ------------------------------------


@dataclass
class SyncResult:
    new: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    records_added: int = 0
    records_removed: int = 0
    record_count: int = 0
    committed: bool = False  # this run wrote the commit point


def examiner_files(knowledge_dir: Path) -> dict[str, Path]:
    """The examiner's knowledge-folder files: every supported file outside a
    .bundled directory, by path relative to the folder."""
    return {
        str(p.relative_to(knowledge_dir)): p
        for p in scan_knowledge_folder(knowledge_dir).supported
        if not _is_in_bundled_dir(p, knowledge_dir)
    }


def sync_examiner_store(
    data_dir: Path,
    knowledge_dir: Path,
    model_name: str,
    encode: Callable[[list[str]], list[list[float]]] | None,
    space: str = DEFAULT_SPACE,
    check_only: bool = False,
) -> SyncResult:
    """Bring user/ in line with the knowledge folder, then commit it.

    An uncommitted user/ (a crash before its commit point) is reset. A file
    is added again when its state lists records the store doesn't hold.
    Before a file's records are added, its old ids and every id of its stem
    are deleted, so an edit made while user/ was out of use still lands.
    """
    import chromadb

    udir = user_dir(data_dir)
    result = SyncResult()
    committed = is_committed(data_dir)
    files = examiner_files(knowledge_dir)
    if check_only:
        state = read_state(udir / "user_state.json") if committed else _empty_state()
        known = state["files"]
        result.new = sorted(r for r in files if r not in known)
        result.modified = sorted(
            r
            for r in files
            if r in known and compute_file_hash(files[r]) != known[r].get("hash")
        )
        result.deleted = sorted(r for r in known if r not in files)
        return result

    udir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(udir / "chroma"))
    try:
        collection = None
        if committed:
            try:
                collection = client.get_collection(USER_COLLECTION)
            except Exception:
                committed = False  # its store is gone: build it again
        if not committed:
            try:
                client.delete_collection(USER_COLLECTION)
            except Exception:
                pass  # nothing to reset
            collection = client.create_collection(
                USER_COLLECTION, metadata={"hnsw:space": space}
            )
        state = read_state(udir / "user_state.json") if committed else _empty_state()
        known = state["files"]
        have = set(collection.get(include=[])["ids"])

        # Every changed file is read and encoded before anything is deleted,
        # so a model that can't load, or any other encode failure, leaves the
        # store and its state as they were.
        changes = []
        for rel, path in sorted(files.items()):
            entry = known.get(rel)
            if entry is None or not set(entry.get("record_ids") or []) <= have:
                result.new.append(rel)
            elif compute_file_hash(path) != entry.get("hash"):
                result.modified.append(rel)
            else:
                continue
            records = get_document_records(path, source_prefix="user")
            if records and encode is None:
                raise RuntimeError("no embedding model to add examiner records")
            texts = [r["text"] for r in records]
            changes.append((rel, path, entry, records, encode(texts) if texts else []))

        for rel in sorted(known):
            if rel not in files:
                ids = known.pop(rel).get("record_ids") or []
                if ids:
                    collection.delete(ids=ids)
                    result.records_removed += len(ids)
                result.deleted.append(rel)
        for rel, path, entry, records, embeddings in changes:
            stale = set((entry or {}).get("record_ids") or [])
            stem = re.compile(rf"^user_{re.escape(_sanitize_id(path.stem))}_\d+$")
            # Ids another file's entry owns stay: same-stem files share ids
            owned = {
                i
                for other, e in known.items()
                if other != rel
                for i in e.get("record_ids") or []
            }
            stale |= {i for i in have if stem.match(i) and i not in owned}
            stale &= have
            if stale:
                collection.delete(ids=sorted(stale))
                result.records_removed += len(stale)
                have -= stale
            ids = [r["id"] for r in records]
            if records:
                collection.add(
                    ids=ids,
                    documents=[r["text"] for r in records],
                    embeddings=embeddings,
                    metadatas=[
                        sanitize_metadata(r.get("metadata", {})) for r in records
                    ],
                )
                have |= set(ids)
                result.records_added += len(ids)
            known[rel] = {  # a file with no records too, so it isn't re-read
                "hash": compute_file_hash(path),
                "size": path.stat().st_size,
                "id_prefix": f"user_{path.stem}",
                "records": len(ids),
                "record_ids": ids,
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

        changed = bool(result.new or result.modified or result.deleted)
        if changed:
            atomic_write_json(udir / "user_state.json", state)
        result.record_count = collection.count()
        if changed or not is_committed(data_dir):
            sources = sorted(
                {
                    (m or {}).get("source", "")
                    for m in collection.get(include=["metadatas"])["metadatas"]
                }
                - {""}
            )
            atomic_write_json(
                udir / "metadata.json",
                {
                    "model": model_name,
                    "hnsw:space": space,
                    "record_count": result.record_count,
                    "sources": sources,
                    "updated": datetime.now(timezone.utc).isoformat(),
                },
            )
            result.committed = True
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result


# --- after the commit: the shipped store keeps only shipped records ----------


def cleanup_shipped(
    data_dir: Path,
    knowledge_dir: Path,
    collection: Any,
    log: Callable[[str], None] = logger.info,
) -> int:
    """Remove the examiner's records from the shipped store, once user/ is
    committed. Repeatable. Returns the number of records removed.

    The shipped state keeps only bundled files; every user_*/ingested_* id it
    doesn't list is deleted from ir_knowledge. A lite install's state in the
    package's data/ is renamed, so an older version sees the examiner's files
    as new again.
    """
    if not is_committed(data_dir):
        return 0
    state_path = data_dir / "user_state.json"
    state = read_state(state_path)
    bundled = {
        rel: entry
        for rel, entry in state["files"].items()
        if _is_in_bundled_dir(knowledge_dir / rel, knowledge_dir)
    }
    if bundled != state["files"]:
        state["files"] = bundled
        atomic_write_json(state_path, state)
    keep = {i for entry in bundled.values() for i in entry.get("record_ids") or []}
    stale = [
        i
        for i in collection.get(include=[])["ids"]
        if _EXAMINER_ID.match(i) and i not in keep
    ]
    if stale:
        in_user = _user_ids(data_dir)
        gone = sorted(
            {
                (m or {}).get("file") or i
                for i, m in zip(
                    stale,
                    collection.get(ids=stale, include=["metadatas"])["metadatas"],
                    strict=False,
                )
                if i not in in_user
            }
        )
        for start in range(0, len(stale), 500):
            collection.delete(ids=stale[start : start + 500])
        log(
            f"  Removed {len(stale)} examiner record(s) from the shipped store "
            "(the examiner store holds the knowledge folder's files)"
        )
        if gone:
            log(
                f"  Removed {len(gone)} record source(s) whose file is no longer "
                f"in knowledge/: {', '.join(Path(g).name for g in gone)}"
            )
    package_state = PACKAGE_DATA_DIR / "user_state.json"
    if package_state.is_file() and package_state.resolve() != state_path.resolve():
        package_state.rename(package_state.with_name("user_state.json.migrated"))
        log(f"  Renamed {package_state} to user_state.json.migrated")
    return len(stale)


def _user_ids(data_dir: Path) -> set[str]:
    state = read_state(user_dir(data_dir) / "user_state.json")
    return {
        i for entry in state["files"].values() for i in entry.get("record_ids") or []
    }
