#!/usr/bin/env python3
"""
Refresh - Incremental update of online sources and user documents.

Usage:
    python -m rag_mcp.refresh                # Update all
    python -m rag_mcp.refresh --check-only   # Report changes without applying
    python -m rag_mcp.refresh --source sigma # Only refresh specific source
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import chromadb
from sentence_transformers import SentenceTransformer

from .sources import (
    SOURCES,
    SOURCES_DIR,
    check_source_updates,
    load_disabled_sources,
    load_sources_state,
    sync_source,
)
from .ingest import (
    DEFAULT_KNOWLEDGE_DIR,
    check_for_changes,
    get_document_records,
    load_user_state,
    save_user_state,
    scan_knowledge_folder,
)
from .utils import DEFAULT_MODEL_NAME, compute_file_hash, load_jsonl_records, sanitize_metadata

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"


@dataclass
class RefreshResult:
    """Result of a refresh operation."""
    status: str  # "success", "error", "no_changes"
    sources_updated: int = 0
    sources_checked: int = 0
    documents_added: int = 0
    documents_modified: int = 0
    documents_deleted: int = 0
    records_added: int = 0
    records_removed: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def refresh(
    check_only: bool = False,
    source_name: Optional[str] = None,
    skip_online: bool = False,
    no_bundled: bool = False,
    data_dir: Optional[Path] = None,
    knowledge_dir: Optional[Path] = None,
    model_name: Optional[str] = None
) -> RefreshResult:
    """
    Incrementally update the index.

    Args:
        check_only: Report changes without applying
        source_name: Only refresh specific online source
        skip_online: Skip online sources (user docs only)
        no_bundled: Skip bundled reference content (AppliedIR, SANS)

    Returns:
        RefreshResult with summary
    """
    data_dir = data_dir or Path(os.environ.get("RAG_INDEX_DIR", DEFAULT_DATA_DIR))
    knowledge_dir = knowledge_dir or Path(os.environ.get("RAG_KNOWLEDGE_DIR", DEFAULT_KNOWLEDGE_DIR))
    model_name = model_name or os.environ.get("RAG_MODEL_NAME", DEFAULT_MODEL_NAME)

    result = RefreshResult(status="success")

    # Check if index exists
    chroma_path = data_dir / "chroma"
    if not chroma_path.exists():
        result.status = "error"
        result.errors.append("Index not found. Run 'python -m rag_mcp.build' first.")
        return result

    # Load ChromaDB
    client = chromadb.PersistentClient(path=str(chroma_path))
    try:
        collection = client.get_collection("ir_knowledge")
    except Exception:
        result.status = "error"
        result.errors.append("Collection 'ir_knowledge' not found. Rebuild index.")
        return result

    # Load model for embedding new content
    model = None
    if not check_only:
        logger.info(f"Loading embedding model: {model_name}")
        model = SentenceTransformer(model_name)

    # =========================================================================
    # Phase 1: Online Sources
    # =========================================================================
    if not skip_online:
        logger.info("=" * 60)
        logger.info("Phase 1: Checking Online Sources")
        logger.info("=" * 60)

        if source_name:
            # Single source
            if source_name not in SOURCES:
                result.errors.append(f"Unknown source: {source_name}")
            else:
                _refresh_single_source(source_name, collection, model, check_only, result)
        else:
            # All sources
            updates = check_source_updates()
            result.sources_checked = len(updates)

            for status in updates:
                if status.error:
                    result.warnings.append(f"{status.name}: {status.error}")
                    logger.info(f"  {status.name}: ERROR ({status.error})")
                elif status.has_update:
                    logger.info(f"  {status.name}: UPDATE AVAILABLE ({status.current_version} -> {status.latest_version})")
                    if not check_only:
                        _refresh_single_source(status.name, collection, model, check_only, result)
                else:
                    logger.info(f"  {status.name}: up to date ({status.current_version})")

    # =========================================================================
    # Phase 2: User Documents
    # =========================================================================
    logger.info("")
    logger.info("=" * 60)
    logger.info("Phase 2: Checking User Documents")
    logger.info("=" * 60)

    changes = check_for_changes(knowledge_dir, skip_bundled=no_bundled)

    if no_bundled:
        logger.info("  (bundled content skipped: --no-bundled)")

    # Report changes
    if changes.new:
        for path in changes.new:
            rel_path = path.relative_to(knowledge_dir)
            logger.info(f"  NEW: {rel_path}")
    if changes.modified:
        for path in changes.modified:
            rel_path = path.relative_to(knowledge_dir)
            logger.info(f"  MODIFIED: {rel_path}")
    if changes.deleted:
        for rel_path in changes.deleted:
            logger.info(f"  DELETED: {rel_path}")

    if not changes.new and not changes.modified and not changes.deleted:
        logger.info("  No changes detected")

    # Apply changes
    if not check_only and (changes.new or changes.modified or changes.deleted):
        state = load_user_state()

        # Handle deleted files
        for rel_path in changes.deleted:
            file_state = state.get("files", {}).get(rel_path, {})
            record_ids = file_state.get("record_ids", [])
            if record_ids:
                collection.delete(ids=record_ids)
                result.records_removed += len(record_ids)
            if rel_path in state.get("files", {}):
                del state["files"][rel_path]
            result.documents_deleted += 1

        # Handle new and modified files
        for path in changes.new + changes.modified:
            rel_path = str(path.relative_to(knowledge_dir))

            # Remove old records if modified
            if path in changes.modified:
                file_state = state.get("files", {}).get(rel_path, {})
                old_ids = file_state.get("record_ids", [])
                if old_ids:
                    collection.delete(ids=old_ids)
                    result.records_removed += len(old_ids)
                result.documents_modified += 1
            else:
                result.documents_added += 1

            # Process and add new records
            records = get_document_records(path, source_prefix="user")
            if records:
                ids = [r["id"] for r in records]
                texts = [r["text"] for r in records]
                metadatas = [sanitize_metadata(r.get("metadata", {})) for r in records]
                embeddings = model.encode(texts).tolist()

                collection.add(
                    ids=ids,
                    documents=texts,
                    embeddings=embeddings,
                    metadatas=metadatas
                )
                result.records_added += len(records)

                # Update state
                state.setdefault("files", {})[rel_path] = {
                    "hash": compute_file_hash(path),
                    "size": path.stat().st_size,
                    "id_prefix": f"user_{path.stem}",
                    "records": len(records),
                    "record_ids": ids,
                    "processed_at": datetime.now().isoformat()
                }

        save_user_state(state)

    # =========================================================================
    # Phase 3: Check for unsupported files
    # =========================================================================
    scan = scan_knowledge_folder(knowledge_dir, skip_bundled=no_bundled)
    if scan.unsupported:
        logger.info("")
        logger.info("Warnings (unsupported files):")
        for path, message in scan.unsupported:
            rel_path = path.relative_to(knowledge_dir)
            result.warnings.append(f"{rel_path}: {message}")
            logger.info(f"  {rel_path}: {message}")

    # =========================================================================
    # Phase 4: Update metadata.json
    # =========================================================================
    if not check_only:
        try:
            all_meta = collection.get(include=["metadatas"])
            all_sources: set[str] = set()
            for meta in all_meta["metadatas"]:
                if meta and "source" in meta:
                    all_sources.add(meta["source"])

            record_count = collection.count()
            metadata_path = data_dir / "metadata.json"

            # Preserve fields from existing metadata
            existing_metadata: dict[str, Any] = {}
            if metadata_path.exists():
                try:
                    with open(metadata_path, encoding="utf-8") as f:
                        existing_metadata = json.load(f)
                except (IOError, json.JSONDecodeError):
                    pass

            metadata = {
                "version": existing_metadata.get("version", "2.0.0"),
                "created": existing_metadata.get("created", datetime.now().isoformat()),
                "refreshed": datetime.now().isoformat(),
                "model": existing_metadata.get("model", model_name),
                "record_count": record_count,
                "source_count": len(all_sources),
                "sources": sorted(all_sources)
            }

            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"  Updated metadata.json: {len(all_sources)} sources, {record_count} records")
        except Exception as e:
            result.warnings.append(f"Failed to update metadata.json: {e}")
            logger.warning(f"  Warning: Could not update metadata.json: {e}")

    # =========================================================================
    # Summary
    # =========================================================================
    logger.info("")
    logger.info("=" * 60)
    if check_only:
        logger.info("Check Complete (no changes applied)")
    else:
        logger.info("Refresh Complete")
    logger.info("=" * 60)

    has_changes = (
        result.sources_updated > 0 or
        result.documents_added > 0 or
        result.documents_modified > 0 or
        result.documents_deleted > 0
    )

    if check_only:
        if source_name:
            logger.info(f"  Source '{source_name}' checked")
        else:
            logger.info(f"  Online sources checked: {result.sources_checked}")
        logger.info(f"  User documents: {len(changes.new)} new, {len(changes.modified)} modified, {len(changes.deleted)} deleted")
    else:
        logger.info(f"  Sources updated: {result.sources_updated}")
        logger.info(f"  Documents: +{result.documents_added} modified:{result.documents_modified} -{result.documents_deleted}")
        logger.info(f"  Records: +{result.records_added} -{result.records_removed}")

    if not has_changes and not check_only:
        result.status = "no_changes"

    # Log structured summary for observability
    _log_refresh_summary(result, check_only)

    return result


def _log_refresh_summary(result: RefreshResult, check_only: bool) -> None:
    """Log structured refresh summary for monitoring/alerting."""
    import json
    from datetime import datetime

    summary = {
        "timestamp": datetime.now().isoformat(),
        "operation": "check" if check_only else "refresh",
        "status": result.status,
        "sources_checked": result.sources_checked,
        "sources_updated": result.sources_updated,
        "documents_added": result.documents_added,
        "documents_modified": result.documents_modified,
        "documents_deleted": result.documents_deleted,
        "records_added": result.records_added,
        "records_removed": result.records_removed,
        "warnings_count": len(result.warnings),
    }

    # Log as JSON for easy parsing
    summary_logger = logging.getLogger("rag_mcp.refresh_summary")
    summary_logger.info(json.dumps(summary))


def _refresh_single_source(
    name: str,
    collection: Any,
    model: Any,
    check_only: bool,
    result: RefreshResult
) -> None:
    """Refresh a single online source."""
    if check_only:
        return

    logger.info(f"  Syncing {name}...")

    # Sync source
    fetch_result = sync_source(name, force=True)

    if fetch_result.status != "success":
        result.warnings.append(f"{name}: {fetch_result.message}")
        return

    # Load new records
    cache_path = SOURCES_DIR / f"{name}.jsonl"
    if not cache_path.exists():
        result.warnings.append(f"{name}: No cache file after sync")
        return

    records = load_jsonl_records(cache_path)

    # Delete old records for this source
    try:
        existing = collection.get(where={"source": name})
        if existing["ids"]:
            collection.delete(ids=existing["ids"])
            result.records_removed += len(existing["ids"])
    except Exception:
        # Source might not exist yet
        pass

    # Add new records
    if records:
        batch_size = 100
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            ids = [r["id"] for r in batch]
            texts = [r["text"] for r in batch]
            metadatas = [sanitize_metadata(r.get("metadata", {})) for r in batch]
            embeddings = model.encode(texts).tolist()

            collection.add(
                ids=ids,
                documents=texts,
                embeddings=embeddings,
                metadatas=metadatas
            )

        result.records_added += len(records)

    result.sources_updated += 1
    logger.info(f"    Updated {name}: {len(records)} records")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Refresh RAG index")
    parser.add_argument("--check-only", action="store_true",
                        help="Report changes without applying")
    parser.add_argument("--source", type=str,
                        help="Only refresh specific online source")
    parser.add_argument("--skip-online", action="store_true",
                        help="Skip online sources")
    parser.add_argument("--no-bundled", action="store_true",
                        help="Skip bundled reference content (AppliedIR, SANS)")
    parser.add_argument("--data-dir", type=Path,
                        help="Data directory")
    parser.add_argument("--knowledge-dir", type=Path,
                        help="Knowledge directory")
    args = parser.parse_args()

    result = refresh(
        check_only=args.check_only,
        source_name=args.source,
        skip_online=args.skip_online,
        no_bundled=args.no_bundled,
        data_dir=args.data_dir,
        knowledge_dir=args.knowledge_dir
    )

    return 0 if result.status in ("success", "no_changes") else 1


if __name__ == "__main__":
    sys.exit(main())
