#!/usr/bin/env python3
"""
Build - Full index build from online sources and user documents.

Usage:
    python -m rag_mcp.build                  # Build from cache or fetch missing
    python -m rag_mcp.build --force-fetch    # Re-fetch all online sources
    python -m rag_mcp.build --skip-online    # Only process user documents
    python -m rag_mcp.build --dry-run        # Show what would be built
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

from .fs_safety import safe_rmtree, safe_mkdir, create_sentinel, FilesystemSafetyError
from .constants import DATA_ROOT, MANAGED_SENTINEL

from .sources import (
    SOURCES,
    SOURCES_DIR,
    get_cached_sources,
    load_disabled_sources,
    load_sources_state,
    save_sources_state,
    sync_source,
)
from .ingest import (
    DEFAULT_KNOWLEDGE_DIR,
    get_document_records,
    load_ingested_state,
    load_user_state,
    save_user_state,
    scan_knowledge_folder,
)
from .utils import (
    ALLOWED_MODELS,
    DEFAULT_MODEL_NAME,
    augment_text_with_mitre,
    compute_file_hash,
    load_jsonl_records,
    load_mitre_lookup,
    sanitize_metadata,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"


@dataclass
class BuildResult:
    """Result of a build operation."""
    status: str  # "success", "error"
    total_records: int = 0
    online_sources: int = 0
    online_records: int = 0
    user_documents: int = 0
    user_records: int = 0
    ingested_documents: int = 0
    ingested_records: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def build(
    force_fetch: bool = False,
    skip_online: bool = False,
    no_bundled: bool = False,
    dry_run: bool = False,
    data_dir: Optional[Path] = None,
    knowledge_dir: Optional[Path] = None,
    model_name: Optional[str] = None
) -> BuildResult:
    """
    Build complete ChromaDB index from scratch.

    Args:
        force_fetch: Re-fetch all online sources regardless of cache
        skip_online: Only process user documents (offline mode)
        no_bundled: Skip bundled reference content (AppliedIR, SANS)
        dry_run: Report what would be built without building

    Returns:
        BuildResult with summary
    """
    data_dir = data_dir or Path(os.environ.get("RAG_INDEX_DIR", DEFAULT_DATA_DIR))
    knowledge_dir = knowledge_dir or Path(os.environ.get("RAG_KNOWLEDGE_DIR", DEFAULT_KNOWLEDGE_DIR))
    model_name = model_name or os.environ.get("RAG_MODEL_NAME", DEFAULT_MODEL_NAME)

    result = BuildResult(status="success")
    all_records = []

    # Ensure directories exist and are marked as managed
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    # Create sentinel files to mark directories as managed by rag-mcp
    data_sentinel = data_dir / MANAGED_SENTINEL
    if not data_sentinel.exists():
        data_sentinel.touch()
        logger.debug(f"Created sentinel: {data_sentinel}")

    sources_sentinel = SOURCES_DIR / MANAGED_SENTINEL
    if not sources_sentinel.exists():
        sources_sentinel.touch()
        logger.debug(f"Created sentinel: {sources_sentinel}")

    # =========================================================================
    # Phase 1: Online Sources
    # =========================================================================
    if not skip_online:
        logger.info("=" * 60)
        logger.info("Phase 1: Online Sources")
        logger.info("=" * 60)

        disabled = load_disabled_sources()
        cached = get_cached_sources()

        for name, source in SOURCES.items():
            if name in disabled:
                logger.info(f"  {name}: DISABLED (skipped)")
                continue

            cache_path = SOURCES_DIR / f"{name}.jsonl"

            # Check if we need to fetch
            need_fetch = force_fetch or not cache_path.exists()

            if need_fetch:
                if dry_run:
                    logger.info(f"  {name}: Would fetch from {source.repo}")
                    continue
                else:
                    fetch_result = sync_source(name, force=force_fetch)
                    if fetch_result.status != "success":
                        result.warnings.append(f"{name}: {fetch_result.message}")
                        # Try to use existing cache if available
                        if not cache_path.exists():
                            continue

            # Load from cache
            if cache_path.exists():
                records = load_jsonl_records(cache_path)
                all_records.extend(records)
                result.online_sources += 1
                result.online_records += len(records)
                logger.info(f"  {name}: {len(records)} records")
            else:
                logger.info(f"  {name}: No cache available")

    # =========================================================================
    # Phase 2: Watched User Documents (knowledge/)
    # =========================================================================
    logger.info("")
    logger.info("=" * 60)
    logger.info("Phase 2: User Documents (knowledge/)")
    logger.info("=" * 60)

    scan = scan_knowledge_folder(knowledge_dir, skip_bundled=no_bundled)

    if no_bundled:
        logger.info("  (bundled content skipped: --no-bundled)")

    # Report unsupported files
    for path, message in scan.unsupported:
        rel_path = path.relative_to(knowledge_dir) if knowledge_dir in path.parents else path
        result.warnings.append(f"{rel_path}: {message}")
        logger.info(f"  {rel_path}: UNSUPPORTED ({message})")

    # Process supported files
    user_state = {"version": 1, "files": {}}

    for path in scan.supported:
        rel_path = str(path.relative_to(knowledge_dir))

        if dry_run:
            logger.info(f"  {rel_path}: Would process")
            continue

        records = get_document_records(path, source_prefix="user")
        if records:
            all_records.extend(records)
            result.user_documents += 1
            result.user_records += len(records)
            logger.info(f"  {rel_path}: {len(records)} records")

            # Track in state
            user_state["files"][rel_path] = {
                "hash": compute_file_hash(path),
                "size": path.stat().st_size,
                "id_prefix": f"user_{path.stem}",
                "records": len(records),
                "record_ids": [r["id"] for r in records],
                "processed_at": datetime.now().isoformat()
            }

    if not scan.supported:
        logger.info("  (no user documents)")

    # =========================================================================
    # Phase 3: Ingested Documents
    # =========================================================================
    logger.info("")
    logger.info("=" * 60)
    logger.info("Phase 3: Ingested Documents")
    logger.info("=" * 60)

    ingested_state = load_ingested_state()
    ingested_docs = ingested_state.get("documents", {})

    if ingested_docs:
        # WARNING: Full rebuild destroys ChromaDB including ingested documents.
        # The original files may no longer exist, so we cannot re-index them.
        # User must re-ingest after rebuild.
        total_ingested = sum(info.get("records", 0) for info in ingested_docs.values())
        result.warnings.append(
            f"Full rebuild will DESTROY {len(ingested_docs)} ingested document(s) "
            f"({total_ingested} records). Re-ingest them after build completes."
        )
        logger.info("")
        logger.info(f"  WARNING: {len(ingested_docs)} ingested document(s) will be lost!")
        logger.info("           ChromaDB is rebuilt from scratch.")
        logger.info("           Re-run 'python -m rag_mcp.ingest' after build.")
        logger.info("")
        for name, info in ingested_docs.items():
            result.ingested_documents += 1
            result.ingested_records += info.get("records", 0)
            logger.info(f"  {name}: {info.get('records', 0)} records (WILL BE LOST)")
    else:
        logger.info("  (no ingested documents)")

    # =========================================================================
    # Phase 4: Build ChromaDB Index
    # =========================================================================
    if dry_run:
        logger.info("")
        logger.info("=" * 60)
        logger.info("Dry Run Summary")
        logger.info("=" * 60)
        logger.info(f"  Would build index with ~{len(all_records)} records")
        result.total_records = len(all_records)
        return result

    logger.info("")
    logger.info("=" * 60)
    logger.info("Phase 4: Building ChromaDB Index")
    logger.info("=" * 60)

    if not all_records:
        logger.info("  No records to index!")
        result.status = "error"
        result.errors.append("No records to index")
        return result

    # Validate model
    if model_name not in ALLOWED_MODELS:
        result.status = "error"
        result.errors.append(f"Invalid model: {model_name}")
        return result

    # Load MITRE lookup for text augmentation
    logger.info("  Loading MITRE technique lookup for text augmentation...")
    mitre_lookup = load_mitre_lookup(SOURCES_DIR)
    logger.info(f"  Loaded {len(mitre_lookup)} MITRE technique mappings")

    # Load embedding model
    logger.info(f"  Loading embedding model: {model_name}")
    model = SentenceTransformer(model_name)

    # Initialize ChromaDB
    chroma_path = data_dir / "chroma"
    logger.info(f"  Initializing ChromaDB at: {chroma_path}")

    # Safely remove old index if exists (requires sentinel file)
    if chroma_path.exists():
        try:
            safe_rmtree(chroma_path, root=data_dir, require_sentinel_file=True)
            logger.info("  Removed existing ChromaDB index")
        except FilesystemSafetyError as e:
            # First build or missing sentinel - use safe_rmtree without sentinel requirement
            # All other safety checks (forbidden paths, root containment, depth) still apply
            logger.warning(f"  Could not safely remove old index: {e}")
            logger.warning("  Attempting first-time setup removal (sentinel not required)...")
            try:
                safe_rmtree(chroma_path, root=data_dir, require_sentinel_file=False)
                logger.info("  Removed old index (first-time setup, no sentinel)")
            except FilesystemSafetyError as e2:
                result.status = "error"
                result.errors.append(f"Filesystem safety error: {e2}")
                return result

    # Create ChromaDB directory with sentinel
    chroma_path.mkdir(parents=True, exist_ok=True)
    create_sentinel(chroma_path)
    logger.info(f"  Created managed directory with sentinel: {chroma_path}")

    client = chromadb.PersistentClient(path=str(chroma_path))
    collection = client.create_collection(
        name="ir_knowledge",
        metadata={"hnsw:space": "cosine"}
    )

    # Batch embed and add records
    batch_size = 100
    total = len(all_records)

    logger.info(f"  Embedding {total} records...")

    augmented_count = 0
    for i in range(0, total, batch_size):
        batch = all_records[i:i + batch_size]

        ids = [r["id"] for r in batch]
        # Augment text with MITRE technique names before embedding
        texts = []
        for r in batch:
            original = r["text"]
            augmented = augment_text_with_mitre(original, mitre_lookup)
            texts.append(augmented)
            if augmented != original:
                augmented_count += 1
        metadatas = [sanitize_metadata(r.get("metadata", {})) for r in batch]

        # Embed batch (using augmented text for richer embeddings)
        embeddings = model.encode(texts).tolist()

        # Add to collection
        collection.add(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=metadatas
        )

        if (i + batch_size) % 1000 == 0 or i + batch_size >= total:
            logger.info(f"    {min(i + batch_size, total)}/{total} records")

    result.total_records = total
    logger.info(f"  Text augmentation: {augmented_count} records enriched with MITRE technique names")

    # =========================================================================
    # Phase 5: Save State and Metadata
    # =========================================================================
    logger.info("")
    logger.info("=" * 60)
    logger.info("Phase 5: Saving State")
    logger.info("=" * 60)

    # Save user state
    if user_state["files"]:
        save_user_state(user_state)
        logger.info(f"  Saved user_state.json ({len(user_state['files'])} files)")

    # Collect all sources for metadata
    all_sources = set()
    for rec in all_records:
        source = rec.get("metadata", {}).get("source", "unknown")
        all_sources.add(source)

    # Save metadata
    metadata = {
        "version": "2.0.0",
        "created": datetime.now().isoformat(),
        "model": model_name,
        "record_count": total,
        "source_count": len(all_sources),
        "sources": sorted(all_sources)
    }

    metadata_path = data_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"  Saved metadata.json")

    # =========================================================================
    # Summary
    # =========================================================================
    logger.info("")
    logger.info("=" * 60)
    logger.info("Build Complete")
    logger.info("=" * 60)
    logger.info(f"  Total records: {result.total_records}")
    logger.info(f"  Online sources: {result.online_sources} ({result.online_records} records)")
    logger.info(f"  User documents: {result.user_documents} ({result.user_records} records)")
    logger.info(f"  Ingested documents: {result.ingested_documents} ({result.ingested_records} records)")

    if result.warnings:
        logger.info("")
        logger.info("Warnings:")
        for w in result.warnings:
            logger.info(f"  - {w}")

    return result


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Build RAG index")
    parser.add_argument("--force-fetch", action="store_true",
                        help="Re-fetch all online sources")
    parser.add_argument("--skip-online", action="store_true",
                        help="Only process user documents")
    parser.add_argument("--no-bundled", action="store_true",
                        help="Skip bundled reference content (AppliedIR, SANS)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be built")
    parser.add_argument("--data-dir", type=Path,
                        help="Data directory (default: ./data)")
    parser.add_argument("--knowledge-dir", type=Path,
                        help="Knowledge directory (default: ./knowledge)")
    args = parser.parse_args()

    result = build(
        force_fetch=args.force_fetch,
        skip_online=args.skip_online,
        no_bundled=args.no_bundled,
        dry_run=args.dry_run,
        data_dir=args.data_dir,
        knowledge_dir=args.knowledge_dir
    )

    return 0 if result.status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
