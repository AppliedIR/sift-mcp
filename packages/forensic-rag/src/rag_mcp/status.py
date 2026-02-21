#!/usr/bin/env python3
"""
Status - Display index status and check for updates.

Usage:
    python -m rag_mcp.status             # Show status
    python -m rag_mcp.status --verbose   # Show additional details
    python -m rag_mcp.status --json      # Output as JSON
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import chromadb

from .sources import (
    SOURCES,
    SOURCES_DIR,
    check_source_updates,
    load_disabled_sources,
    load_sources_state,
)
from .ingest import (
    DEFAULT_KNOWLEDGE_DIR,
    load_ingested_state,
    load_user_state,
    scan_knowledge_folder,
)

logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"


@dataclass
class StatusResult:
    """Complete status information."""
    index_exists: bool
    document_count: int
    source_count: int
    model: str
    online_sources: list[dict]
    watched_documents: list[dict]
    ingested_documents: list[dict]
    warnings: list[str]
    disabled_sources: list[str]


def get_status(
    data_dir: Optional[Path] = None,
    knowledge_dir: Optional[Path] = None,
    check_updates: bool = True
) -> StatusResult:
    """
    Get complete index status.

    Args:
        data_dir: Data directory
        knowledge_dir: Knowledge directory
        check_updates: Whether to check online sources for updates

    Returns:
        StatusResult with all status information
    """
    data_dir = data_dir or Path(os.environ.get("RAG_INDEX_DIR", DEFAULT_DATA_DIR))
    knowledge_dir = knowledge_dir or Path(os.environ.get("RAG_KNOWLEDGE_DIR", DEFAULT_KNOWLEDGE_DIR))

    result = StatusResult(
        index_exists=False,
        document_count=0,
        source_count=0,
        model="",
        online_sources=[],
        watched_documents=[],
        ingested_documents=[],
        warnings=[],
        disabled_sources=[]
    )

    # Check if index exists
    chroma_path = data_dir / "chroma"
    metadata_path = data_dir / "metadata.json"

    if not chroma_path.exists():
        result.warnings.append("Index not found. Run 'python -m rag_mcp.build' first.")
        return result

    result.index_exists = True

    # Load metadata
    if metadata_path.exists():
        try:
            with open(metadata_path, encoding="utf-8") as f:
                metadata = json.load(f)
                result.model = metadata.get("model", "unknown")
                result.source_count = metadata.get("source_count", 0)
        except (json.JSONDecodeError, IOError) as e:
            result.warnings.append(f"Could not read metadata.json: {e}")

    # Get document count from ChromaDB
    try:
        client = chromadb.PersistentClient(path=str(chroma_path))
        collection = client.get_collection("ir_knowledge")
        result.document_count = collection.count()
    except Exception as e:
        result.warnings.append(f"Error reading ChromaDB: {e}")

    # Get disabled sources
    result.disabled_sources = list(load_disabled_sources())

    # Get online source status
    sources_state = load_sources_state()

    if check_updates:
        updates = check_source_updates()
        for status in updates:
            result.online_sources.append({
                "name": status.name,
                "records": status.records,
                "last_sync": status.last_sync,
                "current_version": status.current_version,
                "latest_version": status.latest_version,
                "has_update": status.has_update,
                "error": status.error
            })
    else:
        # Just use state file
        for name in SOURCES:
            source_state = sources_state.get("sources", {}).get(name, {})
            result.online_sources.append({
                "name": name,
                "records": source_state.get("records", 0),
                "last_sync": source_state.get("last_sync", "never"),
                "current_version": source_state.get("version", "unknown"),
                "latest_version": "unknown",
                "has_update": False,
                "error": ""
            })

    # Get watched documents status
    user_state = load_user_state()
    for rel_path, info in user_state.get("files", {}).items():
        result.watched_documents.append({
            "file": rel_path,
            "records": info.get("records", 0),
            "processed_at": info.get("processed_at", "")
        })

    # Get ingested documents status
    ingested_state = load_ingested_state()
    for name, info in ingested_state.get("documents", {}).items():
        result.ingested_documents.append({
            "name": name,
            "original_filename": info.get("original_filename", ""),
            "records": info.get("records", 0),
            "ingested_at": info.get("ingested_at", "")
        })

    # Check for unsupported files in knowledge/
    scan = scan_knowledge_folder(knowledge_dir)
    for path, message in scan.unsupported:
        rel_path = path.relative_to(knowledge_dir) if knowledge_dir in path.parents else path
        result.warnings.append(f"{rel_path}: {message}")

    return result


def format_status(status: StatusResult, verbose: bool = False) -> str:
    """Format status for display."""
    lines = []

    lines.append("RAG-MCP Status")
    lines.append("=" * 70)
    lines.append("")

    if not status.index_exists:
        lines.append("Index: NOT FOUND")
        lines.append("")
        lines.append("Run 'python -m rag_mcp.build' to create the index.")
        return "\n".join(lines)

    lines.append(f"Index: {status.document_count:,} documents | Model: {status.model}")
    lines.append("")

    # Online sources
    enabled_count = len([s for s in status.online_sources if s["name"] not in status.disabled_sources])
    lines.append(f"Online Sources ({enabled_count}):")
    lines.append(f"  {'NAME':<22} {'RECORDS':>8}   {'SYNCED':<12}  STATUS")
    lines.append("  " + "-" * 66)

    for src in sorted(status.online_sources, key=lambda x: x["name"]):
        if src["name"] in status.disabled_sources:
            continue

        name = src["name"]
        records = src["records"]
        last_sync = src["last_sync"][:10] if src["last_sync"] != "never" else "never"

        if src["error"]:
            status_str = f"ERROR: {src['error'][:20]}"
        elif src["has_update"]:
            status_str = f"UPDATE AVAILABLE ({src['latest_version']})"
        else:
            status_str = f"current ({src['current_version'][:12]})"

        lines.append(f"  {name:<22} {records:>8}   {last_sync:<12}  {status_str}")

    if status.disabled_sources:
        lines.append(f"  [{len(status.disabled_sources)} source(s) disabled: {', '.join(status.disabled_sources)}]")

    lines.append("")

    # Watched documents
    lines.append(f"Watched Documents (knowledge/):")
    if status.watched_documents:
        lines.append(f"  {'FILE':<35} {'RECORDS':>8}   PROCESSED")
        lines.append("  " + "-" * 60)
        for doc in sorted(status.watched_documents, key=lambda x: x["file"]):
            file_name = doc["file"]
            if len(file_name) > 35:
                file_name = "..." + file_name[-32:]
            processed = doc["processed_at"][:10] if doc["processed_at"] else "unknown"
            lines.append(f"  {file_name:<35} {doc['records']:>8}   {processed}")
    else:
        lines.append("  (none)")

    lines.append("")

    # Ingested documents
    lines.append(f"Ingested Documents (one-time):")
    if status.ingested_documents:
        lines.append(f"  {'NAME':<25} {'RECORDS':>8}   INGESTED")
        lines.append("  " + "-" * 50)
        for doc in sorted(status.ingested_documents, key=lambda x: x["name"]):
            ingested = doc["ingested_at"][:10] if doc["ingested_at"] else "unknown"
            lines.append(f"  {doc['name']:<25} {doc['records']:>8}   {ingested}")
    else:
        lines.append("  (none)")

    # Warnings
    if status.warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in status.warnings:
            lines.append(f"  - {w}")

    # Verbose details
    if verbose:
        lines.append("")
        lines.append("Verbose Details:")
        lines.append(f"  Data dir: {DEFAULT_DATA_DIR}")
        lines.append(f"  Knowledge dir: {DEFAULT_KNOWLEDGE_DIR}")
        lines.append(f"  Sources dir: {SOURCES_DIR}")

    return "\n".join(lines)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Show RAG index status")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show additional details")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--no-check", action="store_true",
                        help="Skip checking for updates (faster)")
    parser.add_argument("--data-dir", type=Path,
                        help="Data directory")
    parser.add_argument("--knowledge-dir", type=Path,
                        help="Knowledge directory")
    args = parser.parse_args()

    status = get_status(
        data_dir=args.data_dir,
        knowledge_dir=args.knowledge_dir,
        check_updates=not args.no_check
    )

    if args.json:
        print(json.dumps(asdict(status), indent=2, default=str))
    else:
        print(format_status(status, verbose=args.verbose))

    return 0


if __name__ == "__main__":
    sys.exit(main())
