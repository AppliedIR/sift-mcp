"""Shared fixtures for forensic-rag tests.

Tests that depend on the RAG index (ChromaDB + embedding model) are
automatically skipped when the index hasn't been built.  Build it with:

    python -m rag_mcp.build

Tests that don't request ``rag_index`` or ``rag_server`` (audit,
fs_safety, network_safety, review_fixes) run unconditionally.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from rag_mcp.index import DEFAULT_INDEX_DIR, RAGIndex
from rag_mcp.server import RAGServer

_SKIP_MSG = "RAG index not built. Run `python -m rag_mcp.build` to enable these tests."


def _chroma_dir() -> Path:
    """Return the expected chroma directory path."""
    index_dir = Path(os.environ.get("RAG_INDEX_DIR", DEFAULT_INDEX_DIR))
    return index_dir / "chroma"


def rag_index_available() -> bool:
    """Check whether the RAG ChromaDB index exists on disk."""
    return _chroma_dir().exists()


# ---------------------------------------------------------------------------
# Shared fixtures — only loaded when tests request them by name
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rag_index():
    """Shared RAG index for all tests (expensive to load).

    Skips the entire test if the ChromaDB index hasn't been built.
    """
    if not rag_index_available():
        pytest.skip(_SKIP_MSG)
    idx = RAGIndex()
    idx.load()
    return idx


@pytest.fixture(scope="session")
def rag_server():
    """Shared RAG server instance.

    Skips when the index isn't built because most server operations
    (search, list_sources, get_stats) call ``index.load()`` internally.
    """
    if not rag_index_available():
        pytest.skip(_SKIP_MSG)
    return RAGServer()


@pytest.fixture(scope="session")
def available_sources(rag_index):
    """List of sources available in the loaded index."""
    return rag_index.available_sources
