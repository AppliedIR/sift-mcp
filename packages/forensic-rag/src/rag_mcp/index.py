"""
RAG Index - ChromaDB and embedding model wrapper.

This module provides the core search functionality, keeping the embedding
model and vector index loaded in memory for fast queries (~50ms).
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import chromadb
from sentence_transformers import SentenceTransformer

from .utils import (
    ALLOWED_MODELS,
    DEFAULT_MODEL_NAME,
    MAX_TOP_K,
    MAX_RETRIEVE,
    MITRE_ID_PATTERN,
    augment_text_with_mitre,
    load_mitre_lookup,
)
from .tuning_config import load_tuning_config, TuningConfig

logger = logging.getLogger(__name__)

# Query logging is OFF by default for privacy.
# Users must explicitly enable by adding handlers to these loggers.
# See README.md "Query Analysis and Tuning" section.
_metrics_logger = logging.getLogger("rag_mcp.query_metrics")
_attention_logger = logging.getLogger("rag_mcp.attention")
_metrics_logger.addHandler(logging.NullHandler())
_attention_logger.addHandler(logging.NullHandler())
_metrics_logger.propagate = False
_attention_logger.propagate = False

# Default paths - can be overridden via environment or constructor
DEFAULT_INDEX_DIR = Path(__file__).parent.parent.parent / "data"

# Search constants
MAX_TEXT_LENGTH = 1500  # Truncate results for display

# Default values (can be overridden by tuning_config.json)
# These are used if no config file exists
DEFAULT_SOURCE_BOOST = {
    "forensic_clarifications": 1.15,  # Authoritative forensic guidance
}
DEFAULT_KEYWORD_BOOST = 1.15  # 15% boost for results containing query terms
DEFAULT_LOW_SCORE_THRESHOLD = 0.50  # Queries with top scores below this need attention
DEFAULT_WEAK_MITRE_THRESHOLD = 0.60  # MITRE queries scoring below this may have missing data


class RAGIndex:
    """
    Wrapper for ChromaDB vector store and embedding model.

    Keeps the model (~400MB) and index loaded in memory for fast queries.

    Attributes:
        model: SentenceTransformer embedding model
        collection: ChromaDB collection
        available_sources: Cached list of source names
    """

    def __init__(
        self,
        index_dir: Optional[Path] = None,
        model_name: Optional[str] = None
    ) -> None:
        """
        Initialize the RAG index.

        Args:
            index_dir: Path to ChromaDB index directory
            model_name: Sentence transformer model name
        """
        self.index_dir = Path(index_dir or os.environ.get("RAG_INDEX_DIR", DEFAULT_INDEX_DIR))
        self.model_name = model_name or os.environ.get("RAG_MODEL_NAME", DEFAULT_MODEL_NAME)

        self.model: Optional[SentenceTransformer] = None
        self.collection: Optional[Any] = None
        self.available_sources: list[str] = []
        self._mitre_lookup: dict[str, str] = {}  # T1003 -> "OS Credential Dumping"
        self._tuning_config: Optional[TuningConfig] = None
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        """Check if the index is loaded and ready for queries."""
        return self._loaded

    def load(self) -> None:
        """Load the embedding model and ChromaDB index into memory."""
        if self._loaded:
            return

        # Security: validate model name against allowlist
        if self.model_name not in ALLOWED_MODELS:
            raise ValueError(
                f"Model '{self.model_name}' is not allowed. "
                "Use one of the approved embedding models."
            )

        logger.info(f"Loading embedding model: {self.model_name}")
        self.model = SentenceTransformer(self.model_name)

        logger.info("Loading ChromaDB index...")
        chroma_path = self.index_dir / "chroma"
        if not chroma_path.exists():
            # Security: Log internal path but don't expose in exception
            logger.error(f"Index not found at: {chroma_path}")
            raise FileNotFoundError(
                "Index not found. Run `python -m rag_mcp.build` first "
                "or check RAG_INDEX_DIR environment variable."
            )

        client = chromadb.PersistentClient(path=str(chroma_path))
        self.collection = client.get_collection("ir_knowledge")

        # Cache available sources
        self._load_available_sources()

        # Build MITRE technique lookup from source data (dynamic - updates with refresh)
        self._load_mitre_lookup()

        # Load tuning configuration (thresholds, boosts)
        self._tuning_config = load_tuning_config()
        if self._tuning_config.last_modified:
            logger.info(f"Tuning config loaded (last modified: {self._tuning_config.last_modified})")

        count = self.collection.count()
        logger.info(f"Ready. {count} documents indexed from {len(self.available_sources)} sources.")
        logger.info(f"MITRE lookup loaded: {len(self._mitre_lookup)} technique IDs")
        self._loaded = True

    def _load_available_sources(self) -> None:
        """Load source names from metadata.json or scan collection."""
        metadata_file = self.index_dir / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, encoding="utf-8") as f:
                    metadata = json.load(f)
                    self.available_sources = metadata.get("sources", [])
                    if self.available_sources:
                        return
            except (IOError, json.JSONDecodeError):
                pass

        # Fallback: scan collection
        if self.collection is None:
            return
        logger.info("Scanning collection for sources (metadata.json missing)")
        results = self.collection.get(include=["metadatas"])
        sources: set[str] = set()
        for meta in results["metadatas"]:
            if meta and "source" in meta:
                sources.add(meta["source"])
        self.available_sources = sorted(sources)

    def _load_mitre_lookup(self) -> None:
        """
        Build MITRE technique ID -> name lookup from source data.

        Uses the shared load_mitre_lookup function from utils.py, which loads
        dynamically from mitre_attack.jsonl so it stays current when MITRE
        data is refreshed.
        """
        sources_dir = self.index_dir / "sources"
        self._mitre_lookup = load_mitre_lookup(sources_dir)

    def _augment_query(self, query: str) -> str:
        """
        Augment query by expanding MITRE technique IDs with their names.

        Example: "T1003" -> "T1003 OS Credential Dumping"
        Example: "T1003.001 detection" -> "T1003.001 LSASS Memory detection"

        Uses the shared augment_text_with_mitre function from utils.py.

        Args:
            query: Original user query

        Returns:
            Query with MITRE IDs expanded to include technique names
        """
        return augment_text_with_mitre(query, self._mitre_lookup)

    @staticmethod
    def _extract_boost_terms(query: str) -> list[str]:
        """
        Extract significant terms from query for keyword boosting.

        Extracts:
        - Tool/technique names (mimikatz, malfind, volatility)
        - MITRE IDs (T1003, T1003.001)
        - Significant technical terms (3+ chars, not stopwords)

        Args:
            query: Search query

        Returns:
            List of terms to boost in results
        """
        # Common stopwords to ignore
        stopwords = {
            "the", "and", "for", "how", "what", "when", "where", "why",
            "with", "from", "this", "that", "these", "those", "are", "was",
            "were", "been", "being", "have", "has", "had", "does", "did",
            "will", "would", "could", "should", "may", "might", "must",
            "can", "detect", "detection", "find", "search", "query",
            "using", "via", "through"
        }

        terms = []
        # Split on non-alphanumeric (preserve dots for T1003.001)
        for word in re.split(r'[^\w.]', query.lower()):
            word = word.strip('.')
            if len(word) >= 3 and word not in stopwords:
                terms.append(word)

        # Also extract MITRE IDs specifically
        mitre_ids = MITRE_ID_PATTERN.findall(query)
        terms.extend(tid.upper() for tid in mitre_ids)

        return list(set(terms))

    def _calculate_keyword_boost(self, text: str, title: str, terms: list[str]) -> float:
        """
        Calculate keyword boost multiplier based on exact term matches.

        Args:
            text: Document text
            title: Document title
            terms: Terms to check for

        Returns:
            Boost multiplier (1.0 = no boost, configurable full boost)
        """
        if not terms:
            return 1.0

        # Get keyword boost from tuning config
        keyword_boost = DEFAULT_KEYWORD_BOOST
        if self._tuning_config:
            keyword_boost = self._tuning_config.keyword_boost

        text_lower = text.lower()
        title_lower = title.lower()
        combined = f"{title_lower} {text_lower}"

        # Count how many terms appear
        matches = sum(1 for term in terms if term.lower() in combined)

        if matches == 0:
            return 1.0
        elif matches == 1:
            return 1.0 + (keyword_boost - 1.0) * 0.5  # Half boost for 1 term
        else:
            return keyword_boost  # Full boost for 2+ terms

    def get_matching_sources(self, source_filter: Optional[str]) -> list[str]:
        """
        Get sources matching a partial filter string.

        Args:
            source_filter: Partial source name (e.g., "sigma" matches "sigma_rules_rag")

        Returns:
            List of matching source names, or all sources if filter is None
        """
        if not source_filter:
            return self.available_sources
        source_filter = source_filter.lower()
        return [s for s in self.available_sources
                if source_filter in s.lower() or s.lower() in source_filter]

    @staticmethod
    def _is_mitre_id(query: str) -> bool:
        """Check if query is a MITRE technique ID (T1003, TA0001, etc.)."""
        return bool(re.match(r'^T[AS]?\d{4}(\.\d{3})?$', query.strip().upper()))

    @staticmethod
    def _boost_mitre_matches(
        results: list[dict[str, Any]],
        mitre_id: str,
        top_k: int
    ) -> list[dict[str, Any]]:
        """
        Re-rank results to boost exact MITRE technique ID matches to the top.

        Args:
            results: List of search result dicts
            mitre_id: MITRE technique ID to boost (e.g., "T1003")
            top_k: Maximum results to return

        Returns:
            Re-ranked results with exact MITRE matches first
        """
        mitre_id_upper = mitre_id.strip().upper()
        exact_matches: list[dict[str, Any]] = []
        other_results: list[dict[str, Any]] = []

        for r in results:
            techniques = r.get("mitre_techniques", "").upper()
            technique_list = [t.strip() for t in techniques.split(",")]
            if mitre_id_upper in technique_list:
                exact_matches.append(r)
            else:
                other_results.append(r)

        combined = exact_matches + other_results
        for i, r in enumerate(combined[:top_k]):
            r["rank"] = i + 1

        return combined[:top_k]

    def search(
        self,
        query: str,
        top_k: int = 5,
        source: Optional[str] = None,
        source_ids: Optional[list[str]] = None,
        technique: Optional[str] = None,
        platform: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Search the knowledge base using semantic similarity.

        Args:
            query: Natural language search query
            top_k: Number of results to return (max 100)
            source: Optional source filter (partial/substring match, for backward compatibility)
            source_ids: Optional list of exact source IDs to filter (deterministic matching)
            technique: Optional MITRE technique filter
            platform: Optional platform filter (windows, linux, macos)

        Note:
            If both source and source_ids are provided, source_ids takes precedence
            for deterministic behavior. Use source_ids for reliable, exact filtering.

        Returns:
            dict with results, matched_sources, and any warnings
        """
        if not self._loaded:
            self.load()

        # Enforce top_k bounds (defense-in-depth)
        if not isinstance(top_k, int) or top_k < 1:
            top_k = 5
        elif top_k > MAX_TOP_K:
            top_k = MAX_TOP_K

        is_mitre_query = self._is_mitre_id(query)

        # Determine retrieval count
        # source_ids (exact match) takes precedence over source (substring match)
        source_filter = source.lower() if source and not source_ids else None
        source_ids_set = set(source_ids) if source_ids else None
        matched_sources = self.get_matching_sources(source_filter) if source_filter else []

        retrieve_k = top_k
        if source_filter or source_ids_set or technique or platform:
            retrieve_k = min(MAX_RETRIEVE, top_k * 50)

        # Augment query with MITRE technique names for better semantic matching
        augmented_query = self._augment_query(query)
        if augmented_query != query:
            logger.debug(f"Query augmented: '{query}' -> '{augmented_query}'")

        # Extract terms for keyword boosting (hybrid search)
        boost_terms = self._extract_boost_terms(query)

        # Embed query and search
        query_embedding = self.model.encode(augmented_query).tolist()
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=retrieve_k,
            include=["documents", "metadatas", "distances"]
        )

        # Format and filter results
        formatted = []
        for i in range(len(results["ids"][0])):
            doc = results["documents"][0][i]
            meta = results["metadatas"][0][i]
            distance = results["distances"][0][i]
            score = 1 - distance

            # Apply source boost for authoritative sources
            result_source = meta.get("source", "")
            source_boosts = DEFAULT_SOURCE_BOOST
            if self._tuning_config:
                source_boosts = self._tuning_config.source_boosts
            if result_source in source_boosts:
                score = min(1.0, score * source_boosts[result_source])

            # Apply keyword boost for hybrid search (semantic + keyword matching)
            title = meta.get("title", "")
            keyword_boost = self._calculate_keyword_boost(doc, title, boost_terms)
            score = min(1.0, score * keyword_boost)

            # Apply filters
            # source_ids (exact match) takes precedence over source (substring)
            if source_ids_set:
                if result_source not in source_ids_set:
                    continue
            elif source_filter:
                source_lower = result_source.lower()
                if source_filter not in source_lower and source_lower not in source_filter:
                    continue

            if technique:
                techniques_str = meta.get("mitre_techniques", "")
                if technique.upper() not in techniques_str.upper():
                    continue

            if platform:
                platform_str = meta.get("platform", "")
                if platform.lower() not in platform_str.lower():
                    continue

            formatted.append({
                "rank": 0,  # Will be set after sorting
                "score": round(score, 3),
                "source": result_source if result_source else "unknown",
                "mitre_techniques": meta.get("mitre_techniques", ""),
                "platform": meta.get("platform", ""),
                "title": meta.get("title", ""),
                "text": doc[:MAX_TEXT_LENGTH]
            })

        # Boost MITRE matches if applicable
        if is_mitre_query and formatted:
            formatted = self._boost_mitre_matches(formatted, query, top_k)

        # Re-sort by score (descending) after all boosts and trim to top_k
        formatted.sort(key=lambda x: x["score"], reverse=True)
        formatted = formatted[:top_k]

        # Update ranks after sorting
        for i, result in enumerate(formatted):
            result["rank"] = i + 1

        # Log query metrics for production threshold monitoring
        self._log_query_metrics(query, augmented_query, formatted)

        return {
            "results": formatted,
            "source_filter": source_filter,
            "source_ids": list(source_ids_set) if source_ids_set else None,
            "matched_sources": matched_sources if source_filter else None
        }

    def _log_query_metrics(
        self,
        original_query: str,
        augmented_query: str,
        results: list[dict[str, Any]]
    ) -> None:
        """
        Log query metrics for production threshold analysis.

        Logs to two dedicated loggers:
        1. rag_mcp.query_metrics - All queries for general analysis
        2. rag_mcp.attention - Problematic queries needing review

        Attention logger flags:
        - Low scores (< 0.50) indicating poor semantic match
        - Zero results indicating missing content
        - MITRE IDs not in lookup (potential data gaps)
        - MITRE queries with mediocre scores (< 0.60)

        Args:
            original_query: Original user query
            augmented_query: Query after MITRE augmentation
            results: Search results
        """
        metrics_logger = logging.getLogger("rag_mcp.query_metrics")
        attention_logger = logging.getLogger("rag_mcp.attention")

        # Classify query type for analysis
        query_type = "general"
        is_mitre_query = False
        mitre_ids_in_query = MITRE_ID_PATTERN.findall(original_query)
        if mitre_ids_in_query:
            query_type = "mitre_id"
            is_mitre_query = True
        elif any(kw in original_query.lower() for kw in ["detect", "sigma", "rule"]):
            query_type = "detection"
        elif any(kw in original_query.lower() for kw in ["forensic", "artifact", "evidence"]):
            query_type = "forensic"

        top_score = results[0]["score"] if results else 0.0
        result_count = len(results)
        was_augmented = original_query != augmented_query

        # Log all queries to metrics logger
        metrics_logger.info(
            f"query_type={query_type} "
            f"top_score={top_score:.3f} "
            f"result_count={result_count} "
            f"augmented={was_augmented} "
            f"query={original_query!r}"
        )

        # Get thresholds from tuning config
        low_score_threshold = DEFAULT_LOW_SCORE_THRESHOLD
        weak_mitre_threshold = DEFAULT_WEAK_MITRE_THRESHOLD
        if self._tuning_config:
            low_score_threshold = self._tuning_config.low_score_threshold
            weak_mitre_threshold = self._tuning_config.weak_mitre_threshold

        # Check for attention-worthy conditions
        attention_reasons = []

        # Zero results - definite content gap
        if result_count == 0:
            attention_reasons.append("zero_results")

        # Low score - poor semantic match
        if top_score < low_score_threshold and result_count > 0:
            attention_reasons.append(f"low_score:{top_score:.3f}")

        # MITRE ID not in lookup - potential data gap
        if is_mitre_query:
            unknown_ids = [
                tid.upper() for tid in mitre_ids_in_query
                if tid.upper() not in self._mitre_lookup
            ]
            if unknown_ids:
                attention_reasons.append(f"unknown_mitre_ids:{','.join(unknown_ids)}")

            # MITRE query with mediocre score even after augmentation
            if was_augmented and top_score < weak_mitre_threshold:
                attention_reasons.append(f"weak_mitre_match:{top_score:.3f}")

        # Log to attention logger if any issues found
        if attention_reasons:
            top_result_info = ""
            if results:
                r = results[0]
                top_result_info = f" top_result_source={r.get('source', 'unknown')}"

            attention_logger.warning(
                f"reasons=[{','.join(attention_reasons)}] "
                f"query_type={query_type} "
                f"top_score={top_score:.3f} "
                f"result_count={result_count} "
                f"augmented={was_augmented}{top_result_info} "
                f"query={original_query!r}"
            )

        # Log structured JSON summary for easy parsing
        import json
        from datetime import datetime
        summary_logger = logging.getLogger("rag_mcp.query_summary")
        top_sources = list(set(r.get("source", "unknown") for r in results[:5]))
        summary = {
            "timestamp": datetime.now().isoformat(),
            "query_type": query_type,
            "query_length": len(original_query),
            "top_score": round(top_score, 3),
            "result_count": result_count,
            "augmented": was_augmented,
            "top_sources": top_sources,
            "attention_flags": attention_reasons if attention_reasons else None,
        }
        summary_logger.info(json.dumps(summary))

    def get_stats(self) -> dict[str, Any]:
        """Get index statistics (excludes internal paths for security)."""
        if not self._loaded:
            self.load()

        return {
            "document_count": self.collection.count(),
            "source_count": len(self.available_sources),
            "sources": self.available_sources,
            "model": self.model_name
            # Note: index_dir intentionally omitted to avoid path disclosure
        }
