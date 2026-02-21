#!/usr/bin/env python3
"""
Tuning Configuration - Manages adjustable thresholds and boosts.

This module provides a central place for tunable parameters that can be
adjusted based on query analysis. Changes are persisted to a JSON config
file and loaded at runtime.

The config file is meant to be modified by the analyze_queries.py tool
after human/agent approval, not edited directly.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .utils import atomic_write_json

logger = logging.getLogger(__name__)

# Default config location
PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "data" / "tuning_config.json"


@dataclass
class TuningConfig:
    """
    Tunable parameters for RAG search quality.

    These values can be adjusted based on query analysis to optimize
    search quality for your specific usage patterns.
    """
    # Version for config compatibility
    version: str = "1.0"

    # Score thresholds by query type
    # Queries scoring below these thresholds may indicate poor matches
    thresholds: dict[str, float] = field(default_factory=lambda: {
        "general": 0.50,
        "mitre_id": 0.55,
        "detection": 0.55,
        "forensic": 0.55,
    })

    # Source boost multipliers
    # Authoritative sources can receive score boosts
    source_boosts: dict[str, float] = field(default_factory=lambda: {
        "forensic_clarifications": 1.15,
    })

    # Keyword boost for hybrid search
    keyword_boost: float = 1.15

    # Attention thresholds for logging
    low_score_threshold: float = 0.50
    weak_mitre_threshold: float = 0.60

    # Audit trail
    last_modified: Optional[str] = None
    last_modified_by: Optional[str] = None
    modification_history: list[dict[str, Any]] = field(default_factory=list)

    def apply_recommendation(
        self,
        recommendation: dict[str, Any],
        approved_by: str = "unknown"
    ) -> None:
        """
        Apply a recommendation from query analysis.

        Args:
            recommendation: Dict with 'type' and type-specific fields
            approved_by: Identifier for who approved (human/agent name)
        """
        rec_type = recommendation.get("type")

        if rec_type == "threshold":
            query_type = recommendation.get("query_type")
            new_value = recommendation.get("new_value")
            if query_type and new_value is not None:
                old_value = self.thresholds.get(query_type)
                self.thresholds[query_type] = new_value
                self._record_change(
                    f"threshold:{query_type}",
                    old_value,
                    new_value,
                    approved_by,
                    recommendation.get("reason", "")
                )

        elif rec_type == "source_boost":
            source = recommendation.get("source")
            new_value = recommendation.get("new_value")
            if source and new_value is not None:
                old_value = self.source_boosts.get(source)
                self.source_boosts[source] = new_value
                self._record_change(
                    f"source_boost:{source}",
                    old_value,
                    new_value,
                    approved_by,
                    recommendation.get("reason", "")
                )

        elif rec_type == "keyword_boost":
            new_value = recommendation.get("new_value")
            if new_value is not None:
                old_value = self.keyword_boost
                self.keyword_boost = new_value
                self._record_change(
                    "keyword_boost",
                    old_value,
                    new_value,
                    approved_by,
                    recommendation.get("reason", "")
                )

    def _record_change(
        self,
        parameter: str,
        old_value: Any,
        new_value: Any,
        approved_by: str,
        reason: str
    ) -> None:
        """Record a change in the audit trail."""
        self.last_modified = datetime.now().isoformat()
        self.last_modified_by = approved_by
        self.modification_history.append({
            "timestamp": self.last_modified,
            "parameter": parameter,
            "old_value": old_value,
            "new_value": new_value,
            "approved_by": approved_by,
            "reason": reason,
        })
        # Keep last 100 changes, log dropped entries for audit continuity
        if len(self.modification_history) > 100:
            dropped = self.modification_history[:-100]
            for entry in dropped:
                logger.info(
                    f"Audit trail overflow - archiving: "
                    f"{entry['timestamp']} {entry['parameter']} "
                    f"{entry['old_value']}->{entry['new_value']} "
                    f"by {entry['approved_by']}"
                )
            self.modification_history = self.modification_history[-100:]


def load_tuning_config(config_path: Optional[Path] = None) -> TuningConfig:
    """
    Load tuning configuration from file.

    Args:
        config_path: Path to config file (default: data/tuning_config.json)

    Returns:
        TuningConfig instance (defaults if file doesn't exist)
    """
    path = config_path or DEFAULT_CONFIG_PATH

    if not path.exists():
        logger.debug(f"No tuning config at {path}, using defaults")
        return TuningConfig()

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        # Handle version compatibility
        version = data.get("version", "1.0")

        defaults = TuningConfig()
        config = TuningConfig(
            version=version,
            thresholds=data.get("thresholds", defaults.thresholds),
            source_boosts=data.get("source_boosts", defaults.source_boosts),
            keyword_boost=data.get("keyword_boost", 1.15),
            low_score_threshold=data.get("low_score_threshold", 0.50),
            weak_mitre_threshold=data.get("weak_mitre_threshold", 0.60),
            last_modified=data.get("last_modified"),
            last_modified_by=data.get("last_modified_by"),
            modification_history=data.get("modification_history", []),
        )
        logger.debug(f"Loaded tuning config from {path}")
        return config

    except (IOError, json.JSONDecodeError) as e:
        logger.warning(f"Could not load tuning config: {e}, using defaults")
        return TuningConfig()


def save_tuning_config(
    config: TuningConfig,
    config_path: Optional[Path] = None
) -> None:
    """
    Save tuning configuration to file.

    Args:
        config: TuningConfig instance to save
        config_path: Path to config file (default: data/tuning_config.json)
    """
    path = config_path or DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(config)
    atomic_write_json(path, data)

    logger.info(f"Saved tuning config to {path}")
