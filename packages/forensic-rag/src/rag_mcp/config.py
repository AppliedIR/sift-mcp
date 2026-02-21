#!/usr/bin/env python3
"""
Configuration Management - Centralized, validated configuration.

This module provides a single source of truth for all configuration,
replacing scattered env var reads with a validated config object.

Usage:
    from rag_mcp.config import get_config

    cfg = get_config()
    print(cfg.data_dir)
    print(cfg.model_name)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .constants import (
    DATA_ROOT,
    KNOWLEDGE_ROOT,
    PROJECT_ROOT,
    FORBIDDEN_PATHS,
)
from .utils import ALLOWED_MODELS, DEFAULT_MODEL_NAME

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass


@dataclass
class Config:
    """
    Validated configuration for RAG-MCP.

    All paths are resolved and validated at initialization.
    """
    # Paths
    project_root: Path
    data_dir: Path
    knowledge_dir: Path

    # Model
    model_name: str

    # Limits
    max_top_k: int
    max_query_length: int
    max_download_bytes: int
    fetch_max_retries: int

    # Security
    https_only: bool
    allow_http: bool

    # Feature flags
    unsafe_paths: bool = False

    def validate(self) -> None:
        """
        Validate configuration values.

        Raises:
            ConfigurationError: If any validation fails
        """
        errors = []

        # Validate paths exist or can be created
        if not self.project_root.exists():
            errors.append(f"Project root does not exist: {self.project_root}")

        # Validate model is in allowlist
        if self.model_name not in ALLOWED_MODELS:
            errors.append(
                f"Model '{self.model_name}' not in allowed models: {ALLOWED_MODELS}"
            )

        # Validate limits are positive
        if self.max_top_k < 1:
            errors.append(f"max_top_k must be positive, got {self.max_top_k}")
        if self.max_query_length < 1:
            errors.append(f"max_query_length must be positive, got {self.max_query_length}")
        if self.max_download_bytes < 1:
            errors.append(f"max_download_bytes must be positive, got {self.max_download_bytes}")

        # Validate data_dir is not a forbidden path (unless unsafe_paths)
        if not self.unsafe_paths:
            data_resolved = self.data_dir.resolve()
            if data_resolved in FORBIDDEN_PATHS:
                errors.append(
                    f"data_dir '{data_resolved}' is a forbidden path. "
                    f"Set RAG_UNSAFE_PATHS=1 to override (dangerous!)."
                )

        if errors:
            raise ConfigurationError(
                "Configuration validation failed:\n  - " + "\n  - ".join(errors)
            )


# Global config cache
_config: Optional[Config] = None


def get_config(reload: bool = False) -> Config:
    """
    Get validated configuration.

    Loads from environment variables on first call, caches for subsequent calls.

    Args:
        reload: Force reload from environment variables

    Returns:
        Validated Config object

    Raises:
        ConfigurationError: If configuration is invalid
    """
    global _config

    if _config is not None and not reload:
        return _config

    # Load from environment with defaults
    data_dir = Path(os.environ.get("RAG_INDEX_DIR", str(DATA_ROOT))).resolve()
    knowledge_dir = Path(os.environ.get("RAG_KNOWLEDGE_DIR", str(KNOWLEDGE_ROOT))).resolve()
    model_name = os.environ.get("RAG_MODEL_NAME", DEFAULT_MODEL_NAME)

    # Limits
    max_top_k = int(os.environ.get("RAG_MAX_TOP_K", "50"))
    max_query_length = int(os.environ.get("RAG_MAX_QUERY_LENGTH", "1000"))
    max_download_bytes = int(os.environ.get("RAG_MAX_DOWNLOAD_BYTES", str(60 * 1024 * 1024)))
    fetch_max_retries = int(os.environ.get("RAG_FETCH_MAX_RETRIES", "3"))

    # Security
    allow_http = os.environ.get("RAG_ALLOW_HTTP", "").lower() in ("1", "true", "yes")
    https_only = not allow_http
    unsafe_paths = os.environ.get("RAG_UNSAFE_PATHS", "").lower() in ("1", "true", "yes")

    config = Config(
        project_root=PROJECT_ROOT,
        data_dir=data_dir,
        knowledge_dir=knowledge_dir,
        model_name=model_name,
        max_top_k=max_top_k,
        max_query_length=max_query_length,
        max_download_bytes=max_download_bytes,
        fetch_max_retries=fetch_max_retries,
        https_only=https_only,
        allow_http=allow_http,
        unsafe_paths=unsafe_paths,
    )

    # Validate
    config.validate()

    # Log configuration (debug level, no secrets)
    logger.debug(f"Configuration loaded:")
    logger.debug(f"  data_dir: {config.data_dir}")
    logger.debug(f"  knowledge_dir: {config.knowledge_dir}")
    logger.debug(f"  model_name: {config.model_name}")
    logger.debug(f"  https_only: {config.https_only}")

    _config = config
    return config


def reset_config() -> None:
    """Reset cached config (for testing)."""
    global _config
    _config = None
