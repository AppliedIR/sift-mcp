"""
Centralized Configuration for Windows Triage MCP Server

All configuration is managed through this module. Settings can be overridden
via environment variables with the WT_ prefix.

Environment Variables:
    WT_DATA_DIR: Base data directory (default: ./data)
    WT_KNOWN_GOOD_DB: Path to baseline database
    WT_CONTEXT_DB: Path to context database
    WT_LOG_LEVEL: Logging level (default: INFO)
    WT_CACHE_SIZE: LRU cache size for lookups (default: 10000)

Usage:
    from windows_triage.config import get_config
    config = get_config()
    print(config.cache_size)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from .exceptions import ConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Centralized configuration - validated at creation time.

    This class holds all configuration settings for the windows-triage-mcp server.
    Settings can be provided explicitly or loaded from environment variables.
    """

    # Paths
    project_root: Path = field(
        default_factory=lambda: Path(__file__).parent.parent.parent
    )
    data_dir: Path = field(default=None)
    known_good_db: Path = field(default=None)
    context_db: Path = field(default=None)
    registry_db: Path = field(default=None)  # Optional full registry baseline

    # Input validation limits
    max_path_length: int = 4096
    max_hash_length: int = 128
    max_pipe_name_length: int = 256
    max_service_name_length: int = 256
    max_task_path_length: int = 1024
    max_key_path_length: int = 1024

    # Behavior settings
    log_level: str = "INFO"

    # Performance settings
    cache_size: int = 10000  # LRU cache size for lookups

    # Runtime flags
    skip_db_validation: bool = False  # Set True for tests with temp DBs

    def __post_init__(self):
        """Set defaults and validate configuration after creation."""
        # Set default paths if not provided
        if self.data_dir is None:
            self.data_dir = self.project_root / "data"
        if self.known_good_db is None:
            self.known_good_db = self.data_dir / "known_good.db"
        if self.context_db is None:
            self.context_db = self.data_dir / "context.db"
        if self.registry_db is None:
            self.registry_db = self.data_dir / "known_good_registry.db"

        # Ensure paths are Path objects
        self.data_dir = Path(self.data_dir)
        self.known_good_db = Path(self.known_good_db)
        self.context_db = Path(self.context_db)
        self.registry_db = Path(self.registry_db)

        # Validate settings
        self._validate()

    def _validate(self):
        """Validate configuration values."""
        # Validate log level
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        if self.log_level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Invalid log_level: {self.log_level}. "
                f"Must be one of: {', '.join(valid_levels)}"
            )

        # Validate numeric limits with bounds
        if self.max_path_length < 1 or self.max_path_length > 32768:
            raise ConfigurationError("max_path_length must be between 1 and 32768")
        if self.max_hash_length < 32 or self.max_hash_length > 256:
            raise ConfigurationError("max_hash_length must be between 32 and 256")
        if self.cache_size < 0 or self.cache_size > 1_000_000:
            raise ConfigurationError("cache_size must be between 0 and 1,000,000")


def _parse_int_env(name: str, default: int) -> int:
    """Parse integer from environment variable with error handling.

    Args:
        name: Environment variable name
        default: Default value if not set

    Returns:
        Parsed integer value

    Raises:
        ConfigurationError: If value is not a valid integer
    """
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ConfigurationError(f"Invalid integer for {name}: {value!r}") from None


def _load_config_from_env() -> Config:
    """Load configuration from environment variables.

    Returns:
        Config instance with settings from environment variables.

    Raises:
        ConfigurationError: If environment variables are invalid
    """
    project_root = Path(__file__).parent.parent.parent

    # Load paths from environment
    data_dir_str = os.environ.get("WT_DATA_DIR")
    known_good_db_str = os.environ.get("WT_KNOWN_GOOD_DB")
    context_db_str = os.environ.get("WT_CONTEXT_DB")
    registry_db_str = os.environ.get("WT_REGISTRY_DB")

    # Parse paths
    data_dir = Path(data_dir_str) if data_dir_str else None
    known_good_db = Path(known_good_db_str) if known_good_db_str else None
    context_db = Path(context_db_str) if context_db_str else None
    registry_db = Path(registry_db_str) if registry_db_str else None

    return Config(
        project_root=project_root,
        data_dir=data_dir,
        known_good_db=known_good_db,
        context_db=context_db,
        registry_db=registry_db,
        max_path_length=_parse_int_env("WT_MAX_PATH_LENGTH", 4096),
        max_hash_length=_parse_int_env("WT_MAX_HASH_LENGTH", 128),
        max_pipe_name_length=_parse_int_env("WT_MAX_PIPE_NAME_LENGTH", 256),
        max_service_name_length=_parse_int_env("WT_MAX_SERVICE_NAME_LENGTH", 256),
        max_task_path_length=_parse_int_env("WT_MAX_TASK_PATH_LENGTH", 1024),
        max_key_path_length=_parse_int_env("WT_MAX_KEY_PATH_LENGTH", 1024),
        log_level=os.environ.get("WT_LOG_LEVEL", "INFO"),
        cache_size=_parse_int_env("WT_CACHE_SIZE", 10000),
        skip_db_validation=os.environ.get("WT_SKIP_DB_VALIDATION", "").lower()
        in ("1", "true", "yes"),
    )


# Module-level singleton
_config: Config | None = None


def get_config(reload: bool = False) -> Config:
    """Get or create configuration singleton.

    Args:
        reload: If True, reload configuration from environment variables.

    Returns:
        Current Config instance.
    """
    global _config
    if reload or _config is None:
        _config = _load_config_from_env()
        logger.debug(f"Configuration loaded: cache_size={_config.cache_size}")
    return _config


def set_config(config: Config) -> None:
    """Set configuration directly (useful for testing).

    Args:
        config: Config instance to use.
    """
    global _config
    _config = config


def reset_config() -> None:
    """Reset configuration to force reload on next get_config() call."""
    global _config
    _config = None
