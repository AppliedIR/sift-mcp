"""Configuration management for OpenCTI MCP.

Security design:
- Tokens stored as SecretStr (never logged)
- Token file permissions enforced (600)
- Config objects cannot be pickled
- URL validation prevents SSRF
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .errors import ConfigurationError

logger = logging.getLogger(__name__)


# =============================================================================
# Environment Variable Parsing Helpers
# =============================================================================


def _parse_int_env(name: str, default: int) -> int:
    """Parse integer environment variable with fallback to default.

    Logs a warning if the value is invalid instead of crashing.
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(
            f"Invalid integer value for {name}: '{value}', using default {default}"
        )
        return default


def _parse_float_env(name: str, default: float) -> float:
    """Parse float environment variable with fallback to default.

    Logs a warning if the value is invalid instead of crashing.
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning(
            f"Invalid float value for {name}: '{value}', using default {default}"
        )
        return default


def _parse_set_env(name: str) -> frozenset[str]:
    """Parse comma-separated environment variable into a frozenset.

    Empty values and whitespace-only values are filtered out.
    Values are stripped but NOT lowercased (type names are case-sensitive).

    Args:
        name: Environment variable name

    Returns:
        frozenset of parsed values (empty if not set)
    """
    value = os.getenv(name)
    if not value:
        return frozenset()

    items = []
    for item in value.split(","):
        item = item.strip()
        if item:
            items.append(item)

    return frozenset(items)


# =============================================================================
# Secret String Type
# =============================================================================


class SecretStr:
    """String type that hides its value in logs and repr.

    Security: Prevents accidental credential exposure in logs,
    error messages, or debug output.
    """

    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        """Get the actual secret value."""
        return self._value

    def __repr__(self) -> str:
        return "SecretStr('***')"

    def __str__(self) -> str:
        return "***"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self._value == other._value
        return False

    def __hash__(self) -> int:
        return hash(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)


# =============================================================================
# Configuration Class
# =============================================================================


@dataclass(frozen=True)
class Config:
    """Immutable server configuration.

    Security:
    - opencti_token is SecretStr (never logged)
    - Cannot be pickled (prevents serialization of secrets)
    - URL validated to prevent SSRF
    - frozen=True prevents accidental mutation

    Production considerations:
    - timeout_seconds: Increase for remote instances (60-120s recommended)
    - max_retries: Number of retry attempts for transient failures
    - retry_backoff: Exponential backoff multiplier
    - ssl_verify: Enable for production (disable only for local dev)
    - circuit_breaker_threshold: Failures before circuit opens
    """

    opencti_url: str
    opencti_token: SecretStr
    timeout_seconds: int = 60
    max_results: int = 100
    rate_limit_queries: int = 60  # queries per minute
    rate_limit_enrichment: int = 10  # enrichments per hour

    # Production network resilience
    max_retries: int = 3  # retry attempts for transient failures
    retry_base_delay: float = 1.0  # base delay in seconds (exponential backoff)
    retry_max_delay: float = 30.0  # max delay between retries
    ssl_verify: bool = True  # verify SSL certs (disable only for local dev)
    circuit_breaker_threshold: int = 5  # failures before circuit opens
    circuit_breaker_timeout: int = 60  # seconds before circuit half-opens

    # Extensibility - allow custom types for customized OpenCTI instances
    extra_observable_types: frozenset[str] = field(default_factory=frozenset)
    extra_pattern_types: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate configuration after initialization.

        Note: Uses object.__setattr__ because dataclass is frozen.
        """
        # Validate and normalize URL (can't reassign due to frozen, so validate first)
        validated_url = _validate_url(self.opencti_url)
        # Use object.__setattr__ to bypass frozen for initialization
        object.__setattr__(self, "opencti_url", validated_url)
        self._validate_values()

    def _validate_values(self) -> None:
        """Validate configuration values (called from __post_init__)."""
        # Validate token
        if not self.opencti_token:
            raise ConfigurationError("OpenCTI token is required")

        # Validate numeric values
        if self.timeout_seconds < 1 or self.timeout_seconds > 300:
            raise ConfigurationError("timeout_seconds must be between 1 and 300")

        if self.max_results < 1 or self.max_results > 1000:
            raise ConfigurationError("max_results must be between 1 and 1000")

    def __repr__(self) -> str:
        """Safe repr that never includes token."""
        return (
            f"Config(opencti_url={self.opencti_url!r}, "
            f"token=***, timeout={self.timeout_seconds}s)"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __getstate__(self) -> None:
        """Prevent pickling to avoid credential serialization."""
        raise TypeError("Config cannot be pickled (contains secrets)")

    def __reduce__(self) -> None:  # type: ignore[override]
        """Prevent pickling via reduce."""
        raise TypeError("Config cannot be pickled (contains secrets)")

    @classmethod
    def load(cls) -> Config:
        """Load configuration from environment and files.

        Credential sources (precedence order):
        1. OPENCTI_TOKEN environment variable
        2. ~/.config/opencti-mcp/token file
        3. .env file in working directory

        Returns:
            Config: Validated configuration

        Raises:
            ConfigurationError: If token not found or invalid
        """
        # Load URL
        url = os.getenv("OPENCTI_URL", "http://localhost:8080")

        # Load token
        token = _load_token()
        if not token:
            raise ConfigurationError(
                "OpenCTI API token not found. Set OPENCTI_TOKEN environment variable "
                "or create ~/.config/opencti-mcp/token file."
            )

        # Load optional settings with safe parsing
        timeout = _parse_int_env("OPENCTI_TIMEOUT", 60)
        max_results = _parse_int_env("OPENCTI_MAX_RESULTS", 100)

        # Production resilience settings
        max_retries = _parse_int_env("OPENCTI_MAX_RETRIES", 3)
        retry_base_delay = _parse_float_env("OPENCTI_RETRY_DELAY", 1.0)
        retry_max_delay = _parse_float_env("OPENCTI_RETRY_MAX_DELAY", 30.0)
        ssl_verify = os.getenv("OPENCTI_SSL_VERIFY", "true").lower() in (
            "true",
            "1",
            "yes",
        )
        circuit_threshold = _parse_int_env("OPENCTI_CIRCUIT_THRESHOLD", 5)
        circuit_timeout = _parse_int_env("OPENCTI_CIRCUIT_TIMEOUT", 60)

        # Extensibility settings for custom OpenCTI instances
        extra_observable_types = _parse_set_env("OPENCTI_EXTRA_OBSERVABLE_TYPES")
        extra_pattern_types = _parse_set_env("OPENCTI_EXTRA_PATTERN_TYPES")

        return cls(
            opencti_url=url,
            opencti_token=SecretStr(token),
            timeout_seconds=timeout,
            max_results=max_results,
            max_retries=max_retries,
            retry_base_delay=retry_base_delay,
            retry_max_delay=retry_max_delay,
            ssl_verify=ssl_verify,
            circuit_breaker_threshold=circuit_threshold,
            circuit_breaker_timeout=circuit_timeout,
            extra_observable_types=extra_observable_types,
            extra_pattern_types=extra_pattern_types,
        )


# =============================================================================
# Token Loading
# =============================================================================


def _load_token() -> str | None:
    """Load OpenCTI token from available sources.

    Security: Token file permissions are enforced.
    """
    # 1. Environment variable (highest priority)
    token = os.getenv("OPENCTI_TOKEN")
    if token is not None:
        stripped = token.strip()
        if stripped:
            logger.debug("Loaded token from OPENCTI_TOKEN environment variable")
            return stripped
        # Non-empty but whitespace-only — treat as explicitly invalid, don't fall through
        if token:
            return None

    # 2. Config file (primary location)
    config_file = Path.home() / ".config" / "opencti-mcp" / "token"
    token = _load_token_file(config_file)
    if token:
        logger.debug("Loaded token from config file")
        return token

    # 3. Legacy config file (for compatibility with opencti_query.py)
    legacy_config = Path.home() / ".config" / "rag" / "opencti_token"
    token = _load_token_file(legacy_config)
    if token:
        logger.debug(
            "Loaded token from legacy config file (~/.config/rag/opencti_token)"
        )
        return token

    # 4. .env file in current directory
    env_file = Path.cwd() / ".env"
    token = _load_token_from_env_file(env_file)
    if token:
        logger.debug("Loaded token from .env file")
        return token

    return None


def _load_token_file(path: Path) -> str | None:
    """Load token from file with permission check.

    Security: Refuses to load token if file permissions are too open.
    """
    if not path.exists():
        return None

    # Check file permissions on POSIX systems
    if hasattr(os, "stat"):
        mode = path.stat().st_mode
        # Check if group or other can read/write (requires 600 or 400)
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            logger.warning(
                "Token file has insecure permissions",
                extra={"path": str(path), "mode": oct(mode)},
            )
            raise ConfigurationError(
                f"Token file {path} has insecure permissions. Run: chmod 600 {path}"
            )

    try:
        token = path.read_text().strip()
        if not token:
            return None
        return token
    except OSError as e:
        logger.warning(f"Failed to read token file: {e}")
        return None


def _load_token_from_env_file(path: Path) -> str | None:
    """Load token from .env file.

    Security: Enforces file permissions to prevent credential exposure.
    """
    if not path.exists():
        return None

    # Check file permissions on POSIX systems
    if hasattr(os, "stat"):
        mode = path.stat().st_mode
        # Warn if world (other) can read/write (group access OK for dev, 640)
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            logger.warning(
                ".env file has insecure permissions (world-readable)",
                extra={"path": str(path), "mode": oct(mode)},
            )
            # Don't fail, but warn - .env files are often shared in dev

    try:
        content = path.read_text()
        for line in content.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            if line.startswith("OPENCTI_TOKEN=") or line.startswith(
                "OPENCTI_ADMIN_TOKEN="
            ):
                value = line.split("=", 1)[1].strip()
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                return value

        return None
    except OSError as e:
        logger.warning(f"Failed to read .env file: {e}")
        return None


# =============================================================================
# URL Validation
# =============================================================================


def _validate_url(url: str) -> str:
    """Validate and normalize OpenCTI URL.

    Security: Prevents SSRF by restricting URL schemes.
    """
    url = url.strip().rstrip("/")

    if not url:
        raise ConfigurationError("OpenCTI URL cannot be empty")

    parsed = urlparse(url)

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        raise ConfigurationError(
            f"Invalid URL scheme: {parsed.scheme}. Use http or https."
        )

    # Must have a host
    if not parsed.netloc:
        raise ConfigurationError("Invalid URL: missing host")

    # Warn if using HTTP for non-local hosts
    if parsed.scheme == "http":
        host = parsed.hostname or ""
        is_local = host in ("localhost", "127.0.0.1", "::1") or host.startswith(
            (
                "10.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "192.168.",
            )
        )

        if not is_local:
            logger.warning(
                "Using HTTP for non-local OpenCTI - credentials sent in plaintext",
                extra={"url": url},
            )

    return url
