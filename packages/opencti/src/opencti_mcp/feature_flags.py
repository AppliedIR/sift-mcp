"""Feature flags for gradual feature rollout.

Enables/disables features via environment variables without code changes.
Useful for:
- Testing new features in production
- Quick disable of problematic features
- A/B testing configurations
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FeatureFlags:
    """Feature flag configuration.

    All flags are loaded from environment variables with FF_ prefix.
    Default values are conservative (new/risky features disabled).

    Usage:
        flags = FeatureFlags.load()
        if flags.response_caching:
            # use cached response
    """

    # Response caching for search results
    response_caching: bool = False

    # Graceful degradation with cache fallback
    graceful_degradation: bool = True

    # Startup validation (test connectivity on startup)
    startup_validation: bool = True

    # Negative caching (cache "not found" results)
    negative_caching: bool = True

    @classmethod
    def load(cls) -> "FeatureFlags":
        """Load feature flags from environment variables.

        Environment variables use FF_ prefix:
        - FF_RESPONSE_CACHING=true
        - FF_GRACEFUL_DEGRADATION=false
        - etc.
        """
        def parse_bool(name: str, default: bool) -> bool:
            env_name = f"FF_{name.upper()}"
            value = os.environ.get(env_name, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes", "on")

        flags = cls(
            response_caching=parse_bool("response_caching", False),
            graceful_degradation=parse_bool("graceful_degradation", True),
            startup_validation=parse_bool("startup_validation", True),
            negative_caching=parse_bool("negative_caching", True),
        )

        # Log enabled flags at debug level
        enabled = [name for name, value in flags.to_dict().items() if value]
        if enabled:
            logger.debug(f"Feature flags enabled: {', '.join(enabled)}")

        return flags

    def to_dict(self) -> dict[str, bool]:
        """Convert to dictionary for serialization."""
        return {
            "response_caching": self.response_caching,
            "graceful_degradation": self.graceful_degradation,
            "startup_validation": self.startup_validation,
            "negative_caching": self.negative_caching,
        }

    def is_enabled(self, flag_name: str) -> bool:
        """Check if a flag is enabled by name."""
        return getattr(self, flag_name, False)


# Global singleton
_global_flags: FeatureFlags | None = None


def get_feature_flags() -> FeatureFlags:
    """Get or create global feature flags instance."""
    global _global_flags
    if _global_flags is None:
        _global_flags = FeatureFlags.load()
    return _global_flags


def reset_feature_flags() -> None:
    """Reset global feature flags (for testing)."""
    global _global_flags
    _global_flags = None
