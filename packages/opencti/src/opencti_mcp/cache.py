"""TTL-based caching for OpenCTI MCP Server.

Provides response caching to:
- Reduce API load on OpenCTI
- Improve response times
- Enable graceful degradation during outages
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Optional, TypeVar, Generic

from .logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")

# Sentinel for "definitively not found" (negative caching)
NOT_FOUND = object()


@dataclass
class CacheEntry(Generic[T]):
    """A cached value with timestamp."""
    value: T
    timestamp: float
    is_negative: bool = False


class TTLCache(Generic[T]):
    """Thread-safe TTL-based cache with size limit.

    Features:
    - Automatic expiration based on TTL
    - Maximum size with LRU eviction
    - Negative caching support
    - Thread-safe operations
    - Monotonic time (immune to clock adjustments)
    """

    def __init__(
        self,
        ttl_seconds: float,
        negative_ttl_seconds: Optional[float] = None,
        max_size: int = 1000,
        name: str = "cache",
    ):
        """Initialize cache.

        Args:
            ttl_seconds: TTL for positive cache entries
            negative_ttl_seconds: TTL for negative entries (default: ttl/2)
            max_size: Maximum entries before LRU eviction
            name: Cache name for logging
        """
        self.ttl = ttl_seconds
        self.negative_ttl = negative_ttl_seconds or (ttl_seconds / 2)
        self.max_size = max_size
        self.name = name

        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = Lock()

        # Metrics
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str) -> tuple[bool, Optional[T]]:
        """Get value from cache.

        Returns:
            (found, value) tuple:
            - (True, value) - Cache hit with value
            - (True, NOT_FOUND) - Negative cache hit (item doesn't exist)
            - (False, None) - Cache miss
        """
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return (False, None)

            entry = self._cache[key]
            ttl = self.negative_ttl if entry.is_negative else self.ttl

            # Check expiration — don't delete, just return miss.
            # Expired entries are kept for get_stale() (graceful degradation)
            # and will be evicted by LRU when capacity is needed.
            if time.monotonic() - entry.timestamp > ttl:
                self._misses += 1
                return (False, None)

            # Move to end (LRU)
            self._cache.move_to_end(key)
            self._hits += 1
            return (True, entry.value)

    def set(self, key: str, value: T) -> None:
        """Store value in cache."""
        with self._lock:
            self._set_unlocked(key, value, is_negative=False)

    def set_negative(self, key: str) -> None:
        """Store negative result (item doesn't exist)."""
        with self._lock:
            self._set_unlocked(key, NOT_FOUND, is_negative=True)

    def _set_unlocked(self, key: str, value: Any, is_negative: bool) -> None:
        """Store value (must be called with lock held)."""
        # Evict oldest if at capacity
        while len(self._cache) >= self.max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            self._evictions += 1

        self._cache[key] = CacheEntry(
            value=value,
            timestamp=time.monotonic(),
            is_negative=is_negative,
        )

    def get_stale(self, key: str) -> tuple[bool, Optional[T]]:
        """Get value from cache, ignoring TTL expiration.

        Used for graceful degradation when the server is unavailable.
        Returns expired entries that would normally be evicted by get().

        Returns:
            (found, value) tuple (same as get(), but TTL is not enforced)
        """
        with self._lock:
            if key not in self._cache:
                return (False, None)

            entry = self._cache[key]
            return (True, entry.value)

    def invalidate(self, key: str) -> bool:
        """Remove specific entry from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> int:
        """Clear all entries. Returns number cleared."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0.0

            return {
                "name": self.name,
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 3),
                "evictions": self._evictions,
                "ttl_seconds": self.ttl,
                "negative_ttl_seconds": self.negative_ttl,
            }


class CacheManager:
    """Manages multiple caches with coordinated operations."""

    def __init__(self) -> None:
        self._caches: dict[str, TTLCache[Any]] = {}
        self._lock = Lock()

    def register(self, name: str, cache: TTLCache[Any]) -> None:
        """Register a cache for management."""
        with self._lock:
            self._caches[name] = cache

    def get(self, name: str) -> Optional[TTLCache[Any]]:
        """Get cache by name."""
        with self._lock:
            return self._caches.get(name)

    def clear_all(self) -> dict[str, int]:
        """Clear all caches. Returns counts per cache."""
        with self._lock:
            return {name: cache.clear() for name, cache in self._caches.items()}

    def clear(self, name: str) -> int:
        """Clear specific cache."""
        with self._lock:
            if name in self._caches:
                return self._caches[name].clear()
            return 0

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        """Get stats for all caches."""
        with self._lock:
            return {name: cache.get_stats() for name, cache in self._caches.items()}


def generate_cache_key(*args: Any, **kwargs: Any) -> str:
    """Generate consistent cache key from arguments.

    Creates MD5 hash of arguments for use as cache key.
    """
    key_parts = [str(arg) for arg in args]
    key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
    key_str = "|".join(key_parts)
    return hashlib.md5(key_str.encode()).hexdigest()


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


def get_cache_manager() -> CacheManager:
    """Get or create global cache manager."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager


def reset_cache_manager() -> None:
    """Reset global cache manager (for testing)."""
    global _cache_manager
    if _cache_manager is not None:
        _cache_manager.clear_all()
    _cache_manager = None
