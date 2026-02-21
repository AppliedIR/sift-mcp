"""Tests for the TTL cache module."""

from __future__ import annotations

import time
import pytest
from concurrent.futures import ThreadPoolExecutor

from opencti_mcp.cache import (
    TTLCache,
    CacheManager,
    NOT_FOUND,
    generate_cache_key,
    get_cache_manager,
    reset_cache_manager,
)


# =============================================================================
# TTLCache Tests
# =============================================================================

class TestTTLCache:
    """Tests for TTLCache class."""

    def test_set_and_get(self):
        """Basic set and get operations."""
        cache = TTLCache(ttl_seconds=60, name="test")
        cache.set("key1", "value1")

        found, value = cache.get("key1")
        assert found is True
        assert value == "value1"

    def test_cache_miss(self):
        """Get on missing key returns miss."""
        cache = TTLCache(ttl_seconds=60)

        found, value = cache.get("nonexistent")
        assert found is False
        assert value is None

    def test_ttl_expiration(self):
        """Entries expire after TTL."""
        cache = TTLCache(ttl_seconds=0.05)  # 50ms TTL
        cache.set("key1", "value1")

        # Should be present initially
        found, value = cache.get("key1")
        assert found is True

        # Wait for expiration
        time.sleep(0.06)

        # Should be gone
        found, value = cache.get("key1")
        assert found is False

    def test_negative_caching(self):
        """Negative cache entries work."""
        cache = TTLCache(ttl_seconds=60, negative_ttl_seconds=30)
        cache.set_negative("missing_key")

        found, value = cache.get("missing_key")
        assert found is True
        assert value is NOT_FOUND

    def test_negative_cache_shorter_ttl(self):
        """Negative cache has shorter TTL than positive."""
        cache = TTLCache(ttl_seconds=1.0, negative_ttl_seconds=0.05)

        cache.set_negative("negative")
        cache.set("positive", "value")

        # Both present initially
        assert cache.get("negative")[0] is True
        assert cache.get("positive")[0] is True

        # Wait for negative TTL
        time.sleep(0.06)

        # Negative should be gone, positive still present
        assert cache.get("negative")[0] is False
        assert cache.get("positive")[0] is True

    def test_max_size_eviction(self):
        """Cache evicts oldest entries when full."""
        cache = TTLCache(ttl_seconds=60, max_size=3)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # All present
        assert cache.get("key1")[0] is True
        assert cache.get("key2")[0] is True
        assert cache.get("key3")[0] is True

        # Add fourth - should evict oldest
        cache.set("key4", "value4")

        # key1 should be evicted (was oldest)
        assert cache.get("key1")[0] is False
        assert cache.get("key4")[0] is True

    def test_lru_behavior(self):
        """Access moves entry to end (LRU)."""
        cache = TTLCache(ttl_seconds=60, max_size=3)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Access key1 to make it most recently used
        cache.get("key1")

        # Add key4 - should evict key2 (now oldest)
        cache.set("key4", "value4")

        assert cache.get("key1")[0] is True  # Still present (was accessed)
        assert cache.get("key2")[0] is False  # Evicted
        assert cache.get("key4")[0] is True

    def test_invalidate(self):
        """Invalidate removes specific entry."""
        cache = TTLCache(ttl_seconds=60)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        result = cache.invalidate("key1")
        assert result is True
        assert cache.get("key1")[0] is False
        assert cache.get("key2")[0] is True

    def test_invalidate_missing(self):
        """Invalidate returns False for missing key."""
        cache = TTLCache(ttl_seconds=60)
        result = cache.invalidate("nonexistent")
        assert result is False

    def test_clear(self):
        """Clear removes all entries."""
        cache = TTLCache(ttl_seconds=60)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        count = cache.clear()
        assert count == 2
        assert cache.get("key1")[0] is False
        assert cache.get("key2")[0] is False

    def test_stats(self):
        """Stats are tracked correctly."""
        cache = TTLCache(ttl_seconds=60, max_size=10, name="test_stats")

        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("missing")  # Miss

        stats = cache.get_stats()
        assert stats["name"] == "test_stats"
        assert stats["size"] == 1
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate"] == pytest.approx(0.667, abs=0.01)

    def test_thread_safety(self):
        """Cache is thread-safe."""
        cache = TTLCache(ttl_seconds=60, max_size=1000)
        results = []

        def worker(worker_id: int):
            for i in range(100):
                key = f"worker{worker_id}_key{i}"
                cache.set(key, f"value{i}")
                found, value = cache.get(key)
                if found:
                    results.append(value)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for f in futures:
                f.result()

        # All operations should complete without error
        assert len(results) > 0


# =============================================================================
# CacheManager Tests
# =============================================================================

class TestCacheManager:
    """Tests for CacheManager class."""

    def test_register_and_get(self):
        """Register and retrieve caches."""
        manager = CacheManager()
        cache1 = TTLCache(ttl_seconds=60, name="cache1")
        cache2 = TTLCache(ttl_seconds=120, name="cache2")

        manager.register("cache1", cache1)
        manager.register("cache2", cache2)

        assert manager.get("cache1") is cache1
        assert manager.get("cache2") is cache2
        assert manager.get("nonexistent") is None

    def test_clear_specific(self):
        """Clear specific cache."""
        manager = CacheManager()
        cache1 = TTLCache(ttl_seconds=60)
        cache2 = TTLCache(ttl_seconds=60)

        manager.register("cache1", cache1)
        manager.register("cache2", cache2)

        cache1.set("key", "value")
        cache2.set("key", "value")

        manager.clear("cache1")

        assert cache1.get("key")[0] is False
        assert cache2.get("key")[0] is True

    def test_clear_all(self):
        """Clear all caches."""
        manager = CacheManager()
        cache1 = TTLCache(ttl_seconds=60, name="cache1")
        cache2 = TTLCache(ttl_seconds=60, name="cache2")

        manager.register("cache1", cache1)
        manager.register("cache2", cache2)

        cache1.set("key", "value")
        cache2.set("key", "value")

        counts = manager.clear_all()

        assert counts == {"cache1": 1, "cache2": 1}
        assert cache1.get("key")[0] is False
        assert cache2.get("key")[0] is False

    def test_get_all_stats(self):
        """Get stats from all caches."""
        manager = CacheManager()
        cache1 = TTLCache(ttl_seconds=60, name="cache1")
        cache2 = TTLCache(ttl_seconds=120, name="cache2")

        manager.register("cache1", cache1)
        manager.register("cache2", cache2)

        cache1.set("key", "value")

        stats = manager.get_all_stats()

        assert "cache1" in stats
        assert "cache2" in stats
        assert stats["cache1"]["size"] == 1
        assert stats["cache2"]["size"] == 0


# =============================================================================
# Utility Function Tests
# =============================================================================

class TestCacheUtilities:
    """Tests for cache utility functions."""

    def test_generate_cache_key_args(self):
        """Generate key from positional args."""
        key1 = generate_cache_key("arg1", "arg2", 123)
        key2 = generate_cache_key("arg1", "arg2", 123)
        key3 = generate_cache_key("arg1", "arg2", 456)

        assert key1 == key2  # Same args = same key
        assert key1 != key3  # Different args = different key

    def test_generate_cache_key_kwargs(self):
        """Generate key from keyword args."""
        key1 = generate_cache_key(a=1, b=2)
        key2 = generate_cache_key(b=2, a=1)  # Order shouldn't matter
        key3 = generate_cache_key(a=1, b=3)

        assert key1 == key2  # Same kwargs = same key
        assert key1 != key3  # Different kwargs = different key

    def test_generate_cache_key_mixed(self):
        """Generate key from mixed args and kwargs."""
        key = generate_cache_key("query", limit=10, offset=0)
        assert isinstance(key, str)
        assert len(key) == 32  # MD5 hex length

    def test_global_cache_manager(self):
        """Global cache manager singleton works."""
        reset_cache_manager()

        manager1 = get_cache_manager()
        manager2 = get_cache_manager()

        assert manager1 is manager2

    def test_reset_global_cache_manager(self):
        """Reset clears global cache manager."""
        manager1 = get_cache_manager()
        cache = TTLCache(ttl_seconds=60)
        manager1.register("test", cache)
        cache.set("key", "value")

        reset_cache_manager()
        manager2 = get_cache_manager()

        # Should be new manager, cache should be gone
        assert manager2.get("test") is None


# =============================================================================
# Edge Cases
# =============================================================================

class TestCacheEdgeCases:
    """Edge case tests."""

    def test_empty_cache_stats(self):
        """Stats work on empty cache."""
        cache = TTLCache(ttl_seconds=60)
        stats = cache.get_stats()

        assert stats["size"] == 0
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate"] == 0.0

    def test_overwrite_existing_key(self):
        """Setting existing key overwrites value."""
        cache = TTLCache(ttl_seconds=60)
        cache.set("key", "value1")
        cache.set("key", "value2")

        found, value = cache.get("key")
        assert found is True
        assert value == "value2"

    def test_none_value(self):
        """None is a valid cached value."""
        cache = TTLCache(ttl_seconds=60)
        cache.set("key", None)

        found, value = cache.get("key")
        assert found is True
        assert value is None

    def test_complex_values(self):
        """Complex objects can be cached."""
        cache = TTLCache(ttl_seconds=60)

        data = {"id": 123, "items": [1, 2, 3], "nested": {"a": "b"}}
        cache.set("key", data)

        found, value = cache.get("key")
        assert found is True
        assert value == data
