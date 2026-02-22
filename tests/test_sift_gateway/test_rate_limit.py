"""Tests for sift_gateway.rate_limit — sliding window rate limiter."""

import time
from unittest.mock import patch

import pytest

from sift_gateway.rate_limit import (
    RateLimiter,
    _MAX_STORE_SIZE,
    reset_rate_limiter,
)


@pytest.fixture(autouse=True)
def clean_singleton():
    reset_rate_limiter()
    yield
    reset_rate_limiter()


class TestRateLimiterBasic:
    def test_allows_within_limit(self):
        limiter = RateLimiter(limit=5, window=60.0)
        for _ in range(5):
            assert limiter.is_allowed("1.2.3.4") is True

    def test_denies_over_limit(self):
        limiter = RateLimiter(limit=3, window=60.0)
        for _ in range(3):
            assert limiter.is_allowed("1.2.3.4") is True
        assert limiter.is_allowed("1.2.3.4") is False

    def test_per_ip_isolation(self):
        limiter = RateLimiter(limit=2, window=60.0)
        assert limiter.is_allowed("1.1.1.1") is True
        assert limiter.is_allowed("1.1.1.1") is True
        assert limiter.is_allowed("1.1.1.1") is False
        # Different IP should still be allowed
        assert limiter.is_allowed("2.2.2.2") is True
        assert limiter.is_allowed("2.2.2.2") is True


class TestRateLimiterSlidingWindow:
    def test_window_expiry(self):
        """Requests outside the sliding window should expire."""
        limiter = RateLimiter(limit=2, window=1.0)
        assert limiter.is_allowed("1.2.3.4") is True
        assert limiter.is_allowed("1.2.3.4") is True
        assert limiter.is_allowed("1.2.3.4") is False
        # Wait for window to expire
        time.sleep(1.1)
        assert limiter.is_allowed("1.2.3.4") is True

    def test_stale_entries_cleaned(self):
        """Stale entries should be cleaned during periodic cleanup."""
        limiter = RateLimiter(limit=10, window=0.1)
        limiter.is_allowed("1.1.1.1")
        limiter.is_allowed("2.2.2.2")
        time.sleep(0.2)
        # Force cleanup
        limiter._cleanup(time.monotonic())
        assert "1.1.1.1" not in limiter._store
        assert "2.2.2.2" not in limiter._store


class TestRateLimiterMaxStore:
    def test_max_store_size_triggers_cleanup(self):
        """When store exceeds _MAX_STORE_SIZE, cleanup should be triggered."""
        limiter = RateLimiter(limit=100, window=0.1)
        # Fill with entries that will expire quickly
        for i in range(100):
            limiter.is_allowed(f"10.0.0.{i % 256}")
        time.sleep(0.2)
        # Manually set store size to trigger max store check
        for i in range(_MAX_STORE_SIZE + 1):
            limiter._store[f"fake-{i}"] = [time.monotonic() - 1000]
        # Next call should trigger cleanup of stale entries
        limiter.is_allowed("new-ip")
        assert len(limiter._store) < _MAX_STORE_SIZE + 1
