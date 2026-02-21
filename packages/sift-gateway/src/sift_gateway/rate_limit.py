"""Per-IP sliding window rate limiter for the AIIR gateway.

In-memory implementation suitable for a single-process gateway.
Each IP address is tracked independently with a configurable
requests-per-minute limit using a sliding window approach.
"""

import threading
import time

# Default: 60 requests per 60-second window.
DEFAULT_LIMIT = 60
DEFAULT_WINDOW_SECONDS = 60.0

# How often (in seconds) to purge stale entries from the store.
_CLEANUP_INTERVAL = 120.0


class RateLimiter:
    """Sliding-window rate limiter keyed by IP address.

    Thread-safe. Designed for use in an async Starlette app where
    multiple ASGI workers share the same process.

    Args:
        limit: Maximum number of requests allowed per window.
        window: Window size in seconds.
    """

    def __init__(
        self,
        limit: int = DEFAULT_LIMIT,
        window: float = DEFAULT_WINDOW_SECONDS,
    ):
        self.limit = limit
        self.window = window
        self._store: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def is_allowed(self, ip: str) -> bool:
        """Check whether a request from *ip* is within the rate limit.

        Records the request timestamp if allowed.

        Returns:
            True if the request should proceed, False if rate limited.
        """
        now = time.monotonic()

        with self._lock:
            # Periodic cleanup of stale entries
            if now - self._last_cleanup > _CLEANUP_INTERVAL:
                self._cleanup(now)
                self._last_cleanup = now

            timestamps = self._store.get(ip)
            if timestamps is None:
                self._store[ip] = [now]
                return True

            # Trim timestamps outside the sliding window
            cutoff = now - self.window
            # Find first index within the window (list is append-ordered)
            start = 0
            for i, ts in enumerate(timestamps):
                if ts >= cutoff:
                    start = i
                    break
            else:
                # All timestamps are expired
                start = len(timestamps)

            timestamps[:] = timestamps[start:]

            if len(timestamps) >= self.limit:
                return False

            timestamps.append(now)
            return True

    def _cleanup(self, now: float) -> None:
        """Remove IPs with no recent requests. Caller must hold _lock."""
        cutoff = now - self.window
        stale_keys = [
            ip for ip, timestamps in self._store.items()
            if not timestamps or timestamps[-1] < cutoff
        ]
        for key in stale_keys:
            del self._store[key]


# Module-level singleton. Shared across all request handlers in the process.
_limiter: RateLimiter | None = None


def get_rate_limiter(
    limit: int = DEFAULT_LIMIT,
    window: float = DEFAULT_WINDOW_SECONDS,
) -> RateLimiter:
    """Return the module-level rate limiter singleton, creating it on first call.

    Subsequent calls return the existing instance (limit/window args are
    ignored after creation). Call ``reset_rate_limiter()`` to replace it.
    """
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(limit=limit, window=window)
    return _limiter


def reset_rate_limiter() -> None:
    """Replace the module-level rate limiter (useful for tests)."""
    global _limiter
    _limiter = None


def check_rate_limit(ip: str) -> bool:
    """Convenience: check the singleton limiter. Returns True if allowed."""
    return get_rate_limiter().is_allowed(ip)
