"""In-process sliding-window rate limiter.

Sufficient for a single API process (the default deployment). When running several
workers, swap for the Redis-backed limiter planned in Phase 3; the interface is the same.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> tuple[bool, float]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            cutoff = now - window_seconds
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                return False, max(0.0, q[0] + window_seconds - now)
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory under abuse
                for k in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff][:10_000]:
                    self._hits.pop(k, None)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()
