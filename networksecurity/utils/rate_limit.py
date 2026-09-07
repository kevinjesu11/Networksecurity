"""Per-client rate limiting for the prediction endpoints.

/predict-url is unusually expensive for an anonymous endpoint: each call costs a
DNS lookup, an outbound HTTP fetch and a WHOIS query against a target the caller
chooses. Left unlimited on a public port that is both a way to exhaust the
server's worker threads and a way to make the instance generate outbound traffic
on someone else's behalf.

A fixed-window counter, held in memory. That is the right scope for a single
container: it needs no dependencies, and the failure mode of losing counts on
restart is acceptable for what it protects. It does not survive across replicas,
so running more than one container means moving this to shared storage.
"""

import os
import threading
import time
from collections import defaultdict, deque

# Defaults are deliberately generous for interactive use and still low enough to
# make sustained automated abuse impractical.
DEFAULT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "20"))
DEFAULT_WINDOW_SECONDS = float(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Stops the bookkeeping itself becoming a memory-exhaustion vector: a flood from
# spoofed or rotating addresses would otherwise grow the map without bound.
MAX_TRACKED_CLIENTS = 10_000


class RateLimiter:
    """Sliding-window request counter, keyed by client identifier."""

    def __init__(self, max_requests=None, window_seconds=None):
        self.max_requests = max_requests or DEFAULT_MAX_REQUESTS
        self.window_seconds = window_seconds or DEFAULT_WINDOW_SECONDS
        self._hits = defaultdict(deque)
        # Handlers run in FastAPI's threadpool, so several can touch this at once.
        self._lock = threading.Lock()

    def _prune(self, key, now):
        window = self._hits[key]
        cutoff = now - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        return window

    def check(self, key):
        """Records a request for `key`.

        Returns (allowed, retry_after_seconds). retry_after is 0 when allowed.
        """
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > MAX_TRACKED_CLIENTS:
                self._evict_idle(now)

            window = self._prune(key, now)
            if len(window) >= self.max_requests:
                retry_after = max(1, int(window[0] + self.window_seconds - now) + 1)
                return False, retry_after

            window.append(now)
            return True, 0

    def _evict_idle(self, now):
        """Drops clients with no requests left in the window. Caller holds the lock."""
        cutoff = now - self.window_seconds
        for key in [k for k, w in self._hits.items() if not w or w[-1] <= cutoff]:
            del self._hits[key]

    def reset(self):
        with self._lock:
            self._hits.clear()


def client_key(request) -> str:
    """Identifies the caller for rate-limiting purposes.

    Uses the socket peer address. X-Forwarded-For is deliberately ignored: it is
    caller-supplied and trivially spoofed, so honouring it here would let anyone
    bypass the limit by varying a header. Putting this behind a load balancer or
    reverse proxy means revisiting it, and trusting that header only for the
    proxy's own address.
    """
    client = getattr(request, "client", None)
    return client.host if client and client.host else "unknown"
