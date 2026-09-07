"""Tests for the rate limiter and its wiring into the prediction routes.

/predict-url is anonymous and costs a DNS lookup, an outbound HTTP fetch and a
WHOIS query per call against a caller-chosen target. On a public port that is
both a way to exhaust worker threads and a way to make the instance generate
traffic on someone else's behalf.
"""

import time
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import app as app_module
from networksecurity.utils.rate_limit import RateLimiter, client_key


# -- limiter behaviour ----------------------------------------------------

def test_allows_up_to_the_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        allowed, _ = limiter.check("client")
        assert allowed


def test_blocks_past_the_limit():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    limiter.check("client")
    limiter.check("client")
    allowed, retry_after = limiter.check("client")
    assert not allowed
    assert retry_after > 0


def test_clients_are_counted_separately():
    """One noisy caller must not lock everyone else out."""
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    assert limiter.check("1.1.1.1")[0]
    assert not limiter.check("1.1.1.1")[0]
    assert limiter.check("2.2.2.2")[0]


def test_window_expires():
    limiter = RateLimiter(max_requests=1, window_seconds=0.2)
    assert limiter.check("client")[0]
    assert not limiter.check("client")[0]
    time.sleep(0.25)
    assert limiter.check("client")[0], "the window should have rolled over"


def test_idle_clients_are_evicted():
    """The bookkeeping must not itself become a memory-exhaustion vector."""
    limiter = RateLimiter(max_requests=5, window_seconds=0.05)
    for i in range(50):
        limiter.check(f"client-{i}")
    time.sleep(0.1)
    with limiter._lock:
        limiter._evict_idle(time.monotonic())
    assert len(limiter._hits) == 0


def test_concurrent_access_is_consistent():
    """Handlers run in a threadpool, so the counter must not lose increments."""
    import threading

    limiter = RateLimiter(max_requests=1000, window_seconds=60)
    errors = []

    def hammer():
        try:
            for _ in range(100):
                limiter.check("shared")
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=hammer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(limiter._hits["shared"]) == 500


def test_forwarded_header_cannot_change_identity():
    """X-Forwarded-For is caller-supplied; honouring it would make the limit
    bypassable by varying a header."""
    request = mock.Mock()
    request.client.host = "10.1.1.1"
    request.headers = {"X-Forwarded-For": "9.9.9.9"}
    assert client_key(request) == "10.1.1.1"


def test_missing_client_does_not_raise():
    request = mock.Mock()
    request.client = None
    assert client_key(request) == "unknown"


# -- route wiring ---------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_limiter():
    app_module.rate_limiter.reset()
    yield
    app_module.rate_limiter.reset()


def test_predict_url_returns_429_past_the_limit(monkeypatch):
    client = TestClient(app_module.app, raise_server_exceptions=False)
    monkeypatch.setattr(app_module, "rate_limiter", RateLimiter(max_requests=2, window_seconds=60))

    # The limit is enforced before any model or network work, so nothing else
    # needs standing in: the third call must be refused on its own.
    seen = []
    for _ in range(3):
        seen.append(client.post("/predict-url", data={"url": "http://example.com/"}).status_code)

    assert seen[-1] == 429


def test_429_includes_retry_after(monkeypatch):
    client = TestClient(app_module.app, raise_server_exceptions=False)
    monkeypatch.setattr(app_module, "rate_limiter", RateLimiter(max_requests=1, window_seconds=60))

    client.post("/predict-url", data={"url": "http://example.com/"})
    blocked = client.post("/predict-url", data={"url": "http://example.com/"})

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_malformed_csv_returns_400_not_500():
    """A bad upload is the caller's error; 500 made it look like an outage."""
    client = TestClient(app_module.app, raise_server_exceptions=False)
    with mock.patch.object(app_module.os.path, "exists", return_value=True):
        response = client.post(
            "/predict", files={"file": ("bad.csv", b"\x00\x01\x02 not a csv \xff", "text/csv")}
        )
    assert response.status_code == 400
    assert "csv" in response.json()["detail"].lower()


def test_health_is_not_rate_limited(monkeypatch):
    """Liveness checks must keep working while a client is being throttled."""
    client = TestClient(app_module.app, raise_server_exceptions=False)
    monkeypatch.setattr(app_module, "rate_limiter", RateLimiter(max_requests=1, window_seconds=60))

    client.post("/predict-url", data={"url": "http://example.com/"})
    client.post("/predict-url", data={"url": "http://example.com/"})

    for _ in range(5):
        assert client.get("/health").status_code == 200
