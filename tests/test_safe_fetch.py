"""Tests for the SSRF guard on /predict-url.

The endpoint fetches an anonymous visitor's URL server-side, so without these
checks it proxies requests into its own network -- most damagingly to the EC2
metadata endpoint at 169.254.169.254, which hands out IAM role credentials.

DNS is stubbed throughout. These assert the guard's logic, and a test that
needed working name resolution would fail for reasons unrelated to that logic.
"""

import socket
from unittest import mock

import pytest

from networksecurity.utils.safe_fetch import (
    BlockedURLError,
    MAX_REDIRECTS,
    assert_url_is_fetchable,
    safe_get,
)


def _resolve_to(*addresses):
    """Stubs getaddrinfo so a hostname resolves to whatever the test wants."""
    return lambda host, port, *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port)) for addr in addresses
    ]


BLOCKED_ADDRESSES = [
    ("169.254.169.254", "cloud metadata endpoint"),
    ("127.0.0.1", "loopback"),
    ("10.0.0.5", "private class A"),
    ("172.16.0.1", "private class B"),
    ("192.168.1.1", "private class C"),
    ("0.0.0.0", "unspecified"),
    ("224.0.0.1", "multicast"),
]


@pytest.mark.parametrize("address,label", BLOCKED_ADDRESSES)
def test_blocks_internal_addresses(address, label):
    with mock.patch("socket.getaddrinfo", _resolve_to(address)):
        with pytest.raises(BlockedURLError):
            assert_url_is_fetchable(f"http://host.example/{label}")


def test_allows_public_address():
    with mock.patch("socket.getaddrinfo", _resolve_to("93.184.216.34")):
        assert_url_is_fetchable("https://example.com")  # must not raise


def test_blocks_hostname_resolving_to_internal_address():
    """The attack the guard exists for: attacker-controlled DNS.

    Validating the hostname string would let this through -- the name looks
    perfectly ordinary and only the resolved address gives it away.
    """
    with mock.patch("socket.getaddrinfo", _resolve_to("169.254.169.254")):
        with pytest.raises(BlockedURLError, match="non-public"):
            assert_url_is_fetchable("https://totally-normal-site.example")


def test_blocks_when_any_address_is_internal():
    """A host publishing both a public and a private record must be refused:
    connect() is free to pick either one."""
    with mock.patch("socket.getaddrinfo", _resolve_to("93.184.216.34", "10.0.0.5")):
        with pytest.raises(BlockedURLError):
            assert_url_is_fetchable("https://dual.example")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x.example/f", "gopher://x.example/"])
def test_blocks_non_http_schemes(url):
    with pytest.raises(BlockedURLError, match="Unsupported URL scheme"):
        assert_url_is_fetchable(url)


def test_blocks_unresolvable_hostname():
    def _fail(*a, **kw):
        raise socket.gaierror("no such host")

    with mock.patch("socket.getaddrinfo", _fail):
        with pytest.raises(BlockedURLError, match="could not be resolved"):
            assert_url_is_fetchable("http://nx.example")


class _Response:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status=200, location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.text = "<html></html>"

    @property
    def is_redirect(self):
        return "Location" in self.headers


def test_redirect_to_internal_address_is_blocked():
    """The bypass that `allow_redirects=True` would leave open.

    The first hop is a legitimate public host, so a check that ran only against
    the submitted URL would pass -- and then follow the 302 to the metadata
    endpoint.
    """
    def fake_get(url, **kw):
        return _Response(302, location="http://169.254.169.254/latest/meta-data/")

    resolutions = {"public.example": "93.184.216.34", "169.254.169.254": "169.254.169.254"}

    def fake_resolve(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolutions[host], port))]

    with mock.patch("socket.getaddrinfo", fake_resolve):
        with mock.patch("requests.get", fake_get):
            with pytest.raises(BlockedURLError, match="non-public"):
                safe_get("http://public.example", timeout=5, headers={})


def test_redirect_chain_is_bounded():
    """A server that redirects forever must not tie up a worker."""
    def fake_get(url, **kw):
        return _Response(302, location="http://public.example/next")

    with mock.patch("socket.getaddrinfo", _resolve_to("93.184.216.34")):
        with mock.patch("requests.get", fake_get):
            with pytest.raises(BlockedURLError, match="Too many redirects"):
                safe_get("http://public.example", timeout=5, headers={})


def test_returns_response_when_not_redirect():
    with mock.patch("socket.getaddrinfo", _resolve_to("93.184.216.34")):
        with mock.patch("requests.get", lambda url, **kw: _Response(200)):
            assert safe_get("http://public.example", timeout=5, headers={}).status_code == 200
