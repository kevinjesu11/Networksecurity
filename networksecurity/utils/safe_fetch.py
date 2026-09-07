"""SSRF-hardened HTTP fetching for user-supplied URLs.

/predict-url takes a URL from an anonymous visitor and fetches it server-side.
Without restrictions that turns this service into a proxy into its own network:
on EC2 the instance metadata endpoint (169.254.169.254) hands out IAM role
credentials, and private ranges expose whatever else runs in the VPC.

Two properties matter and neither is optional:

1. Validation happens on the resolved IP addresses, not the hostname. An
   attacker controls DNS for their own domain, so evil.example can simply
   resolve to 169.254.169.254.
2. Every hop of a redirect chain is validated. A permitted public host that
   answers with "302 -> http://169.254.169.254/" defeats a check that only ran
   against the original URL, which is why redirects are followed manually here
   rather than by requests.

The residual gap is DNS rebinding: the address is resolved for the check and
resolved again by the socket layer, and a hostile resolver can answer
differently between the two. Closing that entirely means pinning the connection
to the validated IP; the check below still removes the direct attacks.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from networksecurity.logging.logger import logging

# Redirect chains are bounded to keep a hostile server from tarpitting a worker.
MAX_REDIRECTS = 5

# Shown to the user in place of the raw exception, whose text distinguishes
# "connection refused" from "timed out" and so reports which internal hosts and
# ports are live.
GENERIC_FETCH_ERROR = "The page could not be retrieved."


class BlockedURLError(Exception):
    """Raised when a URL resolves to an address this service must not contact."""


def _address_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private          # 10/8, 172.16/12, 192.168/16, and IPv6 ULA
        or ip.is_loopback      # 127/8, ::1
        or ip.is_link_local    # 169.254/16 -- the cloud metadata endpoint
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def assert_url_is_fetchable(url: str) -> None:
    """Raises BlockedURLError unless every address `url` resolves to is public."""
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise BlockedURLError(f"Unsupported URL scheme: {parsed.scheme or 'none'}")

    hostname = parsed.hostname
    if not hostname:
        raise BlockedURLError("URL has no hostname")

    try:
        # Every A/AAAA record, since a host may publish both a public and a
        # private address and connect() is free to pick either.
        infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as e:
        raise BlockedURLError(f"Hostname could not be resolved: {hostname}") from e

    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise BlockedURLError(f"Hostname resolved to no addresses: {hostname}")

    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise BlockedURLError(f"Unparseable address for {hostname}: {addr}")
        if _address_is_blocked(ip):
            logging.info(
                f"SSRF guard: refusing {url} -- {hostname} resolves to internal address {ip}"
            )
            raise BlockedURLError(
                f"'{hostname}' resolves to a non-public address and will not be fetched."
            )


def safe_get(url: str, timeout: float, headers: dict):
    """Fetches `url`, validating the target before every hop of the redirect chain.

    Returns the final requests.Response. Raises BlockedURLError if any hop points
    at a non-public address, and propagates requests' own exceptions otherwise.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        assert_url_is_fetchable(current)

        response = requests.get(
            current,
            timeout=timeout,
            headers=headers,
            allow_redirects=False,
        )

        if not response.is_redirect:
            return response

        location = response.headers.get("Location")
        if not location:
            return response
        # Relative redirects are resolved against the URL just fetched.
        current = requests.compat.urljoin(current, location)

    raise BlockedURLError(f"Too many redirects (limit {MAX_REDIRECTS}).")
