"""Deterministic URL checks that run alongside the ML verdict.

The trained model comes from a 2015-era feature set whose strongest signal is
"has a valid HTTPS certificate". That assumption no longer holds -- phishing
sites get free certificates -- so the model can score an obviously crafted URL
as legitimate. These rules do not depend on the model, the dataset, or a
successful page fetch: they read the URL string itself, which is the part an
attacker controls and the part a victim actually sees.

Critical flags describe deception that has no legitimate use in a link a user is
asked to click. Warning flags are suspicious but do occur benignly, so they
downgrade a verdict to inconclusive instead of condemning it.
"""

import ipaddress
import re
from urllib.parse import urlparse

# Shorteners hide the real destination entirely, so the model ends up scoring
# the shortener's own reputable page rather than wherever the link leads.
_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "t.ly", "s.id", "clck.ru", "soo.gd",
}

# Cheap/free TLDs that see disproportionate abuse.
_HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "xyz", "click",
    "country", "kim", "work", "party", "gdn", "review",
}

# Brands impersonated often enough that their name appearing outside their own
# domain is worth calling out.
_TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "chase", "wellsfargo", "hsbc",
    "santander", "dhl", "fedex", "usps", "coinbase", "binance", "steam",
    "outlook", "office365", "icloud", "dropbox", "adobe",
]

_CREDENTIAL_WORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "banking", "password", "billing", "invoice",
    "suspended", "unlock", "recover",
]


def _registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1 without pulling in a public-suffix dependency."""
    parts = [p for p in hostname.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def url_red_flags(url: str):
    """Returns (critical_flags, warning_flags) as lists of plain-English strings."""
    critical, warning = [], []

    raw = (url or "").strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "http://" + raw

    parsed = urlparse(raw)
    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    domain = _registrable_domain(hostname)
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    # An "@" in the authority makes everything before it userinfo, which the
    # browser ignores. http://paypal.com@evil.ru loads evil.ru while reading as
    # PayPal to a human. There is no honest reason for this in a shared link.
    if "@" in netloc:
        shown = netloc.split("@")[0]
        critical.append(
            f"URL uses the '@' trick: it displays '{shown}' but actually loads '{hostname}'."
        )

    if hostname:
        try:
            ipaddress.ip_address(hostname)
            critical.append(
                f"Link points at a bare IP address ({hostname}) instead of a domain name."
            )
        except ValueError:
            pass

    # Punycode can render as visually identical Unicode (apple.com vs аpple.com).
    if "xn--" in hostname:
        critical.append(
            f"Domain uses punycode ('{hostname}'), which can imitate another name on screen."
        )

    if domain in _SHORTENERS:
        warning.append(
            f"'{domain}' is a link shortener, so the real destination is hidden."
        )

    if tld in _HIGH_RISK_TLDS:
        warning.append(f"'.{tld}' is a low-cost domain heavily used for abuse.")

    # A brand name in a subdomain or path, on a domain that is not the brand's.
    for brand in _TARGETED_BRANDS:
        if brand in hostname and not domain.startswith(brand + "."):
            if brand not in domain.split(".")[0]:
                warning.append(
                    f"Mentions '{brand}' but the real domain is '{domain}'."
                )
                break

    if hostname.count(".") >= 4:
        warning.append(
            f"Unusually deep subdomain nesting ({hostname.count('.') + 1} labels)."
        )

    if parsed.scheme == "http":
        lowered = raw.lower()
        if any(w in lowered for w in _CREDENTIAL_WORDS):
            warning.append(
                "Asks for sign-in/account actions over plain HTTP, which is unencrypted."
            )

    if "-" in domain and any(b in domain for b in _TARGETED_BRANDS):
        warning.append(f"Domain '{domain}' blends a brand name with extra words.")

    return critical, warning
