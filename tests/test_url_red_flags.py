"""Tests for the deterministic URL checks.

These run alongside the model because the 2015 training set treats valid HTTPS
as strong evidence of legitimacy, which free certificates have since made
worthless. The rules read only the URL string, so they are fully testable
without network access.

The false-positive direction matters as much as the true-positive one: a
detector that flags github.com trains its users to ignore it.
"""

import pytest

from networksecurity.utils.url_red_flags import url_red_flags


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://paypal.com@evil.ru/login", "@"),
        ("http://192.168.1.1/verify.php", "IP address"),
        ("https://xn--pple-43d.com/login", "punycode"),
    ],
)
def test_critical_flags(url, expected):
    critical, _ = url_red_flags(url)
    assert critical, f"expected a critical flag for {url}"
    assert any(expected.lower() in f.lower() for f in critical)


def test_at_symbol_names_both_the_shown_and_real_host():
    """The message has to say what the user is actually being sent to."""
    critical, _ = url_red_flags("http://secure-paypal.com@evil.ru/login")
    assert any("secure-paypal.com" in f and "evil.ru" in f for f in critical)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://bit.ly/xyz", "shortener"),
        ("http://login.tk/verify", ".tk"),
        ("http://paypal.evil.com/", "paypal"),
        ("http://a.b.c.d.e.example.com/", "subdomain"),
    ],
)
def test_warning_flags(url, expected):
    _, warnings = url_red_flags(url)
    assert warnings, f"expected a warning for {url}"
    assert any(expected.lower() in w.lower() for w in warnings)


@pytest.mark.parametrize(
    "url",
    [
        "https://google.com",
        "https://github.com",
        "https://www.wikipedia.org",
        "https://docs.python.org/3/library/index.html",
        "https://en.wikipedia.org/wiki/Phishing",
    ],
)
def test_no_false_positives_on_legitimate_sites(url):
    critical, warnings = url_red_flags(url)
    assert not critical, f"false critical flag on {url}: {critical}"
    assert not warnings, f"false warning on {url}: {warnings}"


def test_brand_own_domain_is_not_flagged():
    """paypal.com mentioning 'paypal' is not impersonation."""
    critical, warnings = url_red_flags("https://www.paypal.com/signin")
    assert not critical
    assert not any("paypal" in w.lower() for w in warnings)


def test_handles_scheme_less_and_junk_input():
    """Called on raw user input, so it must not raise on anything."""
    for url in ["google.com", "", "   ", "http://", "not a url", "http://[::1]/"]:
        critical, warnings = url_red_flags(url)
        assert isinstance(critical, list) and isinstance(warnings, list)
