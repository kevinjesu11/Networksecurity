"""Tests for live URL feature extraction, in particular sign conventions.

The dataset encodes -1 as phishing and 1 as legitimate, but the raw extractor
functions are written the natural way round ("return 1 if the @ is present"),
with _FLIP_POLARITY negating the ones that need it. A feature missing from that
set is silently inverted: it feeds the model the exact opposite of what it
learned, and nothing errors. having_At_Symbol was missing, so URLs using @ to
disguise their destination received a legitimacy bonus.

Network access is stubbed -- these test the conventions, not connectivity.
"""

from unittest import mock

import pytest

from networksecurity.utils import url_feature_extraction as ufe
from networksecurity.utils.url_feature_extraction import (
    FEATURE_ORDER,
    extract_url_features,
)


class _Response:
    status_code = 200
    text = "<html><body><a href='/x'>x</a></body></html>"
    url = "http://placeholder.example/"
    history = []


@pytest.fixture
def offline():
    """Runs extraction without touching the network or WHOIS."""
    with mock.patch.object(ufe, "safe_get", return_value=_Response()):
        with mock.patch.object(ufe, "whois", None):
            yield


def _feature(url, name, offline_fixture=None):
    features, _ = extract_url_features(url)
    return features[name]


def test_at_symbol_polarity(offline):
    """URLs containing @ must score -1 (phishing), not +1.

    This is the regression test for the inverted feature: before the fix,
    http://paypal.com@evil.ru returned 1 and was read as a point in its favour.
    """
    assert _feature("http://paypal.com@evil.ru/login", "having_At_Symbol") == -1
    assert _feature("http://example.com/login", "having_At_Symbol") == 1


def test_ip_address_polarity(offline):
    assert _feature("http://192.168.1.1/x", "having_IP_Address") == -1
    assert _feature("http://example.com/x", "having_IP_Address") == 1


def test_prefix_suffix_polarity(offline):
    """A hyphenated domain is the suspicious case and must be negative."""
    assert _feature("http://pay-pal-secure.com/", "Prefix_Suffix") == -1
    assert _feature("http://paypal.com/", "Prefix_Suffix") == 1


def test_ssl_state_polarity(offline):
    """Plain HTTP must never score as the legitimate end of this feature."""
    assert _feature("http://example.com/", "SSLfinal_State") == -1


def test_subdomain_depth_polarity(offline):
    assert _feature("http://example.com/", "having_Sub_Domain") == 1
    assert _feature("http://a.b.c.d.example.com/", "having_Sub_Domain") == -1


def test_every_feature_is_in_valid_range(offline):
    """The model was trained on -1/0/1 only; anything else is out of distribution."""
    features, _ = extract_url_features("http://example.com/path")
    for name, value in features.items():
        assert value in (-1, 0, 1), f"{name} produced {value!r}, outside {{-1,0,1}}"


def test_feature_order_matches_model_input(offline):
    """Column order is positional once it reaches the preprocessor, so a
    reordering here would misalign every value without raising."""
    features, _ = extract_url_features("http://example.com/")
    assert list(features.keys()) == FEATURE_ORDER


def test_feature_order_matches_training_schema():
    """FEATURE_ORDER must equal the schema minus the target and dropped columns."""
    import yaml

    from networksecurity.constant.training_pipeline import (
        LEGACY_FEATURE_COLUMNS_TO_DROP,
        TARGET_COLUMN,
    )

    with open("data_schema/schema.yaml") as fh:
        schema = yaml.safe_load(fh)

    columns = [list(c.keys())[0] for c in schema["columns"]]
    expected = [
        c for c in columns
        if c != TARGET_COLUMN and c not in LEGACY_FEATURE_COLUMNS_TO_DROP
    ]
    assert FEATURE_ORDER == expected


def test_blocked_url_reports_reason_and_skips_fetch():
    """A refused target must be reported, not silently scored on defaults."""
    from networksecurity.utils.safe_fetch import BlockedURLError

    with mock.patch.object(ufe, "safe_get", side_effect=BlockedURLError("internal address")):
        with mock.patch.object(ufe, "whois", None):
            _, meta = extract_url_features("http://169.254.169.254/latest/meta-data/")

    assert meta["blocked_reason"] is not None
    assert "internal address" in meta["blocked_reason"]


def test_generic_error_does_not_leak_internal_detail():
    """Ordinary fetch failures must not report which host/port refused."""
    import requests

    with mock.patch.object(
        ufe, "safe_get",
        side_effect=requests.exceptions.ConnectionError("Connection refused to 10.0.1.5:8080"),
    ):
        with mock.patch.object(ufe, "whois", None):
            _, meta = extract_url_features("http://example.com/")

    assert "10.0.1.5" not in meta["fetch_error"]
    assert meta["blocked_reason"] is None
