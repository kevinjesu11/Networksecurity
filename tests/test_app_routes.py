"""End-to-end tests for the HTTP surface.

Covers the two access-control fixes (/train had been an unauthenticated GET that
overwrote the production model, and /predict accepted unbounded uploads) and the
verdict banding, which exists so a near-coin-flip score stops rendering as a
confident green "Legitimate".
"""

import io
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import app as app_module

client = TestClient(app_module.app, raise_server_exceptions=False)


# -- /train access control ------------------------------------------------

def test_train_rejects_get():
    """It mutates state, so a crawler or browser prefetch must not reach it."""
    assert client.get("/train").status_code == 405


def test_train_disabled_without_configured_key(monkeypatch):
    """Fails closed: a deployment that forgets the variable is off, not open."""
    monkeypatch.delenv("TRAIN_API_KEY", raising=False)
    response = client.post("/train")
    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()


def test_train_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("TRAIN_API_KEY", "correct-horse-battery-staple")
    assert client.post("/train").status_code == 401


def test_train_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("TRAIN_API_KEY", "correct-horse-battery-staple")
    response = client.post("/train", headers={"X-API-Key": "guess"})
    assert response.status_code == 401


def test_train_accepts_correct_key(monkeypatch):
    """Authorisation is checked before the pipeline runs; the pipeline itself is
    stubbed so the suite does not retrain a model."""
    monkeypatch.setenv("TRAIN_API_KEY", "correct-horse-battery-staple")
    with mock.patch.object(app_module, "TrainingPipeline") as pipeline:
        response = client.post("/train", headers={"X-API-Key": "correct-horse-battery-staple"})
    assert response.status_code == 200
    pipeline.return_value.run_pipeline.assert_called_once()


# -- /predict upload limits -----------------------------------------------

def test_predict_rejects_oversized_upload():
    oversized = b"x" * (app_module.MAX_UPLOAD_BYTES + 1024)
    response = client.post("/predict", files={"file": ("big.csv", oversized, "text/csv")})
    assert response.status_code == 413


def test_predict_accepts_valid_csv():
    with open("valid_data/test.csv", "rb") as fh:
        response = client.post("/predict", files={"file": ("test.csv", fh.read(), "text/csv")})
    assert response.status_code == 200


# -- /predict-url verdicts ------------------------------------------------

def _stub_extraction(monkeypatch, blocked=None):
    from networksecurity.utils.url_feature_extraction import FEATURE_ORDER

    features = {name: 1 for name in FEATURE_ORDER}
    meta = {
        "resolved_url": "http://stub.example/",
        "fetch_error": None,
        "blocked_reason": blocked,
        "whois_available": False,
    }
    monkeypatch.setattr(app_module, "extract_url_features", lambda url: (features, meta))


def test_predict_url_rejects_blocked_target(monkeypatch):
    """A refused URL was never fetched, so it must not receive a verdict."""
    _stub_extraction(monkeypatch, blocked="'169.254.169.254' resolves to a non-public address")
    response = client.post("/predict-url", data={"url": "http://169.254.169.254/"})
    assert response.status_code == 400
    assert "non-public" in response.json()["detail"]


def test_low_confidence_renders_inconclusive(monkeypatch):
    """Below the threshold the page must not show a green tick."""
    _stub_extraction(monkeypatch)
    monkeypatch.setattr(app_module, "url_red_flags", lambda url: ([], []))

    with mock.patch.object(app_module, "NetworkModel") as network_model:
        instance = network_model.return_value
        instance.predict.return_value = [1]
        instance.preprocessor.transform.return_value = [[0]]
        instance.model.predict_proba.return_value = [[0.45, 0.55]]
        with mock.patch.object(app_module, "validate_tree_model_integrity"):
            with mock.patch.object(app_module, "load_object"):
                response = client.post("/predict-url", data={"url": "http://stub.example/"})

    assert response.status_code == 200
    assert "Inconclusive" in response.text
    assert "Likely Legitimate" not in response.text


def test_critical_flag_forces_phishing_verdict(monkeypatch):
    """A structural red flag outranks a confident model score."""
    _stub_extraction(monkeypatch)
    monkeypatch.setattr(
        app_module, "url_red_flags", lambda url: (["URL uses the '@' trick"], [])
    )

    with mock.patch.object(app_module, "NetworkModel") as network_model:
        instance = network_model.return_value
        instance.predict.return_value = [1]          # model says legitimate
        instance.preprocessor.transform.return_value = [[0]]
        instance.model.predict_proba.return_value = [[0.01, 0.99]]   # very confidently
        with mock.patch.object(app_module, "validate_tree_model_integrity"):
            with mock.patch.object(app_module, "load_object"):
                response = client.post("/predict-url", data={"url": "http://a.com@b.ru/"})

    assert "Likely Phishing" in response.text


# -- basic availability ---------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/health", "/docs"])
def test_pages_render(path):
    assert client.get(path).status_code == 200


def test_health_payload():
    assert client.get("/health").json() == {"status": "ok"}
