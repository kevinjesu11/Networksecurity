"""Regression tests for the scikit-learn version-skew bug.

The shipped model had been pickled by sklearn 1.3.2 and was being loaded by
1.9.0. Those versions disagree about the contents of a decision tree's ``value``
array -- 1.3 stored raw class counts, 1.4+ expects fractions summing to 1.0 --
and unpickling does not convert between them. Nothing raised. The forest simply
averaged counts instead of votes, which weights each leaf by how many training
samples landed in it, and collapsed almost every prediction onto the majority
class. Every URL came back "legitimate" with a confidence of 29870%.

These tests assert the property that was silently violated, so the same class of
mismatch fails loudly at CI time instead of shipping.
"""

import os

import pytest

from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.ml_utils.model.estimator import (
    validate_tree_model_integrity,
)

MODEL_PATH = "final_model/model.pkl"

pytestmark = pytest.mark.skipif(
    not os.path.exists(MODEL_PATH),
    reason="final_model/model.pkl not present; run the training pipeline first",
)


@pytest.fixture(scope="module")
def model():
    return load_object(MODEL_PATH)


def test_tree_values_are_normalized(model):
    """Each tree's root must sum to 1.0 under the running sklearn version."""
    for i, est in enumerate(model.estimators_):
        root_sum = float(est.tree_.value[0].sum())
        assert root_sum == pytest.approx(1.0, abs=0.01), (
            f"tree {i} root sums to {root_sum}, not 1.0 -- the pickle was written "
            f"by an incompatible scikit-learn version"
        )


def test_predict_proba_returns_probabilities(model):
    """Probabilities must sum to 1.0; the bug produced rows summing to ~400."""
    import numpy as np

    n_features = model.n_features_in_
    proba = model.predict_proba(np.zeros((1, n_features)))
    assert proba.sum() == pytest.approx(1.0, abs=0.01)
    assert 0.0 <= proba.max() <= 1.0


def test_validator_accepts_current_model(model):
    validate_tree_model_integrity(model)  # must not raise


def test_validator_rejects_unnormalized_trees(model):
    """The guard has to actually fire, not just pass on healthy input."""
    import copy

    broken = copy.deepcopy(model)
    # Reproduce the 1.3-style array: raw counts rather than fractions.
    broken.estimators_[0].tree_.value[:] *= 5000.0

    with pytest.raises(RuntimeError, match="incompatible with scikit-learn"):
        validate_tree_model_integrity(broken)


def test_validator_ignores_non_tree_estimators():
    """Non-tree models have no trees to check and must pass through."""
    from sklearn.linear_model import LogisticRegression

    assert validate_tree_model_integrity(LogisticRegression()) is None
