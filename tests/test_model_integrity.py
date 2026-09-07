"""Regression tests for the scikit-learn version-skew bug.

The shipped model had been pickled by sklearn 1.3.2 and was being loaded by
1.9.0. Those versions disagree about the contents of a classifier tree's
``value`` array -- 1.3 stored raw class counts, 1.4+ expects fractions summing
to 1.0 -- and unpickling does not convert between them. Nothing raised. The
forest simply averaged counts instead of votes, which weights each leaf by how
many training samples landed in it, and collapsed almost every prediction onto
the majority class. Every URL came back "legitimate" with a confidence of
29870%.

The trainer selects a winner from five candidates, so the artifact's type is
not fixed between runs: CI has produced both a RandomForestClassifier and a
DecisionTreeClassifier from the same code. Nothing here may assume a particular
one.
"""

import os

import numpy as np
import pytest
from sklearn.ensemble import (
    AdaBoostClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.ml_utils.model.estimator import (
    _classifier_trees,
    validate_tree_model_integrity,
)

MODEL_PATH = "final_model/model.pkl"


@pytest.fixture(scope="module")
def model():
    if not os.path.exists(MODEL_PATH):
        pytest.skip("final_model/model.pkl not present; run the training pipeline first")
    return load_object(MODEL_PATH)


def _fitted(estimator):
    rng = np.random.RandomState(0)
    X = rng.rand(60, 4)
    y = (X[:, 0] > 0.5).astype(int)
    return estimator.fit(X, y)


# -- the shipped artifact -------------------------------------------------

def test_shipped_model_tree_values_are_normalized(model):
    """Every classifier tree in the artifact must sum to 1.0 at its root."""
    trees = list(_classifier_trees(model))
    if not trees:
        pytest.skip(f"{type(model).__name__} contains no classifier trees")
    for i, tree in enumerate(trees):
        root_sum = float(tree.value[0].sum())
        assert root_sum == pytest.approx(1.0, abs=0.01), (
            f"tree {i} root sums to {root_sum}, not 1.0 -- the pickle was written "
            f"by an incompatible scikit-learn version"
        )


def test_shipped_model_predict_proba_returns_probabilities(model):
    """Probabilities must sum to 1.0; the bug produced rows summing to ~400."""
    proba = model.predict_proba(np.zeros((1, model.n_features_in_)))
    assert proba.sum() == pytest.approx(1.0, abs=0.01)
    assert 0.0 <= proba.max() <= 1.0


def test_validator_accepts_shipped_model(model):
    validate_tree_model_integrity(model)  # must not raise


# -- the validator, across every candidate the trainer may pick -----------

@pytest.mark.parametrize(
    "estimator",
    [
        RandomForestClassifier(n_estimators=5, random_state=0),
        DecisionTreeClassifier(random_state=0),
        GradientBoostingClassifier(n_estimators=5, random_state=0),
        AdaBoostClassifier(n_estimators=5, random_state=0),
        LogisticRegression(),
    ],
    ids=lambda e: type(e).__name__,
)
def test_validator_accepts_every_candidate_model(estimator):
    """The trainer chooses between these five, so the guard must handle all of
    them. GradientBoosting is the trap: it is built from regression trees whose
    values are mean targets and have no reason to sum to 1.0, so a naive check
    rejects a perfectly healthy model.
    """
    validate_tree_model_integrity(_fitted(estimator))  # must not raise


@pytest.mark.parametrize(
    "estimator",
    [
        RandomForestClassifier(n_estimators=5, random_state=0),
        DecisionTreeClassifier(random_state=0),
        AdaBoostClassifier(n_estimators=5, random_state=0),
    ],
    ids=lambda e: type(e).__name__,
)
def test_validator_rejects_unnormalized_trees(estimator):
    """The guard has to actually fire, not merely pass on healthy input."""
    fitted = _fitted(estimator)
    # Reproduce the 1.3-style array: raw counts rather than fractions.
    for tree in _classifier_trees(fitted):
        tree.value[:] *= 5000.0

    with pytest.raises(RuntimeError, match="incompatible with scikit-learn"):
        validate_tree_model_integrity(fitted)


def test_validator_ignores_models_without_classifier_trees():
    assert validate_tree_model_integrity(_fitted(LogisticRegression())) is None
    assert validate_tree_model_integrity(LogisticRegression()) is None


def test_gradient_boosting_regression_trees_are_not_inspected():
    """Explicitly pins the GradientBoosting carve-out, since the naive version
    of this check failed CI on a healthy model."""
    fitted = _fitted(GradientBoostingClassifier(n_estimators=5, random_state=0))
    assert list(_classifier_trees(fitted)) == []
