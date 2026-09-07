from networksecurity.constant.training_pipeline import SAVED_MODEL_DIR,MODEL_FILE_NAME

import os
import sys

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

class NetworkModel:
    def __init__(self,preprocessor,model):
        try:
            self.preprocessor = preprocessor
            self.model = model
        except Exception as e:
            raise NetworkSecurityException(e,sys)
    
    def predict(self,x):
        try:
            x_transform = self.preprocessor.transform(x)
            y_hat = self.model.predict(x_transform)
            return y_hat
        except Exception as e:
            raise NetworkSecurityException(e,sys)

def _classifier_trees(model):
    """Yields the fitted classifier decision trees inside `model`, if any.

    The trainer picks a winner from five candidates, so the artifact may be a
    bare tree, a forest, a boosted ensemble, or no tree at all. Only classifier
    trees are yielded: GradientBoostingClassifier is built from
    DecisionTreeRegressor internally, and a regression tree's `value` holds mean
    target values with no reason to sum to anything in particular.
    """
    import numpy as np
    from sklearn.base import is_classifier

    if hasattr(model, "tree_"):
        if is_classifier(model):
            yield model.tree_
        return

    estimators = getattr(model, "estimators_", None)
    if estimators is None:
        return

    # RandomForest and AdaBoost store a flat list; GradientBoosting a 2D array.
    for est in np.asarray(estimators, dtype=object).ravel():
        if hasattr(est, "tree_") and is_classifier(est):
            yield est.tree_


def validate_tree_model_integrity(model):
    """Detects tree models unpickled under an incompatible scikit-learn version.

    sklearn <=1.3 stored raw class COUNTS in each classifier tree's ``value``
    array, while >=1.4 expects normalized fractions that sum to 1.0 per node.
    Unpickling does not convert between the two, so a model saved on 1.3.x and
    loaded on 1.4+ still predicts -- it just averages counts instead of votes,
    which silently collapses every prediction toward whichever leaves hold the
    most samples. Checking a root node catches that before it reaches a user as
    a verdict.

    Returns None when the model contains no classifier trees to check.
    """
    for tree in _classifier_trees(model):
        root_sum = float(tree.value[0].sum())
        if abs(root_sum - 1.0) > 0.01:
            import sklearn

            raise RuntimeError(
                f"Model artifact is incompatible with scikit-learn {sklearn.__version__}: "
                f"tree root node sums to {root_sum:.1f} instead of 1.0. The pickle was "
                f"almost certainly written by scikit-learn <=1.3. Predictions from this "
                f"model are unreliable -- retrain with the current version (POST /train)."
            )
        # One tree is enough: they all come from the same pickle.
        return None
    return None
