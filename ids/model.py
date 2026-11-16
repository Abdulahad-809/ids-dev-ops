"""Loads the trained CICIDS 2017 model and turns raw flows into predictions.

The model in model/cicids_intrusion_model.pkl is the RandomForestClassifier
(n_estimators=20, max_depth=4) exported by the notebook. It was trained on the
77 CICFlowMeter features left after dropping 'Destination Port', on raw
(unscaled) values, so no scaler is needed here.
"""

import os
import pickle
import threading

import numpy as np
import pandas as pd

from utils import (LABEL_COLUMNS, SHORTCUT_COLUMNS, clean_column_name,
                   risk_level, to_binary_label)

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "model", "cicids_intrusion_model.pkl")

# Test-set results recorded when the notebook trained the models
# (80/20 stratified split, random_state=42, 442,406 test flows).
NOTEBOOK_RESULTS = [
    {"model": "Logistic Regression", "accuracy": 0.9230, "precision": 0.8429,
     "recall": 0.8417, "f1_score": 0.8423, "deployed": False},
    {"model": "Random Forest", "accuracy": 0.9566,
     "precision": 0.9918, "recall": 0.8292, "f1_score": 0.9033, "deployed": True},
]


class FeatureError(ValueError):
    """Raised when input flows cannot be turned into the model's feature matrix."""


class IntrusionDetector:
    def __init__(self, model_path=DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self._lock = threading.Lock()
        with open(model_path, "rb") as fh:
            self.model = pickle.load(fh)
        if not hasattr(self.model, "feature_names_in_"):
            raise RuntimeError("Model was saved without feature names; cannot map inputs.")
        self.features = [str(f) for f in self.model.feature_names_in_]

    # ---------- metadata ----------
    def info(self):
        m = self.model
        importances = sorted(
            zip(self.features, getattr(m, "feature_importances_", [0] * len(self.features))),
            key=lambda x: x[1], reverse=True)
        return {
            "type": type(m).__name__,
            "n_features": len(self.features),
            "n_estimators": getattr(m, "n_estimators", None),
            "max_depth": getattr(m, "max_depth", None),
            "classes": {"0": "BENIGN", "1": "ATTACK"},
            "dataset": "CICIDS 2017 (Canadian Institute for Cybersecurity)",
            "top_features": [{"feature": f, "importance": round(float(i), 4)}
                             for f, i in importances[:10]],
            "notebook_results": NOTEBOOK_RESULTS,
        }

    # ---------- preprocessing ----------
    def prepare(self, df, fill_missing=False):
        """Clean a DataFrame of flows the same way the notebook did.

        Returns (X, valid_mask, labels) where X holds only the valid rows in the
        model's column order, valid_mask marks which input rows were usable and
        labels is the optional ground-truth Series (0/1) or None.
        """
        if df.empty:
            raise FeatureError("No rows supplied.")
        df = df.copy()
        df.columns = [clean_column_name(c) for c in df.columns]

        labels = None
        if "Label" in df.columns:
            labels = df["Label"].map(to_binary_label)
        elif "Target" in df.columns:
            labels = pd.to_numeric(df["Target"], errors="coerce")

        missing = [f for f in self.features if f not in df.columns]
        if missing and not fill_missing:
            preview = ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else "")
            raise FeatureError(f"Missing {len(missing)} required feature(s): {preview}")
        for f in missing:
            df[f] = 0.0

        X = df[self.features].apply(pd.to_numeric, errors="coerce")
        X = X.replace([np.inf, -np.inf], np.nan)
        if fill_missing:
            X = X.fillna(0.0)
        valid = X.notna().all(axis=1)
        return X[valid], valid, labels

    # ---------- prediction ----------
    def predict_frame(self, df, fill_missing=False):
        X, valid, labels = self.prepare(df, fill_missing=fill_missing)
        results = [None] * len(valid)
        if len(X):
            with self._lock:
                proba = self.model.predict_proba(X)
            classes = list(self.model.classes_)
            attack_idx = classes.index(1) if 1 in classes else len(classes) - 1
            for pos, (row_idx, p) in enumerate(zip(np.flatnonzero(valid.values), proba)):
                p_attack = float(p[attack_idx])
                results[row_idx] = {
                    "row": int(row_idx),
                    "prediction": "ATTACK" if p_attack >= 0.5 else "BENIGN",
                    "attack_probability": round(p_attack, 4),
                    "confidence": round(max(p_attack, 1 - p_attack), 4),
                    "risk": risk_level(p_attack),
                }
        for i, r in enumerate(results):
            if r is None:
                results[i] = {"row": i, "prediction": "INVALID",
                              "error": "Row contains missing, non-numeric or infinite values."}
            elif labels is not None and pd.notna(labels.iloc[i]):
                r["actual"] = "ATTACK" if int(labels.iloc[i]) == 1 else "BENIGN"
        return results

    def predict_one(self, features, fill_missing=True):
        return self.predict_frame(pd.DataFrame([features]), fill_missing=fill_missing)[0]

    @staticmethod
    def ignored_columns():
        return list(LABEL_COLUMNS) + list(SHORTCUT_COLUMNS)
