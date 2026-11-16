"""Small, deterministic helpers used by the IDS web app.

These mirror the cleaning steps in notebooks/Intrusion_Detection_System.ipynb
and have no dependency on the trained model, so they can be unit-tested
quickly in CI (see tests/test_utils.py).
"""

import math

# Columns that the notebook removes before training.
LABEL_COLUMNS = ("Label", "Target")
SHORTCUT_COLUMNS = ("Destination Port",)


def clean_column_name(name):
    """CICIDS 2017 CSVs have stray spaces around column names (e.g. ' Flow Duration')."""
    return str(name).strip()


def to_binary_label(label):
    """BENIGN -> 0, any attack -> 1 (same rule as the notebook)."""
    return 0 if str(label).strip().upper() == "BENIGN" else 1


def safe_float(value):
    """Convert a value to a finite float.

    Returns None for missing, non-numeric, NaN or infinite values, matching the
    notebook's approach of treating inf as NaN and dropping it.
    """
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def risk_level(attack_probability):
    """Map the model's attack probability to a human-readable severity."""
    if attack_probability < 0 or attack_probability > 1:
        raise ValueError("Probability must be between 0 and 1")
    if attack_probability >= 0.85:
        return "Critical"
    if attack_probability >= 0.5:
        return "High"
    if attack_probability >= 0.25:
        return "Medium"
    return "Low"


def classification_metrics(y_true, y_pred):
    """Accuracy / precision / recall / F1 for binary labels (1 = attack)."""
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")
    if not y_true:
        raise ValueError("Cannot compute metrics on empty input")

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": (tp + tn) / len(y_true),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }
