"""Export the trained Random Forest to plain JSON so the browser can run it.

GitHub Pages only serves static files, so the Pages build ships this JSON and
static/js/app.js walks the trees itself. Each tree is stored as parallel
arrays (sklearn's own layout): for node i, `feature[i]` / `threshold[i]` pick
the split, `left[i]` / `right[i]` are child indices (-1 at a leaf) and
`p[i]` is the leaf's attack probability. Like sklearn, inputs are compared as
float32: go left when float32(x[feature]) <= threshold.
"""

import numpy as np

from ids.model import IntrusionDetector


def export_forest(detector: IntrusionDetector):
    model = detector.model
    attack_idx = list(model.classes_).index(1)
    trees = []
    for est in model.estimators_:
        t = est.tree_
        values = t.value[:, 0, :]
        probs = values[:, attack_idx] / values.sum(axis=1)
        trees.append({
            "feature": t.feature.tolist(),
            "threshold": [float(x) for x in t.threshold],
            "left": t.children_left.tolist(),
            "right": t.children_right.tolist(),
            "p": [round(float(x), 10) for x in probs],
        })
    return {"features": detector.features, "trees": trees}


def predict_proba_json(forest, rows):
    """Reference implementation of the browser algorithm, used in tests."""
    out = []
    for row in rows:
        x = np.asarray(row, dtype=np.float32)
        total = 0.0
        for t in forest["trees"]:
            node = 0
            while t["left"][node] != -1:
                if x[t["feature"][node]] <= t["threshold"][node]:
                    node = t["left"][node]
                else:
                    node = t["right"][node]
            total += t["p"][node]
        out.append(total / len(forest["trees"]))
    return out
