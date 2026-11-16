"""The JSON model used on GitHub Pages must predict exactly like the .pkl."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from ids.export import export_forest, predict_proba_json  # noqa: E402
from ids.model import IntrusionDetector  # noqa: E402
from ids.samples import SAMPLES  # noqa: E402


class TestForestExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = IntrusionDetector()
        # Round-trip through JSON text, exactly as the browser receives it.
        cls.forest = json.loads(json.dumps(export_forest(cls.detector)))

    def test_shape(self):
        self.assertEqual(len(self.forest["trees"]), self.detector.model.n_estimators)
        self.assertEqual(self.forest["features"], self.detector.features)

    def _compare(self, X):
        expected = self.detector.model.predict_proba(X)[:, 1]
        got = predict_proba_json(self.forest, X.values.tolist())
        np.testing.assert_allclose(got, expected, atol=1e-7)

    def test_matches_sklearn_on_samples(self):
        X = pd.DataFrame([s["features"] for s in SAMPLES.values()])[self.detector.features]
        self._compare(X)

    def test_matches_sklearn_on_random_flows(self):
        rng = np.random.default_rng(0)
        base = pd.DataFrame([s["features"] for s in SAMPLES.values()])[self.detector.features]
        rows = base.sample(400, replace=True, random_state=0).values
        X = pd.DataFrame(rows * rng.uniform(0.2, 5.0, size=rows.shape),
                         columns=self.detector.features)
        self._compare(X)


if __name__ == "__main__":
    unittest.main()
