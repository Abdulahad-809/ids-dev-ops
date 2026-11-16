import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (classification_metrics, clean_column_name, risk_level,  # noqa: E402
                   safe_float, to_binary_label)


class TestCleaning(unittest.TestCase):
    def test_clean_column_name_strips_spaces(self):
        self.assertEqual(clean_column_name(" Flow Duration "), "Flow Duration")

    def test_binary_label(self):
        self.assertEqual(to_binary_label("BENIGN"), 0)
        self.assertEqual(to_binary_label(" benign "), 0)
        self.assertEqual(to_binary_label("DDoS"), 1)
        self.assertEqual(to_binary_label("PortScan"), 1)

    def test_safe_float(self):
        self.assertEqual(safe_float("12.5"), 12.5)
        self.assertEqual(safe_float(3), 3.0)
        self.assertIsNone(safe_float(""))
        self.assertIsNone(safe_float("abc"))
        self.assertIsNone(safe_float(float("inf")))
        self.assertIsNone(safe_float(float("nan")))
        self.assertIsNone(safe_float(None))


class TestRiskLevel(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(risk_level(0.0), "Low")
        self.assertEqual(risk_level(0.3), "Medium")
        self.assertEqual(risk_level(0.6), "High")
        self.assertEqual(risk_level(0.95), "Critical")

    def test_invalid_probability(self):
        with self.assertRaises(ValueError):
            risk_level(1.5)


class TestMetrics(unittest.TestCase):
    def test_perfect(self):
        m = classification_metrics([0, 1, 1, 0], [0, 1, 1, 0])
        self.assertEqual(m["accuracy"], 1.0)
        self.assertEqual(m["f1_score"], 1.0)

    def test_mixed(self):
        m = classification_metrics([1, 1, 0, 0], [1, 0, 1, 0])
        self.assertEqual(m["accuracy"], 0.5)
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["recall"], 0.5)
        self.assertEqual(m["confusion_matrix"], {"tn": 1, "fp": 1, "fn": 1, "tp": 1})

    def test_no_positive_predictions(self):
        m = classification_metrics([1, 0], [0, 0])
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["f1_score"], 0.0)

    def test_length_mismatch(self):
        with self.assertRaises(ValueError):
            classification_metrics([1], [1, 0])


if __name__ == "__main__":
    unittest.main()
