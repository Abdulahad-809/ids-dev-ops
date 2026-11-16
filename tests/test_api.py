"""End-to-end tests for the Flask API using the real trained model."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd  # noqa: E402

from app import create_app  # noqa: E402
from ids.samples import SAMPLES  # noqa: E402


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = create_app().test_client()

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["n_features"], 77)

    def test_index_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Sentinel IDS", r.data)

    def test_features_exclude_port(self):
        feats = self.client.get("/api/features").get_json()["features"]
        self.assertNotIn("Destination Port", feats)
        self.assertIn("Flow Duration", feats)

    def test_samples_match_expected_label(self):
        for key, sample in SAMPLES.items():
            with self.subTest(sample=key):
                r = self.client.post("/api/predict", json={"features": sample["features"]})
                self.assertEqual(r.status_code, 200)
                body = r.get_json()
                self.assertEqual(body["prediction"], sample["expected"])
                self.assertTrue(0.0 <= body["attack_probability"] <= 1.0)

    def test_batch_json(self):
        flows = [SAMPLES["benign_dns"]["features"], SAMPLES["dos_hulk"]["features"]]
        r = self.client.post("/api/predict", json={"flows": flows})
        preds = [x["prediction"] for x in r.get_json()["results"]]
        self.assertEqual(preds, ["BENIGN", "ATTACK"])

    def test_strict_mode_rejects_missing_features(self):
        r = self.client.post("/api/predict", json={"features": {"Flow Duration": 5}, "strict": True})
        self.assertEqual(r.status_code, 400)

    def test_bad_json(self):
        r = self.client.post("/api/predict", data="nope", content_type="text/plain")
        self.assertEqual(r.status_code, 400)

    def test_csv_upload_with_labels_and_invalid_row(self):
        rows = []
        for key in ("benign_web", "port_scan"):
            row = {" " + k: v for k, v in SAMPLES[key]["features"].items()}
            row[" Destination Port"] = 80
            row[" Label"] = "BENIGN" if key.startswith("benign") else "PortScan"
            rows.append(row)
        bad = dict(rows[0])
        bad[" Flow Bytes/s"] = float("inf")
        rows.append(bad)
        buf = io.BytesIO(pd.DataFrame(rows).to_csv(index=False).encode())

        r = self.client.post("/api/predict/csv", data={"file": (buf, "flows.csv")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        s = r.get_json()["summary"]
        self.assertEqual(s["rows"], 3)
        self.assertEqual(s["invalid_rows"], 1)
        self.assertEqual(s["attacks"], 1)
        self.assertEqual(s["metrics"]["accuracy"], 1.0)

    def test_csv_missing_columns(self):
        buf = io.BytesIO(b"a,b\n1,2\n")
        r = self.client.post("/api/predict/csv", data={"file": (buf, "x.csv")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_history_records_predictions(self):
        self.client.delete("/api/history")
        self.client.post("/api/predict", json={"features": SAMPLES["ddos"]["features"]})
        stats = self.client.get("/api/history").get_json()["stats"]
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["attack"], 1)


if __name__ == "__main__":
    unittest.main()
