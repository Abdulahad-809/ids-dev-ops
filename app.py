"""Flask web app: CICIDS 2017 intrusion detection dashboard + REST API.

Run:  python app.py   then open http://127.0.0.1:5000
"""

import io
import os
import threading
import time
from collections import Counter, deque

import pandas as pd
from flask import Flask, jsonify, render_template, request

from ids.model import FeatureError, IntrusionDetector
from ids.samples import SAMPLES
from utils import classification_metrics

MAX_UPLOAD_MB = int(os.environ.get("IDS_MAX_UPLOAD_MB", "200"))
MAX_RETURNED_ROWS = 1000


def create_app(model_path=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    detector = IntrusionDetector(model_path) if model_path else IntrusionDetector()

    history = deque(maxlen=50)
    stats = Counter()
    lock = threading.Lock()

    def record(source, result, label=None):
        if result.get("prediction") not in ("ATTACK", "BENIGN"):
            return
        with lock:
            stats["total"] += 1
            stats[result["prediction"].lower()] += 1
            history.appendleft({
                "time": time.strftime("%H:%M:%S"),
                "source": source,
                "label": label or source,
                "prediction": result["prediction"],
                "attack_probability": result["attack_probability"],
                "risk": result["risk"],
            })

    # ---------------- pages ----------------
    @app.get("/")
    def index():
        return render_template("index.html")

    # ---------------- API ----------------
    @app.get("/api/health")
    def health():
        return jsonify(status="ok", model_loaded=True, n_features=len(detector.features))

    @app.get("/api/model")
    def model_info():
        return jsonify(detector.info())

    @app.get("/api/features")
    def features():
        return jsonify(features=detector.features, ignored=detector.ignored_columns())

    @app.get("/api/samples")
    def samples():
        return jsonify(SAMPLES)

    @app.post("/api/predict")
    def predict():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify(error="Send a JSON body: {\"features\": {...}} or {\"flows\": [...]}"), 400

        if isinstance(payload, dict) and isinstance(payload.get("flows"), list):
            flows, single = payload["flows"], False
        elif isinstance(payload, dict) and isinstance(payload.get("features"), dict):
            flows, single = [payload["features"]], True
        elif isinstance(payload, dict):
            flows, single = [payload], True
        else:
            return jsonify(error="JSON body must be an object."), 400

        if not flows:
            return jsonify(error="No flows supplied."), 400
        if not all(isinstance(f, dict) for f in flows):
            return jsonify(error="Each flow must be a JSON object of feature: value."), 400

        strict = bool(payload.get("strict", False))
        try:
            results = detector.predict_frame(pd.DataFrame(flows), fill_missing=not strict)
        except FeatureError as exc:
            return jsonify(error=str(exc)), 400

        label = payload.get("label")
        for r in results:
            record("manual" if single else "api", r, label)
        return jsonify(results[0] if single else {"results": results})

    @app.post("/api/predict/csv")
    def predict_csv():
        upload = request.files.get("file")
        if upload is None or upload.filename == "":
            return jsonify(error="Attach a CSV file in the 'file' field."), 400
        if not upload.filename.lower().endswith(".csv"):
            return jsonify(error="Only .csv files are supported."), 400

        try:
            df = pd.read_csv(io.BytesIO(upload.read()), low_memory=False)
        except Exception as exc:  # malformed CSV
            return jsonify(error=f"Could not parse CSV: {exc}"), 400

        started = time.perf_counter()
        try:
            results = detector.predict_frame(df)
        except FeatureError as exc:
            return jsonify(error=str(exc)), 400
        elapsed = time.perf_counter() - started

        valid = [r for r in results if r["prediction"] != "INVALID"]
        summary = {
            "file": upload.filename,
            "rows": len(results),
            "valid_rows": len(valid),
            "invalid_rows": len(results) - len(valid),
            "attacks": sum(r["prediction"] == "ATTACK" for r in valid),
            "benign": sum(r["prediction"] == "BENIGN" for r in valid),
            "risk_counts": dict(Counter(r["risk"] for r in valid)),
            "seconds": round(elapsed, 3),
        }

        labelled = [r for r in valid if "actual" in r]
        if labelled:
            y_true = [1 if r["actual"] == "ATTACK" else 0 for r in labelled]
            y_pred = [1 if r["prediction"] == "ATTACK" else 0 for r in labelled]
            summary["metrics"] = classification_metrics(y_true, y_pred)
            summary["labelled_rows"] = len(labelled)

        with lock:
            stats["total"] += len(valid)
            stats["attack"] += summary["attacks"]
            stats["benign"] += summary["benign"]
            history.appendleft({
                "time": time.strftime("%H:%M:%S"), "source": "csv",
                "label": f"{upload.filename} ({len(valid)} flows)",
                "prediction": "ATTACK" if summary["attacks"] else "BENIGN",
                "attack_probability": round(summary["attacks"] / len(valid), 4) if valid else 0,
                "risk": f"{summary['attacks']} attacks",
            })

        # Return attacks first so the most relevant rows survive truncation.
        ordered = sorted(results, key=lambda r: (r["prediction"] != "ATTACK",
                                                 -r.get("attack_probability", 0)))
        return jsonify(summary=summary, results=ordered[:MAX_RETURNED_ROWS],
                       truncated=len(results) > MAX_RETURNED_ROWS)

    @app.get("/api/history")
    def get_history():
        with lock:
            return jsonify(stats=dict(stats), history=list(history))

    @app.delete("/api/history")
    def clear_history():
        with lock:
            history.clear()
            stats.clear()
        return jsonify(status="cleared")

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error=f"File too large (limit {MAX_UPLOAD_MB} MB)."), 413

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG") == "1")
