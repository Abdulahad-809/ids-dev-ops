/*
 * In-browser backend for the static (GitHub Pages) build.
 *
 * Mirrors the Flask API in app.py using the Random Forest exported to
 * static/model.json by scripts/build_pages.py (see ids/export.py). Results
 * match the Python model: tests/test_export.py checks the same algorithm.
 */
(() => {
  "use strict";

  const round4 = (x) => Math.round(x * 1e4) / 1e4;

  function riskLevel(p) {
    if (p >= 0.85) return "Critical";
    if (p >= 0.5) return "High";
    if (p >= 0.25) return "Medium";
    return "Low";
  }

  // Same rule as utils.safe_float / pandas.to_numeric: anything non-finite is invalid.
  function toNumber(v) {
    if (v === null || v === undefined) return NaN;
    if (typeof v === "number") return v;
    const s = String(v).trim();
    return s === "" ? NaN : Number(s);
  }

  function parseCSV(text) {
    const rows = [];
    let row = [], field = "", inQuotes = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (inQuotes) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
        } else field += c;
      } else if (c === '"') inQuotes = true;
      else if (c === ",") { row.push(field); field = ""; }
      else if (c === "\n" || c === "\r") {
        if (c === "\r" && text[i + 1] === "\n") i++;
        row.push(field); field = "";
        if (row.length > 1 || row[0] !== "") rows.push(row);
        row = [];
      } else field += c;
    }
    if (field !== "" || row.length) { row.push(field); rows.push(row); }
    return rows;
  }

  function metrics(yTrue, yPred) {
    let tp = 0, tn = 0, fp = 0, fn = 0;
    yTrue.forEach((t, i) => {
      const p = yPred[i];
      if (t === 1 && p === 1) tp++;
      else if (t === 0 && p === 0) tn++;
      else if (t === 0 && p === 1) fp++;
      else fn++;
    });
    const precision = tp + fp ? tp / (tp + fp) : 0;
    const recall = tp + fn ? tp / (tp + fn) : 0;
    return {
      accuracy: (tp + tn) / yTrue.length,
      precision, recall,
      f1_score: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
      confusion_matrix: { tn, fp, fn, tp },
    };
  }

  class LocalBackend {
    constructor(bundle) {
      this.features = bundle.features;
      this.trees = bundle.trees;
      this.info = bundle.info;
      this.samples = bundle.samples;
      this.stats = { total: 0, attack: 0, benign: 0 };
      this.log = [];
    }

    static async load(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Could not load model (${res.status})`);
      return new LocalBackend(await res.json());
    }

    attackProbability(x) {
      const xf = x.map(Math.fround); // sklearn compares float32 inputs
      let total = 0;
      for (const t of this.trees) {
        let n = 0;
        while (t.left[n] !== -1) n = xf[t.feature[n]] <= t.threshold[n] ? t.left[n] : t.right[n];
        total += t.p[n];
      }
      return total / this.trees.length;
    }

    result(row, x) {
      if (x.some((v) => !Number.isFinite(v))) {
        return { row, prediction: "INVALID", error: "Row contains missing, non-numeric or infinite values." };
      }
      const p = this.attackProbability(x);
      return {
        row,
        prediction: p >= 0.5 ? "ATTACK" : "BENIGN",
        attack_probability: round4(p),
        confidence: round4(Math.max(p, 1 - p)),
        risk: riskLevel(p),
      };
    }

    record(entry) {
      this.log.unshift({ time: new Date().toTimeString().slice(0, 8), ...entry });
      this.log.length = Math.min(this.log.length, 50);
    }

    // ----- API-compatible methods -----
    async health() { return { status: "ok", model_loaded: true, n_features: this.features.length }; }
    async model() { return this.info; }
    async featureList() { return { features: this.features }; }
    async sampleFlows() { return this.samples; }

    async predict(values, label) {
      const x = this.features.map((f) => (f in values ? toNumber(values[f]) : 0));
      const r = this.result(0, x);
      if (r.prediction !== "INVALID") {
        this.stats.total++;
        this.stats[r.prediction.toLowerCase()]++;
        this.record({ label: label || "manual", prediction: r.prediction });
      }
      return r;
    }

    async predictCsv(file) {
      const started = performance.now();
      const rows = parseCSV(await file.text());
      if (rows.length < 2) throw new Error("No rows supplied.");
      const header = rows[0].map((h) => h.trim());
      const idx = Object.fromEntries(header.map((h, i) => [h, i]));
      const missing = this.features.filter((f) => !(f in idx));
      if (missing.length) {
        const preview = missing.slice(0, 5).join(", ") + (missing.length > 5 ? " ..." : "");
        throw new Error(`Missing ${missing.length} required feature(s): ${preview}`);
      }
      const labelCol = idx.Label, targetCol = idx.Target;

      const results = rows.slice(1).map((cells, i) => {
        const r = this.result(i, this.features.map((f) => toNumber(cells[idx[f]])));
        if (r.prediction !== "INVALID") {
          if (labelCol !== undefined && cells[labelCol] !== undefined) {
            r.actual = cells[labelCol].trim().toUpperCase() === "BENIGN" ? "BENIGN" : "ATTACK";
          } else if (targetCol !== undefined && Number.isFinite(toNumber(cells[targetCol]))) {
            r.actual = toNumber(cells[targetCol]) === 1 ? "ATTACK" : "BENIGN";
          }
        }
        return r;
      });

      const valid = results.filter((r) => r.prediction !== "INVALID");
      const attacks = valid.filter((r) => r.prediction === "ATTACK").length;
      const riskCounts = {};
      valid.forEach((r) => { riskCounts[r.risk] = (riskCounts[r.risk] || 0) + 1; });
      const summary = {
        file: file.name, rows: results.length, valid_rows: valid.length,
        invalid_rows: results.length - valid.length, attacks, benign: valid.length - attacks,
        risk_counts: riskCounts, seconds: round4((performance.now() - started) / 1000),
      };
      const labelled = valid.filter((r) => r.actual);
      if (labelled.length) {
        summary.metrics = metrics(
          labelled.map((r) => (r.actual === "ATTACK" ? 1 : 0)),
          labelled.map((r) => (r.prediction === "ATTACK" ? 1 : 0)));
        summary.labelled_rows = labelled.length;
      }

      this.stats.total += valid.length;
      this.stats.attack += attacks;
      this.stats.benign += valid.length - attacks;
      this.record({ label: `${file.name} (${valid.length} flows)`, prediction: attacks ? "ATTACK" : "BENIGN" });

      const ordered = [...results].sort((a, b) =>
        (a.prediction !== "ATTACK") - (b.prediction !== "ATTACK") ||
        (b.attack_probability || 0) - (a.attack_probability || 0));
      return { summary, results: ordered.slice(0, 1000), truncated: results.length > 1000 };
    }

    async history() { return { stats: { ...this.stats }, history: [...this.log] }; }
    async clearHistory() { this.stats = { total: 0, attack: 0, benign: 0 }; this.log = []; }
  }

  window.LocalBackend = LocalBackend;
})();
