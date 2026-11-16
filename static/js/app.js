(() => {
  "use strict";

  const KEY_FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Bwd Packet Length Max", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Max Packet Length", "Avg Fwd Segment Size", "Flow IAT Mean", "Fwd IAT Std",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
  ];

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const pct = (x, d = 1) => `${(x * 100).toFixed(d)}%`;
  const fmt = (n) => Number(n).toLocaleString();
  const slug = (f) => "f-" + f.replace(/[^a-z0-9]+/gi, "-").toLowerCase();

  let FEATURES = [];
  let SAMPLES = {};

  async function api(path, opts = {}) {
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  // ---------------- tabs ----------------
  $$(".tab").forEach((tab) => tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.toggle("is-active", t === tab));
    $$("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
  }));

  // ---------------- form ----------------
  function fieldHTML(f, idPrefix) {
    return `<div class="field" data-name="${esc(f.toLowerCase())}">
      <label for="${idPrefix}${slug(f)}" title="${esc(f)}">${esc(f)}</label>
      <input class="input" id="${idPrefix}${slug(f)}" data-feature="${esc(f)}" inputmode="decimal" placeholder="0">
    </div>`;
  }

  function buildForm() {
    const keys = KEY_FEATURES.filter((f) => FEATURES.includes(f));
    $("#key-fields").innerHTML = keys.map((f) => fieldHTML(f, "k-")).join("");
    $("#all-fields").innerHTML = FEATURES.map((f) => fieldHTML(f, "a-")).join("");

    // Keep the key inputs and their twins in "all features" in sync.
    $$("#flow-form .input[data-feature]").forEach((inp) => {
      inp.addEventListener("input", () => {
        $$(`#flow-form .input[data-feature="${CSS.escape(inp.dataset.feature)}"]`)
          .forEach((o) => { if (o !== inp) o.value = inp.value; });
        $$(".preset").forEach((p) => p.classList.remove("is-active"));
        updateFilled();
      });
    });
  }

  function setValues(values) {
    $$("#flow-form .input[data-feature]").forEach((inp) => {
      const v = values[inp.dataset.feature];
      inp.value = v === undefined || v === null ? "" : +Number(v).toFixed(4);
    });
    updateFilled();
  }

  function readValues() {
    const out = {};
    $$("#all-fields .input[data-feature]").forEach((inp) => {
      const raw = inp.value.trim();
      if (raw !== "") out[inp.dataset.feature] = Number(raw);
    });
    return out;
  }

  function updateFilled() {
    const n = $$("#all-fields .input").filter((i) => i.value.trim() !== "").length;
    $("#filled-count").textContent = n ? `· ${n} filled` : "";
  }

  $("#feature-filter").addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    $$("#all-fields .field").forEach((f) => { f.hidden = q && !f.dataset.name.includes(q); });
  });

  $("#btn-reset").addEventListener("click", () => {
    setValues({});
    $$(".preset").forEach((p) => p.classList.remove("is-active"));
    currentLabel = null;
  });

  let currentLabel = null;
  function buildPresets() {
    $("#presets").innerHTML = Object.entries(SAMPLES).map(([key, s]) =>
      `<button type="button" class="preset" data-key="${esc(key)}" data-expected="${esc(s.expected)}" title="${esc(s.description)}">${esc(s.name)}</button>`
    ).join("");
    $$(".preset").forEach((btn) => btn.addEventListener("click", () => {
      const s = SAMPLES[btn.dataset.key];
      setValues(s.features);
      $$(".preset").forEach((p) => p.classList.toggle("is-active", p === btn));
      currentLabel = s.name;
    }));
  }

  $("#flow-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const values = readValues();
    if (Object.values(values).some((v) => !Number.isFinite(v))) {
      showVerdictError("All feature values must be numbers.");
      return;
    }
    if (!Object.keys(values).length) {
      showVerdictError("Enter at least one feature value or load an example flow.");
      return;
    }
    const btn = $("#btn-analyse");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analysing…';
    try {
      const r = await api("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features: values, label: currentLabel || "Custom flow" }),
      });
      renderVerdict(r);
      refreshHistory();
    } catch (err) {
      showVerdictError(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Analyse flow";
    }
  });

  // ---------------- verdict ----------------
  function renderVerdict(r) {
    const attack = r.prediction === "ATTACK";
    const p = r.attack_probability;
    const C = 2 * Math.PI * 45;
    const color = attack ? "var(--danger)" : "var(--ok)";
    const el = $("#verdict");
    el.className = `card verdict ${attack ? "verdict--attack" : "verdict--benign"}`;
    el.innerHTML = `
      <div class="verdict__top">
        <svg class="gauge" viewBox="0 0 110 110" role="img" aria-label="Attack probability ${pct(p)}">
          <circle class="track" cx="55" cy="55" r="45"/>
          <circle class="bar" cx="55" cy="55" r="45" stroke="${color}"
            stroke-dasharray="${C}" stroke-dashoffset="${C}"/>
          <text x="55" y="58" text-anchor="middle">${pct(p, 0)}</text>
          <text class="sub" x="55" y="73" text-anchor="middle">attack prob.</text>
        </svg>
        <div>
          <div class="muted">Verdict</div>
          <div class="verdict__label">${attack ? "INTRUSION" : "BENIGN"}</div>
          <div class="muted">${attack ? "This flow matches attack traffic patterns." : "No malicious pattern detected in this flow."}</div>
        </div>
      </div>
      <div class="verdict__meta">
        <div><span>Risk level</span><strong class="risk-${esc(r.risk)}">${esc(r.risk)}</strong></div>
        <div><span>Confidence</span><strong>${pct(r.confidence)}</strong></div>
        <div><span>Benign prob.</span><strong>${pct(1 - p)}</strong></div>
      </div>`;
    requestAnimationFrame(() => {
      $(".gauge .bar", el).style.strokeDashoffset = C * (1 - p);
    });
  }

  function showVerdictError(msg) {
    const el = $("#verdict");
    el.className = "card verdict";
    el.innerHTML = `<div class="alert">${esc(msg)}</div>`;
  }

  // ---------------- history ----------------
  async function refreshHistory() {
    try {
      const { stats, history } = await api("/api/history");
      const total = stats.total || 0, attack = stats.attack || 0;
      $("#st-total").textContent = fmt(total);
      $("#st-attack").textContent = fmt(attack);
      $("#st-benign").textContent = fmt(stats.benign || 0);
      $("#st-rate").textContent = total ? pct(attack / total) : "0%";
      $("#log").innerHTML = history.length
        ? history.map((h) => `<li>
            <time>${esc(h.time)}</time>
            <span class="lbl" title="${esc(h.label)}">${esc(h.label)}</span>
            <span class="pill pill--${h.prediction === "ATTACK" ? "attack" : "benign"}">${esc(h.prediction)}</span>
          </li>`).join("")
        : '<li class="muted">No detections yet.</li>';
    } catch { /* stats are non-critical */ }
  }

  $("#btn-clear-history").addEventListener("click", async () => {
    await api("/api/history", { method: "DELETE" });
    refreshHistory();
  });

  // ---------------- batch ----------------
  const drop = $("#drop");
  const input = $("#csv-input");
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("is-over"); }));
  drop.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) uploadCSV(e.dataTransfer.files[0]); });
  input.addEventListener("change", () => { if (input.files[0]) uploadCSV(input.files[0]); input.value = ""; });

  async function uploadCSV(file) {
    const out = $("#batch-out");
    $("#drop-name").textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    out.innerHTML = '<p class="muted" style="margin-top:16px">Analysing flows…</p>';
    const fd = new FormData();
    fd.append("file", file);
    try {
      const data = await api("/api/predict/csv", { method: "POST", body: fd });
      renderBatch(data);
      refreshHistory();
    } catch (err) {
      out.innerHTML = `<div class="alert">${esc(err.message)}</div>`;
    }
  }

  function renderBatch({ summary: s, results, truncated }) {
    const valid = s.valid_rows || 1;
    let html = `
      <div class="summary">
        <div><span>Rows</span><strong>${fmt(s.rows)}</strong></div>
        <div><span>Attacks</span><strong style="color:var(--danger)">${fmt(s.attacks)}</strong></div>
        <div><span>Benign</span><strong style="color:var(--ok)">${fmt(s.benign)}</strong></div>
        <div><span>Invalid rows</span><strong>${fmt(s.invalid_rows)}</strong></div>
        <div><span>Time</span><strong>${s.seconds}s</strong></div>
      </div>
      <div class="bar-split" title="${pct(s.attacks / valid)} attacks">
        <div class="a" style="width:${(s.attacks / valid) * 100}%"></div>
        <div class="b" style="width:${(s.benign / valid) * 100}%"></div>
      </div>`;

    if (s.metrics) {
      const m = s.metrics, cm = m.confusion_matrix;
      html += `
        <h3 class="subhead">Evaluation against the Label column (${fmt(s.labelled_rows)} rows)</h3>
        <div class="metrics-grid">
          <div class="summary" style="grid-template-columns:repeat(4,1fr);margin:0">
            <div><span>Accuracy</span><strong>${pct(m.accuracy, 2)}</strong></div>
            <div><span>Precision</span><strong>${pct(m.precision, 2)}</strong></div>
            <div><span>Recall</span><strong>${pct(m.recall, 2)}</strong></div>
            <div><span>F1 score</span><strong>${pct(m.f1_score, 2)}</strong></div>
          </div>
          <div class="cm">
            <div class="h"></div><div class="h">Pred benign</div><div class="h">Pred attack</div>
            <div class="h">Benign</div><div class="good">TN ${fmt(cm.tn)}</div><div class="bad">FP ${fmt(cm.fp)}</div>
            <div class="h">Attack</div><div class="bad">FN ${fmt(cm.fn)}</div><div class="good">TP ${fmt(cm.tp)}</div>
          </div>
        </div>`;
    }

    const hasActual = results.some((r) => r.actual);
    html += `
      <h3 class="subhead">Per-flow results${truncated ? ` (first ${results.length}, attacks first)` : ""}</h3>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Row</th><th>Prediction</th>${hasActual ? "<th>Actual</th>" : ""}<th>Attack prob.</th><th>Risk</th></tr></thead>
        <tbody>${results.map((r) => {
          const cls = r.prediction === "ATTACK" ? "attack" : r.prediction === "BENIGN" ? "benign" : "invalid";
          return `<tr>
            <td class="num">${r.row + 1}</td>
            <td><span class="pill pill--${cls}">${esc(r.prediction)}</span></td>
            ${hasActual ? `<td>${r.actual ? `<span class="pill pill--${r.actual === "ATTACK" ? "attack" : "benign"}">${esc(r.actual)}</span>` : ""}</td>` : ""}
            <td class="num">${r.attack_probability !== undefined ? pct(r.attack_probability) : "—"}</td>
            <td class="${r.risk ? "risk-" + esc(r.risk) : "muted"}">${esc(r.risk || r.error || "")}</td>
          </tr>`;
        }).join("")}</tbody>
      </table></div>`;
    $("#batch-out").innerHTML = html;
  }

  // ---------------- model tab ----------------
  function renderModel(info) {
    $("#model-kv").innerHTML = [
      ["Algorithm", info.type],
      ["Trees", info.n_estimators],
      ["Max depth", info.max_depth],
      ["Input features", info.n_features],
      ["Classes", "0 = BENIGN, 1 = ATTACK"],
      ["Dataset", info.dataset],
    ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");

    $("#results-table").innerHTML = `
      <thead><tr><th>Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
      <tbody>${info.notebook_results.map((r) => `
        <tr class="${r.deployed ? "deployed" : ""}">
          <td>${esc(r.model)}</td><td class="num">${pct(r.accuracy, 2)}</td><td class="num">${pct(r.precision, 2)}</td>
          <td class="num">${pct(r.recall, 2)}</td><td class="num">${pct(r.f1_score, 2)}</td>
        </tr>`).join("")}</tbody>`;

    const max = Math.max(...info.top_features.map((f) => f.importance)) || 1;
    $("#importance").innerHTML = info.top_features.map((f) => `
      <div class="imp">
        <span class="name" title="${esc(f.feature)}">${esc(f.feature)}</span>
        <div class="track"><div class="fill" style="width:${(f.importance / max) * 100}%"></div></div>
        <span class="val">${f.importance.toFixed(3)}</span>
      </div>`).join("");
  }

  // ---------------- boot ----------------
  async function init() {
    const status = $("#status");
    try {
      const [health, feats, samples, info] = await Promise.all([
        api("/api/health"), api("/api/features"), api("/api/samples"), api("/api/model"),
      ]);
      FEATURES = feats.features;
      SAMPLES = samples;
      buildForm();
      buildPresets();
      renderModel(info);
      refreshHistory();
      status.className = "status status--ok";
      $("#status-text").textContent = `Model online · ${health.n_features} features`;
    } catch (err) {
      status.className = "status status--err";
      $("#status-text").textContent = "Backend unavailable";
      showVerdictError(`Could not reach the API: ${err.message}`);
    }
  }

  init();
})();
