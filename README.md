# Sentinel IDS: Intrusion Detection on CICIDS 2017

A machine-learning network intrusion detection system with a web dashboard and REST API.
The model is trained on the **CICIDS 2017** dataset published by the Canadian Institute for
Cybersecurity (University of New Brunswick). It classifies network flows as **BENIGN** or **ATTACK**.

## Project Description
The notebook loads CICIDS 2017, cleans it, merges every attack type into a single binary
label and trains two classifiers. The better model (by F1) is saved as a `.pkl` file.
A Flask backend serves that model, and a browser frontend lets you:

- analyse a single flow, typing feature values or loading an example (DNS, HTTPS, DoS Hulk, DDoS, port scan)
- upload a CICFlowMeter / CICIDS CSV for batch detection, with accuracy, precision, recall, F1 and a confusion matrix when a `Label` column is present
- see model details, notebook test results and feature importances
- follow live detection statistics and a recent-activity log

## Dataset
- Source: [CICIDS 2017 on Kaggle (sweety18/cicids2017-full-dataset)](https://www.kaggle.com/datasets/sweety18/cicids2017-full-dataset)
- Original: <https://www.unb.ca/cic/datasets/ids-2017.html>

The dataset (~170 MB) is **not** stored in this repository. The notebook downloads it with `kagglehub`.

After cleaning: 2,212,030 flows, 78 features (75.6% benign, 24.4% attack).
Attack classes: DoS Hulk, PortScan, DDoS, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, Bot, Infiltration, Heartbleed.

## Preprocessing (from the notebook)
1. Strip spaces from column names
2. Replace ±inf with NaN and drop rows with missing values
3. `Label` → `Target` (BENIGN = 0, any attack = 1)
4. Convert `Destination Port` to numeric, then **drop it** as a shortcut feature
5. 80/20 stratified train/test split (`random_state=42`)

The web app repeats steps 1, 2 and 4 on every input so it matches training.

## Algorithms
- Logistic Regression (`max_iter=500`, on standardised features)
- Random Forest (`n_estimators=20`, `max_depth=4`, raw features), **deployed**

## Results
Test set: 442,406 flows. Results are also saved in [output/model_results.csv](output/model_results.csv).

| Model | Accuracy | Precision | Recall | F1-score | Experiment |
|---|---|---|---|---|---|
| Logistic Regression | 0.9230 | 0.8429 | 0.8417 | 0.8423 | Baseline |
| Random Forest | 0.9566 | 0.9918 | 0.8292 | 0.9033 | Baseline (deployed) |

## Project Files
```
├── app.py                         Flask app: web UI + REST API
├── utils.py                       Small tested helpers (cleaning, labels, metrics, risk)
├── ids/
│   ├── model.py                   Model loading, preprocessing, prediction
│   ├── export.py                  Exports the forest to JSON for the browser
│   └── samples.py                 Example flows for the dashboard
├── model/cicids_intrusion_model.pkl   Trained Random Forest from the notebook
├── notebooks/Intrusion_Detection_System.ipynb   Training notebook (Colab)
├── templates/index.html           Dashboard page
├── static/                        CSS, JS, sample_flows.csv
├── scripts/make_sample_csv.py     Regenerates static/sample_flows.csv
├── scripts/build_pages.py         Builds the static GitHub Pages site into site/
├── output/model_results.csv       Recorded model metrics
├── tests/                         unittest suite (utils + API)
└── .github/workflows/
    ├── python-test.yml            CI: unit tests on push / PR
    └── deploy-pages.yml           CD: publish frontend to GitHub Pages after CI passes
```

## How to Run
1. Install Python 3.10 or newer.
2. Create a virtual environment and install the packages:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate        # Windows  (macOS/Linux: source .venv/bin/activate)
   pip install -r requirements.txt
   ```
3. Start the server:
   ```bash
   python app.py
   ```
4. Open <http://127.0.0.1:5000>.

`scikit-learn` is pinned to 1.6.1, the version the model loads with without warnings.

## REST API
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Service and model status |
| GET | `/api/model` | Model info, notebook results, feature importances |
| GET | `/api/features` | The 77 input feature names |
| GET | `/api/samples` | Example flows |
| POST | `/api/predict` | `{"features": {...}}` for one flow or `{"flows": [...]}` for several. Missing features count as 0 unless `"strict": true` |
| POST | `/api/predict/csv` | Multipart upload, field `file` |
| GET / DELETE | `/api/history` | Session statistics and recent detections |

Example:
```bash
curl -X POST http://127.0.0.1:5000/api/predict -H "Content-Type: application/json" -d "{\"features\": {\"Flow Duration\": 45, \"Total Fwd Packets\": 1, \"Total Backward Packets\": 1, \"Bwd Packet Length Max\": 6}}"
```

Response:
```json
{"row": 0, "prediction": "ATTACK", "attack_probability": 0.5047, "confidence": 0.5047, "risk": "High"}
```
With only four features filled in, the model is close to 50/50. Send all 77 features for reliable results.

## Tests and CI
```bash
python -m unittest discover -s tests -v
```
GitHub Actions runs the same command on every push and pull request to `main`. It does not retrain the model.

## Live demo on GitHub Pages (CD)
**<https://abdulahad-809.github.io/ids-dev-ops/>**

GitHub Pages only hosts static files and cannot run Flask. For the Pages version,
`scripts/build_pages.py` exports the Random Forest's 20 trees to `static/model.json`,
and `static/js/engine.js` runs them in the browser. Single-flow analysis, CSV upload and metrics
all work with no server. `tests/test_export.py` checks that the exported model gives exactly
the same probabilities as the `.pkl`.

Pipeline:
```
push to main ──► Python CI (python-test.yml: unit tests)
                     │ passed
                     ▼
               Deploy to GitHub Pages (deploy-pages.yml: build site/ ──► publish)
```
If the tests fail, nothing is deployed. To preview the Pages build locally:
```bash
python scripts/build_pages.py
python -m http.server 8000 -d site
```

One-time setup: in the repository, go to **Settings → Pages → Build and deployment → Source** and choose **GitHub Actions**.

## Limitations
- Binary detection only: it does not name the attack type.
- Recall is 0.83, so roughly 1 in 6 attack flows in the test set were missed.
- The example flows in the dashboard are synthetic, shaped after CICIDS traffic patterns, and are for demonstration.
- Detection statistics are kept in memory and reset when the server restarts (on Pages, when the page reloads).

## Contributors
- Original author: Abdulahad-809
- Collaborator: _add your partner's name_
