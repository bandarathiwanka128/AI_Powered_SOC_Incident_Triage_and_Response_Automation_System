# AI-Powered SOC Analyst Assistant — Full Project Documentation

> EC6301 Mini Project | Team: Herath H.M.T.B | Hettiarachchi H.A.K.G | Fernando N.D.H

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [File-by-File Breakdown](#3-file-by-file-breakdown)
   - [app.py](#apppy--main-streamlit-dashboard)
   - [api_server.py](#api_serverpy--rest-api-server)
   - [config.py](#configpy--global-configuration)
   - [modules/preprocessor.py](#modulespreprocessorpy)
   - [modules/expert_system.py](#modulesexpert_systempy)
   - [modules/severity_engine.py](#modulesseverity_enginepy)
   - [modules/ml_predictor.py](#modulesml_predictorpy)
   - [modules/gemini_integration.py](#modulesgemini_integrationpy)
   - [modules/playbook_engine.py](#modulesplaybook_enginepy)
   - [modules/auth.py](#modulesauthpy)
4. [Models & Saved Files](#4-models--saved-files)
5. [Data Folder](#5-data-folder)
6. [Python Modules (Dependencies)](#6-python-modules-dependencies)
7. [Deployment Files](#7-deployment-files)
8. [How the AI Pipeline Works (End-to-End)](#8-how-the-ai-pipeline-works-end-to-end)
9. [API Reference](#9-api-reference)
10. [Environment Variables (.env)](#10-environment-variables-env)
11. [How to Run](#11-how-to-run)

---

## 1. Project Overview

This is a **Security Operations Centre (SOC) Analyst Assistant** — a full-stack AI application that automatically detects, classifies, and prioritises cyber threats from network traffic logs.

| Layer | Technology |
|---|---|
| Frontend | Streamlit |
| Backend API | FastAPI + Uvicorn |
| ML Model | PyTorch ANN (Artificial Neural Network) |
| Rule Engine | Custom Python expert system |
| AI Summaries | Google Gemini 1.5 Flash |
| Database | MongoDB Atlas (cloud) |
| Deployment | Docker / Streamlit Cloud / Azure |

---

## 2. Architecture Diagram

```
Network Log + Extracted Features (28 fields)
                    │
                    ▼
      ┌─────────────────────────────────┐
      │  STAGE 1 — ANN MODEL (Primary)  │  ← MLPredictor (ml_predictor.py)
      │  Runs on EVERY row              │
      │  PyTorch 4-layer ANN            │
      │  Trained on CICIDS2017          │
      │  (confidence > 70%?)            │
      └──────────┬────────────┬─────────┘
                YES           NO
                 │             │
      CLASSIFIED │             ▼
                 │  ┌──────────────────────────────────┐
                 │  │  STAGE 2 — PRE-FILTER             │  ← PreFilter (expert_system.py)
                 │  │  Only runs when ANN uncertain     │
                 │  │  Cannot silently override ANN     │
                 │  ├──────────────────────────────────┤
                 │  │  SSH:  port=22 + fail>5?          │
                 │  │  FTP:  port=21 + fail>5?          │
                 │  │  DDoS: pkt>50k + ips>50?          │
                 │  │  Scan: ports>50 + <10s?           │
                 │  └──────────┬───────────┬────────────┘
                 │            YES          NO
                 │             │            │
                 │   RESOLVED  │            ▼
                 │             │  ┌──────────────────────────┐
                 │             │  │  STAGE 3 — EXPERT SYSTEM  │  ← ExpertSystem
                 │             │  │  8 lambda rules           │    (expert_system.py)
                 │             │  │  Final fallback           │
                 │             │  └────────────┬─────────────┘
                 │             │               │
                 └──────┬──────┴───────────────┘
                        │  (classification + "stage" label)
                        ▼
          ┌─────────────────────────────┐
          │  MITRE ATT&CK Mapping        │  ← config.py MITRE_MAPPING
          │  (T1110, T1046, T1498…)      │
          └─────────────────────────────┘
                        ▼
          ┌─────────────────────────────┐
          │  Severity Engine             │  ← severity_engine.py
          │  Score 0–100 →              │
          │  Low / Medium / High /       │
          │  Critical                   │
          └─────────────────────────────┘
                        ▼
          ┌─────────────────────────────┐
          │  Dashboard Alert             │
          │  Stage: ANN Model /          │
          │         Pre-filter /         │
          │         Expert System        │
          └─────────────────────────────┘

[app.py]        → Streamlit Dashboard (charts, alerts, deep-dive)
[api_server.py] → REST API (for external integrations)
[auth.py]       → MongoDB login + API key management
```

---

## 3. File-by-File Breakdown

---

### `app.py` — Main Streamlit Dashboard

**What it does:**
The main entry point of the application. Renders the full SOC dashboard in the browser using Streamlit. Handles login/register UI, sidebar navigation, log loading, AI classification pipeline, charts, alert table, and incident deep-dive.

**Key code sections:**

#### Session state — tracks login
```python
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.nav = "Dashboard"
```

#### Cached module loading — loads all AI modules once
```python
@st.cache_resource
def load_modules():
    return ExpertSystem(), SeverityEngine(), PlaybookEngine(), GeminiAnalyst(), MLPredictor()

expert_sys, severity_eng, playbook_eng, gemini, ml_predictor = load_modules()
```

#### AI classification pipeline — the core logic
```python
@st.cache_data
def process_logs(df_json: str, filter_lvl: str):
    for _, row in df.iterrows():
        ml_result = ml_predictor.predict(row)
        if ml_result["attack_type"] and ml_result["confidence"] > 0.7:
            # Use ML model result
            classification = { "attack_type": attack, ... }
        else:
            # Fall back to rule-based expert system
            classification = expert_sys.classify(features)
        severity = severity_eng.score(...)
```
> ML model runs first. If confidence > 70%, ML wins. Otherwise, expert system rules take over.

#### Noise filter — removes low-priority alerts
```python
filter_level = st.select_slider(
    "Show alerts from severity:",
    options=["Low", "Medium", "High", "Critical"],
    value="Medium",
)
```

#### Gemini AI summary button
```python
if st.button("Generate AI Summary", key="gen_summary"):
    summary = gemini.generate_summary(incident_data)
    st.markdown(summary)
```

**Modules used:** `streamlit`, `pandas`, `plotly`, all `modules/` files, `config.py`

---

### `api_server.py` — REST API Server

**What it does:**
Exposes the same AI detection pipeline as a REST API using FastAPI. External applications (Python scripts, cron jobs, SIEM tools) call this API with a CSV file or JSON row and receive back threat classifications.

**Key code sections:**

#### FastAPI app setup with CORS
```python
app = FastAPI(title="SOC Analyst Assistant API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], ...)
```

#### API key authentication
```python
def verify_key(api_key: str):
    user = get_user_by_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user
```

#### POST /api/detect — upload CSV, get all threats
```python
@app.post("/api/detect")
async def detect(file: UploadFile = File(...), x_api_key: str = Header(...)):
    df = pd.read_csv(io.StringIO(content.decode("latin-1")))
    for _, row in df.iterrows():
        ml_result = ml.predict(row)
        # ML → expert fallback → severity scoring
    return { "total_rows": ..., "threats_found": ..., "results": [...] }
```

#### POST /api/detect/single — send one JSON row
```python
@app.post("/api/detect/single")
async def detect_single(data: dict, x_api_key: str = Header(...)):
    row = pd.Series(data)
    # Same pipeline as CSV detect
```

**How to start the API:**
```bash
uvicorn api_server:app --reload --port 8000
```

**Modules used:** `fastapi`, `uvicorn`, `pandas`, all `modules/` files

---

### `config.py` — Global Configuration

**What it does:**
Central place for all constants shared across modules — severity level definitions, MITRE ATT&CK technique mappings, and the Gemini API key loader.

**Key code sections:**

#### Gemini key loaded from .env
```python
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
```

#### Severity thresholds
```python
SEVERITY_LEVELS = {
    "Low":      { "min_score": 0  },
    "Medium":   { "min_score": 30 },
    "High":     { "min_score": 60 },
    "Critical": { "min_score": 80 },
}
```

#### MITRE ATT&CK mapping table
```python
MITRE_MAPPING = {
    "Brute Force": { "id": "T1110", "tactic": "Credential Access", ... },
    "Port Scan":   { "id": "T1046", "tactic": "Discovery", ... },
    "DoS":         { "id": "T1498", "tactic": "Impact", ... },
    "DDoS":        { "id": "T1498.001", ... },
    "Web Attack":  { "id": "T1190", "tactic": "Initial Access", ... },
    "Infiltration":{ "id": "T1078", "tactic": "Defense Evasion", ... },
    "Bot":         { "id": "T1071", "tactic": "Command and Control", ... },
}
```

**Modules used:** `os`, `python-dotenv`

---

### `modules/preprocessor.py`

**What it does:**
Reads CSV log files and converts each row into a normalised feature dictionary that all other modules can consume.

**Key code sections:**

#### Load CSV data
```python
def load_sample_data(filepath: str = "data/sample_logs.csv") -> pd.DataFrame:
    return pd.read_csv(filepath)
```

#### Extract features from a row
```python
def extract_features(row: pd.Series) -> dict:
    return {
        "dst_port":      int(row.get("Destination Port", 0)),
        "protocol":      str(row.get("Protocol", "TCP")),
        "pkt_count":     float(row.get("Total Fwd Packets", 0)) + float(row.get("Total Backward Packets", 0)),
        "flow_duration": float(row.get("Flow Duration", 0)),
        "failed_logins": float(row.get("Failed Logins", 0)),
        "unique_ports":  float(row.get("Unique Ports", 0)),
        "anomaly_score": float(row.get("Anomaly Score", 0.0)),
        "src_ip":        str(row.get("Source IP", "0.0.0.0")),
        "dst_ip":        str(row.get("Destination IP", "0.0.0.0")),
    }
```
> This function is the bridge between raw CSV columns and the feature names expected by the expert system and ML model.

**Modules used:** `pandas`, `numpy`

---

### `modules/expert_system.py`

**What it does:**
Contains two classes used at different stages of the pipeline:
- `PreFilter` — **Stage 1**: fast deterministic rules for obvious, high-confidence attacks. Runs before the ML model to skip unnecessary inference.
- `ExpertSystem` — **Stage 3**: broader rule-based fallback for traffic the ANN model is uncertain about.

**Key code sections:**

#### PreFilter — Stage 1 rules (new)
```python
class PreFilter:
    def detect(self, features: dict):
        for rule in self._RULES:
            if rule["conditions"](features):
                return { "attack_type": ..., "confidence": ..., "stage": "Pre-filter" }
        return None   # → caller moves to Stage 2
```

| Pre-filter Rule | Condition | Attack | Confidence |
|---|---|---|---|
| SSH Brute Force | port=22 + failed_logins > 5 | Brute Force | 97% |
| FTP Brute Force | port=21 + failed_logins > 5 | Brute Force | 95% |
| Volumetric DDoS | pkt_count > 50,000 + unique_src_ips > 50 | DDoS | 98% |
| Aggressive Port Scan | unique_ports > 50 + flow_duration < 10s | Port Scan | 96% |

#### ExpertSystem — Stage 3 rule structure
```python
{
    "name": "SSH Brute Force",
    "conditions": lambda f: (
        f.get("dst_port") == 22
        and f.get("failed_logins", 0) > 5
        and f.get("protocol") == "TCP"
    ),
    "attack_type": "Brute Force",
    "confidence": 0.92,
},
```

#### All rules defined
| Rule Name | Key Condition | Attack Type | Confidence |
|---|---|---|---|
| SSH Brute Force | port 22 + failed_logins > 5 | Brute Force | 92% |
| FTP Brute Force | port 21 + failed_logins > 5 | Brute Force | 88% |
| General Brute Force | failed_logins > 10 | Brute Force | 85% |
| Port Scan | unique_ports > 10 + pkt_count < 5 | Port Scan | 90% |
| DoS Attack | pkt_count > 10000 + single source | DoS | 87% |
| DDoS Attack | pkt_count > 10000 + unique_src_ips > 10 | DDoS | 93% |
| Web Attack | port 80/443/8080 + anomaly_score > 0.7 | Web Attack | 80% |
| Bot Traffic | long duration + high packets + anomaly | Bot | 75% |

#### Classify function — picks highest confidence rule
```python
def classify(self, features: dict) -> dict:
    matched_rules = [r for r in self.rules if r["conditions"](features)]
    if not matched_rules:
        return { "attack_type": "Benign", "confidence": 0.95 }
    best = max(matched_rules, key=lambda r: r["confidence"])
    return { "attack_type": best["attack_type"], "confidence": best["confidence"], ... }
```

**Modules used:** `config.MITRE_MAPPING`

---

### `modules/severity_engine.py`

**What it does:**
Takes a classified attack and computes a numeric severity score (0–100), then maps it to a level: Low / Medium / High / Critical.

**Key code sections:**

#### Severity matrix — base scores per attack type
```python
SEVERITY_MATRIX = {
    "DDoS":        { "base_score": 90, "escalation_factor": 1.5 },
    "Infiltration":{ "base_score": 85, "escalation_factor": 1.4 },
    "DoS":         { "base_score": 80, "escalation_factor": 1.4 },
    "Web Attack":  { "base_score": 70, "escalation_factor": 1.2 },
    "Brute Force": { "base_score": 65, "escalation_factor": 1.3 },
    "Bot":         { "base_score": 55, "escalation_factor": 1.2 },
    "Port Scan":   { "base_score": 35, "escalation_factor": 1.1 },
    "Benign":      { "base_score":  0, "escalation_factor": 1.0 },
}
```

#### Score calculation
```python
def score(self, attack_type, features, confidence):
    score = base_score * confidence          # Scale by ML/rule confidence
    if features["pkt_count"] > 50000:        # Volumetric boost
        score *= escalation_factor
    if features["failed_logins"] > 20:       # Login attack boost
        score = min(score * 1.2, 100)
    # Map numeric → level
    if score >= 80: level = "Critical"
    elif score >= 60: level = "High"
    elif score >= 30: level = "Medium"
    else: level = "Low"
```

#### Noise filter
```python
def should_show(self, severity_level: str, filter_level: str) -> bool:
    order = ["Low", "Medium", "High", "Critical"]
    return order.index(severity_level) >= order.index(filter_level)
```

**Modules used:** None (pure Python logic)

---

### `modules/ml_predictor.py`

**What it does:**
Loads a trained **PyTorch Artificial Neural Network (ANN)** and uses it to classify network traffic rows. Trained on the **CICIDS2017 Tuesday dataset** (Benign vs Brute Force traffic).

**Model Architecture:**
```
Input Layer  → 128 neurons (ReLU) → Dropout 0.3
           → 64 neurons  (ReLU) → Dropout 0.2
           → 32 neurons  (ReLU)
           → Output: num_classes (softmax)
```

**Key code sections:**

#### PyTorch model definition
```python
self.model = nn.Sequential(
    nn.Linear(input_size, 128),
    nn.ReLU(),
    nn.Dropout(0.3),
    nn.Linear(128, 64),
    nn.ReLU(),
    nn.Dropout(0.2),
    nn.Linear(64, 32),
    nn.ReLU(),
    nn.Linear(32, num_classes)
)
```

#### Load saved model weights
```python
self.model.load_state_dict(
    torch.load("models/soc_pytorch_model.pt", map_location="cpu", weights_only=True)
)
self.model.eval()
```

#### Prediction
```python
def predict(self, row) -> dict:
    features  = [float(row.get(col, 0)) for col in self.feature_cols]
    X_scaled  = self.scaler.transform([features])
    tensor    = torch.FloatTensor(X_scaled)
    outputs   = self.model(tensor)
    probs     = torch.softmax(outputs, dim=1).numpy()[0]
    pred_idx  = int(np.argmax(probs))
    confidence= float(probs[pred_idx])
    return { "attack_type": self.classes[pred_idx], "confidence": confidence }
```

**Training dataset:** CICIDS2017 (Canadian Institute for Cybersecurity)
**Training environment:** Google Colab (GPU)

**Modules used:** `torch`, `torch.nn`, `numpy`, `joblib`

---

### `modules/gemini_integration.py`

**What it does:**
Calls **Google Gemini 1.5 Flash** to generate a plain-English incident summary with recommended actions. If the API key is not set, returns a static fallback summary.

**Key code sections:**

#### Model initialisation
```python
genai.configure(api_key=GEMINI_API_KEY)
self.model = genai.GenerativeModel("gemini-1.5-flash")
```

#### Prompt sent to Gemini
```python
prompt = f"""You are a senior SOC analyst assistant. Write a brief, professional incident summary.
- Attack Type: {incident['attack_type']}
- Severity: {incident['severity_level']} (Score: {incident['severity_score']}/100)
- Source IP: {incident['src_ip']}
- MITRE ATT&CK: {incident['mitre_id']} - {incident['mitre_name']}
- Confidence: {incident['confidence']:.0%}

Write: 1. A 2-sentence description 2. Top 3 immediate recommended actions"""
response = self.model.generate_content(prompt)
```

#### Fallback (no API key)
```python
def _fallback_summary(self, incident):
    return f"**{incident['severity_level']} Alert: {incident['attack_type']} Detected** ..."
```

**To enable:** Add `GEMINI_API_KEY=your_key_here` to `.env` file.

**Modules used:** `google-generativeai`

---

### `modules/playbook_engine.py`

**What it does:**
Returns a role-specific response playbook for each attack type. Analysts select their role (L1/L2/L3) and the playbook gives them the exact steps to follow.

**Analyst roles:**
| Role | Description |
|---|---|
| L1 | Junior Analyst — document, escalate |
| L2 | Senior Analyst — investigate, contain, remediate |
| L3 | Threat Hunter / IR — forensics, full incident response |

**Key code sections:**

#### Playbook lookup
```python
def get_playbook(self, attack_type: str, analyst_role: str) -> dict:
    attack_playbooks = PLAYBOOKS.get(attack_type, PLAYBOOKS["Benign"])
    return attack_playbooks.get(analyst_role, attack_playbooks["L1"])
```

#### Example — L1 Brute Force playbook
```python
"Brute Force": {
    "L1": {
        "title": "Brute Force Attack — L1 Response",
        "steps": [
            "Document the incident: source IP, target account, timestamp",
            "Check if any login attempts SUCCEEDED",
            "If Critical severity: Escalate to L2 immediately",
            ...
        ],
        "escalate_if": "Critical or High severity, or if any login succeeded",
        "tools": ["SIEM", "Firewall Console", "Ticketing System"],
    }
}
```

**Attack types covered:** Brute Force, Port Scan, DoS, DDoS, Web Attack, Bot, Infiltration, Benign

**Modules used:** None (pure Python data)

---

### `modules/auth.py`

**What it does:**
Handles user registration, login, and API key management. Stores user data in **MongoDB Atlas**. Passwords are hashed with bcrypt. API keys are 48-character random hex tokens prefixed with `soc-`.

**Key code sections:**

#### MongoDB connection
```python
MONGO_URI  = "mongodb+srv://..."
DB_NAME    = "Soc_Analizer"
COLLECTION = "Soc_Users"
client     = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
```

#### Register a new user
```python
def register_user(username, email, password):
    api_key = "soc-" + secrets.token_hex(24)          # Generate unique API key
    hashed  = bcrypt.hashpw(password[:72].encode(), bcrypt.gensalt())
    users.insert_one({
        "username": username, "email": email,
        "password": hashed, "api_key": api_key,
        "requests": 0
    })
    return True, api_key
```

#### Login
```python
def login_user(email, password):
    user = users.find_one({"email": email.lower()})
    if bcrypt.checkpw(password[:72].encode(), user["password"]):
        return True, "Login successful", user
```

#### Regenerate API key
```python
def regenerate_api_key(email):
    new_key = "soc-" + secrets.token_hex(24)
    users.update_one({"email": email}, {"$set": {"api_key": new_key}})
    return new_key
```

**Modules used:** `pymongo`, `bcrypt`, `secrets`, `datetime`

---

## 4. Models & Saved Files

All saved model files are in the `models/` folder:

| File | What it stores |
|---|---|
| `soc_pytorch_model.pt` | Trained PyTorch ANN weights |
| `pytorch_model_info.pkl` | Class names, input size, num_classes |
| `scaler.pkl` | sklearn StandardScaler fitted on training data |
| `feature_cols.pkl` | List of feature column names the model expects |
| `soc_model.pkl` | (Legacy) original sklearn model — superseded by PyTorch |
| `label_encoder.pkl` | (Legacy) sklearn LabelEncoder for class labels |

**How the model was trained (summary):**
- Dataset: CICIDS2017 Tuesday (CSV, ~400k rows)
- Training platform: Google Colab (GPU)
- Algorithm: 4-layer ANN with Dropout regularisation
- Input: 76 network flow features (packet counts, durations, flags, etc.)
- Output: Binary classification — Benign vs Brute Force
- Saved with `torch.save()` and `joblib.dump()`

---

## 5. Data Folder

| File | Description |
|---|---|
| `data/sample_logs.csv` | Sample network log data for demo/testing in the dashboard |
| `data/README.md` | Notes about the dataset format |

**Expected CSV columns:**
```
Destination Port, Total Fwd Packets, Total Backward Packets,
Flow Duration, Failed Logins, Unique Ports, Unique Src IPs,
Anomaly Score, Source IP, Destination IP, Protocol, Timestamp, Label
```

---

## 6. Python Modules (Dependencies)

All listed in `requirements.txt`:

| Module | Version | Used for |
|---|---|---|
| `streamlit` | ≥1.32.0 | Web dashboard UI |
| `pandas` | ≥2.2.1 | CSV loading and row processing |
| `numpy` | ≥1.26.4 | Array operations for ML |
| `scikit-learn` | ≥1.4.1 | StandardScaler (saved as scaler.pkl) |
| `plotly` | ≥5.20.0 | Interactive charts in dashboard |
| `python-dotenv` | ≥1.0.1 | Load `.env` file for API keys |
| `joblib` | ≥1.3.2 | Load/save sklearn objects (.pkl files) |
| `pymongo` | ≥4.6.0 | MongoDB Atlas database connection |
| `bcrypt` | ≥4.0.0 | Password hashing for user auth |
| `google-generativeai` | ≥0.5.2 | Gemini 1.5 Flash AI summaries |
| `torch` | (install separately) | PyTorch ANN model inference |
| `fastapi` | (install separately) | REST API server |
| `uvicorn` | (install separately) | ASGI server for FastAPI |

> **Note:** `torch`, `fastapi`, and `uvicorn` are not in `requirements.txt` to keep the Streamlit Cloud build lean. Install them separately for full functionality:
> ```bash
> pip install torch fastapi uvicorn
> ```

---

## 7. Deployment Files

### `Dockerfile`
Builds a Docker container for the Streamlit dashboard.

```dockerfile
FROM python:3.11-slim          # Lightweight Python 3.11
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
```

**Build and run:**
```bash
docker build -t soc-analyst .
docker run -p 8501:8501 soc-analyst
```

### `.azure/config`
Azure deployment configuration for hosting on Azure App Service or Azure Container Apps.

### `.streamlit/secrets.toml`
Streamlit Cloud secrets file — stores `GEMINI_API_KEY` for cloud deployment.
```toml
GEMINI_API_KEY = "your_gemini_api_key_here"
```

### `.dockerignore`
Excludes `.git/`, `__pycache__/`, `.env` from Docker build context.

### `.gitignore`
Excludes secrets, cache, and large files from git.

---

## 8. How the AI Pipeline Works (End-to-End)

```
Step 1 — Load CSV
    app.py calls load_sample_data() or reads uploaded file
    └── pandas reads CSV into DataFrame

Step 2 — Feature Extraction (per row)
    preprocessor.extract_features(row)
    └── returns dict: dst_port, pkt_count, failed_logins, src_ip, ...

Step 3 — Stage 1: ANN Model (primary, runs on EVERY row)
    ml_predictor.predict(row)
    ├── scales features with StandardScaler
    ├── runs through PyTorch 4-layer ANN
    ├── applies softmax → probability per class
    └── returns { attack_type, confidence }

    IF confidence > 0.7 → classification = ANN result  →  DONE
    ELSE                → ANN uncertain, continue to Stage 2

Step 4 — Stage 2: Pre-filter (only when ANN confidence < 0.7)
    PreFilter.detect(features)
    ├── SSH Brute Force:  port=22  + failed_logins > 5  → confidence 0.97
    ├── FTP Brute Force:  port=21  + failed_logins > 5  → confidence 0.95
    ├── Volumetric DDoS:  pkt>50k  + unique_src_ips>50  → confidence 0.98
    └── Aggressive Scan:  ports>50 + flow_duration<10s  → confidence 0.96

    Pre-filter CANNOT fire when ANN was already confident — no silent overrides.

    IF any rule fires → classification = Pre-filter result  →  DONE
    ELSE              → continue to Stage 3

Step 5 — Stage 3: Expert System (final fallback)
    expert_system.classify(features)
    └── evaluates 8 broader lambda rules
    └── picks highest-confidence matching rule (stage="Expert System")
    └── returns "Benign" if no rule matches

Step 6 — Severity Scoring
    severity_engine.score(attack_type, features, confidence)
    └── base_score × confidence + feature boosts
    └── maps to Low / Medium / High / Critical

Step 7 — Noise Filtering
    severity_engine.should_show(severity_level, filter_level)
    └── removes alerts below analyst's selected threshold

Step 8 — Display
    app.py renders:
    ├── KPI metrics (total, critical, high, noise filtered)
    ├── Bar chart — attack type distribution
    ├── Pie chart — severity distribution
    ├── Alert table sorted by severity
    │     (includes "Stage" column: ANN Model / Pre-filter / Expert System)
    └── Incident deep-dive:
        ├── Severity score + "Detected by: Stage X" label
        ├── MITRE ATT&CK details
        ├── Gemini AI summary (on button click)
        └── Role-based playbook (L1/L2/L3)
```

### Why this order? Trade-off analysis

| Stage | Role | Runs when | Why this position |
|---|---|---|---|
| ANN Model (1st) | Primary classifier | Every row | Most accurate; cross-validates everything; catches nuanced/novel patterns |
| Pre-filter (2nd) | Uncertainty resolver | ANN confidence < 0.7 only | Provides high-confidence answer for patterns ANN may underscore; cannot override a confident ANN |
| Expert System (3rd) | Final fallback | ANN + Pre-filter both uncertain | Handles attack types outside the ANN's training classes |

**Honest limitations that remain:**

- **Pre-filter false positives are still possible** — if a user mistyped SSH password 6 times AND the ANN happened to be under 70% confidence on that row, the pre-filter would label it Brute Force. However, this is far less likely than before (ANN must first fail to be confident).
- **ANN is only trained on Benign / Brute Force** — for DDoS, Port Scan, Web Attack, the ANN will often return low confidence, so pre-filter and expert system handle most of those.
- **Expert System covers only 8 attack types** — Heartbleed, DoS Hulk variants, Infiltration (if ANN misses) fall back to Benign unless the expert system rules match.
- **No feedback loop** — misclassifications are not fed back to retrain the ANN. A production system would log analyst corrections and periodically retrain.

---

## 9. API Reference

Start server: `uvicorn api_server:app --reload --port 8000`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/` | None | Health + version info |
| GET | `/api/health` | None | Returns `{ status: ok, ml_model: true/false }` |
| POST | `/api/detect` | X-API-Key header | Upload CSV → returns all row classifications |
| POST | `/api/detect/single` | X-API-Key header | Send JSON dict → returns single classification |

**Example — detect threats from CSV:**
```bash
curl -X POST http://localhost:8000/api/detect \
  -H "X-API-Key: soc-your_api_key_here" \
  -F "file=@network_logs.csv"
```

**Example response:**
```json
{
  "total_rows": 500,
  "threats_found": 23,
  "clean_rows": 477,
  "results": [
    {
      "src_ip": "45.33.32.156",
      "dst_ip": "192.168.1.10",
      "attack_type": "Brute Force",
      "severity": "Critical",
      "score": 95.0,
      "confidence": 0.9821,
      "mitre_id": "T1110",
      "mitre_name": "Brute Force",
      "source": "ML Model"
    }
  ]
}
```

---

## 10. Environment Variables (.env)

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_google_gemini_api_key_here
```

- **GEMINI_API_KEY** — Get from [Google AI Studio](https://aistudio.google.com/). If not set, the dashboard shows static fallback summaries instead of AI-generated ones.
- MongoDB URI is currently hard-coded in `modules/auth.py` — move to `.env` for production.

---

## 11. How to Run

### Local Development

```bash
# 1. Install dependencies
pip install -r requirements.txt
pip install torch fastapi uvicorn

# 2. Create .env file
echo "GEMINI_API_KEY=your_key" > .env

# 3. Run Streamlit dashboard
streamlit run app.py

# 4. (Optional) Run REST API in a separate terminal
uvicorn api_server:app --reload --port 8000
```

### Docker

```bash
docker build -t soc-analyst .
docker run -p 8501:8501 --env GEMINI_API_KEY=your_key soc-analyst
```

### Streamlit Cloud

1. Push code to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Add `GEMINI_API_KEY` in Secrets settings
4. Deploy — Streamlit auto-runs `app.py`

---

*Documentation generated for EC6301 Mini Project — AI-Powered SOC Incident Triage and Response Automation System*
