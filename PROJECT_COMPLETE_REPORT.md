# AI-Powered SOC Analyst Assistant — Complete Project Report
**EC6301 Mini Project | 2026**
**Team:** Herath H.M.T.B | Hettiarachchi H.A.K.G | Fernando N.D.H | [Member 4]
**Live URL:** https://aipoweredsocincidenttriageandresponseautomationsystem-9xqlpxz2.streamlit.app/
**GitHub:** https://github.com/bandarathiwanka128/AI_Powered_SOC_Incident_Triage_and_Response_Automation_System

---

## 1. PROJECT OVERVIEW

### What Problem Does This Solve?

Security Operations Centers (SOCs) receive thousands of network alerts every day.
Over 80% of these alerts are false positives — harmless events that look suspicious.

Junior analysts (L1) waste hours manually:
- Reading raw network log CSV files
- Deciding if traffic is an attack or not
- Looking up MITRE ATT&CK techniques manually
- Figuring out what to do next for each attack type

Our system automates this entire first layer of triage using AI and Machine Learning.

### What Our System Does

```
Raw Network Log CSV (uploaded by analyst)
              ↓
    Feature Extraction (preprocessor.py)
              ↓
    ┌──────────────────────────────────┐
    │  STAGE 1 — PyTorch ANN Model     │  ← 99.90% accuracy
    │  Runs on EVERY row (primary)     │     (ml_predictor.py)
    └──────────────┬───────────────────┘
                   │
          confidence ≥ 70%? ──YES──► classification = ANN result
                   │
                  NO
                   ↓
    ┌──────────────────────────────────┐
    │  STAGE 2 — Pre-filter            │  ← fast rule patterns
    │  Only when ANN is uncertain      │     (expert_system.py)
    │  SSH / FTP / DDoS / Port Scan    │
    └──────────────┬───────────────────┘
                   │
           rule fires? ──YES──► classification = Pre-filter result
                   │
                  NO
                   ↓
    ┌──────────────────────────────────┐
    │  STAGE 3 — Expert System         │  ← rule-based fallback
    │  Final fallback (8 rules)        │     (expert_system.py)
    └──────────────────────────────────┘
              ↓
    Severity Engine → Low / Medium / High / Critical
              ↓
    MITRE ATT&CK Mapping (7 attack techniques)
              ↓
    Role-Based Playbook (L1 / L2 / L3 analyst)
              ↓
    Gemini AI → Professional Incident Summary
              ↓
    Streamlit Dashboard → Visual Alerts + Charts
              (alert table shows which Stage detected each threat)
```

---

## 2. CYBERSECURITY PART — WHAT WAS IMPLEMENTED

### 2.1 Attack Types Detected (7 Types)

| Attack Type | MITRE ID | Tactic | Description |
|---|---|---|---|
| Brute Force | T1110 | Credential Access | Hundreds of login attempts to SSH/FTP ports |
| Port Scan | T1046 | Discovery | Probing network to find open ports |
| DoS | T1498 | Impact | Flooding server to make it unavailable |
| DDoS | T1498.001 | Impact | Multiple IPs flooding target simultaneously |
| Web Attack | T1190 | Initial Access | SQL injection, XSS, web brute force |
| Bot | T1071 | Command & Control | Infected machine communicating with C2 server |
| Infiltration | T1078 | Defense Evasion | Using valid credentials to hide in network |

### 2.2 MITRE ATT&CK Framework Integration

Every detected attack is mapped to the global MITRE ATT&CK framework.
This is the same framework used by:
- CrowdStrike
- Microsoft Defender
- IBM QRadar
- Splunk Enterprise Security

Example mapping in config.py:
```python
MITRE_MAPPING = {
    "Brute Force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Attacker attempts to gain access by systematically trying many passwords.",
    },
    "DDoS": {
        "id": "T1498.001",
        "name": "Direct Network Flood",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
    },
    ...
}
```

### 2.3 Severity Scoring Engine

Each alert gets a severity score from 0-100 based on:
- Attack type base score
- Anomaly score from network features
- Packet count
- Failed login count
- Number of unique source IPs

Severity levels:
```
Score 0-29   → Low      (green)
Score 30-59  → Medium   (yellow)
Score 60-79  → High     (orange)
Score 80-100 → Critical (red)
```

### 2.4 Noise Filtering

Real SOC problem: Too many low-priority alerts hiding real threats.
Our system lets analysts filter alerts by minimum severity level.

```
Filter set to "Medium" → only shows Medium, High, Critical
Filter set to "Low"    → shows everything
```

Result: Up to 100% noise filtering on clean datasets.

### 2.5 Role-Based Playbooks (L1 / L2 / L3)

Different analysts have different responsibilities:

| Role | Title | What They Do |
|---|---|---|
| L1 | Junior Analyst | First response, basic triage, escalate if needed |
| L2 | Senior Analyst | Deep investigation, containment |
| L3 | Threat Hunter / IR | Root cause analysis, forensics, remediation |

For each attack type + analyst role, the system shows:
- Step-by-step response actions
- When to escalate
- Which tools to use

### 2.6 Gemini AI Incident Summaries

After detecting an attack, clicking "Generate AI Summary" sends the incident data
to Google Gemini 1.5 Flash API which generates:
- A 2-sentence professional description of what happened
- Top 3 immediate recommended actions
- Written in SOC analyst language

---

## 3. MACHINE LEARNING — FULL JOURNEY

### 3.1 Dataset — CICIDS2017

**Full name:** Canadian Institute for Cybersecurity Intrusion Detection System 2017
**Made by:** University of New Brunswick, Canada
**Purpose:** Researchers set up a real network lab, ran real attacks for 5 days, recorded every packet

Files used in this project:
- Tuesday-WorkingHours.pcap_ISCX.csv (128.8 MB)
- Contains 445,909 real network flow records
- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (73.6 MB)
- Friday-WorkingHours-Morning.pcap_ISCX.csv (55.6 MB)

Each row = 1 network connection with 79 features including:
- Destination Port
- Flow Duration
- Total Forward/Backward Packets
- Flow Bytes/s
- SYN Flag Count
- Init_Win_bytes_forward
- ...and 73 more traffic statistics

Label distribution in Tuesday file:
```
BENIGN       → 432,074 rows  (normal traffic)
FTP-Patator  →   7,938 rows  (FTP brute force)
SSH-Patator  →   5,897 rows  (SSH brute force)
Total        → 445,909 rows
```

### 3.2 Feature Engineering

Selected 28 most important features from 79 available:
```python
FEATURE_COLS = [
    'Destination Port',       # Target port being attacked
    'Flow Duration',          # How long connection lasted
    'Total Fwd Packets',      # Packets sent to target
    'Total Backward Packets', # Packets received from target
    'Fwd Packet Length Max',  # Largest packet size sent
    'Bwd Packet Length Max',  # Largest packet size received
    'Flow Bytes/s',           # Data transfer speed
    'Flow Packets/s',         # Packet rate
    'Flow IAT Mean',          # Average time between packets
    'Fwd IAT Mean',           # Forward inter-arrival time
    'Bwd IAT Mean',           # Backward inter-arrival time
    'Fwd PSH Flags',          # Push flag count
    'Fwd Packets/s',          # Forward packet rate
    'Bwd Packets/s',          # Backward packet rate
    'Packet Length Mean',     # Average packet size
    'Packet Length Std',      # Packet size variation
    'FIN Flag Count',         # Connection termination flags
    'SYN Flag Count',         # Connection initiation flags
    'RST Flag Count',         # Connection reset flags
    'PSH Flag Count',         # Push data flags
    'ACK Flag Count',         # Acknowledgement flags
    'Average Packet Size',    # Mean packet size
    'Avg Fwd Segment Size',   # Forward segment size
    'Avg Bwd Segment Size',   # Backward segment size
    'Init_Win_bytes_forward', # Initial TCP window size (forward)
    'Init_Win_bytes_backward',# Initial TCP window size (backward)
    'act_data_pkt_fwd',       # Active data packets forward
    'min_seg_size_forward',   # Minimum segment size forward
]
```

Why brute force has a clear pattern:
```
Normal SSH:   port=22, packets=6,  duration=800,  SYN=1, failed_logins=0
Brute Force:  port=22, packets=67, duration=5200, SYN=50, failed_logins=24
```
The model learned this pattern from 13,835 real attack examples.

### 3.3 Model Evolution — Before vs After

#### PHASE 1 — Expert System Only (Original)
```python
# modules/expert_system.py
if features["failed_logins"] > 10:
    return "Brute Force"
elif features["unique_ports"] > 20:
    return "Port Scan"
elif features["pkt_count"] > 10000:
    return "DoS"
```
- Human-written rules
- No learning from data
- Easy to understand
- Fails on new attack patterns

#### PHASE 2 — Scikit-learn MLP Added
```python
# modules/ml_predictor.py (old version)
from sklearn.neural_network import MLPClassifier

model = MLPClassifier(hidden_layer_sizes=(100,100), max_iter=20)
model.fit(X_train, y_train)
# Test Accuracy: 99.88%
```
Training output:
```
Iteration 1, loss = 0.04538926
Iteration 2, loss = 0.01288640
...
Iteration 20, loss = 0.00401790
Test Accuracy: 99.88%
```
- Machine learning model
- Learned from 445,909 real examples
- Works on new data it has never seen
- Saves as soc_model.pkl (449 KB)

#### PHASE 3 — PyTorch ANN (Current — Best)
```python
# modules/ml_predictor.py (current version)
import torch
import torch.nn as nn

class SOCModel(nn.Module):
    def __init__(self, input_size, num_classes):
        super(SOCModel, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 128),  # Input layer: 28 → 128 neurons
            nn.ReLU(),                    # Activation function
            nn.Dropout(0.3),             # Prevent overfitting (30% dropout)
            nn.Linear(128, 64),          # Hidden layer: 128 → 64 neurons
            nn.ReLU(),
            nn.Dropout(0.2),             # Prevent overfitting (20% dropout)
            nn.Linear(64, 32),           # Hidden layer: 64 → 32 neurons
            nn.ReLU(),
            nn.Linear(32, num_classes)   # Output layer: 32 → 2 classes
        )
```

Training on GPU (CUDA):
```
Device: cuda  ← Google Colab T4 GPU
Epoch  1/20 — Loss: 0.0458
Epoch  2/20 — Loss: 0.0139
Epoch  3/20 — Loss: 0.0111
...
Epoch 20/20 — Loss: 0.0064

Test Accuracy: 99.90%

Classification Report:
              precision  recall  f1-score  support
      Benign       1.00    1.00      1.00    86363
 Brute Force       0.99    0.98      0.98     2766
    accuracy                         1.00    89129
```

**Comparison table:**

| | Expert System | Scikit-learn MLP | PyTorch ANN |
|---|---|---|---|
| Type | Rule-based | Machine Learning | Deep Learning |
| Accuracy | ~70% | 99.88% | **99.90%** |
| Learns from data | No | Yes | Yes |
| Industry standard | No | Partial | Yes |
| GPU support | No | No | Yes (CUDA) |
| Used by companies | No | Limited | Google, Meta, Tesla |
| File size | 0 KB (code) | 449 KB | 450 KB |
| Training time | 0 (manual) | 2 min | 2 min (GPU) |

### 3.4 How Prediction Works in the Dashboard

```python
# app.py — process_logs function (3-stage pipeline)
for _, row in df.iterrows():
    features = extract_features(row)         # Extract 28 features

    # ── Stage 1: ANN Model (runs on every row) ───────────────────────────
    ml_result = ml_predictor.predict(row)

    if ml_result["attack_type"] and ml_result["confidence"] > 0.7:
        # ANN is confident — use its result, skip stages 2 & 3
        classification = {
            "attack_type": ml_result["attack_type"],  # "Brute Force"
            "confidence":  ml_result["confidence"],   # 0.9821
            "rule_name":   "ANN Model (CICIDS2017)",
            "mitre":       MITRE_MAPPING[attack],
            "stage":       "ANN Model",
        }
    else:
        # ANN uncertain — try Stage 2 before falling back to rules
        # ── Stage 2: Pre-filter (only when ANN confidence < 70%) ─────────
        classification = pre_filter.detect(features)

        if classification is None:
            # ── Stage 3: Expert System (final fallback) ───────────────────
            classification = expert_sys.classify(features)
```

Why ANN runs first: if pre-filter ran first, a user mistyping their SSH
password 6 times would be permanently labeled "Brute Force" with no ANN
cross-check. ANN always gets the first say — pre-filter can only act when
ANN itself was not confident enough to decide.

PyTorch inference code (ml_predictor.py):
```python
def predict(self, row) -> dict:
    features = [float(row.get(col, 0)) for col in self.feature_cols]
    X        = np.array([features])
    X_scaled = self.scaler.transform(X)          # Normalize 0-1

    with self.torch.no_grad():                   # No gradient calculation needed
        tensor  = self.torch.FloatTensor(X_scaled)
        outputs = self.model(tensor)             # Forward pass
        probs   = self.torch.softmax(outputs, dim=1).numpy()[0]  # Probabilities

    pred_idx   = int(np.argmax(probs))           # Highest probability class
    confidence = float(probs[pred_idx])          # e.g. 0.9821
    label      = self.classes[pred_idx]          # e.g. "Brute Force"

    return {"attack_type": label, "confidence": confidence}
```

---

## 4. MLFLOW EXPERIMENT TRACKING

### Why MLflow?

Without MLflow:
```
Train model → see accuracy once → forget forever
Cannot prove model improved over time
Cannot compare different configurations
```

With MLflow:
```
Every training run is saved automatically
Can compare runs side by side
Can reproduce any past result
Professional ML engineering practice
```

### MLflow Integration in Colab

```python
import mlflow
import mlflow.sklearn

mlflow.set_experiment("SOC-Threat-Detection")

with mlflow.start_run(run_name="MLP-CICIDS2017"):

    # Log what settings were used
    mlflow.log_param("algorithm",    "MLPClassifier")
    mlflow.log_param("dataset",      "CICIDS2017-Tuesday")
    mlflow.log_param("features",     28)
    mlflow.log_param("train_size",   356516)
    mlflow.log_param("test_size",    89129)

    # Log the results
    mlflow.log_metric("accuracy",        0.9988)
    mlflow.log_metric("f1_brute_force",  0.9800)
    mlflow.log_metric("f1_benign",       0.9994)

    # Save the model itself
    mlflow.sklearn.log_model(model, "soc_mlp_model")
```

### Actual Tracked Results

```
============================================================
MLflow Experiment: SOC-Threat-Detection
============================================================
      Run Name  Accuracy  F1 Brute Force  F1 Benign    Algorithm          Dataset  Features
MLP-CICIDS2017  0.998811          0.9810     0.9994  MLPClassifier  CICIDS2017-Tuesday       28
```

---

## 5. DOCKER — CONTAINERIZATION

### Why Docker?

Without Docker — to run this project:
```
Step 1: Install Python 3.11 exactly
Step 2: pip install -r requirements.txt
Step 3: Create .env file
Step 4: Download model files
Step 5: Configure paths
Step 6: Debug 10 dependency errors
Total time: 2+ hours, fails on different OS
```

With Docker:
```
docker run thiwanka14535/soc-dashboard
Total time: 30 seconds, works on any machine
```

### Dockerfile

```dockerfile
# Use Python 3.11 slim — minimal OS, smaller image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first — Docker caching optimization
# If requirements don't change, Docker skips reinstalling (saves time)
COPY requirements.txt .

# Install all dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Streamlit uses port 8501
EXPOSE 8501

# Command to run when container starts
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
```

### .dockerignore

```
.env                    ← never include secrets in image
.git                    ← git history not needed
.azure                  ← Azure config not needed
__pycache__             ← compiled Python files not needed
.streamlit/secrets.toml ← secrets not needed
notebooks/              ← training notebooks not needed
```

### Build and Deploy Commands

```bash
# Build image locally
docker build -t soc-dashboard .

# Test locally
docker run -p 8501:8501 soc-dashboard

# Tag for Docker Hub
docker tag soc-dashboard thiwanka14535/soc-dashboard:latest

# Push to Docker Hub (public registry)
docker push thiwanka14535/soc-dashboard:latest
```

Docker Hub repository:
```
hub.docker.com/repository/docker/thiwanka14535/soc-dashboard
Repository size: 274.3 MB
```

### Azure Deployment with Docker

```bash
# Create web app using Docker image
az webapp create \
  --name soc-dashboard-thiwanka \
  --resource-group rg-soc-project \
  --plan plan-soc \
  --deployment-container-image-name thiwanka14535/soc-dashboard:latest

# Set environment variables
az webapp config appsettings set \
  --name soc-dashboard-thiwanka \
  --resource-group rg-soc-project \
  --settings "MONGO_URI=mongodb+srv://..." "WEBSITES_PORT=8501"

# Upgrade to B1 plan (no quota limits, ~$13/month)
az appservice plan update \
  --name plan-soc \
  --resource-group rg-soc-project \
  --sku B1
```

---

## 6. AUTHENTICATION SYSTEM

### Why Authentication?

Without auth: Anyone can access the dashboard
With auth:
- Users register → get unique API key
- Login required to use dashboard
- API keys can be regenerated
- MongoDB tracks usage per user

### MongoDB Atlas Setup

Database: Soc_Analizer
Collection: Soc_Users

Each user document:
```json
{
  "_id": "ObjectId(...)",
  "username": "Thiwanka",
  "email": "bandarathiwanka88@gmail.com",
  "password": "$2b$12$hashedpassword...",
  "api_key": "soc-abc123def456...",
  "requests": 0
}
```

### auth.py — Key Functions

```python
import bcrypt
from pymongo import MongoClient

def register_user(username, email, password):
    # Check if email already exists
    if users.find_one({"email": email}):
        return False, "Email already exists"

    # Hash password with bcrypt (industry standard)
    hashed  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Generate unique API key
    api_key = "soc-" + secrets.token_hex(16)

    # Save to MongoDB
    users.insert_one({
        "username": username,
        "email":    email,
        "password": hashed,
        "api_key":  api_key,
        "requests": 0
    })
    return True, api_key

def login_user(email, password):
    user = users.find_one({"email": email})
    if not user:
        return False, "User not found", None
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return False, "Wrong password", None
    return True, "Login successful", user
```

### Security Features

- Passwords hashed with bcrypt (never stored as plain text)
- API keys are random 32-character hex strings
- Session state managed by Streamlit
- MongoDB Atlas with IP whitelist
- Environment variables for all secrets (never hardcoded)

---

## 7. TECH STACK — COMPLETE

| Technology | Version | Purpose | Why This? |
|---|---|---|---|
| Python | 3.14 | Core language | Dominant in ML/AI |
| Streamlit | 1.32+ | Web dashboard | Fastest for data apps, no HTML needed |
| PyTorch | Latest | ML model (ANN) | Industry standard deep learning |
| Scikit-learn | 1.4+ | Data preprocessing, scaler | Best tools for feature engineering |
| Pandas | 2.2+ | Data manipulation | Standard for CSV/dataframe work |
| NumPy | 1.26+ | Numerical computing | Foundation for all ML |
| Plotly | 5.20+ | Interactive charts | Better than matplotlib for web |
| MongoDB Atlas | Cloud | User database | NoSQL, free cloud tier, JSON native |
| PyMongo | 4.6+ | MongoDB driver | Official Python connector |
| bcrypt | 4.0+ | Password hashing | Industry security standard |
| Google Gemini | 1.5 Flash | AI summaries | Best free LLM API available |
| MLflow | Latest | Experiment tracking | Industry ML ops standard |
| Docker | Latest | Containerization | Deploy anywhere identically |
| Git + GitHub | Latest | Version control | Code history + collaboration |
| Google Colab | Cloud | Model training | Free GPU (T4 CUDA) |
| CICIDS2017 | 2017 | Training dataset | Industry benchmark dataset |
| MITRE ATT&CK | v14 | Threat framework | Global SOC standard |
| python-dotenv | 1.0+ | Secret management | Keep credentials out of code |
| joblib | 1.3+ | Model serialization | Save/load scaler and encoder |

---

## 8. PROJECT STRUCTURE

```
d:\Soc_Analize\
├── app.py                          ← Main Streamlit dashboard (604 lines)
├── api_server.py                   ← FastAPI REST API server
├── config.py                       ← MITRE mappings, severity thresholds
├── requirements.txt                ← Python dependencies
├── Dockerfile                      ← Docker container definition
├── .dockerignore                   ← Files excluded from Docker image
├── .gitignore                      ← Files excluded from GitHub
├── HOW_TO_COMPLETE.md              ← Project completion guide
├── PROJECT_COMPLETE_REPORT.md      ← This document
│
├── modules/
│   ├── preprocessor.py             ← CSV loading, feature extraction
│   ├── expert_system.py            ← PreFilter (Stage 2) + ExpertSystem (Stage 3)
│   ├── severity_engine.py          ← Severity scoring (0-100)
│   ├── playbook_engine.py          ← L1/L2/L3 response playbooks
│   ├── gemini_integration.py       ← Google Gemini AI summaries
│   ├── ml_predictor.py             ← PyTorch ANN inference
│   └── auth.py                     ← MongoDB register/login/API keys
│
├── models/
│   ├── soc_pytorch_model.pt        ← Trained PyTorch model weights
│   ├── pytorch_model_info.pkl      ← Model architecture metadata
│   ├── soc_model.pkl               ← Trained scikit-learn model (backup)
│   ├── scaler.pkl                  ← MinMaxScaler (normalize features)
│   ├── label_encoder.pkl           ← LabelEncoder (class names)
│   └── feature_cols.pkl            ← List of 28 feature column names
│
├── data/
│   └── sample_logs.csv             ← 50-row demo dataset
│
└── .streamlit/
    └── secrets.toml                ← API keys (not in GitHub)
```

---

## 9. DEPLOYMENT

### Primary — Streamlit Community Cloud (Live)

URL: https://aipoweredsocincidenttriageandresponseautomationsystem-9xqlpxz2.streamlit.app/
Cost: Free forever
Auto-redeploy: Yes (on every git push to main)
Secrets stored in: Streamlit Cloud secrets manager

### Secondary — Docker Hub (Image Registry)

URL: hub.docker.com/r/thiwanka14535/soc-dashboard
Image size: 274.3 MB
Last pushed: 2026-04-12

### Azure App Service (Configured)

URL: https://soc-dashboard-thiwanka.azurewebsites.net
Plan: B1 (upgraded from F1)
Region: Southeast Asia
Docker image: thiwanka14535/soc-dashboard:latest

---

## 10. HOW THE FULL PIPELINE RUNS — STEP BY STEP

User opens: https://aipoweredsocincidenttriageandresponseautomationsystem-9xqlpxz2.streamlit.app/

```
Step 1: Login page shown
        User enters email + password
        bcrypt.checkpw() verifies password against MongoDB hash
        Session state set: logged_in = True

Step 2: Dashboard loads
        PyTorch model loaded from models/soc_pytorch_model.pt
        PreFilter + ExpertSystem rules loaded from modules/expert_system.py
        Gemini API key loaded from Streamlit secrets

Step 3: User selects "Sample Dataset" or uploads CSV
        pandas.read_csv() loads the file
        50 rows (sample) or up to 445,909 rows (CICIDS2017)

Step 4: process_logs() runs for each row — 3-stage pipeline:
        a) extract_features(row) → extracts 28 network features

        b) STAGE 1 — ml_predictor.predict(row):
           - Normalize features with StandardScaler
           - Forward pass through PyTorch ANN (4-layer, 128→64→32→classes)
           - softmax() → probabilities for each class
           - Returns: {"attack_type": "Brute Force", "confidence": 0.9821}
           - confidence ≥ 0.7? → use ANN result, skip stages 2 & 3

        c) STAGE 2 — pre_filter.detect(features):  [only if ANN < 70%]
           - Checks 4 fast rules: SSH/FTP brute force, volumetric DDoS,
             aggressive port scan
           - Rule fires? → use Pre-filter result, skip stage 3
           - Cannot override a confident ANN result

        d) STAGE 3 — expert_sys.classify(features):  [only if stages 1+2 both uncertain]
           - Evaluates 8 broader lambda condition rules
           - Returns best match or "Benign" if nothing matches

        e) severity_eng.score() → calculates 0-100 severity score
        f) Filter by user's selected severity level
        g) Append to results list  (includes "Stage" field for each alert)

Step 5: Dashboard renders:
        - 5 KPI metric cards (total, alerts, critical, high, noise%)
        - Bar chart: Attack Type Distribution
        - Pie chart: Severity Distribution
        - Sortable alert table (sorted by severity, includes Stage column)

Step 6: User clicks incident → Deep Dive:
        - Source IP, Destination IP, Port
        - Confidence score + "Detected by: Stage X" label
        - MITRE ATT&CK technique details + link
        - "Generate AI Summary" → Gemini API call → professional report
        - Role-based playbook (L1/L2/L3 response steps)
```

---

## 11. ACTUAL PERFORMANCE DATA

### ML Model Training Results

Dataset: CICIDS2017 Tuesday (real network traffic)
Training rows: 356,516
Test rows: 89,129
Training device: Google Colab T4 GPU (CUDA)

Scikit-learn MLP:
```
Test Accuracy: 99.88%
Benign    — precision: 1.00, recall: 1.00, f1: 1.00
BruteForce— precision: 0.99, recall: 0.98, f1: 0.98
Training time: ~2 minutes
```

PyTorch ANN (final model):
```
Test Accuracy: 99.90%  ← IMPROVEMENT
Benign    — precision: 1.00, recall: 1.00, f1: 1.00
BruteForce— precision: 0.99, recall: 0.98, f1: 0.98
Training time: ~2 minutes (GPU)
Epochs: 20
Final loss: 0.0064
```

MLflow Tracked Run:
```
Run Name:       MLP-CICIDS2017
Accuracy:       0.998811
F1 Brute Force: 0.9810
F1 Benign:      0.9994
Algorithm:      MLPClassifier
Dataset:        CICIDS2017-Tuesday
Features:       28
```

---

## 12. API INTEGRATION (FOR EXTERNAL APPS)

The system includes a REST API (api_server.py) so any application can
use the SOC detection engine.

### Endpoints

```
GET  /api/health          → Check if API is running
POST /api/detect          → Upload CSV → get all threats
POST /api/detect/single   → Send JSON row → get one prediction
```

### Example — Python Integration

```python
import os, requests
from dotenv import load_dotenv

load_dotenv()

API_KEY  = os.getenv("SOC_API_KEY")   # from .env file
ENDPOINT = os.getenv("SOC_ENDPOINT")  # from .env file

with open("network_logs.csv", "rb") as f:
    response = requests.post(
        ENDPOINT,
        files={"file": f},
        headers={"X-API-Key": API_KEY}
    )

result = response.json()
print(f"Threats found: {result['threats_found']}")
for r in result["results"]:
    if r["attack_type"] != "Benign":
        print(f"[{r['severity']}] {r['attack_type']} — {r['src_ip']}")
```

### Example JSON Response

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
      "score": 95,
      "confidence": 0.9821,
      "mitre_id": "T1110",
      "mitre_name": "Brute Force"
    }
  ]
}
```

### CMD Usage (Windows)

```cmd
python detect.py
```

Output:
```
Total rows:    500
Threats found: 23
[CRITICAL] Brute Force — 45.33.32.156 → 192.168.1.10
[HIGH]     Port Scan   — 91.241.19.100 → 192.168.1.100
[MEDIUM]   Bot         — 185.56.80.65 → 192.168.1.30
```

---

## 13. SUMMARY — EVERYTHING BUILT

| Feature | Technology | Status |
|---|---|---|
| Web Dashboard | Streamlit | ✅ Live |
| PyTorch ANN (99.90%) — Stage 1 | PyTorch + CUDA | ✅ Done |
| Pre-filter (uncertainty resolver) — Stage 2 | Python rules | ✅ Done |
| Expert System fallback — Stage 3 | Python rules | ✅ Done |
| MLflow experiment tracking | MLflow | ✅ Done |
| Docker containerization | Docker | ✅ Done |
| Docker Hub registry | Docker Hub | ✅ Pushed |
| Azure deployment | Azure App Service B1 | ✅ Configured |
| Streamlit Cloud deployment | Streamlit Community | ✅ Live |
| MongoDB authentication | MongoDB Atlas | ✅ Working |
| bcrypt password security | bcrypt | ✅ Done |
| API key system | Python secrets | ✅ Done |
| MITRE ATT&CK mapping | 7 techniques | ✅ Done |
| Severity scoring | Custom engine | ✅ Done |
| Noise filtering | Streamlit slider | ✅ Done |
| Role-based playbooks | L1/L2/L3 | ✅ Done |
| Gemini AI summaries | Gemini 1.5 Flash | ✅ Done |
| REST API | FastAPI | ✅ Done |
| GitHub version control | Git | ✅ Pushed |
| CICIDS2017 training data | Real network attacks | ✅ Used |

---

*EC6301 Mini Project | AI-Powered SOC Analyst Assistant | 2026*
*Team: Herath H.M.T.B | Hettiarachchi H.A.K.G | Fernando N.D.H | [Member 4]*
