# How to Complete the Project — Step-by-Step Guide
**EC6301 Mini Project | AI-Powered SOC Analyst Assistant**

---

## What You Still Need to Do

| Task | Status |
|---|---|
| Train ML model (ANN) on CICIDS2017 dataset | NOT DONE |
| Create Colab training notebook | NOT DONE |
| Integrate trained model into dashboard | NOT DONE |
| Set up Gemini API key | OPTIONAL |
| Run and test the dashboard | QUICK TEST |

---

---

# PART 1 — Quick Test (Run What's Already Built)

Do this first to make sure the existing dashboard works before adding anything new.

### Step 1 — Open a terminal in the project folder

1. Open **VS Code**
2. Press `Ctrl + `` ` (backtick) to open the terminal
3. Make sure you see `d:\Soc_Analize>` in the terminal

### Step 2 — Install dependencies

Type this and press Enter:
```
pip install -r requirements.txt
```
Wait for it to finish. You will see many packages being installed.

### Step 3 — Run the dashboard

Type this and press Enter:
```
streamlit run app.py
```

### Step 4 — View in browser

1. A browser window will open automatically
2. If not, look at the terminal — you will see a line like:
   `Local URL: http://localhost:8501`
3. Open that URL in your browser

### Step 5 — Test it

1. In the sidebar on the left, make sure **"Sample Dataset"** is selected
2. You should see the dashboard load with charts and alerts
3. Click any incident in the **"Incident Deep Dive"** section
4. Click **"Generate AI Summary"** (will show a fallback message — that is normal without Gemini API key)

**If the dashboard loads — the base project is working.**

---

---

# PART 2 — Train the ML Model in Google Colab

This is the main remaining task. You will train an ANN (neural network) and use it in the dashboard.

---

## Step 1 — Download the CICIDS2017 Dataset

1. Open your browser
2. Go to: `https://www.unb.ca/cic/datasets/ids-2017.html`
3. Scroll down to find the **"Download"** section
4. Download these CSV files (they are large — ~1GB total):
   - `Monday-WorkingHours.pcap_ISCX.csv`
   - `Tuesday-WorkingHours.pcap_ISCX.csv`
   - `Wednesday-workingHours.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

> **Note:** If download is too slow, you can use just the Tuesday file (has Brute Force attacks) and Friday file (has DDoS attacks). That is enough for a good demo.

---

## Step 2 — Upload Dataset to Google Drive

1. Open your browser and go to: `https://drive.google.com`
2. Sign in with your Google account
3. Click **"+ New"** button (top left)
4. Click **"New folder"**
5. Name it: `CICIDS2017`
6. Double-click to open that folder
7. Click **"+ New"** again → **"File upload"**
8. Select the CSV files you downloaded in Step 1
9. Wait for all files to finish uploading (may take 10-20 minutes for large files)

---

## Step 3 — Open Google Colab

1. Go to: `https://colab.research.google.com`
2. Click **"New notebook"** button
3. At the top, change the notebook name from "Untitled" to: `SOC_Model_Training`

---

## Step 4 — Enable GPU in Colab (Important for faster training)

1. In Colab, click **"Runtime"** menu at the top
2. Click **"Change runtime type"**
3. Under "Hardware accelerator", select **"T4 GPU"**
4. Click **"Save"**

---

## Step 5 — Write the Training Code

Copy and paste each code block below into a new Colab cell. Press the **Play button** (▶) on each cell to run it one by one.

---

### Cell 1 — Mount Google Drive
```python
from google.colab import drive
drive.mount('/content/drive')
```
> After running: A popup will ask for permission. Click **"Connect to Google Drive"** and allow access.

---

### Cell 2 — Install Libraries
```python
pip install scikit-learn pandas numpy joblib
```
> Wait for this to finish before moving to next cell.

---

### Cell 3 — Load and Combine Dataset
```python
import pandas as pd
import numpy as np
import os

# Path to your uploaded folder in Google Drive
DATA_PATH = '/content/drive/MyDrive/CICIDS2017/'

# Load all CSV files from the folder
all_files = [f for f in os.listdir(DATA_PATH) if f.endswith('.csv')]
print(f"Found {len(all_files)} files: {all_files}")

dfs = []
for file in all_files:
    path = os.path.join(DATA_PATH, file)
    df = pd.read_csv(path, encoding='latin-1', low_memory=False)
    dfs.append(df)
    print(f"Loaded {file}: {len(df)} rows")

df = pd.concat(dfs, ignore_index=True)
print(f"\nTotal rows: {len(df)}")
print(f"Columns: {list(df.columns)}")
```

---

### Cell 4 — Clean Column Names
```python
# CICIDS2017 has spaces in column names — strip them
df.columns = df.columns.str.strip()
print("Label column unique values:")
print(df['Label'].value_counts())
```

---

### Cell 5 — Preprocess Data
```python
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Drop rows with NaN or Infinity
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f"Rows after cleaning: {len(df)}")

# Select features (same columns used by our preprocessor.py)
FEATURE_COLS = [
    'Destination Port',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Duration',
    'Fwd Packet Length Max',
    'Bwd Packet Length Max',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd PSH Flags',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Packet Length Mean',
    'Packet Length Std',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'act_data_pkt_fwd',
    'min_seg_size_forward',
]

# Only keep columns that actually exist in the dataset
FEATURE_COLS = [c for c in FEATURE_COLS if c in df.columns]
print(f"Using {len(FEATURE_COLS)} features")

X = df[FEATURE_COLS].values

# Encode labels
label_map = {
    'BENIGN': 'Benign',
    'FTP-Patator': 'Brute Force',
    'SSH-Patator': 'Brute Force',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'Heartbleed': 'DoS',
    'Web Attack  Brute Force': 'Web Attack',
    'Web Attack  XSS': 'Web Attack',
    'Web Attack  Sql Injection': 'Web Attack',
    'Infiltration': 'Infiltration',
    'Bot': 'Bot',
    'DDoS': 'DDoS',
    'PortScan': 'Port Scan',
}

df['mapped_label'] = df['Label'].map(label_map).fillna('Benign')
print("\nMapped label distribution:")
print(df['mapped_label'].value_counts())

le = LabelEncoder()
y = le.fit_transform(df['mapped_label'])
print(f"\nClasses: {list(le.classes_)}")
```

---

### Cell 6 — Scale Features + Train/Test Split
```python
from sklearn.model_selection import train_test_split

# Normalize features to 0-1
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Split: 80% train, 20% test
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Train size: {len(X_train)}")
print(f"Test size:  {len(X_test)}")
```

---

### Cell 7 — Build and Train the ANN
```python
import tensorflow as tf
from tensorflow import keras

num_classes = len(le.classes_)
num_features = X_train.shape[1]

print(f"Input features: {num_features}")
print(f"Output classes: {num_classes}")

# Build ANN model
model = keras.Sequential([
    keras.layers.Dense(128, activation='relu', input_shape=(num_features,)),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(64, activation='relu'),
    keras.layers.Dropout(0.2),
    keras.layers.Dense(32, activation='relu'),
    keras.layers.Dense(num_classes, activation='softmax')
])

model.compile(
    optimizer='adam',
    loss='sparse_categorical_crossentropy',
    metrics=['accuracy']
)

model.summary()

# Train
history = model.fit(
    X_train, y_train,
    epochs=20,
    batch_size=256,
    validation_split=0.1,
    verbose=1
)
```
> Training will take **5-15 minutes** with GPU. You will see accuracy numbers printing after each epoch.

---

### Cell 8 — Evaluate the Model
```python
from sklearn.metrics import classification_report

# Evaluate on test set
test_loss, test_acc = model.evaluate(X_test, y_test, verbose=0)
print(f"\nTest Accuracy: {test_acc:.4f} ({test_acc*100:.1f}%)")

# Detailed report
y_pred = np.argmax(model.predict(X_test), axis=1)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))
```
> You should see accuracy above 90%. That is good for a university project.

---

### Cell 9 — Save the Model and Scaler
```python
import joblib

# Save the model
model.save('/content/drive/MyDrive/CICIDS2017/soc_ann_model.h5')

# Save the scaler and label encoder (needed to use model later)
joblib.dump(scaler, '/content/drive/MyDrive/CICIDS2017/scaler.pkl')
joblib.dump(le, '/content/drive/MyDrive/CICIDS2017/label_encoder.pkl')

# Save feature column names
joblib.dump(FEATURE_COLS, '/content/drive/MyDrive/CICIDS2017/feature_cols.pkl')

print("Model saved to Google Drive!")
print("Files saved:")
print("  - soc_ann_model.h5")
print("  - scaler.pkl")
print("  - label_encoder.pkl")
print("  - feature_cols.pkl")
```

---

## Step 6 — Download the Saved Files

1. Open Google Drive: `https://drive.google.com`
2. Navigate to your `CICIDS2017` folder
3. Download these 4 files (right-click → Download):
   - `soc_ann_model.h5`
   - `scaler.pkl`
   - `label_encoder.pkl`
   - `feature_cols.pkl`
4. Move all 4 files into your project's `models/` folder:
   ```
   d:\Soc_Analize\models\soc_ann_model.h5
   d:\Soc_Analize\models\scaler.pkl
   d:\Soc_Analize\models\label_encoder.pkl
   d:\Soc_Analize\models\feature_cols.pkl
   ```

---

---

# PART 3 — Integrate the Trained Model into the Dashboard

After placing the files in `models/`, add ML prediction to the project.

### Step 1 — Create the ML Predictor module

Create a new file: `d:\Soc_Analize\modules\ml_predictor.py`

Paste this code:

```python
"""
ML Predictor — Uses trained ANN model for network traffic classification
"""

import numpy as np
import os

MODEL_PATH = "models/soc_ann_model.h5"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/label_encoder.pkl"
FEATURES_PATH = "models/feature_cols.pkl"


class MLPredictor:
    """ANN-based traffic classifier trained on CICIDS2017."""

    def __init__(self):
        self.enabled = False
        self._load_model()

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            return
        try:
            import joblib
            import tensorflow as tf
            self.model = tf.keras.models.load_model(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.le = joblib.load(ENCODER_PATH)
            self.feature_cols = joblib.load(FEATURES_PATH)
            self.enabled = True
            print("ML model loaded successfully.")
        except Exception as e:
            print(f"ML model load failed: {e}")

    def predict(self, row) -> dict:
        """Predict attack class from a raw dataframe row."""
        if not self.enabled:
            return {"attack_type": None, "confidence": 0.0, "source": "ml"}

        try:
            features = []
            for col in self.feature_cols:
                features.append(float(row.get(col, 0)))

            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            probs = self.model.predict(X_scaled, verbose=0)[0]
            pred_idx = np.argmax(probs)
            confidence = float(probs[pred_idx])
            label = self.le.inverse_transform([pred_idx])[0]

            return {
                "attack_type": label,
                "confidence": confidence,
                "source": "ml",
            }
        except Exception as e:
            return {"attack_type": None, "confidence": 0.0, "source": "ml", "error": str(e)}
```

---

### Step 2 — Add ML Predictor to the dashboard

Open `app.py`. Find this line (around line 14):
```python
from modules.gemini_integration import GeminiAnalyst
```

Add one line below it:
```python
from modules.ml_predictor import MLPredictor
```

Then find this function (around line 44):
```python
def load_modules():
    return ExpertSystem(), SeverityEngine(), PlaybookEngine(), GeminiAnalyst()
```

Change it to:
```python
def load_modules():
    return ExpertSystem(), SeverityEngine(), PlaybookEngine(), GeminiAnalyst(), MLPredictor()
```

Then find line 47:
```python
expert_sys, severity_eng, playbook_eng, gemini = load_modules()
```

Change it to:
```python
expert_sys, severity_eng, playbook_eng, gemini, ml_predictor = load_modules()
```

Then find the `process_logs` function, inside the loop where `classification` is set (around line 104):
```python
classification = expert_sys.classify(features)
```

Replace it with:
```python
# Try ML model first, fall back to expert system
ml_result = ml_predictor.predict(row)
if ml_result["attack_type"] and ml_result["confidence"] > 0.7:
    from config import MITRE_MAPPING
    attack = ml_result["attack_type"]
    classification = {
        "attack_type": attack,
        "confidence": ml_result["confidence"],
        "rule_name": "ANN Model",
        "mitre": MITRE_MAPPING.get(attack, MITRE_MAPPING["Benign"]),
    }
else:
    classification = expert_sys.classify(features)
```

---

### Step 3 — Re-run the dashboard

Back in your terminal:
```
streamlit run app.py
```

If the model files are in `models/`, you will see `ML model loaded successfully.` in the terminal. The dashboard will now use the ANN model for predictions.

---

---

# PART 4 — Set Up Gemini API Key (Optional but Recommended)

This enables real AI-generated incident summaries instead of the default template.

### Step 1 — Get a Gemini API key

1. Go to: `https://aistudio.google.com`
2. Sign in with your Google account
3. Click **"Get API key"** button (top left area)
4. Click **"Create API key"**
5. Copy the key — it looks like: `AIzaSy...`

### Step 2 — Add the key to the project

1. In VS Code, in the Explorer panel on the left, click **"New File"**
2. Name it: `.env`
3. Type this inside (replace with your actual key):
   ```
   GEMINI_API_KEY=AIzaSyYOUR_ACTUAL_KEY_HERE
   ```
4. Save the file (`Ctrl + S`)

### Step 3 — Restart the dashboard

In your terminal, press `Ctrl + C` to stop, then run again:
```
streamlit run app.py
```

Now click **"Generate AI Summary"** on any incident — it will use real Gemini AI.

---

---

# PART 5 — Final Checklist Before Submission

Go through each item:

- [ ] `streamlit run app.py` runs without errors
- [ ] Dashboard loads with sample data in the browser
- [ ] Charts show (Attack Type Distribution, Severity Distribution)
- [ ] Alert table shows rows sorted by severity
- [ ] Incident Deep Dive section works — can select any incident
- [ ] Playbook section shows steps for selected role (L1/L2/L3)
- [ ] ML model files are in `models/` folder (if training is complete)
- [ ] Gemini AI summary works (if API key is set up)
- [ ] All 4 team member names are in `README.md` and `app.py`

---

# Quick Reference — Common Problems

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'google.generativeai'` | Run `pip install google-generativeai` |
| Dashboard shows "Load a dataset" and nothing happens | Check sidebar — make sure "Sample Dataset" is selected |
| Gemini shows "_(Gemini unavailable)_" | Add your API key to `.env` file |
| ML model not loading | Make sure all 4 files are in `models/` folder exactly as named |
| Colab training too slow | Make sure GPU is enabled: Runtime → Change runtime type → T4 GPU |
| CICIDS2017 download very slow | Use a VPN or try at a university network. Alternatively ask lecturer for dataset |
