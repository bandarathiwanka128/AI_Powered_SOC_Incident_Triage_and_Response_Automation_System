"""
ML Predictor — Uses trained MLP model for network traffic classification
Trained on CICIDS2017 Tuesday dataset (Benign, Brute Force)
"""

import numpy as np
import os
import joblib

MODEL_PATH    = "models/soc_model.pkl"
SCALER_PATH   = "models/scaler.pkl"
ENCODER_PATH  = "models/label_encoder.pkl"
FEATURES_PATH = "models/feature_cols.pkl"


class MLPredictor:
    """Scikit-learn MLP classifier trained on CICIDS2017."""

    def __init__(self):
        self.enabled = False
        self._load_model()

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            return
        try:
            self.model        = joblib.load(MODEL_PATH)
            self.scaler       = joblib.load(SCALER_PATH)
            self.le           = joblib.load(ENCODER_PATH)
            self.feature_cols = joblib.load(FEATURES_PATH)
            self.enabled      = True
            print("ML model loaded successfully.")
        except Exception as e:
            print(f"ML model load failed: {e}")

    def predict(self, row) -> dict:
        """Predict attack class from a raw dataframe row."""
        if not self.enabled:
            return {"attack_type": None, "confidence": 0.0}

        try:
            # Skip ML if none of the expected columns exist in the row
            matching_cols = [c for c in self.feature_cols if c in row.index]
            if len(matching_cols) < 5:
                return {"attack_type": None, "confidence": 0.0}

            features = [float(row.get(col, 0)) for col in self.feature_cols]
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            probs = self.model.predict_proba(X_scaled)[0]
            pred_idx = int(np.argmax(probs))
            confidence = float(probs[pred_idx])
            label = self.le.inverse_transform([pred_idx])[0]
            return {"attack_type": label, "confidence": confidence}
        except Exception:
            return {"attack_type": None, "confidence": 0.0}
