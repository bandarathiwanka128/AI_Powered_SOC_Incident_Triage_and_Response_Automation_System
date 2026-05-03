"""
ML Predictor — Uses trained PyTorch ANN for network traffic classification
Trained on CICIDS2017 Tuesday dataset (Benign, Brute Force)
"""

import numpy as np
import os
import joblib
from collections import OrderedDict

MODEL_PATH    = "models/soc_pytorch_model.pt"
INFO_PATH     = "models/pytorch_model_info.pkl"
SCALER_PATH   = "models/scaler.pkl"
FEATURES_PATH = "models/feature_cols.pkl"


class SOCModel:
    """PyTorch ANN model wrapper."""
    def __init__(self, input_size, num_classes):
        import torch.nn as nn
        import torch
        self.network = nn.Sequential(
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

    def __call__(self, x):
        return self.network(x)

    def eval(self):
        self.network.eval()

    def load_state_dict(self, state_dict):
        self.network.load_state_dict(state_dict)


class MLPredictor:
    """PyTorch ANN classifier trained on CICIDS2017."""

    def __init__(self):
        self.enabled = False
        self._load_model()

    def _load_state_dict(self, torch):
        checkpoint = torch.load(
            MODEL_PATH,
            map_location=torch.device("cpu"),
            weights_only=True,
        )

        if isinstance(checkpoint, dict):
            for key in ("state_dict", "model_state_dict", "model"):
                if key in checkpoint and isinstance(checkpoint[key], dict):
                    checkpoint = checkpoint[key]
                    break

        if not isinstance(checkpoint, dict):
            raise TypeError("Unsupported PyTorch checkpoint format")

        state_dict = OrderedDict()
        for key, value in checkpoint.items():
            clean_key = key
            for prefix in ("module.", "model.", "network."):
                if clean_key.startswith(prefix):
                    clean_key = clean_key[len(prefix):]
            state_dict[clean_key] = value

        return state_dict

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            print("PyTorch model not found — falling back to expert system.")
            return
        try:
            import torch
            info              = joblib.load(INFO_PATH)
            self.classes      = info["classes"]
            self.num_classes  = info["num_classes"]
            self.input_size   = info["input_size"]
            self.scaler       = joblib.load(SCALER_PATH)
            self.feature_cols = joblib.load(FEATURES_PATH)

            # Build model and load weights
            import torch.nn as nn
            self.model = nn.Sequential(
                nn.Linear(self.input_size, 128),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, self.num_classes)
            )
            self.model.load_state_dict(self._load_state_dict(torch))
            self.model.eval()
            self.torch   = torch
            self.enabled = True
            print("PyTorch ML model loaded successfully.")
        except Exception as e:
            print(f"PyTorch model load failed: {e}")

    def predict(self, row) -> dict:
        """Predict attack class from a raw dataframe row."""
        if not self.enabled:
            return {"attack_type": None, "confidence": 0.0}

        try:
            # Skip if columns don't match
            matching = [c for c in self.feature_cols if c in row.index]
            if len(matching) < 5:
                return {"attack_type": None, "confidence": 0.0}

            features = [float(row.get(col, 0)) for col in self.feature_cols]
            X        = np.array([features])
            X_scaled = self.scaler.transform(X)

            with self.torch.no_grad():
                tensor  = self.torch.FloatTensor(X_scaled)
                outputs = self.model(tensor)
                probs   = self.torch.softmax(outputs, dim=1).numpy()[0]

            pred_idx   = int(np.argmax(probs))
            confidence = float(probs[pred_idx])
            label      = self.classes[pred_idx]

            return {"attack_type": label, "confidence": confidence}
        except Exception as e:
            return {"attack_type": None, "confidence": 0.0}
