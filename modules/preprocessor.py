"""
Data Preprocessor
Handles loading and normalizing network log data for analysis
"""

import pandas as pd
import numpy as np


def load_sample_data(filepath: str = "data/sample_logs.csv") -> pd.DataFrame:
    """Load sample or uploaded CSV log data."""
    df = pd.read_csv(filepath)
    return df


def extract_features(row: pd.Series) -> dict:
    """
    Extract feature dictionary from a dataframe row.
    Maps CSV columns to features expected by expert system.
    """
    return {
        "dst_port": int(row.get("Destination Port", 0)),
        "protocol": str(row.get("Protocol", "TCP")),
        "pkt_count": float(row.get("Total Fwd Packets", 0)) + float(row.get("Total Backward Packets", 0)),
        "flow_duration": float(row.get("Flow Duration", 0)),
        "failed_logins": float(row.get("Failed Logins", 0)),
        "unique_ports": float(row.get("Unique Ports", 0)),
        "unique_src_ips": float(row.get("Unique Src IPs", 1)),
        "anomaly_score": float(row.get("Anomaly Score", 0.0)),
        "src_ip": str(row.get("Source IP", "0.0.0.0")),
        "dst_ip": str(row.get("Destination IP", "0.0.0.0")),
        "label": str(row.get("Label", "Benign")),
    }


def preprocess_for_model(df: pd.DataFrame) -> pd.DataFrame:
    """
    Basic preprocessing for ML model input.
    (Full preprocessing / training is done in Google Colab)
    """
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    df[numeric_cols] = (df[numeric_cols] - df[numeric_cols].min()) / (
        df[numeric_cols].max() - df[numeric_cols].min() + 1e-9
    )
    return df
