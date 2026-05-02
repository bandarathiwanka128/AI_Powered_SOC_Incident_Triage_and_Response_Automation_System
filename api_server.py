"""
SOC Analyst Assistant — REST API Server
Run with: uvicorn api_server:app --reload --port 8000
"""

from fastapi import FastAPI, UploadFile, File, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import io

from modules.auth import get_user_by_api_key, increment_request_count
from modules.ml_predictor import MLPredictor
from modules.expert_system import ExpertSystem, PreFilter
from modules.severity_engine import SeverityEngine
from modules.preprocessor import extract_features
from config import MITRE_MAPPING

app = FastAPI(
    title="SOC Analyst Assistant API",
    description="AI-powered threat detection API. Send network logs, get attack classifications.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ml         = MLPredictor()
expert     = ExpertSystem()
severity   = SeverityEngine()
pre_filter = PreFilter()


def verify_key(api_key: str):
    user = get_user_by_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user


@app.get("/")
def root():
    return {"message": "SOC Analyst Assistant API", "status": "running", "version": "1.0.0"}


@app.get("/api/health")
def health():
    return {"status": "ok", "ml_model": ml.enabled}


@app.post("/api/detect")
async def detect(
    file: UploadFile = File(...),
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """
    Upload a CSV file of network logs and get threat classifications back.
    Requires X-API-Key header.
    """
    user = verify_key(x_api_key)

    content = await file.read()
    try:
        df = pd.read_csv(io.StringIO(content.decode("latin-1")), low_memory=False)
        df.columns = df.columns.str.strip()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid CSV file")

    results = []
    for _, row in df.iterrows():
        features = extract_features(row)

        # Stage 1: ANN Model (primary — runs on every row)
        ml_result = ml.predict(row)
        if ml_result["attack_type"] and ml_result["confidence"] > 0.7:
            attack = ml_result["attack_type"]
            classification = {
                "attack_type": attack,
                "confidence":  ml_result["confidence"],
                "stage":       "ANN Model",
                "mitre":       MITRE_MAPPING.get(attack, MITRE_MAPPING["Benign"]),
            }
        else:
            # Stage 2: Pre-filter (only when ANN is uncertain — cannot override ANN)
            classification = pre_filter.detect(features)

            if classification is None:
                # Stage 3: Expert System (final fallback)
                classification = expert.classify(features)

        sev = severity.score(
            classification["attack_type"], features, classification["confidence"]
        )

        results.append({
            "timestamp":    row.get("Timestamp", "N/A"),
            "src_ip":       features["src_ip"],
            "dst_ip":       features["dst_ip"],
            "dst_port":     features["dst_port"],
            "attack_type":  classification["attack_type"],
            "severity":     sev["level"],
            "score":        sev["score"],
            "confidence":   round(classification["confidence"], 4),
            "mitre_id":     classification["mitre"]["id"],
            "mitre_name":   classification["mitre"]["name"],
            "stage":        classification.get("stage", "Expert System"),
        })

    increment_request_count(x_api_key)

    threats = [r for r in results if r["attack_type"] != "Benign"]
    return {
        "total_rows":    len(results),
        "threats_found": len(threats),
        "clean_rows":    len(results) - len(threats),
        "results":       results,
    }


@app.post("/api/detect/single")
async def detect_single(
    data: dict,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """Send a single row as JSON and get classification back."""
    verify_key(x_api_key)

    row = pd.Series(data)
    features = extract_features(row)

    # Stage 1: ANN Model (primary — runs on every row)
    ml_result = ml.predict(row)
    if ml_result["attack_type"] and ml_result["confidence"] > 0.7:
        attack = ml_result["attack_type"]
        classification = {
            "attack_type": attack,
            "confidence":  ml_result["confidence"],
            "stage":       "ANN Model",
            "mitre":       MITRE_MAPPING.get(attack, MITRE_MAPPING["Benign"]),
        }
    else:
        # Stage 2: Pre-filter (only when ANN is uncertain — cannot override ANN)
        classification = pre_filter.detect(features)

        if classification is None:
            # Stage 3: Expert System (final fallback)
            classification = expert.classify(features)

    sev = severity.score(
        classification["attack_type"], features, classification["confidence"]
    )

    increment_request_count(x_api_key)

    return {
        "attack_type": classification["attack_type"],
        "severity":    sev["level"],
        "score":       sev["score"],
        "confidence":  round(classification["confidence"], 4),
        "mitre_id":    classification["mitre"]["id"],
        "mitre_name":  classification["mitre"]["name"],
        "stage":       classification.get("stage", "Expert System"),
    }
