"""
URL Threat Analysis Pipeline Service for PhishGuard-AI.
Extracts 16 static features locally, runs ANN inference, generates heuristic explanations,
and packages a full RiskAssessment.
"""

import datetime
from typing import Dict, Any

from backend.app.schemas import URLScanResponse, RiskAssessment
from backend.app.services.model_loader import ModelManager
from backend.app.services.risk_engine import evaluate_risk
from backend.app.services.explanation_engine import explain_url_threats
from backend.app.services.history_service import log_scan
from backend.app.services.trusted_domains import is_authentic_trusted_url
try:
    from training.features.url_features import extract_url_features, url_to_feature_vector
except ImportError:
    from backend.app.features.url_features import extract_url_features, url_to_feature_vector


def analyze_url(url: str) -> URLScanResponse:
    """
    Completely local, static threat analysis for user-provided URLs.
    CRITICAL RULE: Never visits, makes HTTP requests, or resolves DNS for the URL.
    """
    model_mgr = ModelManager.get_instance()
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Local static feature extraction
    features_dict = extract_url_features(url)
    features_vec = url_to_feature_vector(url)

    # 2. Heuristic explanation indicators (distinct from model prediction)
    indicators = explain_url_threats(url, features_dict)

    # 3. Model Inference or Fallback
    if model_mgr.is_url_ready:
        prob = model_mgr.predict_url(features_vec)
        model_loaded = True
        model_name = "Artificial Neural Network (Dense-Dropout-Sigmoid)"
    else:
        # Fallback: Count risk indicators to provide heuristic risk estimate
        danger_count = sum(1 for ind in indicators if ind.severity == "danger")
        warning_count = sum(1 for ind in indicators if ind.severity == "warning")
        if danger_count > 0:
            prob = 0.75
        elif warning_count >= 2:
            prob = 0.50
        elif warning_count == 1:
            prob = 0.35
        else:
            prob = 0.10
        model_loaded = False
        model_name = "Heuristic-Only Fallback (Model Not Loaded)"

    # 4. Verified Authority Safeguard
    # If the domain is an authentic trusted authority (e.g. YouTube, Google, GitHub)
    # and has no deceptive danger markers, prevent false positives.
    if is_authentic_trusted_url(url, features_dict):
        danger_count = sum(1 for ind in indicators if ind.severity == "danger")
        if danger_count == 0:
            prob = min(prob, 0.05)

    # 5. Risk Engine Assessment
    risk = evaluate_risk(prob)

    # 5. Persist to History Database
    scan_id = log_scan(
        scan_type="URL",
        input_text=url,
        probability=risk.probability,
        risk_level=risk.risk_level,
        confidence=risk.confidence_percentage
    )

    return URLScanResponse(
        id=scan_id if scan_id > 0 else None,
        input_url=url,
        features=features_dict,
        risk=risk,
        indicators=indicators,
        model_loaded=model_loaded,
        model_used=model_name,
        timestamp=timestamp_str
    )
