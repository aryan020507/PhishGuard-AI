"""
API Endpoints Router for PhishGuard-AI.
Exposes /health, /predict/url, /predict/message, /models/metrics, and /history.
"""

import json
import time
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status

from backend.app.config import (
    APP_NAME,
    APP_VERSION,
    URL_METRICS_PATH,
    MESSAGE_METRICS_PATH
)
from backend.app.schemas import (
    URLScanRequest,
    URLScanResponse,
    MessageScanRequest,
    MessageScanResponse,
    HealthResponse,
    MetricsResponse,
    HistoryListResponse,
    HistoryItem
)
from backend.app.services.model_loader import ModelManager
from backend.app.services.url_pipeline import analyze_url
from backend.app.services.message_pipeline import analyze_message
from backend.app.services.history_service import get_recent_scans

router = APIRouter()


@router.api_route("/health", methods=["GET", "HEAD"], response_model=HealthResponse, tags=["System"])
async def get_health():
    """
    Health check endpoint: returns application uptime, loaded models status, and safety disclaimer.
    """
    mgr = ModelManager.get_instance()
    uptime = time.time() - mgr.start_time

    return HealthResponse(
        status="healthy",
        app_name=APP_NAME,
        version=APP_VERSION,
        models_loaded=mgr.loaded_status,
        uptime_seconds=round(uptime, 2),
        disclaimer="Predictions are automated risk assessments, not absolute guarantees. Never click or visit unverified links."
    )


@router.post(
    "/api/v1/predict/url",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Prediction"]
)
async def predict_url_threat(payload: URLScanRequest):
    """
    Analyze a URL for phishing and deceptive patterns using local static feature extraction + ANN.
    Zero external network queries are executed.
    """
    try:
        response = analyze_url(payload.url)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during URL threat analysis: {str(e)}"
        )


@router.post(
    "/api/v1/predict/message",
    response_model=MessageScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Prediction"]
)
async def predict_message_threat(payload: MessageScanRequest):
    """
    Analyze an SMS or textual message for social engineering, urgency manipulation, or phishing indicators using RNN.
    """
    try:
        response = analyze_message(payload.message)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during message threat analysis: {str(e)}"
        )


@router.get(
    "/api/v1/models/metrics",
    response_model=MetricsResponse,
    tags=["Models"]
)
async def get_model_metrics():
    """
    Serve verified test-set evaluation metrics directly from the training artifacts.
    Metrics are never fabricated.
    """
    url_metrics: Dict[str, Any] = {}
    message_metrics: Dict[str, Any] = {}

    if URL_METRICS_PATH.exists():
        try:
            with open(URL_METRICS_PATH, "r", encoding="utf-8") as f:
                url_metrics = json.load(f)
        except Exception as e:
            url_metrics = {"error": f"Failed to parse URL metrics: {str(e)}"}
    else:
        url_metrics = {"status": "Metrics artifact not found. Please run training pipeline."}

    if MESSAGE_METRICS_PATH.exists():
        try:
            with open(MESSAGE_METRICS_PATH, "r", encoding="utf-8") as f:
                message_metrics = json.load(f)
        except Exception as e:
            message_metrics = {"error": f"Failed to parse Message metrics: {str(e)}"}
    else:
        message_metrics = {"status": "Metrics artifact not found. Please run training pipeline."}

    return MetricsResponse(
        url_model=url_metrics,
        message_model=message_metrics
    )


@router.get(
    "/api/v1/history",
    response_model=HistoryListResponse,
    tags=["History"]
)
async def get_scan_history(limit: int = 50):
    """
    Retrieve past local scan records for review.
    """
    safe_limit = max(1, min(100, limit))
    records = get_recent_scans(limit=safe_limit)
    items = [HistoryItem(**r) for r in records]
    return HistoryListResponse(total_scans=len(items), scans=items)
