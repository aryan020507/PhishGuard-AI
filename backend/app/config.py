"""
Configuration settings and constants for PhishGuard-AI.
"""

import os
from pathlib import Path

# Base Paths
APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

# Models directory with serverless fallback detection
MODELS_DIR = PROJECT_ROOT / "models"
if not (MODELS_DIR / "url_weights.npz").exists():
    for candidate in [
        Path.cwd() / "models",
        APP_DIR.parent.parent / "models",
        Path("/var/task/models")
    ]:
        if (candidate / "url_weights.npz").exists():
            MODELS_DIR = candidate
            break

# Frontend directory with serverless fallback detection
FRONTEND_DIR = PROJECT_ROOT / "public"
if not FRONTEND_DIR.exists():
    FRONTEND_DIR = PROJECT_ROOT / "frontend"
if not FRONTEND_DIR.exists():
    for candidate in [
        Path.cwd() / "public",
        Path.cwd() / "frontend",
        Path("/var/task/public"),
        Path("/var/task/frontend")
    ]:
        if candidate.exists():
            FRONTEND_DIR = candidate
            break

DATA_DIR = PROJECT_ROOT / "training" / "datasets"

# Artifact file paths
URL_MODEL_PATH = MODELS_DIR / "url_ann_model.keras"
URL_SCALER_PATH = MODELS_DIR / "url_scaler.joblib"
URL_METRICS_PATH = MODELS_DIR / "url_metrics.json"

MESSAGE_MODEL_PATH = MODELS_DIR / "message_rnn_model.keras"
MESSAGE_TOKENIZER_PATH = MODELS_DIR / "message_tokenizer.pkl"
MESSAGE_METRICS_PATH = MODELS_DIR / "message_metrics.json"

# SQLite Database (must use /tmp on serverless read-only filesystems)
if (
    os.environ.get("VERCEL")
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    or not os.access(str(PROJECT_ROOT), os.W_OK)
):
    SQLITE_DB_PATH = Path("/tmp/scans_history.db")
else:
    SQLITE_DB_PATH = PROJECT_ROOT / "scans_history.db"

# Risk Engine Thresholds
RISK_THRESHOLD_LOW = 0.40
RISK_THRESHOLD_HIGH = 0.70

# Input Limits
MAX_URL_LENGTH = 2048
MAX_MESSAGE_LENGTH = 5000

# App Meta
APP_NAME = "PhishGuard-AI"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "AI-Powered Phishing URL & Message Threat Analyzer"
