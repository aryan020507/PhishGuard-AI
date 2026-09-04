"""
Configuration settings and constants for PhishGuard-AI.
"""

import os
from pathlib import Path

# Base Paths
APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

MODELS_DIR = PROJECT_ROOT / "models"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = PROJECT_ROOT / "training" / "datasets"

# Artifact file paths
URL_MODEL_PATH = MODELS_DIR / "url_ann_model.keras"
URL_SCALER_PATH = MODELS_DIR / "url_scaler.joblib"
URL_METRICS_PATH = MODELS_DIR / "url_metrics.json"

MESSAGE_MODEL_PATH = MODELS_DIR / "message_rnn_model.keras"
MESSAGE_TOKENIZER_PATH = MODELS_DIR / "message_tokenizer.pkl"
MESSAGE_METRICS_PATH = MODELS_DIR / "message_metrics.json"

# SQLite Database
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
