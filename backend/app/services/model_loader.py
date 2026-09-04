"""
Singleton Model Loader Service for PhishGuard-AI.
Loads models and artifacts once during application startup.
Supports both TensorFlow/Keras runtime and lightweight pure NumPy forward-pass fallback
(essential for serverless environments like Vercel with strict bundle size limits).
"""

import os
import time
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import numpy as np

# Suppress verbose TF C++ logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

try:
    import joblib
    HAS_JOBLIB = True
except Exception:
    HAS_JOBLIB = False

try:
    import tensorflow as tf
    from tensorflow import keras
    HAS_TF = True
except Exception:
    HAS_TF = False

from backend.app.config import (
    URL_MODEL_PATH,
    URL_SCALER_PATH,
    MESSAGE_MODEL_PATH,
    MESSAGE_TOKENIZER_PATH,
    MODELS_DIR
)

URL_WEIGHTS_PATH = MODELS_DIR / "url_weights.npz"
URL_SCALER_NPZ = MODELS_DIR / "url_scaler.npz"
MESSAGE_WEIGHTS_PATH = MODELS_DIR / "message_weights.npz"
MESSAGE_VOCAB_JSON = MODELS_DIR / "message_word_index.json"

logger = logging.getLogger("phishguard.model_loader")


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -50.0, 50.0)))


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


class NumpyScaler:
    """Lightweight pure-numpy equivalent of StandardScaler."""
    def __init__(self, mean: np.ndarray, scale: np.ndarray):
        self.mean_ = mean
        self.scale_ = scale

    def transform(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean_) / self.scale_


class ModelManager:
    """Manages lifecycle, memory caching, and inference for PhishGuard ML models."""
    _instance: Optional["ModelManager"] = None

    def __init__(self):
        self.url_model: Optional[Any] = None
        self.url_scaler: Optional[Any] = None
        self.url_weights: Optional[Dict[str, np.ndarray]] = None

        self.message_model: Optional[Any] = None
        self.message_tokenizer: Optional[Any] = None
        self.message_weights: Optional[Dict[str, np.ndarray]] = None

        self.start_time: float = time.time()
        self.loaded_status: Dict[str, bool] = {
            "url_ann": False,
            "url_scaler": False,
            "message_rnn": False,
            "message_tokenizer": False
        }

    @classmethod
    def get_instance(cls) -> "ModelManager":
        if cls._instance is None:
            cls._instance = ModelManager()
        return cls._instance

    def load_all_models(self):
        """Load all ML models and preprocessing pipelines once on startup."""
        logger.info("Initializing PhishGuard-AI ML Model Manager...")

        # 1. URL Scaler (Joblib or NumPy NPZ)
        if HAS_JOBLIB and URL_SCALER_PATH.exists():
            try:
                self.url_scaler = joblib.load(str(URL_SCALER_PATH))
                self.loaded_status["url_scaler"] = True
                logger.info(f"Loaded URL Scaler from {URL_SCALER_PATH}")
            except Exception as e:
                logger.warning(f"Error loading joblib scaler: {e}")

        if not self.loaded_status["url_scaler"] and URL_SCALER_NPZ.exists():
            try:
                data = np.load(str(URL_SCALER_NPZ))
                self.url_scaler = NumpyScaler(data["mean"], data["scale"])
                self.loaded_status["url_scaler"] = True
                logger.info(f"Loaded URL Scaler from {URL_SCALER_NPZ}")
            except Exception as e:
                logger.error(f"Error loading url_scaler.npz: {e}")

        # 2. URL ANN Model (Keras or NumPy fallback)
        loaded_url_keras = False
        if HAS_TF:
            try:
                if URL_MODEL_PATH.exists():
                    self.url_model = keras.models.load_model(str(URL_MODEL_PATH))
                    self.loaded_status["url_ann"] = True
                    loaded_url_keras = True
                    logger.info(f"Loaded URL ANN Keras model from {URL_MODEL_PATH}")
            except Exception as e:
                logger.warning(f"Keras URL load failed: {e}. Attempting NumPy fallback...")

        if not loaded_url_keras and URL_WEIGHTS_PATH.exists():
            try:
                data = np.load(str(URL_WEIGHTS_PATH))
                self.url_weights = {k: data[k] for k in data.files}
                self.loaded_status["url_ann"] = True
                logger.info(f"Loaded URL ANN NumPy weights from {URL_WEIGHTS_PATH}")
            except Exception as e:
                logger.error(f"Error loading URL NumPy weights: {e}")
                self.loaded_status["url_ann"] = False

        # 3. Message Tokenizer (Pickle or JSON)
        if MESSAGE_TOKENIZER_PATH.exists():
            try:
                with open(MESSAGE_TOKENIZER_PATH, "rb") as f:
                    self.message_tokenizer = pickle.load(f)
                self.loaded_status["message_tokenizer"] = True
                logger.info(f"Loaded Message Tokenizer from {MESSAGE_TOKENIZER_PATH}")
            except Exception as e:
                logger.warning(f"Error loading pickle tokenizer: {e}")

        if not self.loaded_status["message_tokenizer"] and MESSAGE_VOCAB_JSON.exists():
            try:
                with open(MESSAGE_VOCAB_JSON, "r", encoding="utf-8") as f:
                    self.message_tokenizer = json.load(f)
                self.loaded_status["message_tokenizer"] = True
                logger.info(f"Loaded Message Tokenizer from {MESSAGE_VOCAB_JSON}")
            except Exception as e:
                logger.error(f"Error loading message_word_index.json: {e}")

        # 4. Message RNN Model (Keras or NumPy fallback)
        loaded_msg_keras = False
        if HAS_TF:
            try:
                if MESSAGE_MODEL_PATH.exists():
                    self.message_model = keras.models.load_model(str(MESSAGE_MODEL_PATH))
                    self.loaded_status["message_rnn"] = True
                    loaded_msg_keras = True
                    logger.info(f"Loaded Message RNN Keras model from {MESSAGE_MODEL_PATH}")
            except Exception as e:
                logger.warning(f"Keras Message load failed: {e}. Attempting NumPy fallback...")

        if not loaded_msg_keras and MESSAGE_WEIGHTS_PATH.exists():
            try:
                data = np.load(str(MESSAGE_WEIGHTS_PATH))
                self.message_weights = {k: data[k] for k in data.files}
                self.loaded_status["message_rnn"] = True
                logger.info(f"Loaded Message RNN NumPy weights from {MESSAGE_WEIGHTS_PATH}")
            except Exception as e:
                logger.error(f"Error loading Message NumPy weights: {e}")
                self.loaded_status["message_rnn"] = False

    @property
    def is_url_ready(self) -> bool:
        if not (self.loaded_status["url_ann"] and self.loaded_status["url_scaler"]):
            self.load_all_models()
        return bool(self.loaded_status["url_ann"] and self.loaded_status["url_scaler"])

    @property
    def is_message_ready(self) -> bool:
        if not (self.loaded_status["message_rnn"] and self.loaded_status["message_tokenizer"]):
            self.load_all_models()
        return bool(self.loaded_status["message_rnn"] and self.loaded_status["message_tokenizer"])

    def predict_url(self, raw_features_1d: np.ndarray) -> float:
        """Scale features and run inference with URL ANN."""
        if not self.is_url_ready:
            raise RuntimeError("URL ANN model or scaler is not loaded.")

        X = raw_features_1d.reshape(1, -1)
        X_scaled = self.url_scaler.transform(X)

        if self.url_model is not None:
            pred = self.url_model.predict(X_scaled, verbose=0)
            return float(pred[0][0])
        elif self.url_weights is not None:
            w = self.url_weights
            h1 = _relu(np.dot(X_scaled, w["W1"]) + w["b1"])
            h2 = _relu(np.dot(h1, w["W2"]) + w["b2"])
            y = _sigmoid(np.dot(h2, w["W3"]) + w["b3"])
            return float(y[0][0])
        else:
            raise RuntimeError("No URL model available.")

    def predict_message(self, padded_sequence: np.ndarray) -> float:
        """Run inference with Message RNN."""
        if not self.is_message_ready:
            raise RuntimeError("Message RNN model or tokenizer is not loaded.")

        if self.message_model is not None:
            X = padded_sequence.reshape(1, -1)
            pred = self.message_model.predict(X, verbose=0)
            return float(pred[0][0])
        elif self.message_weights is not None:
            w = self.message_weights
            seq = padded_sequence.flatten()
            E = w["emb_W"][seq]
            h = np.zeros(32, dtype=np.float32)
            for token, x in zip(seq, E):
                if token == 0:
                    continue
                h = np.tanh(np.dot(x, w["rnn_W"]) + np.dot(h, w["rnn_U"]) + w["rnn_b"])
            h_dense = _relu(np.dot(h, w["d1_W"]) + w["d1_b"])
            y = _sigmoid(np.dot(h_dense, w["out_W"]) + w["out_b"])
            return float(y[0] if isinstance(y, (np.ndarray, list)) else y)
        else:
            raise RuntimeError("No Message model available.")
