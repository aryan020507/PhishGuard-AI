"""
Singleton Model Loader Service for PhishGuard-AI.
Loads models and artifacts once during application startup.
Provides thread-safe, memory-efficient inference and graceful degradation if artifacts are missing.
"""

import os
import time
import pickle
import logging
from typing import Dict, Optional, Tuple, Any
import numpy as np
import joblib

# Suppress verbose TF C++ logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow import keras

from backend.app.config import (
    URL_MODEL_PATH,
    URL_SCALER_PATH,
    MESSAGE_MODEL_PATH,
    MESSAGE_TOKENIZER_PATH
)

logger = logging.getLogger("phishguard.model_loader")


class ModelManager:
    """Manages lifecycle, memory caching, and inference for PhishGuard ML models."""
    _instance: Optional["ModelManager"] = None

    def __init__(self):
        self.url_model: Optional[keras.Model] = None
        self.url_scaler: Optional[Any] = None
        self.message_model: Optional[keras.Model] = None
        self.message_tokenizer: Optional[Any] = None
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

        # 1. URL ANN Model & Scaler
        try:
            if URL_MODEL_PATH.exists():
                self.url_model = keras.models.load_model(str(URL_MODEL_PATH))
                self.loaded_status["url_ann"] = True
                logger.info(f"Loaded URL ANN model from {URL_MODEL_PATH}")
            else:
                logger.warning(f"URL model artifact missing at {URL_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Error loading URL model: {e}")
            self.loaded_status["url_ann"] = False

        try:
            if URL_SCALER_PATH.exists():
                self.url_scaler = joblib.load(str(URL_SCALER_PATH))
                self.loaded_status["url_scaler"] = True
                logger.info(f"Loaded URL Scaler from {URL_SCALER_PATH}")
            else:
                logger.warning(f"URL scaler artifact missing at {URL_SCALER_PATH}")
        except Exception as e:
            logger.error(f"Error loading URL scaler: {e}")
            self.loaded_status["url_scaler"] = False

        # 2. Message RNN Model & Tokenizer
        try:
            if MESSAGE_MODEL_PATH.exists():
                self.message_model = keras.models.load_model(str(MESSAGE_MODEL_PATH))
                self.loaded_status["message_rnn"] = True
                logger.info(f"Loaded Message RNN model from {MESSAGE_MODEL_PATH}")
            else:
                logger.warning(f"Message model artifact missing at {MESSAGE_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Error loading Message model: {e}")
            self.loaded_status["message_rnn"] = False

        try:
            if MESSAGE_TOKENIZER_PATH.exists():
                with open(MESSAGE_TOKENIZER_PATH, "rb") as f:
                    self.message_tokenizer = pickle.load(f)
                self.loaded_status["message_tokenizer"] = True
                logger.info(f"Loaded Message Tokenizer from {MESSAGE_TOKENIZER_PATH}")
            else:
                logger.warning(f"Message tokenizer artifact missing at {MESSAGE_TOKENIZER_PATH}")
        except Exception as e:
            logger.error(f"Error loading Message tokenizer: {e}")
            self.loaded_status["message_tokenizer"] = False

    @property
    def is_url_ready(self) -> bool:
        return bool(self.loaded_status["url_ann"] and self.loaded_status["url_scaler"])

    @property
    def is_message_ready(self) -> bool:
        return bool(self.loaded_status["message_rnn"] and self.loaded_status["message_tokenizer"])

    def predict_url(self, raw_features_1d: np.ndarray) -> float:
        """
        Scale features and run inference with URL ANN.
        Returns float probability in range [0.0, 1.0].
        """
        if not self.is_url_ready:
            raise RuntimeError("URL ANN model or scaler is not loaded.")

        # Reshape to 2D for scaler
        X = raw_features_1d.reshape(1, -1)
        X_scaled = self.url_scaler.transform(X)

        # Run model inference
        pred = self.url_model.predict(X_scaled, verbose=0)
        prob = float(pred[0][0])
        return prob

    def predict_message(self, padded_sequence: np.ndarray) -> float:
        """
        Run inference with Message RNN.
        Returns float probability in range [0.0, 1.0].
        """
        if not self.is_message_ready:
            raise RuntimeError("Message RNN model or tokenizer is not loaded.")

        # Reshape to 2D
        X = padded_sequence.reshape(1, -1)
        pred = self.message_model.predict(X, verbose=0)
        prob = float(pred[0][0])
        return prob
