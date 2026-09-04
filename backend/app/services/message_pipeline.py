"""
Message Threat Analysis Pipeline Service for PhishGuard-AI.
Cleans raw text, tokenizes, sequence-pads, runs RNN inference,
evaluates heuristic explanation cues, and generates a structured RiskAssessment.
"""

import datetime
from typing import Any
import numpy as np

from backend.app.schemas import MessageScanResponse, RiskAssessment
from backend.app.services.model_loader import ModelManager
from backend.app.services.risk_engine import evaluate_risk
from backend.app.services.explanation_engine import explain_message_threats
from backend.app.services.history_service import log_scan
from training.features.message_features import clean_text, MAX_SEQUENCE_LENGTH


def _to_padded_sequence(cleaned_text: str, tokenizer_or_vocab: Any) -> np.ndarray:
    if hasattr(tokenizer_or_vocab, "texts_to_sequences"):
        seqs = tokenizer_or_vocab.texts_to_sequences([cleaned_text])
        seq = seqs[0] if seqs else []
    elif isinstance(tokenizer_or_vocab, dict):
        words = cleaned_text.split()
        oov_idx = tokenizer_or_vocab.get("<OOV>", 1)
        seq = [tokenizer_or_vocab.get(w, oov_idx) for w in words]
    else:
        seq = []

    if len(seq) > MAX_SEQUENCE_LENGTH:
        padded = seq[:MAX_SEQUENCE_LENGTH]
    else:
        padded = seq + [0] * (MAX_SEQUENCE_LENGTH - len(seq))
    return np.array(padded, dtype=np.int32)


def analyze_message(message: str) -> MessageScanResponse:
    """
    NLP & RNN threat analysis for SMS, email, or direct messages.
    """
    model_mgr = ModelManager.get_instance()
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Text Cleaning
    cleaned = clean_text(message)

    # 2. Heuristic explanation indicators (distinct from model prediction)
    indicators = explain_message_threats(message, cleaned)

    # 3. Model Inference or Fallback
    if model_mgr.is_message_ready:
        tokenizer = model_mgr.message_tokenizer
        padded = _to_padded_sequence(cleaned, tokenizer)
        prob = model_mgr.predict_message(padded)
        model_loaded = True
        model_name = "Recurrent Neural Network (Embedding-SimpleRNN-Dense)"
    else:
        # Fallback: Heuristic count
        danger_count = sum(1 for ind in indicators if ind.severity == "danger")
        warning_count = sum(1 for ind in indicators if ind.severity == "warning")
        if danger_count >= 2:
            prob = 0.85
        elif danger_count == 1 or warning_count >= 2:
            prob = 0.60
        elif warning_count == 1:
            prob = 0.35
        else:
            prob = 0.08
        model_loaded = False
        model_name = "Heuristic-Only Fallback (Model Not Loaded)"

    # 4. Risk Assessment
    risk = evaluate_risk(prob)

    # 5. Persist to History Database
    scan_id = log_scan(
        scan_type="Message",
        input_text=message,
        probability=risk.probability,
        risk_level=risk.risk_level,
        confidence=risk.confidence_percentage
    )

    return MessageScanResponse(
        id=scan_id if scan_id > 0 else None,
        input_message=message,
        cleaned_text=cleaned,
        risk=risk,
        indicators=indicators,
        model_loaded=model_loaded,
        model_used=model_name,
        timestamp=timestamp_str
    )
