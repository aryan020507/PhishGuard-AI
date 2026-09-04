"""
Risk Engine Service for PhishGuard-AI.
Maps predicted threat probabilities to categorical risk tiers and actionable security guidance.

Thresholds:
  - LOW:    prob < 0.40
  - MEDIUM: 0.40 <= prob < 0.70
  - HIGH:   prob >= 0.70
"""

from backend.app.schemas import RiskAssessment
from backend.app.config import RISK_THRESHOLD_LOW, RISK_THRESHOLD_HIGH


def evaluate_risk(probability: float) -> RiskAssessment:
    """
    Map a raw neural network probability (0.0 - 1.0) to a standardized RiskAssessment.
    """
    # Clamp probability to [0.0, 1.0]
    prob = max(0.0, min(1.0, float(probability)))

    if prob < RISK_THRESHOLD_LOW:
        risk_level = "LOW"
        risk_color = "#10b981"  # Emerald
        # High confidence in benign nature when prob is close to 0
        confidence = (1.0 - prob) * 100.0
        recommendation = (
            "Benign profile detected. The analyzed content exhibits standard legitimate "
            "characteristics. Normal caution is always recommended."
        )
    elif prob < RISK_THRESHOLD_HIGH:
        risk_level = "MEDIUM"
        risk_color = "#f59e0b"  # Amber
        # Confidence reflects uncertainty around the decision boundary
        confidence = (prob if prob >= 0.5 else (1.0 - prob)) * 100.0
        recommendation = (
            "Caution advised. Suspicious or ambiguous threat indicators detected. "
            "Do NOT provide credentials, personal data, or click unknown links."
        )
    else:
        risk_level = "HIGH"
        risk_color = "#ef4444"  # Crimson
        confidence = prob * 100.0
        recommendation = (
            "CRITICAL ALERT: High probability of phishing or social engineering attack! "
            "Deceptive markers identified. Do not interact with this content."
        )

    return RiskAssessment(
        risk_level=risk_level,
        probability=round(prob, 4),
        confidence_percentage=round(confidence, 1),
        risk_color=risk_color,
        recommendation=recommendation
    )
