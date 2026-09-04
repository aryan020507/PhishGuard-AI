"""Unit tests for Risk Engine and Explanation Engine."""

import pytest
from backend.app.services.risk_engine import evaluate_risk
from backend.app.services.explanation_engine import explain_url_threats, explain_message_threats


def test_risk_threshold_low():
    assessment = evaluate_risk(0.15)
    assert assessment.risk_level == "LOW"
    assert assessment.risk_color == "#10b981"
    assert assessment.confidence_percentage == 85.0


def test_risk_threshold_medium():
    assessment = evaluate_risk(0.55)
    assert assessment.risk_level == "MEDIUM"
    assert assessment.risk_color == "#f59e0b"
    assert assessment.confidence_percentage == 55.0


def test_risk_threshold_high():
    assessment = evaluate_risk(0.88)
    assert assessment.risk_level == "HIGH"
    assert assessment.risk_color == "#ef4444"
    assert assessment.confidence_percentage == 88.0


def test_risk_bounds_clamping():
    assert evaluate_risk(-0.5).probability == 0.0
    assert evaluate_risk(1.5).probability == 1.0


def test_url_explanation_heuristics():
    features = {
        "has_ip": 1.0,
        "has_https": 0.0,
        "suspicious_keywords_count": 2.0,
        "has_shortener": 1.0,
        "url_length": 120.0,
        "entropy": 4.8,
        "num_subdomains": 3.0,
        "num_at": 1.0,
        "has_port": 1.0
    }
    indicators = explain_url_threats("http://192.168.1.1/test", features)
    codes = [i.code for i in indicators]

    assert "URL_IP_HOSTNAME" in codes
    assert "URL_NO_HTTPS" in codes
    assert "URL_SUSPICIOUS_KEYWORDS" in codes
    assert "URL_SHORTENER_DETECTED" in codes
    assert "URL_EXCESSIVE_LENGTH" in codes
    assert "URL_HIGH_ENTROPY" in codes
    assert "URL_DEEP_SUBDOMAINS" in codes
    assert "URL_AT_SYMBOL" in codes
    assert "URL_NON_STANDARD_PORT" in codes


def test_message_explanation_heuristics():
    raw_spam = "URGENT: Your bank account is locked! Call immediately to claim your $1000 prize or refund."
    cleaned = "urgent your bank account is locked call immediately to claim your money num prize or refund"
    indicators = explain_message_threats(raw_spam, cleaned)
    codes = [i.code for i in indicators]

    assert "MSG_URGENCY_PRESSURE" in codes
    assert "MSG_FINANCIAL_LURE" in codes
    assert "MSG_CALL_TO_ACTION" in codes
