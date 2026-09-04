"""Integration tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "models_loaded" in data
    assert data["models_loaded"]["url_ann"] is True
    assert data["models_loaded"]["message_rnn"] is True


def test_predict_url_legitimate(client):
    payload = {"url": "https://www.google.com/search?q=open+source"}
    response = client.post("/api/v1/predict/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_url"] == payload["url"]
    assert "risk" in data
    assert data["risk"]["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    assert "features" in data
    assert len(data["features"]) == 16
    assert "indicators" in data
    assert data["model_loaded"] is True


def test_predict_url_phishing(client):
    payload = {"url": "http://192.168.1.50/paypal/login/verify-account.php?id=839"}
    response = client.post("/api/v1/predict/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["risk_level"] in ["MEDIUM", "HIGH"]
    assert any(ind["code"] == "URL_IP_HOSTNAME" for ind in data["indicators"])


def test_predict_message_legitimate(client):
    payload = {"message": "Hey Aryan, let's sync up for lunch tomorrow around 1pm."}
    response = client.post("/api/v1/predict/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["risk_level"] == "LOW"
    assert data["model_loaded"] is True


def test_predict_message_phishing(client):
    payload = {"message": "URGENT! Your account is suspended. Call 08712345678 immediately to claim your $1000 prize or update details."}
    response = client.post("/api/v1/predict/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["risk_level"] in ["MEDIUM", "HIGH"]
    assert len(data["indicators"]) > 0


def test_validation_empty_url(client):
    response = client.post("/api/v1/predict/url", json={"url": "   "})
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "Validation Error"
    assert "status_code" in data
    assert "traceback" not in data


def test_validation_empty_message(client):
    response = client.post("/api/v1/predict/message", json={"message": " "})
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "Validation Error"


def test_validation_excessive_url_length(client):
    huge_url = "https://example.com/" + ("a" * 2500)
    response = client.post("/api/v1/predict/url", json={"url": huge_url})
    assert response.status_code == 422


def test_validation_excessive_message_length(client):
    huge_msg = "Spam " * 1500
    response = client.post("/api/v1/predict/message", json={"message": huge_msg})
    assert response.status_code == 422


def test_models_metrics_endpoint(client):
    response = client.get("/api/v1/models/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "url_model" in data
    assert "message_model" in data
    assert "test_metrics" in data["url_model"]
    assert "test_metrics" in data["message_model"]


def test_history_endpoint(client):
    response = client.get("/api/v1/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "scans" in data
    assert isinstance(data["scans"], list)
