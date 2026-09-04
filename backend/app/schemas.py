"""
Pydantic Schemas for PhishGuard-AI API.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class URLScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="URL to analyze for phishing threats (never visited or fetched).",
        min_length=3,
        max_length=2048,
        examples=["https://example.com/login"]
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("URL cannot be empty or solely whitespace.")
        if len(cleaned) < 3:
            raise ValueError("URL must be at least 3 characters long.")
        return cleaned


class MessageScanRequest(BaseModel):
    message: str = Field(
        ...,
        description="Message or SMS text to analyze for social engineering or phishing threats.",
        min_length=2,
        max_length=5000,
        examples=["URGENT: Your account has been suspended. Click here to verify."]
    )

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Message cannot be empty or solely whitespace.")
        if len(cleaned) < 2:
            raise ValueError("Message must be at least 2 characters long.")
        return cleaned


class HeuristicIndicator(BaseModel):
    code: str
    name: str
    description: str
    severity: str = Field(..., description="'info', 'warning', or 'danger'")
    matched: bool


class RiskAssessment(BaseModel):
    risk_level: str = Field(..., description="LOW, MEDIUM, or HIGH")
    probability: float = Field(..., description="Raw model threat probability [0.0 - 1.0]")
    confidence_percentage: float = Field(..., description="Confidence score [0.0 - 100.0%]")
    risk_color: str = Field(..., description="Hex color code for UI rendering")
    recommendation: str


class URLScanResponse(BaseModel):
    id: Optional[int] = None
    input_url: str
    features: Dict[str, float]
    risk: RiskAssessment
    indicators: List[HeuristicIndicator]
    model_loaded: bool
    model_used: str
    timestamp: str


class MessageScanResponse(BaseModel):
    id: Optional[int] = None
    input_message: str
    cleaned_text: str
    risk: RiskAssessment
    indicators: List[HeuristicIndicator]
    model_loaded: bool
    model_used: str
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    models_loaded: Dict[str, bool]
    uptime_seconds: float
    disclaimer: str


class MetricsResponse(BaseModel):
    url_model: Dict[str, Any]
    message_model: Dict[str, Any]


class HistoryItem(BaseModel):
    id: int
    scan_type: str
    input_preview: str
    probability: float
    risk_level: str
    confidence_percentage: float
    timestamp: str


class HistoryListResponse(BaseModel):
    total_scans: int
    scans: List[HistoryItem]


class ErrorResponse(BaseModel):
    error: str
    detail: str
    status_code: int
