"""
schemas.py — Pydantic Request & Response Models for PhishGuard Pro API
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, HttpUrl, Field


# ── Requests ───────────────────────────────────────────────────────────

class URLAnalysisRequest(BaseModel):
    url: HttpUrl = Field(..., example="http://paypa1-secure.tk/login")
    analyze_page: bool = Field(
        default=False,
        description="If True, fetches the page HTML for mismatch/content analysis (slower)"
    )

    model_config = {"json_schema_extra": {
        "example": {"url": "http://paypa1-secure-login.tk/confirm", "analyze_page": False}
    }}


class BatchAnalysisRequest(BaseModel):
    urls: List[HttpUrl] = Field(..., max_length=50, description="Up to 50 URLs")
    analyze_pages: bool = False

    model_config = {"json_schema_extra": {
        "example": {
            "urls": ["http://evil.tk/steal", "https://google.com"],
            "analyze_pages": False
        }
    }}


# ── Responses ──────────────────────────────────────────────────────────

class ThreatIntelResponse(BaseModel):
    virustotal: Dict[str, Any] = Field(default_factory=dict)
    tor_exit_node: bool = False
    hidden_url_mismatch: Dict[str, Any] = Field(default_factory=dict)


class URLAnalysisResponse(BaseModel):
    url: str
    prediction: str = Field(..., description="'phishing' or 'legitimate'")
    confidence: float = Field(..., ge=0, le=1, description="Model confidence [0-1]")
    threat_score: int = Field(..., ge=0, le=100, description="Composite threat score 0-100")
    risk_level: str = Field(..., description="SAFE / LOW / MEDIUM / HIGH / CRITICAL")
    risk_emoji: str
    triggered_signals: List[str] = Field(default_factory=list)
    recommendation: str
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    features: Dict[str, Any] = Field(default_factory=dict)
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    analysis_time_ms: int


class BatchAnalysisResponse(BaseModel):
    results: List[URLAnalysisResponse]
    total: int
    phishing_count: int
    legitimate_count: int


class HealthResponse(BaseModel):
    status: str
    uptime_seconds: int
    model_loaded: bool
    version: str


class StatsResponse(BaseModel):
    total_analyzed: int
    phishing_detected: int
    legitimate_detected: int
    phishing_rate: float
    uptime_seconds: int
