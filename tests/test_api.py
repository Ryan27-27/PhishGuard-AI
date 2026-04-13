"""
test_api.py — Integration tests for PhishGuard Pro FastAPI endpoints

Run: pytest tests/test_api.py -v
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock

from src.api.main import app


MOCK_PHISHING_RESULT = {
    "url": "http://paypa1-secure.tk/login",
    "prediction": "phishing",
    "confidence": 0.97,
    "threat_score": 91,
    "risk_level": "CRITICAL",
    "risk_emoji": "🚨",
    "triggered_signals": ["Suspicious TLD", "Typosquatting detected"],
    "recommendation": "CRITICAL THREAT. Block immediately.",
    "score_breakdown": {"ml": 38.8, "virustotal": 25.0, "heuristics": 20.0, "threat_intel": 7.0, "url_mismatch": 0.0},
    "features": {"has_ip_address": 0, "has_suspicious_tld": 1},
    "threat_intel": {"virustotal": {"positives": 14}, "tor_exit_node": False},
    "analysis_time_ms": 320
}

MOCK_LEGIT_RESULT = {
    "url": "https://google.com",
    "prediction": "legitimate",
    "confidence": 0.99,
    "threat_score": 3,
    "risk_level": "SAFE",
    "risk_emoji": "✅",
    "triggered_signals": [],
    "recommendation": "This URL appears safe.",
    "score_breakdown": {"ml": 0.5, "virustotal": 0.0, "heuristics": 0.0, "threat_intel": 0.0, "url_mismatch": 0.0},
    "features": {"uses_https": 1, "ssl_valid": 1},
    "threat_intel": {"virustotal": {"positives": 0}, "tor_exit_node": False},
    "analysis_time_ms": 150
}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def mock_predictor(monkeypatch):
    """Patch the global predictor with a mock."""
    mock = MagicMock()
    mock.predict = AsyncMock(return_value=MOCK_PHISHING_RESULT)
    mock.predict_batch = AsyncMock(return_value=[MOCK_PHISHING_RESULT, MOCK_LEGIT_RESULT])
    import src.api.main as main_module
    monkeypatch.setattr(main_module, "predictor", mock)
    return mock


class TestHealthEndpoints:

    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
        assert "version" in data

    def test_stats_endpoint(self, client):
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_analyzed" in data
        assert "phishing_rate" in data


class TestAnalyzeEndpoint:

    def test_analyze_phishing_url(self, client):
        resp = client.post("/analyze", json={"url": "http://paypa1-secure.tk/login"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["prediction"] == "phishing"
        assert data["threat_score"] == 91
        assert data["risk_level"] == "CRITICAL"

    def test_analyze_response_has_required_fields(self, client):
        resp = client.post("/analyze", json={"url": "http://paypa1-secure.tk/login"})
        data = resp.json()
        required = [
            "url", "prediction", "confidence", "threat_score",
            "risk_level", "triggered_signals", "recommendation",
            "features", "threat_intel", "analysis_time_ms"
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_analyze_invalid_url(self, client):
        resp = client.post("/analyze", json={"url": "not-a-url"})
        assert resp.status_code == 422  # Pydantic validation error

    def test_analyze_missing_url(self, client):
        resp = client.post("/analyze", json={})
        assert resp.status_code == 422

    def test_confidence_in_range(self, client):
        resp = client.post("/analyze", json={"url": "http://evil.tk"})
        data = resp.json()
        assert 0 <= data["confidence"] <= 1

    def test_threat_score_in_range(self, client):
        resp = client.post("/analyze", json={"url": "http://evil.tk"})
        data = resp.json()
        assert 0 <= data["threat_score"] <= 100


class TestBatchEndpoint:

    def test_batch_analysis(self, client):
        resp = client.post("/batch", json={
            "urls": ["http://evil.tk", "https://google.com"]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["results"]) == 2

    def test_batch_counts(self, client):
        resp = client.post("/batch", json={
            "urls": ["http://evil.tk", "https://google.com"]
        })
        data = resp.json()
        assert "phishing_count" in data
        assert "legitimate_count" in data
        assert data["phishing_count"] + data["legitimate_count"] == data["total"]

    def test_batch_empty_list(self, client):
        resp = client.post("/batch", json={"urls": []})
        # Should return 200 with empty results or 422
        assert resp.status_code in (200, 422)


class TestRecentEndpoint:

    def test_recent_returns_list(self, client):
        # First analyze something to populate
        client.post("/analyze", json={"url": "http://evil.tk"})
        resp = client.get("/recent")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert isinstance(data["results"], list)
