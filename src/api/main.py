"""
main.py — PhishGuard Pro FastAPI Application

Real-time phishing detection REST API with:
  - Single URL analysis
  - Batch URL analysis
  - WebSocket live feed
  - Health check & stats
  - Rate limiting
  - Redis caching

Run: uvicorn src.api.main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, field_validator

from src.api.schemas import (
    URLAnalysisRequest, URLAnalysisResponse,
    BatchAnalysisRequest, BatchAnalysisResponse,
    HealthResponse, StatsResponse
)

logger = logging.getLogger(__name__)

# ── App State ─────────────────────────────────────────────────────────
predictor = None
stats = {
    "total_analyzed": 0,
    "phishing_detected": 0,
    "legitimate_detected": 0,
    "start_time": time.time()
}

recent_analyses: List[dict] = []  # In-memory recent results (capped at 100)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global predictor
    logger.info("🚀 PhishGuard Pro starting up...")

    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    model_dir = os.getenv("MODEL_DIR", "models/")

    try:
        from src.ml.predictor import PhishGuardPredictor
        predictor = PhishGuardPredictor.load(
            model_dir=model_dir,
            vt_api_key=vt_api_key or None,
            fetch_whois=True,
            fetch_ssl=True,
        )
        logger.info("✅ ML models and threat intel loaded")
    except FileNotFoundError:
        logger.warning("⚠️  Models not found. Run: python src/ml/train.py")
        logger.info("   Using demo predictor for testing.")
        predictor = _create_demo_predictor()

    yield

    logger.info("👋 PhishGuard Pro shutting down.")


app = FastAPI(
    title="PhishGuard Pro",
    description=(
        "🛡️ Advanced phishing detection API with ML ensemble, "
        "VirusTotal integration, Tor detection, and URL mismatch analysis."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
    
)
app.mount("/ui", StaticFiles(directory="src/api/static", html=True), name="ui")

# ── Middleware ─────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ── Routes ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, tags=["Root"])
async def root():
    """Redirect to dashboard."""
    return HTMLResponse("""
    <html><head><meta http-equiv="refresh" content="0; url=/docs"/></head>
    <body><p>Redirecting to <a href="/docs">API Documentation</a></p></body></html>
    """)


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Health check endpoint."""
    uptime = int(time.time() - stats["start_time"])
    return {
        "status": "healthy",
        "uptime_seconds": uptime,
        "model_loaded": predictor is not None,
        "version": "2.0.0"
    }


@app.get("/stats", response_model=StatsResponse, tags=["System"])
async def get_stats():
    """Get analysis statistics."""
    total = stats["total_analyzed"] or 1
    return {
        "total_analyzed": stats["total_analyzed"],
        "phishing_detected": stats["phishing_detected"],
        "legitimate_detected": stats["legitimate_detected"],
        "phishing_rate": round(stats["phishing_detected"] / total, 4),
        "uptime_seconds": int(time.time() - stats["start_time"])
    }


@app.post("/analyze", response_model=URLAnalysisResponse, tags=["Detection"])
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a single URL for phishing indicators.

    Returns ML prediction, threat score (0-100), risk level,
    VirusTotal results, Tor detection, and URL mismatch analysis.
    """
    if predictor is None:
        raise HTTPException(503, "Models not loaded. Run train.py first.")

    url_str = str(request.url)
    try:
        result = await predictor.predict(url_str, analyze_page=request.analyze_page)
    except Exception as e:
        logger.exception(f"Analysis error for {url_str}: {e}")
        raise HTTPException(500, f"Analysis failed: {str(e)}")

    # Update stats
    stats["total_analyzed"] += 1
    if result["prediction"] == "phishing":
        stats["phishing_detected"] += 1
    else:
        stats["legitimate_detected"] += 1

    # Store in recent analyses (cap at 100)
    recent_analyses.insert(0, {
        "url": url_str,
        "prediction": result["prediction"],
        "threat_score": result["threat_score"],
        "risk_level": result["risk_level"],
        "timestamp": time.time()
    })
    if len(recent_analyses) > 100:
        recent_analyses.pop()

    return result


@app.post("/batch", response_model=BatchAnalysisResponse, tags=["Detection"])
async def analyze_batch(request: BatchAnalysisRequest):
    """
    Analyze multiple URLs in parallel. Maximum 50 URLs per request.
    """
    if predictor is None:
        raise HTTPException(503, "Models not loaded.")

    urls = [str(u) for u in request.urls[:50]]  # Cap at 50

    results = await predictor.predict_batch(urls, analyze_pages=False)

    for r in results:
        stats["total_analyzed"] += 1
        if r["prediction"] == "phishing":
            stats["phishing_detected"] += 1
        else:
            stats["legitimate_detected"] += 1

    phishing_count = sum(1 for r in results if r["prediction"] == "phishing")
    return {
        "results": results,
        "total": len(results),
        "phishing_count": phishing_count,
        "legitimate_count": len(results) - phishing_count
    }


@app.get("/recent", tags=["Detection"])
async def get_recent_analyses(limit: int = 20):
    """Get recent URL analysis results."""
    return {"results": recent_analyses[:limit]}


@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """
    WebSocket endpoint for real-time detection feed.
    Client sends URLs, server streams results as they complete.

    Message format:
        Send: {"url": "http://example.com"}
        Receive: {full analysis result}
    """
    await websocket.accept()
    logger.info("[WS] Client connected to real-time feed")

    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
                url = payload.get("url", "")
                if not url:
                    await websocket.send_json({"error": "Missing 'url' field"})
                    continue

                await websocket.send_json({"status": "analyzing", "url": url})

                result = await predictor.predict(url, analyze_page=False)
                await websocket.send_json(result)

            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON"})
            except Exception as e:
                await websocket.send_json({"error": str(e)})

    except WebSocketDisconnect:
        logger.info("[WS] Client disconnected")


# ── Demo predictor for testing without trained model ──────────────────
def _create_demo_predictor():
    """Creates a rule-based demo predictor when models aren't trained yet."""
    class DemoPredictor:
        async def predict(self, url: str, analyze_page: bool = False) -> dict:
            from src.features.url_features import URLFeatureExtractor, SUSPICIOUS_TLDS
            import tldextract

            ext = tldextract.extract(url)
            suspicious = ext.suffix in SUSPICIOUS_TLDS
            has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
            has_susp_kw = any(k in url.lower() for k in ["login", "verify", "secure", "account"])

            score = 0
            signals = []
            if suspicious:
                score += 40
                signals.append("Suspicious TLD")
            if has_ip:
                score += 30
                signals.append("IP address in URL")
            if has_susp_kw:
                score += 20
                signals.append("Suspicious keywords")

            prediction = "phishing" if score >= 40 else "legitimate"
            risk_map = {(0, 20): ("SAFE", "✅"), (21, 40): ("LOW", "🟡"),
                        (41, 60): ("MEDIUM", "🟠"), (61, 80): ("HIGH", "🔴"), (81, 100): ("CRITICAL", "🚨")}
            risk_level, emoji = next(
                (v for k, v in risk_map.items() if k[0] <= score <= k[1]),
                ("UNKNOWN", "❓")
            )
            return {
                "url": url, "prediction": prediction, "confidence": 0.75,
                "threat_score": score, "risk_level": risk_level, "risk_emoji": emoji,
                "triggered_signals": signals, "recommendation": "Demo mode — train models for full analysis",
                "score_breakdown": {"ml": score * 0.4, "heuristics": score * 0.6},
                "features": {}, "threat_intel": {}, "analysis_time_ms": 10, "demo_mode": True
            }

        async def predict_batch(self, urls, **kwargs):
            return [await self.predict(u) for u in urls]

    import re
    return DemoPredictor()
