"""
predictor.py — PhishGuard Inference Engine

Loads trained models and provides a clean prediction interface
that combines ML inference + threat intelligence signals.

Usage:
    predictor = PhishGuardPredictor.load("models/")
    result = await predictor.predict("http://suspicious-url.tk")
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

import joblib
import numpy as np

from src.core.url_features import URLFeatureExtractor
from src.core.tor_detector import get_tor_detector
from src.core.mismatch_detector import URLMismatchDetector
from src.core.threat_scorer import ThreatScorer
from src.ml.train import TRAINING_FEATURES

logger = logging.getLogger(__name__)


class PhishGuardPredictor:
    """
    End-to-end phishing detection predictor.

    Pipeline:
      URL → Feature Extraction → ML Prediction → Threat Intel → Score → Report
    """

    def __init__(
        self,
        ensemble_model,
        vt_client=None,
        use_tor_check: bool = True,
        use_mismatch_check: bool = True,
        fetch_whois: bool = True,
        fetch_ssl: bool = True,
    ):
        self.model = ensemble_model
        self.vt_client = vt_client
        self.use_tor_check = use_tor_check
        self.use_mismatch_check = use_mismatch_check

        self.feature_extractor = URLFeatureExtractor(
            fetch_whois=fetch_whois,
            fetch_ssl=fetch_ssl,
            fetch_dns=True,
            follow_redirects=False
        )
        self.tor_detector = get_tor_detector() if use_tor_check else None
        self.mismatch_detector = URLMismatchDetector() if use_mismatch_check else None
        self.threat_scorer = ThreatScorer()

    @classmethod
    def load(cls, model_dir: str, vt_api_key: Optional[str] = None, **kwargs) -> "PhishGuardPredictor":
        """Load saved ensemble model from disk."""
        model_path = Path(model_dir) / "ensemble_model.pkl"
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model not found at {model_path}. Run: python src/ml/train.py"
            )
        model = joblib.load(model_path)
        logger.info(f"[Predictor] Loaded ensemble model from {model_path}")

        vt_client = None
        if vt_api_key:
            from src.core.virustotal import VirusTotalClient
            vt_client = VirusTotalClient(vt_api_key)
            logger.info("[Predictor] VirusTotal client initialized")
        else:
            from src.core.virustotal import MockVirusTotalClient
            vt_client = MockVirusTotalClient()
            logger.warning("[Predictor] No VT API key — using mock VirusTotal client")

        return cls(model, vt_client=vt_client, **kwargs)

    async def predict(self, url: str, analyze_page: bool = False) -> Dict[str, Any]:
        """
        Full phishing analysis for a given URL.

        Args:
            url: The URL to analyze
            analyze_page: If True, fetches page for HTML/mismatch analysis (slower)

        Returns:
            Comprehensive analysis report dict
        """
        start_time = time.perf_counter()
        logger.info(f"[Predictor] Analyzing: {url}")

        # ── Step 1: URL Feature Extraction ──────────────────────────
        features = self.feature_extractor.extract(url)

        # ── Step 2: ML Prediction ────────────────────────────────────
        feature_vector = [float(features.get(f, 0)) for f in TRAINING_FEATURES]
        X = np.array(feature_vector).reshape(1, -1)

        ml_proba = self.model.predict_proba(X)[0]
        phishing_prob = float(ml_proba[1])
        ml_prediction = "phishing" if phishing_prob >= 0.5 else "legitimate"
        ml_confidence = phishing_prob if ml_prediction == "phishing" else 1 - phishing_prob

        # ── Step 3: Threat Intelligence (async) ─────────────────────
        vt_result, tor_detected, mismatch_result = await asyncio.gather(
            self._run_virustotal(url),
            self._run_tor_check(url),
            self._run_mismatch_check(url, analyze_page),
        )

        # ── Step 4: Threat Scoring ───────────────────────────────────
        features["is_tor_exit_node"] = int(tor_detected)
        features["virustotal_positives"] = vt_result.get("positives", 0) if vt_result else 0
        features["hidden_url_mismatch"] = int(
            mismatch_result.get("has_mismatch", False) if mismatch_result else False
        )

        threat_report = self.threat_scorer.compute(
            ml_confidence=ml_confidence,
            ml_prediction=ml_prediction,
            features=features,
            virustotal=vt_result,
            tor_exit_node=tor_detected,
            hidden_url_mismatch=features["hidden_url_mismatch"] == 1,
        )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000)

        return {
            "url": url,
            "prediction": ml_prediction,
            "confidence": round(ml_confidence, 4),
            "threat_score": threat_report["score"],
            "risk_level": threat_report["risk_level"],
            "risk_emoji": threat_report["risk_emoji"],
            "triggered_signals": threat_report["triggered_signals"],
            "recommendation": threat_report["recommendation"],
            "score_breakdown": threat_report["breakdown"],
            "features": features,
            "threat_intel": {
                "virustotal": vt_result or {},
                "tor_exit_node": tor_detected,
                "hidden_url_mismatch": mismatch_result or {},
            },
            "analysis_time_ms": elapsed_ms,
        }

    async def predict_batch(self, urls: list, analyze_pages: bool = False) -> list:
        """Analyze multiple URLs concurrently."""
        tasks = [self.predict(url, analyze_pages) for url in urls]
        return await asyncio.gather(*tasks)

    async def _run_virustotal(self, url: str) -> Optional[Dict]:
        if not self.vt_client:
            return None
        try:
            return await self.vt_client.scan_url(url)
        except Exception as e:
            logger.warning(f"[VT] Error: {e}")
            return None

    async def _run_tor_check(self, url: str) -> bool:
        if not self.tor_detector:
            return False
        try:
            return self.tor_detector.check_url(url)
        except Exception:
            return False

    async def _run_mismatch_check(self, url: str, analyze_page: bool) -> Optional[Dict]:
        if not self.mismatch_detector or not analyze_page:
            return None
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self.mismatch_detector.analyze_page, url
            )
        except Exception as e:
            logger.warning(f"[Mismatch] Error: {e}")
            return None
