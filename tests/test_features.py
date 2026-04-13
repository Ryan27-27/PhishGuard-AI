"""
test_features.py — Unit tests for PhishGuard feature extraction modules

Run: pytest tests/ -v
"""

import pytest
from unittest.mock import patch, MagicMock

from src.features.url_features import URLFeatureExtractor, _levenshtein, _shannon_entropy, _detect_typosquatting
from src.features.tor_detector import TorExitNodeDetector
from src.features.mismatch_detector import URLMismatchDetector
from src.utils.threat_scorer import ThreatScorer


# ── URL Feature Tests ──────────────────────────────────────────────────

class TestURLFeatureExtractor:

    def setup_method(self):
        # Disable live network calls in tests
        self.extractor = URLFeatureExtractor(
            fetch_whois=False,
            fetch_ssl=False,
            fetch_dns=False,
            follow_redirects=False
        )

    def test_ip_address_detection(self):
        features = self.extractor.extract("http://192.168.1.1/login")
        assert features["has_ip_address"] == 1

    def test_no_ip_address(self):
        features = self.extractor.extract("https://google.com")
        assert features["has_ip_address"] == 0

    def test_url_length(self):
        url = "http://paypal-secure-login.com/verify/account"
        features = self.extractor.extract(url)
        assert features["url_length"] == len(url)

    def test_at_symbol(self):
        features = self.extractor.extract("http://legit.com@evil.com/login")
        assert features["has_at_symbol"] == 1

    def test_no_at_symbol(self):
        features = self.extractor.extract("https://google.com")
        assert features["has_at_symbol"] == 0

    def test_suspicious_tld_tk(self):
        features = self.extractor.extract("http://paypal.tk/login")
        assert features["has_suspicious_tld"] == 1

    def test_legitimate_tld(self):
        features = self.extractor.extract("https://paypal.com")
        assert features["has_suspicious_tld"] == 0

    def test_https_detection(self):
        features = self.extractor.extract("https://bank.com")
        assert features["uses_https"] == 1

    def test_http_no_https(self):
        features = self.extractor.extract("http://bank.com")
        assert features["uses_https"] == 0

    def test_subdomain_count(self):
        features = self.extractor.extract("http://secure.login.paypal.evil.tk")
        assert features["subdomain_count"] >= 2

    def test_dash_in_domain(self):
        features = self.extractor.extract("http://paypal-secure-login.tk")
        assert features["has_dash_in_domain"] == 1

    def test_suspicious_keywords(self):
        features = self.extractor.extract("http://evil.tk/secure/login/verify")
        assert features["has_suspicious_keywords"] == 1

    def test_url_depth(self):
        features = self.extractor.extract("http://evil.com/a/b/c/d")
        assert features["url_depth"] == 4

    def test_brand_in_subdomain(self):
        features = self.extractor.extract("http://paypal.evil.tk/login")
        assert features["has_brand_in_subdomain"] == 1

    def test_encoded_chars(self):
        features = self.extractor.extract("http://evil.com/%70%61%79%70%61%6C")
        assert features["url_has_encoded_chars"] == 1

    def test_to_vector_length(self):
        features = self.extractor.extract("https://google.com")
        vector = self.extractor.to_vector(features)
        from src.features.url_features import FEATURE_NAMES
        assert len(vector) == len(FEATURE_NAMES)

    def test_feature_values_are_numeric(self):
        features = self.extractor.extract("http://192.168.1.1/phish@evil.tk/login")
        vector = self.extractor.to_vector(features)
        assert all(isinstance(v, (int, float)) for v in vector)


# ── Utility Function Tests ─────────────────────────────────────────────

class TestUtilities:

    def test_levenshtein_identical(self):
        assert _levenshtein("paypal", "paypal") == 0

    def test_levenshtein_typo(self):
        assert _levenshtein("paypa1", "paypal") == 1  # 1 substitution

    def test_levenshtein_different(self):
        assert _levenshtein("google", "evil") > 3

    def test_shannon_entropy_uniform(self):
        # Uniform distribution has max entropy
        entropy = _shannon_entropy("abcdefgh")
        assert entropy > 2.5

    def test_shannon_entropy_repeated(self):
        # All same chars = zero entropy
        entropy = _shannon_entropy("aaaaaaa")
        assert entropy == 0.0

    def test_shannon_entropy_empty(self):
        assert _shannon_entropy("") == 0.0

    def test_typosquatting_detected(self):
        result = _detect_typosquatting("paypa1")
        assert result["detected"] is True
        assert result["target_brand"] == "paypal"

    def test_typosquatting_not_detected(self):
        result = _detect_typosquatting("google")
        assert result["detected"] is False  # exact match, not typosquat

    def test_typosquatting_clearly_different(self):
        result = _detect_typosquatting("completelydifferent")
        assert result["detected"] is False


# ── Threat Scorer Tests ────────────────────────────────────────────────

class TestThreatScorer:

    def setup_method(self):
        self.scorer = ThreatScorer()

    def test_high_confidence_phishing_high_score(self):
        result = self.scorer.compute(
            ml_confidence=0.98,
            ml_prediction="phishing",
            features={"has_suspicious_tld": 1, "has_ip_address": 1, "domain_age_days": 5},
            virustotal={"positives": 20, "total": 72, "status": "malicious"},
            tor_exit_node=True,
            hidden_url_mismatch=True
        )
        assert result["score"] > 70
        assert result["risk_level"] in ("HIGH", "CRITICAL")

    def test_legitimate_low_score(self):
        result = self.scorer.compute(
            ml_confidence=0.95,
            ml_prediction="legitimate",
            features={
                "uses_https": 1, "ssl_valid": 1, "whois_available": 1,
                "has_dns_a_record": 1, "domain_age_days": 3000,
                "has_suspicious_tld": 0, "typosquatting_detected": 0
            },
            virustotal={"positives": 0, "total": 72, "status": "clean"},
        )
        assert result["score"] < 30
        assert result["risk_level"] in ("SAFE", "LOW")

    def test_score_within_bounds(self):
        result = self.scorer.compute(
            ml_confidence=1.0,
            ml_prediction="phishing",
            features={k: 1 for k in ThreatScorer.HEURISTIC_WEIGHTS},
            virustotal={"positives": 72, "total": 72},
            tor_exit_node=True,
            hidden_url_mismatch=True,
            is_blacklisted=True
        )
        assert 0 <= result["score"] <= 100

    def test_triggered_signals_not_empty_for_phishing(self):
        result = self.scorer.compute(
            ml_confidence=0.9,
            ml_prediction="phishing",
            features={"typosquatting_detected": 1, "has_suspicious_tld": 1},
            virustotal={"positives": 5, "total": 72},
        )
        assert len(result["triggered_signals"]) > 0

    def test_risk_levels_defined(self):
        from src.utils.threat_scorer import get_risk_level
        assert get_risk_level(0)[0] == "SAFE"
        assert get_risk_level(50)[0] == "MEDIUM"
        assert get_risk_level(90)[0] == "CRITICAL"


# ── Tor Detector Tests ─────────────────────────────────────────────────

class TestTorDetector:

    def setup_method(self):
        self.detector = TorExitNodeDetector(use_dns_fallback=False)

    def test_known_tor_ip_in_cache(self):
        self.detector._exit_nodes = {"1.2.3.4"}
        self.detector._loaded = True
        self.detector._last_refresh = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        )
        assert self.detector.is_tor_exit("1.2.3.4") is True

    def test_non_tor_ip(self):
        self.detector._exit_nodes = {"1.2.3.4"}
        self.detector._loaded = True
        self.detector._last_refresh = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        )
        assert self.detector.is_tor_exit("8.8.8.8") is False

    def test_empty_cache_non_tor(self):
        self.detector._exit_nodes = set()
        self.detector._loaded = True
        self.detector._last_refresh = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        )
        assert self.detector.is_tor_exit("9.9.9.9") is False


# ── Mismatch Detector Tests ────────────────────────────────────────────

class TestMismatchDetector:

    def setup_method(self):
        self.detector = URLMismatchDetector()

    def test_quick_check_mismatch(self):
        # Visible text says paypal.com, href goes to evil.tk
        assert self.detector.quick_check("https://paypal.com", "http://evil.tk/login") is True

    def test_quick_check_match(self):
        # Both go to same domain
        assert self.detector.quick_check("https://paypal.com/login", "https://paypal.com/verify") is False

    def test_quick_check_non_url_text(self):
        # Visible text is not a URL, should return False
        assert self.detector.quick_check("Click here to login", "http://evil.tk") is False
