"""
threat_scorer.py — Multi-Signal Threat Scoring Engine

Combines ML model probability, threat intelligence, and heuristic
signals into a single threat score 0–100 with risk level labels.

Score interpretation:
  0–20   = SAFE
  21–40  = LOW RISK
  41–60  = MEDIUM RISK
  61–80  = HIGH RISK
  81–100 = CRITICAL

Weighting strategy:
  - ML confidence: 40%
  - VirusTotal positives: 25%
  - URL/domain heuristics: 20%
  - Tor/blacklist: 10%
  - Hidden URL mismatch: 5%
"""

from typing import Dict, Any, List, Tuple,Optional
import logging

logger = logging.getLogger(__name__)


RISK_LEVELS = [
    (0, 20, "SAFE", "✅"),
    (21, 40, "LOW", "🟡"),
    (41, 60, "MEDIUM", "🟠"),
    (61, 80, "HIGH", "🔴"),
    (81, 100, "CRITICAL", "🚨")
]


def get_risk_level(score: int) -> Tuple[str, str]:
    """Return (risk_label, emoji) for a given score."""
    for low, high, label, emoji in RISK_LEVELS:
        if low <= score <= high:
            return label, emoji
    return "UNKNOWN", "❓"


class ThreatScorer:
    """
    Aggregates all detection signals into a single threat score.

    Signals consumed:
      - ml_confidence: float [0,1] from ensemble model
      - ml_prediction: "phishing" | "legitimate"
      - features: dict of extracted URL features
      - virustotal: dict with "positives", "total", "status"
      - tor_exit_node: bool
      - hidden_url_mismatch: bool/dict
      - is_blacklisted: bool
    """

    # Feature weights for heuristic sub-score
    HEURISTIC_WEIGHTS: Dict[str, Tuple[float, str]] = {
        "has_ip_address":           (8.0,  "IP address in URL"),
        "has_suspicious_tld":       (7.0,  "Suspicious TLD"),
        "typosquatting_detected":   (9.0,  "Typosquatting detected"),
        "has_homoglyph":            (10.0, "Homoglyph/IDN spoofing"),
        "domain_age_days":          (0.0,  ""),    # calculated below
        "ssl_valid":                (-5.0, ""),    # negative = reduces score
        "uses_https":               (-3.0, ""),    # negative
        "has_at_symbol":            (6.0,  "@ symbol in URL"),
        "has_double_slash_redirect":(5.0,  "Double slash redirect"),
        "has_brand_in_subdomain":   (8.0,  "Brand name in subdomain"),
        "whois_available":          (-2.0, ""),    # negative
        "has_dns_a_record":         (-1.0, ""),    # negative
        "entropy_domain":           (0.0,  ""),    # calculated below
        "digit_ratio_in_domain":    (0.0,  ""),    # calculated below
        "redirect_count":           (0.0,  ""),    # calculated below
        "has_suspicious_keywords":  (5.0,  "Suspicious keywords in URL"),
        "ssl_self_signed":          (4.0,  "Self-signed SSL certificate"),
        "registrar_is_free":        (3.0,  "Free/suspicious registrar"),
    }

    def compute(
        self,
        ml_confidence: float,
        ml_prediction: str,
        features: Dict[str, Any],
        virustotal: Optional[Dict[str, Any]] = None,
        tor_exit_node: bool = False,
        hidden_url_mismatch: bool = False,
        is_blacklisted: bool = False,
    ) -> Dict[str, Any]:
        """
        Compute final threat score and full threat report.

        Returns:
            {
                "score": int (0-100),
                "risk_level": str,
                "risk_emoji": str,
                "breakdown": dict (component scores),
                "triggered_signals": list of signal descriptions,
                "recommendation": str
            }
        """
        triggered_signals = []
        component_scores = {}

        # ── 1. ML Component (40%) ─────────────────────────────────────
        if ml_prediction == "phishing":
            ml_score = ml_confidence * 40
        else:
            ml_score = (1 - ml_confidence) * 10  # low score if confident it's legit
        component_scores["ml"] = round(ml_score, 2)
        if ml_prediction == "phishing" and ml_confidence > 0.7:
            triggered_signals.append(f"ML model: {ml_confidence:.0%} phishing confidence")

        # ── 2. VirusTotal Component (25%) ────────────────────────────
        vt_score = 0.0
        if virustotal and not virustotal.get("error"):
            positives = virustotal.get("positives", 0)
            total = virustotal.get("total", 72) or 72
            if positives > 0:
                vt_ratio = min(positives / total, 1.0)
                vt_score = vt_ratio * 25
                triggered_signals.append(f"VirusTotal: {positives}/{total} engines flagged malicious")
            categories = virustotal.get("categories", [])
            if "phishing" in categories:
                vt_score = min(vt_score + 5, 25)
                triggered_signals.append("VirusTotal: categorized as phishing")
        component_scores["virustotal"] = round(vt_score, 2)

        # ── 3. Heuristic Features Component (20%) ───────────────────
        heuristic_score = 0.0
        for feat, (weight, label) in self.HEURISTIC_WEIGHTS.items():
            val = features.get(feat, 0)
            if feat == "domain_age_days":
                age = features.get("domain_age_days", -1)
                if 0 < age < 30:
                    heuristic_score += 8
                    triggered_signals.append(f"Domain age: only {age} days old")
                elif 0 < age < 90:
                    heuristic_score += 4
                    triggered_signals.append(f"Domain age: only {age} days old")
            elif feat == "entropy_domain":
                entropy = features.get("entropy_domain", 0)
                if entropy > 3.8:
                    heuristic_score += 5
                    triggered_signals.append(f"High domain entropy ({entropy:.2f}) — random-looking")
            elif feat == "digit_ratio_in_domain":
                ratio = features.get("digit_ratio_in_domain", 0)
                if ratio > 0.3:
                    heuristic_score += 4
                    triggered_signals.append(f"High digit ratio in domain ({ratio:.0%})")
            elif feat == "redirect_count":
                redirects = features.get("redirect_count", 0)
                if redirects >= 3:
                    heuristic_score += min(redirects * 2, 8)
                    triggered_signals.append(f"Excessive redirects: {redirects}")
            elif weight != 0 and val:
                if weight > 0:
                    heuristic_score += weight
                    if label:
                        triggered_signals.append(label)
                else:
                    heuristic_score += weight  # reduces score

        heuristic_score = max(0, min(heuristic_score, 20))
        component_scores["heuristics"] = round(heuristic_score, 2)

        # ── 4. Threat Intel Component (10%) ─────────────────────────
        threat_intel_score = 0.0
        if tor_exit_node:
            threat_intel_score += 7
            triggered_signals.append("Tor exit node detected — anonymized connection")
        if is_blacklisted:
            threat_intel_score += 10
            triggered_signals.append("Domain is blacklisted")
        threat_intel_score = min(threat_intel_score, 10)
        component_scores["threat_intel"] = round(threat_intel_score, 2)

        # ── 5. Mismatch Component (5%) ───────────────────────────────
        mismatch_score = 0.0
        if hidden_url_mismatch:
            mismatch_score = 5
            triggered_signals.append("Hidden/visible URL mismatch detected")
        component_scores["url_mismatch"] = round(mismatch_score, 2)

        # ── Final Score ──────────────────────────────────────────────
        total_score = (
            component_scores["ml"]
            + component_scores["virustotal"]
            + component_scores["heuristics"]
            + component_scores["threat_intel"]
            + component_scores["url_mismatch"]
        )
        final_score = max(0, min(round(total_score), 100))
        risk_level, risk_emoji = get_risk_level(final_score)

        # ── Recommendation ───────────────────────────────────────────
        recommendation = self._get_recommendation(risk_level, triggered_signals)

        return {
            "score": final_score,
            "risk_level": risk_level,
            "risk_emoji": risk_emoji,
            "breakdown": component_scores,
            "triggered_signals": list(dict.fromkeys(triggered_signals)),  # deduplicate
            "recommendation": recommendation
        }

    def _get_recommendation(self, risk_level: str, signals: List[str]) -> str:
        recommendations = {
            "SAFE": "This URL appears safe. Standard browsing caution still applies.",
            "LOW": "Minor risk indicators detected. Proceed with caution.",
            "MEDIUM": "Several phishing indicators found. Avoid entering sensitive information.",
            "HIGH": "Strong phishing signals detected. Do NOT visit this URL or enter credentials.",
            "CRITICAL": "CRITICAL THREAT. This URL is almost certainly malicious. Block immediately.",
        }
        return recommendations.get(risk_level, "Unable to assess risk.")


# Reexport for convenience
from typing import Optional
