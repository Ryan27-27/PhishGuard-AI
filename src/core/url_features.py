"""
url_features.py — Advanced URL & Domain Feature Extractor
Extracts 40+ features for phishing detection ML model.

Upgrades over original:
  - 40+ features vs 17
  - SSL certificate analysis
  - Typosquatting detection (Levenshtein distance against Alexa top sites)
  - Entropy-based randomness detection
  - Homoglyph/IDN spoofing detection
  - Redirection chain analysis
  - WHOIS enhanced parsing
"""

import re
import math
import socket
import ssl
import hashlib
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode
from typing import Dict, Any, Optional, List

import tldextract
import whois
import dns.resolver
import dns.exception
import requests

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "pw", "top", "click", "link",
    "xyz", "work", "date", "faith", "review", "gdn", "stream",
    "download", "racing", "online", "accountant", "party", "loan"
}

# URL shortener domains
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "tiny.cc", "is.gd", "cli.gs", "yfrog.com", "migre.me",
    "ff.im", "su.pr", "twit.ac", "twitthis.com", "u.nu", "clout.io",
    "short.to", "BudURL.com", "snipurl.com", "po.st", "lnkd.in"
}

# Known brands for typosquatting detection
BRAND_DOMAINS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "yahoo", "ebay", "walmart", "bankofamerica", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "lloyds", "natwest", "santander"
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (high = random/suspicious)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _is_ip_address(host: str) -> bool:
    """Check if hostname is a raw IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _get_ssl_info(hostname: str) -> Dict[str, Any]:
    """Retrieve SSL certificate info for the domain."""
    result = {"valid": False, "days_until_expiry": -1, "issuer": "", "self_signed": True}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            result["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName", "")
        result["self_signed"] = issuer.get("commonName", "") == cert.get("subject", {}).get("commonName", "UNKNOWN")
        result["valid"] = True
    except Exception:
        pass
    return result


def _get_dns_records(domain: str) -> Dict[str, Any]:
    """Query DNS for A, MX, NS records."""
    result = {"has_a": False, "has_mx": False, "has_ns": False, "ip_count": 0}
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        result["has_a"] = True
        result["ip_count"] = len(list(answers))
    except Exception:
        pass
    try:
        dns.resolver.resolve(domain, "MX", lifetime=5)
        result["has_mx"] = True
    except Exception:
        pass
    try:
        dns.resolver.resolve(domain, "NS", lifetime=5)
        result["has_ns"] = True
    except Exception:
        pass
    return result


def _get_whois_info(domain: str) -> Dict[str, Any]:
    """Extract WHOIS domain registration data."""
    result = {
        "domain_age_days": -1,
        "expiry_days": -1,
        "registrar": "",
        "country": "",
        "whois_available": False
    }
    try:
        w = whois.whois(domain)
        now = datetime.now(timezone.utc)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            result["domain_age_days"] = (now - created).days

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            result["expiry_days"] = (expiry - now).days

        result["registrar"] = str(w.registrar or "")
        result["country"] = str(w.country or "")
        result["whois_available"] = True
    except Exception:
        pass
    return result


def _detect_typosquatting(domain_name: str) -> Dict[str, Any]:
    """
    Check if domain is typosquatting a well-known brand.
    Uses Levenshtein distance ≤ 2 as the threshold.
    """
    result = {"detected": False, "target_brand": "", "edit_distance": -1}
    for brand in BRAND_DOMAINS:
        dist = _levenshtein(domain_name.lower(), brand)
        if 0 < dist <= 2:
            result["detected"] = True
            result["target_brand"] = brand
            result["edit_distance"] = dist
            return result
    return result


def _detect_homoglyphs(domain: str) -> bool:
    """
    Check for IDN homoglyph attacks — domain uses non-ASCII chars
    that visually mimic ASCII (e.g. pаypal.com with Cyrillic 'а').
    """
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def _count_redirects(url: str) -> int:
    """Follow redirect chain and count hops."""
    try:
        resp = requests.get(url, allow_redirects=True, timeout=8, verify=False)
        return len(resp.history)
    except Exception:
        return 0


class URLFeatureExtractor:
    """
    Extracts 40+ structured features from a URL for phishing ML model.

    Usage:
        extractor = URLFeatureExtractor()
        features = extractor.extract("http://paypa1-secure.tk/login")
    """

    FEATURE_NAMES = [
        # --- Address Bar / URL Structure (15) ---
        "has_ip_address",
        "url_length",
        "url_depth",
        "has_at_symbol",
        "has_double_slash_redirect",
        "has_http_in_domain",
        "is_shortened_url",
        "has_dash_in_domain",
        "subdomain_count",
        "has_suspicious_tld",
        "digit_ratio_in_domain",
        "special_char_count",
        "entropy_domain",
        "entropy_path",
        "has_port",

        # --- Domain Intelligence (10) ---
        "domain_age_days",
        "domain_expiry_days",
        "whois_available",
        "has_dns_a_record",
        "has_mx_record",
        "dns_ip_count",
        "typosquatting_detected",
        "typosquatting_edit_distance",
        "has_homoglyph",
        "registrar_is_free",

        # --- SSL / HTTPS (5) ---
        "uses_https",
        "ssl_valid",
        "ssl_days_until_expiry",
        "ssl_self_signed",
        "ssl_issuer_trusted",

        # --- Page / Content (5) ---
        "redirect_count",
        "has_suspicious_keywords",
        "num_query_params",
        "has_brand_in_subdomain",
        "url_has_encoded_chars",

        # --- Threat Intelligence (5) ---
        "virustotal_positives",     # set externally by threat_scorer
        "is_tor_exit_node",         # set externally by tor_detector
        "hidden_url_mismatch",      # set externally by mismatch_detector
        "is_blacklisted",           # set externally
        "phishtank_listed",         # set externally
    ]

    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "verify", "account", "update", "banking",
        "secure", "confirm", "password", "credential", "paypal", "ebay",
        "amazon", "appleid", "microsoft", "support", "wallet", "recover",
        "suspend", "validate", "billing", "invoice"
    ]

    TRUSTED_SSL_ISSUERS = {
        "DigiCert", "GlobalSign", "Comodo", "Let's Encrypt", "Sectigo",
        "GoDaddy", "Entrust", "VeriSign", "Thawte", "GeoTrust"
    }

    def __init__(self, fetch_whois: bool = True, fetch_ssl: bool = True,
                 fetch_dns: bool = True, follow_redirects: bool = False):
        self.fetch_whois = fetch_whois
        self.fetch_ssl = fetch_ssl
        self.fetch_dns = fetch_dns
        self.follow_redirects = follow_redirects

    def extract(self, url: str) -> Dict[str, Any]:
        """
        Extract all features from a URL.
        Returns dict with feature_name -> value.
        External features (VT, Tor, mismatch) default to 0 and
        should be set by the caller after extraction.
        """
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        domain = extracted.domain
        suffix = extracted.suffix
        subdomain = extracted.subdomain
        hostname = parsed.hostname or ""
        path = parsed.path or ""

        features: Dict[str, Any] = {}

        # ── URL Structure Features ──────────────────────────────────────
        features["has_ip_address"] = int(_is_ip_address(hostname))
        features["url_length"] = len(url)
        features["url_depth"] = len([p for p in path.split("/") if p])
        features["has_at_symbol"] = int("@" in url)
        features["has_double_slash_redirect"] = int(url.count("//") > 1)
        features["has_http_in_domain"] = int("http" in domain.lower())
        features["is_shortened_url"] = int(f"{domain}.{suffix}" in SHORTENERS)
        features["has_dash_in_domain"] = int("-" in domain)
        features["subdomain_count"] = len([s for s in subdomain.split(".") if s]) if subdomain else 0
        features["has_suspicious_tld"] = int(suffix in SUSPICIOUS_TLDS)
        digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
        features["digit_ratio_in_domain"] = round(digit_ratio, 4)
        special_chars = sum(c in "!#$%^&*()+=[]{}|;:,<>?~`'\"\\" for c in url)
        features["special_char_count"] = special_chars
        features["entropy_domain"] = round(_shannon_entropy(domain), 4)
        features["entropy_path"] = round(_shannon_entropy(path), 4)
        features["has_port"] = int(parsed.port is not None and parsed.port not in (80, 443))

        # ── Domain Intelligence Features ────────────────────────────────
        whois_info = _get_whois_info(f"{domain}.{suffix}") if self.fetch_whois else {}
        features["domain_age_days"] = whois_info.get("domain_age_days", -1)
        features["domain_expiry_days"] = whois_info.get("expiry_days", -1)
        features["whois_available"] = int(whois_info.get("whois_available", False))

        dns_info = _get_dns_records(hostname) if self.fetch_dns else {}
        features["has_dns_a_record"] = int(dns_info.get("has_a", False))
        features["has_mx_record"] = int(dns_info.get("has_mx", False))
        features["dns_ip_count"] = dns_info.get("ip_count", 0)

        typo_info = _detect_typosquatting(domain)
        features["typosquatting_detected"] = int(typo_info["detected"])
        features["typosquatting_edit_distance"] = typo_info["edit_distance"] if typo_info["detected"] else 0
        features["has_homoglyph"] = int(_detect_homoglyphs(hostname))

        registrar = whois_info.get("registrar", "").lower()
        free_registrars = ["freenom", "dot.tk", "namecheap", "godaddy"]
        features["registrar_is_free"] = int(any(fr in registrar for fr in free_registrars))

        # ── SSL / HTTPS Features ────────────────────────────────────────
        features["uses_https"] = int(parsed.scheme == "https")
        ssl_info = _get_ssl_info(hostname) if self.fetch_ssl and parsed.scheme == "https" else {}
        features["ssl_valid"] = int(ssl_info.get("valid", False))
        features["ssl_days_until_expiry"] = ssl_info.get("days_until_expiry", -1)
        features["ssl_self_signed"] = int(ssl_info.get("self_signed", True))
        issuer = ssl_info.get("issuer", "")
        features["ssl_issuer_trusted"] = int(any(ti in issuer for ti in self.TRUSTED_SSL_ISSUERS))

        # ── Page / Behavioral Features ──────────────────────────────────
        features["redirect_count"] = _count_redirects(url) if self.follow_redirects else 0
        lower_url = url.lower()
        features["has_suspicious_keywords"] = int(
            any(kw in lower_url for kw in self.SUSPICIOUS_KEYWORDS)
        )
        features["num_query_params"] = len(parsed.query.split("&")) if parsed.query else 0
        features["has_brand_in_subdomain"] = int(
            any(brand in subdomain.lower() for brand in BRAND_DOMAINS) and bool(subdomain)
        )
        features["url_has_encoded_chars"] = int("%" in url)

        # ── Threat Intelligence (defaults; caller fills these in) ───────
        features["virustotal_positives"] = 0
        features["is_tor_exit_node"] = 0
        features["hidden_url_mismatch"] = 0
        features["is_blacklisted"] = 0
        features["phishtank_listed"] = 0

        return features

    def extract_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract features from multiple URLs."""
        return [self.extract(url) for url in urls]

    def to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert feature dict to ordered numeric vector for ML model input."""
        return [float(features.get(name, 0)) for name in self.FEATURE_NAMES]
