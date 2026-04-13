"""
virustotal.py — VirusTotal API v3 Integration

Submits URLs to VirusTotal for multi-engine threat analysis.
VT checks the URL against 70+ security vendors simultaneously.

Free tier: 4 requests/minute, 500/day
Paid tier: higher limits

Usage:
    vt = VirusTotalClient(api_key="YOUR_KEY")
    result = await vt.scan_url("http://suspicious-site.com")
    print(result["positives"])  # Number of vendors flagging as malicious
"""

import asyncio
import base64
import hashlib
import logging
import time
from typing import Dict, Any, Optional

import httpx

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    """
    Async VirusTotal API v3 client for URL reputation analysis.

    Methods:
        scan_url(url): Submit URL for analysis, get results
        get_url_report(url): Get cached report without new scan
        get_domain_report(domain): Domain-level threat intelligence
    """

    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self._headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        self._last_request_time: float = 0
        self._rate_limit_delay = 15  # 4 req/min = 1 per 15s on free tier

    def _url_id(self, url: str) -> str:
        """VirusTotal URL ID: base64url-encoded URL (no padding)."""
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async def _wait_rate_limit(self):
        """Enforce free-tier rate limit: 1 request per 15 seconds."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    async def scan_url(self, url: str, wait_for_results: bool = True) -> Dict[str, Any]:
        """
        Submit a URL to VirusTotal for scanning.

        Args:
            url: The URL to analyze
            wait_for_results: If True, waits for analysis to complete (up to 30s)

        Returns:
            {
                "positives": int,       # vendors flagging as malicious
                "total": int,           # total vendors checked
                "categories": [...],    # threat categories assigned
                "reputation": int,      # VT domain reputation score
                "last_analysis_date": str,
                "permalink": str,       # VT analysis link
                "status": "clean" | "malicious" | "suspicious" | "unknown"
            }
        """
        await self._wait_rate_limit()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Step 1: Submit URL for analysis
            try:
                resp = await client.post(
                    f"{VT_BASE}/urls",
                    headers=self._headers,
                    data={"url": url}
                )
                if resp.status_code == 401:
                    return self._error_result("Invalid VirusTotal API key")
                if resp.status_code == 429:
                    return self._error_result("VirusTotal rate limit exceeded")
                resp.raise_for_status()
                analysis_id = resp.json().get("data", {}).get("id", "")
            except Exception as e:
                logger.error(f"[VT] URL submission failed: {e}")
                return self._error_result(str(e))

            if not wait_for_results:
                return {"status": "submitted", "analysis_id": analysis_id, "positives": 0}

            # Step 2: Poll for results (max 3 attempts, 10s apart)
            await self._wait_rate_limit()
            url_id = self._url_id(url)

            for attempt in range(3):
                try:
                    result_resp = await client.get(
                        f"{VT_BASE}/urls/{url_id}",
                        headers=self._headers
                    )
                    result_resp.raise_for_status()
                    data = result_resp.json().get("data", {})
                    attributes = data.get("attributes", {})

                    last_analysis = attributes.get("last_analysis_stats", {})
                    malicious = last_analysis.get("malicious", 0)
                    suspicious = last_analysis.get("suspicious", 0)
                    total = sum(last_analysis.values())

                    categories = list(attributes.get("categories", {}).values())

                    status = "clean"
                    if malicious > 0:
                        status = "malicious"
                    elif suspicious > 0:
                        status = "suspicious"

                    return {
                        "positives": malicious,
                        "suspicious": suspicious,
                        "total": total,
                        "categories": list(set(categories)),
                        "reputation": attributes.get("reputation", 0),
                        "last_analysis_date": attributes.get("last_analysis_date", ""),
                        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                        "status": status,
                        "engines": self._parse_engines(attributes.get("last_analysis_results", {}))
                    }

                except Exception as e:
                    logger.warning(f"[VT] Result poll attempt {attempt + 1} failed: {e}")
                    if attempt < 2:
                        await asyncio.sleep(10)

        return self._error_result("Analysis timed out")

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get domain-level threat intelligence from VirusTotal.
        Includes historical scan results, WHOIS, categories.
        """
        await self._wait_rate_limit()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"{VT_BASE}/domains/{domain}",
                    headers=self._headers
                )
                resp.raise_for_status()
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "domain": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": list(attrs.get("categories", {}).values()),
                    "creation_date": attrs.get("creation_date", ""),
                    "registrar": attrs.get("registrar", ""),
                }
            except Exception as e:
                logger.error(f"[VT] Domain report failed for {domain}: {e}")
                return {"domain": domain, "malicious": 0, "error": str(e)}

    def _parse_engines(self, results: Dict) -> Dict[str, str]:
        """Extract malicious engine verdicts."""
        return {
            engine: data.get("result", "")
            for engine, data in results.items()
            if data.get("category") in ("malicious", "suspicious")
        }

    def _error_result(self, msg: str) -> Dict[str, Any]:
        return {
            "positives": 0,
            "total": 0,
            "categories": [],
            "reputation": 0,
            "status": "error",
            "error": msg
        }


class MockVirusTotalClient:
    """
    Mock VT client for development/testing without an API key.
    Returns realistic-looking fake results based on URL heuristics.
    """

    async def scan_url(self, url: str, wait_for_results: bool = True) -> Dict[str, Any]:
        import tldextract
        from src.features.url_features import SUSPICIOUS_TLDS

        ext = tldextract.extract(url)
        suspicious = ext.suffix in SUSPICIOUS_TLDS or "login" in url.lower()

        positives = 14 if suspicious else 0
        return {
            "positives": positives,
            "total": 72,
            "status": "malicious" if positives > 0 else "clean",
            "categories": ["phishing"] if suspicious else [],
            "reputation": -50 if suspicious else 0,
            "permalink": f"https://www.virustotal.com/gui/url/{url[:20]}",
            "mock": True
        }

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        return {"domain": domain, "malicious": 0, "mock": True}
