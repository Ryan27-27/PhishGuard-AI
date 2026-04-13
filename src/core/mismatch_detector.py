"""
mismatch_detector.py — Hidden vs. Visible URL Mismatch Detector

One of the most common phishing techniques:
  - Display "https://paypal.com" as link text
  - But href points to "http://evil.tk/steal-creds"

This module:
  1. Parses HTML to find all anchor tags
  2. Compares the visible anchor text vs the href
  3. Detects domain mismatches (a key phishing signal)
  4. Also checks for JavaScript-obfuscated redirects
  5. Detects misleading form action URLs

Usage:
    detector = URLMismatchDetector()
    result = detector.analyze_page("https://suspicious-site.com")
    if result["has_mismatch"]:
        print(f"Mismatch found! {result['mismatches']}")
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
import tldextract

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


def _extract_domain(url: str) -> str:
    """Extract the registered domain (e.g. 'paypal.com') from a URL."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()


def _is_url(text: str) -> bool:
    """Check if anchor text looks like a URL."""
    return bool(re.match(r"https?://|www\.", text.strip(), re.IGNORECASE))


def _domains_match(visible_url: str, actual_url: str) -> bool:
    """Return True if the visible and actual domains are the same."""
    return _extract_domain(visible_url) == _extract_domain(actual_url)


class URLMismatchDetector:
    """
    Fetches a webpage and detects deceptive link mismatches.

    Detects:
    - <a href="evil.com">paypal.com</a>  ← text says one domain, href is another
    - Forms that POST to a different domain than the page
    - JS-based redirect obfuscation (window.location tricks)
    - Iframe sources that differ from the page domain
    """

    def __init__(self, timeout: int = 10, max_links: int = 200):
        self.timeout = timeout
        self.max_links = max_links

    def _fetch_html(self, url: str) -> Optional[str]:
        """Fetch page HTML, return None on failure."""
        try:
            resp = requests.get(
                url,
                headers=HEADERS,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return resp.text
        except Exception as e:
            logger.warning(f"[MismatchDetector] Could not fetch {url}: {e}")
            return None

    def _check_anchor_mismatches(
        self, soup: BeautifulSoup, page_url: str
    ) -> List[Dict[str, str]]:
        """
        Find <a> tags where the visible text domain ≠ href domain.
        Classic phishing trick.
        """
        mismatches = []
        anchors = soup.find_all("a", href=True)[: self.max_links]

        for tag in anchors:
            href = tag["href"].strip()
            text = tag.get_text(strip=True)

            # Skip fragment links, mailto, javascript, tel
            if href.startswith(("#", "mailto:", "javascript:", "tel:", "/")):
                continue
            if not href.startswith("http"):
                href = urljoin(page_url, href)

            # Only check when visible text looks like a URL
            if _is_url(text):
                text_domain = _extract_domain(text)
                href_domain = _extract_domain(href)

                if text_domain and href_domain and text_domain != href_domain:
                    mismatches.append({
                        "type": "anchor_text_mismatch",
                        "visible_text": text[:120],
                        "visible_domain": text_domain,
                        "actual_href": href[:200],
                        "actual_domain": href_domain,
                        "severity": "HIGH"
                    })

        return mismatches

    def _check_form_action_mismatches(
        self, soup: BeautifulSoup, page_url: str
    ) -> List[Dict[str, str]]:
        """
        Detect forms that submit data to a different domain.
        Classic credential harvesting pattern.
        """
        mismatches = []
        page_domain = _extract_domain(page_url)
        forms = soup.find_all("form", action=True)

        for form in forms:
            action = form["action"].strip()
            if not action or action.startswith("#"):
                continue
            if not action.startswith("http"):
                action = urljoin(page_url, action)

            action_domain = _extract_domain(action)
            if action_domain and action_domain != page_domain:
                mismatches.append({
                    "type": "form_action_mismatch",
                    "page_domain": page_domain,
                    "form_action": action[:200],
                    "action_domain": action_domain,
                    "severity": "CRITICAL"
                })

        return mismatches

    def _check_iframe_mismatches(
        self, soup: BeautifulSoup, page_url: str
    ) -> List[Dict[str, str]]:
        """
        Detect iframes loading content from foreign domains.
        Often used to embed fake login forms.
        """
        mismatches = []
        page_domain = _extract_domain(page_url)
        iframes = soup.find_all("iframe", src=True)

        for iframe in iframes:
            src = iframe["src"].strip()
            if not src or src.startswith("data:"):
                continue
            if not src.startswith("http"):
                src = urljoin(page_url, src)

            src_domain = _extract_domain(src)
            if src_domain and src_domain != page_domain:
                mismatches.append({
                    "type": "iframe_domain_mismatch",
                    "page_domain": page_domain,
                    "iframe_src": src[:200],
                    "iframe_domain": src_domain,
                    "severity": "HIGH"
                })

        return mismatches

    def _check_js_redirects(self, html: str) -> List[Dict[str, str]]:
        """
        Detect JavaScript-based redirect obfuscation.
        Looks for window.location = / document.location patterns.
        """
        mismatches = []
        patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                redirect_url = match.group(1)
                if redirect_url.startswith("http"):
                    mismatches.append({
                        "type": "js_redirect",
                        "redirect_target": redirect_url[:200],
                        "severity": "MEDIUM"
                    })
        return mismatches

    def analyze_page(self, url: str) -> Dict[str, Any]:
        """
        Full mismatch analysis on a given URL.

        Returns:
            {
                "has_mismatch": bool,
                "mismatch_count": int,
                "mismatches": [...],
                "severity": "NONE" | "MEDIUM" | "HIGH" | "CRITICAL",
                "checked": bool
            }
        """
        html = self._fetch_html(url)
        if not html:
            return {
                "has_mismatch": False,
                "mismatch_count": 0,
                "mismatches": [],
                "severity": "UNKNOWN",
                "checked": False
            }

        soup = BeautifulSoup(html, "html.parser")
        all_mismatches: List[Dict] = []

        all_mismatches.extend(self._check_anchor_mismatches(soup, url))
        all_mismatches.extend(self._check_form_action_mismatches(soup, url))
        all_mismatches.extend(self._check_iframe_mismatches(soup, url))
        all_mismatches.extend(self._check_js_redirects(html))

        # Determine overall severity
        severity = "NONE"
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        for m in all_mismatches:
            ms = m.get("severity", "LOW")
            if severity_order.get(ms, 0) > severity_order.get(severity, 0):
                severity = ms

        return {
            "has_mismatch": len(all_mismatches) > 0,
            "mismatch_count": len(all_mismatches),
            "mismatches": all_mismatches,
            "severity": severity,
            "checked": True
        }

    def quick_check(self, visible_text: str, href: str) -> bool:
        """
        Lightweight check: does visible_text domain match href domain?
        Used for single link analysis without fetching the page.
        """
        if not _is_url(visible_text):
            return False
        return not _domains_match(visible_text, href)
