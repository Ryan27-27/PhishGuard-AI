"""
html_features.py — Page Content Feature Extractor

Fetches a webpage and extracts behavioral/content features
that indicate phishing (invisible iframes, brand impersonation,
form data exfiltration, etc.)
"""

import re
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

BRAND_LOGOS = ["paypal", "amazon", "apple", "microsoft", "google", "facebook",
               "netflix", "ebay", "instagram", "twitter", "linkedin", "bankofamerica",
               "chase", "wellsfargo", "citibank", "hsbc"]


class HTMLFeatureExtractor:
    """
    Fetches a page and extracts HTML-based phishing indicators.

    Features extracted:
    - invisible_iframe: hidden iframe tag detected
    - form_with_external_action: form POSTs to a different domain
    - password_field_present: login form detected
    - has_disable_right_click: JS disables context menu (hides source)
    - has_status_bar_fake: JS manipulates status bar
    - uses_popup: window.open or alert detected
    - favicon_domain_mismatch: favicon from different domain
    - brand_logo_present: contains known brand logos (impersonation)
    - link_count_external_vs_internal: ratio of external links
    - script_count: number of script tags (high = obfuscation)
    - title_domain_mismatch: page title contains different brand than domain
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return requests.get(
                url, headers=HEADERS, timeout=self.timeout,
                verify=False, allow_redirects=True
            )
        except Exception as e:
            logger.warning(f"[HTMLExtractor] Fetch failed for {url}: {e}")
            return None

    def extract(self, url: str) -> Dict[str, Any]:
        """Extract HTML content features from a URL."""
        defaults = {
            "invisible_iframe": 0,
            "form_with_external_action": 0,
            "password_field_present": 0,
            "has_disable_right_click": 0,
            "has_status_bar_fake": 0,
            "uses_popup": 0,
            "favicon_domain_mismatch": 0,
            "brand_logo_present": 0,
            "external_link_ratio": 0.0,
            "script_count": 0,
            "title_has_brand_mismatch": 0,
            "html_fetched": 0
        }

        resp = self._fetch(url)
        if resp is None:
            return defaults

        soup = BeautifulSoup(resp.text, "html.parser")
        html = resp.text
        parsed = urlparse(url)
        page_domain = parsed.netloc.lower()

        result = dict(defaults)
        result["html_fetched"] = 1

        # 1. Invisible iframe (zero width/height or visibility:hidden)
        for iframe in soup.find_all("iframe"):
            style = iframe.get("style", "").lower()
            width = iframe.get("width", "1")
            height = iframe.get("height", "1")
            if "display:none" in style or "visibility:hidden" in style:
                result["invisible_iframe"] = 1
                break
            try:
                if int(width) == 0 or int(height) == 0:
                    result["invisible_iframe"] = 1
                    break
            except (ValueError, TypeError):
                pass

        # 2. Form with external action
        for form in soup.find_all("form", action=True):
            action = form["action"]
            if action.startswith("http") and page_domain not in action:
                result["form_with_external_action"] = 1
                break

        # 3. Password field
        if soup.find("input", {"type": "password"}):
            result["password_field_present"] = 1

        # 4. JS that disables right-click
        right_click_patterns = [
            r"event\.button\s*==\s*2",
            r"oncontextmenu\s*=",
            r"contextmenu.*return\s+false",
            r"preventDefault.*contextmenu"
        ]
        for pat in right_click_patterns:
            if re.search(pat, html, re.IGNORECASE):
                result["has_disable_right_click"] = 1
                break

        # 5. Status bar manipulation
        if re.search(r"window\.status\s*=|onmouseover.*window\.status", html, re.IGNORECASE):
            result["has_status_bar_fake"] = 1

        # 6. Popups
        if re.search(r"window\.open\s*\(|alert\s*\(|confirm\s*\(", html, re.IGNORECASE):
            result["uses_popup"] = 1

        # 7. Favicon domain mismatch
        favicon_tag = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower())
        if favicon_tag and favicon_tag.get("href", "").startswith("http"):
            fav_domain = urlparse(favicon_tag["href"]).netloc.lower()
            if fav_domain and fav_domain != page_domain:
                result["favicon_domain_mismatch"] = 1

        # 8. Brand logo in images
        for img in soup.find_all("img"):
            src = (img.get("src", "") + img.get("alt", "")).lower()
            if any(brand in src for brand in BRAND_LOGOS):
                result["brand_logo_present"] = 1
                break

        # 9. External vs internal link ratio
        all_links = soup.find_all("a", href=True)
        external = sum(
            1 for a in all_links
            if a["href"].startswith("http") and page_domain not in a["href"]
        )
        total = len(all_links) or 1
        result["external_link_ratio"] = round(external / total, 4)

        # 10. Script count
        result["script_count"] = len(soup.find_all("script"))

        # 11. Title brand mismatch
        title_tag = soup.find("title")
        if title_tag:
            title_text = title_tag.get_text().lower()
            for brand in BRAND_LOGOS:
                if brand in title_text and brand not in page_domain:
                    result["title_has_brand_mismatch"] = 1
                    break

        return result
