"""
build_dataset.py — Training Dataset Builder

Downloads PhishTank phishing URLs + UNB legitimate URLs,
runs feature extraction on both sets, and saves the merged
dataset as data/urldata.csv ready for model training.

Usage:
    python build_dataset.py --phishing 5000 --legit 5000
    python build_dataset.py --phishing 10000 --legit 10000 --output data/urldata_large.csv
"""

import argparse
import logging
import os
import random
import time
from pathlib import Path

import pandas as pd
import requests
from tqdm import tqdm

from src.core.url_features import URLFeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
UNB_LEGITIMATE_URL = "https://raw.githubusercontent.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall/master/goodqueries.txt"


def download_phishing_urls(max_count: int = 5000) -> list:
    """Download phishing URLs from PhishTank."""
    logger.info(f"Downloading PhishTank phishing URLs (requesting {max_count})...")
    try:
        resp = requests.get(PHISHTANK_URL, timeout=60, stream=True)
        resp.raise_for_status()

        # PhishTank CSV has column: url
        from io import StringIO
        df = pd.read_csv(StringIO(resp.text))
        url_col = "url" if "url" in df.columns else df.columns[1]
        urls = df[url_col].dropna().tolist()
        urls = random.sample(urls, min(max_count, len(urls)))
        logger.info(f"Got {len(urls)} phishing URLs from PhishTank")
        return urls
    except Exception as e:
        logger.warning(f"PhishTank download failed: {e}")
        logger.info("Using bundled sample phishing URLs for demo...")
        return _sample_phishing_urls()[:max_count]


def download_legitimate_urls(max_count: int = 5000) -> list:
    """Download legitimate URLs from a trusted source."""
    logger.info(f"Downloading legitimate URLs (requesting {max_count})...")

    # Try Alexa top 1M (cached locally if available)
    alexa_file = Path("data/alexa_top1m.txt")
    if alexa_file.exists():
        with open(alexa_file) as f:
            urls = [f"https://{line.strip()}" for line in f if line.strip()]
        urls = random.sample(urls, min(max_count, len(urls)))
        logger.info(f"Loaded {len(urls)} legitimate URLs from Alexa cache")
        return urls

    # Fallback: use bundled list
    logger.info("Using bundled sample legitimate URLs...")
    return _sample_legitimate_urls()[:max_count]


def extract_features_batch(urls: list, label: int, extractor: URLFeatureExtractor) -> list:
    """
    Extract features from a list of URLs with progress bar.
    label: 1 = phishing, 0 = legitimate
    """
    rows = []
    failed = 0

    for url in tqdm(urls, desc=f"{'Phishing' if label else 'Legitimate'} URLs"):
        try:
            features = extractor.extract(url)
            features["url"] = url
            features["label"] = label
            rows.append(features)
        except Exception as e:
            failed += 1
            logger.debug(f"Feature extraction failed for {url}: {e}")
        time.sleep(0.05)  # Be polite to WHOIS servers

    logger.info(f"Extracted {len(rows)} features ({failed} failed)")
    return rows


def _sample_phishing_urls() -> list:
    """Built-in sample phishing URLs for testing when PhishTank is unavailable."""
    return [
        "http://paypa1-secure-login.tk/confirm/account",
        "http://192.168.1.100/bankofamerica/signin",
        "http://amazon-account-suspended.ml/verify",
        "http://appleid-locked.cf/unlock",
        "http://microsoft-security-alert.gq/update",
        "http://login-secure-paypal.work/auth",
        "http://netflix-billing-update.click/pay",
        "http://ebay-suspended-account.online/restore",
        "http://gmail-verify-account.xyz/confirm",
        "http://chase-bank-secure.tk/signin",
    ]


def _sample_legitimate_urls() -> list:
    """Built-in sample legitimate URLs for testing."""
    return [
        "https://google.com",
        "https://youtube.com",
        "https://facebook.com",
        "https://amazon.com",
        "https://wikipedia.org",
        "https://twitter.com",
        "https://linkedin.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://reddit.com",
        "https://microsoft.com",
        "https://apple.com",
        "https://netflix.com",
        "https://ebay.com",
        "https://paypal.com",
    ]


def main():
    parser = argparse.ArgumentParser(description="Build PhishGuard training dataset")
    parser.add_argument("--phishing", type=int, default=5000, help="Number of phishing URLs")
    parser.add_argument("--legit", type=int, default=5000, help="Number of legitimate URLs")
    parser.add_argument("--output", default="data/urldata.csv", help="Output CSV path")
    parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookups (faster)")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL checks (faster)")
    args = parser.parse_args()

    Path("data").mkdir(exist_ok=True)

    extractor = URLFeatureExtractor(
        fetch_whois=not args.no_whois,
        fetch_ssl=not args.no_ssl,
        fetch_dns=True,
        follow_redirects=False
    )

    # Download URLs
    phishing_urls = download_phishing_urls(args.phishing)
    legit_urls = download_legitimate_urls(args.legit)

    # Extract features
    logger.info("Extracting features from phishing URLs...")
    phishing_rows = extract_features_batch(phishing_urls, label=1, extractor=extractor)

    logger.info("Extracting features from legitimate URLs...")
    legit_rows = extract_features_batch(legit_urls, label=0, extractor=extractor)

    # Merge and save
    all_rows = phishing_rows + legit_rows
    random.shuffle(all_rows)

    df = pd.DataFrame(all_rows)
    df.to_csv(args.output, index=False)

    logger.info(f"✅ Dataset saved: {args.output}")
    logger.info(f"   Total samples: {len(df)}")
    logger.info(f"   Phishing: {df['label'].sum()} ({df['label'].mean():.1%})")
    logger.info(f"   Legitimate: {(1 - df['label']).sum()}")
    logger.info(f"\nNext step: python src/ml/train.py --data {args.output}")


if __name__ == "__main__":
    main()
