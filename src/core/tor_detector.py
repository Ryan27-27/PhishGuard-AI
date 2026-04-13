"""
tor_detector.py — Real-Time Tor Exit Node Detection

Downloads and caches the official Tor Project exit node list,
then checks if a given IP resolves to a known Tor exit node.

Tor exit nodes are heavily abused for phishing & anonymized attacks.
"""

import ipaddress
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Set
import logging

import requests

logger = logging.getLogger(__name__)

# Official Tor Project exit node list (updated every ~30 minutes by Tor Project)
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

# Dan Pollock's list as fallback
TOR_FALLBACK_URL = "https://www.dan.me.uk/torlist/"

# DNS-based check: query <reversed-IP>.dnsel.torproject.org
# If it resolves to 127.0.0.2, it's a Tor exit node
TOR_DNSEL = "dnsel.torproject.org"


class TorExitNodeDetector:
    """
    Maintains a cached set of Tor exit node IPs and checks URLs/IPs against it.

    Features:
    - Downloads Tor exit list from official source
    - Falls back to DNS-based real-time lookup (most reliable)
    - Auto-refreshes cache every `refresh_interval` seconds
    - Thread-safe

    Usage:
        detector = TorExitNodeDetector()
        detector.load()  # downloads list once
        is_tor = detector.is_tor_exit("1.2.3.4")
    """

    def __init__(self, refresh_interval: int = 1800, use_dns_fallback: bool = True):
        self._exit_nodes: Set[str] = set()
        self._lock = threading.RLock()
        self._last_refresh: Optional[datetime] = None
        self.refresh_interval = refresh_interval
        self.use_dns_fallback = use_dns_fallback
        self._loaded = False

    def load(self) -> bool:
        """Download and parse the Tor exit node list. Returns True on success."""
        with self._lock:
            try:
                resp = requests.get(TOR_EXIT_LIST_URL, timeout=15)
                resp.raise_for_status()
                ips = {
                    line.strip()
                    for line in resp.text.splitlines()
                    if line.strip() and not line.startswith("#")
                }
                self._exit_nodes = ips
                self._last_refresh = datetime.now(timezone.utc)
                self._loaded = True
                logger.info(f"[TorDetector] Loaded {len(ips)} Tor exit nodes")
                return True
            except Exception as e:
                logger.warning(f"[TorDetector] Failed to load exit list: {e}. Falling back to DNS.")
                self._loaded = False
                return False

    def _needs_refresh(self) -> bool:
        if self._last_refresh is None:
            return True
        elapsed = (datetime.now(timezone.utc) - self._last_refresh).total_seconds()
        return elapsed > self.refresh_interval

    def _auto_refresh(self):
        if self._needs_refresh():
            self.load()

    def _dns_check(self, ip: str) -> bool:
        """
        Real-time DNS-based Tor exit node check via DNSEL.
        Constructs: <reversed-ip>.dnsel.torproject.org
        If resolves to 127.0.0.2 → confirmed Tor exit node.
        """
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.{TOR_DNSEL}"
            result = socket.gethostbyname(query)
            return result == "127.0.0.2"
        except socket.gaierror:
            return False  # NXDOMAIN = not a Tor exit node
        except Exception as e:
            logger.debug(f"[TorDetector] DNS check error for {ip}: {e}")
            return False

    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve a hostname to its IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def is_tor_exit(self, host: str) -> bool:
        """
        Check if a host (IP or hostname) is a known Tor exit node.

        Priority:
          1. Cached exit node list (fast)
          2. Real-time DNS check via DNSEL (accurate)

        Args:
            host: IP address or hostname string

        Returns:
            True if the host is a Tor exit node
        """
        self._auto_refresh()

        # Resolve hostname to IP if needed
        ip = host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ip = self._resolve_hostname(host)
            if not ip:
                return False

        # 1. Check cached list
        with self._lock:
            if ip in self._exit_nodes:
                logger.info(f"[TorDetector] ✓ Tor exit node (cached): {ip}")
                return True

        # 2. Real-time DNS-based check
        if self.use_dns_fallback:
            result = self._dns_check(ip)
            if result:
                logger.info(f"[TorDetector] ✓ Tor exit node (DNS): {ip}")
                with self._lock:
                    self._exit_nodes.add(ip)  # Cache for future
            return result

        return False

    def check_url(self, url: str) -> bool:
        """
        Check if the host in a URL is a Tor exit node.

        Args:
            url: Full URL string

        Returns:
            True if the URL's server IP is a Tor exit node
        """
        from urllib.parse import urlparse
        try:
            hostname = urlparse(url).hostname or ""
            return self.is_tor_exit(hostname)
        except Exception:
            return False

    @property
    def node_count(self) -> int:
        """Number of known exit nodes currently cached."""
        return len(self._exit_nodes)

    @property
    def last_updated(self) -> Optional[datetime]:
        return self._last_refresh


# Global singleton instance
_detector_instance: Optional[TorExitNodeDetector] = None


def get_tor_detector() -> TorExitNodeDetector:
    """Get or create the global TorExitNodeDetector singleton."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = TorExitNodeDetector()
        _detector_instance.load()
    return _detector_instance
