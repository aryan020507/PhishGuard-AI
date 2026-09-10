"""
Trusted Domain Authority Service for PhishGuard-AI.
Provides fast-path verification for globally recognized authoritative domains
(e.g., YouTube, Google, GitHub, Microsoft, Wikipedia) to protect against
neural network out-of-distribution false positives on authentic root and apex URLs.
"""

import re
from urllib.parse import urlparse
from typing import Optional, Set

# Curated set of high-reputation, authoritative domains
TRUSTED_AUTHORITY_DOMAINS: Set[str] = {
    # Video & Media
    "youtube.com",
    "youtu.be",
    "vimeo.com",
    "netflix.com",
    "spotify.com",

    # Search & Cloud Providers
    "google.com",
    "googlevideo.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",

    # Developer & Open Source
    "github.com",
    "gitlab.com",
    "stackoverflow.com",
    "python.org",
    "pypi.org",
    "mozilla.org",
    "w3.org",
    "w3schools.com",
    "docker.com",
    "apache.org",

    # Reference, Knowledge & News
    "wikipedia.org",
    "wikimedia.org",
    "archive.org",
    "nytimes.com",
    "bbc.com",
    "reuters.com",
    "arxiv.org",

    # Social & Professional
    "linkedin.com",
    "reddit.com",
    "twitter.com",
    "x.com"
}


def extract_hostname(url: str) -> str:
    """Extract lowercase hostname from URL safely without network calls."""
    target = url.strip()
    if not target:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        target = "http://" + target
    try:
        parsed = urlparse(target)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def is_trusted_domain(hostname: str) -> bool:
    """
    Check if a hostname matches an authoritative trusted domain or legitimate subdomain.
    Example: 'www.youtube.com', 'm.youtube.com', 'youtube.com', 'youtu.be' -> True
             'fake-youtube.com', 'youtube.com.attacker.com' -> False
    """
    if not hostname:
        return False
    host = hostname.lower().strip()
    for trusted in TRUSTED_AUTHORITY_DOMAINS:
        if host == trusted or host.endswith("." + trusted):
            return True
    return False


def is_authentic_trusted_url(url: str, features: dict) -> bool:
    """
    Evaluate whether a URL belongs to a verified trusted authority domain
    and exhibits zero deceptive exploitation markers (e.g. '@' credentials, raw IP, non-standard port).
    """
    hostname = extract_hostname(url)
    if not is_trusted_domain(hostname):
        return False

    # Deceptive markers immediately disqualify even if host appears trusted:
    # 1. Using '@' symbol to mask destination (e.g. 'http://youtube.com@evil.com')
    if features.get("num_at", 0.0) > 0:
        return False

    # 2. Host is a numeric IP
    if features.get("has_ip", 0.0) == 1.0:
        return False

    # 3. Non-standard port bypass
    if features.get("has_port", 0.0) == 1.0:
        return False

    return True
