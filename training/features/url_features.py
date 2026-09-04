"""
Static URL Feature Extraction Module for PhishGuard-AI.
Extracts 16 structural, statistical, and lexical features locally without any external network calls.
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, List, Any
import numpy as np

URL_FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question_marks",
    "num_equal_signs",
    "num_slashes",
    "num_digits",
    "digit_ratio",
    "has_https",
    "has_ip",
    "num_subdomains",
    "suspicious_keywords_count",
    "has_port",
    "entropy",
    "has_shortener",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking", "secure",
    "signin", "confirm", "password", "paypal", "ebayisapi", "wallet",
    "alert", "authenticate", "billing", "support", "admin", "service",
    "webscr", "recover", "security", "customer", "validation"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly"
}

IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob_dist if p > 0)


def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extract a dictionary of 16 numerical features from a URL string.
    Ensures safe, completely local extraction.
    """
    cleaned_url = url.strip()
    if not cleaned_url:
        return {name: 0.0 for name in URL_FEATURE_NAMES}

    # Prepend scheme if missing for uniform parsing
    parse_target = cleaned_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url):
        parse_target = "http://" + cleaned_url

    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()
    except Exception:
        hostname = ""
        netloc = ""

    url_lower = cleaned_url.lower()

    # 1. url_length
    url_length = float(len(cleaned_url))

    # 2. num_dots
    num_dots = float(cleaned_url.count("."))

    # 3. num_hyphens
    num_hyphens = float(cleaned_url.count("-"))

    # 4. num_at
    num_at = float(cleaned_url.count("@"))

    # 5. num_question_marks
    num_question_marks = float(cleaned_url.count("?"))

    # 6. num_equal_signs
    num_equal_signs = float(cleaned_url.count("="))

    # 7. num_slashes
    num_slashes = float(cleaned_url.count("/"))

    # 8. num_digits
    num_digits = float(sum(c.isdigit() for c in cleaned_url))

    # 9. digit_ratio
    digit_ratio = float(num_digits / max(len(cleaned_url), 1))

    # 10. has_https
    has_https = 1.0 if url_lower.startswith("https://") else 0.0

    # 11. has_ip (IPv4 / IPv6)
    has_ip = 1.0 if IPV4_PATTERN.match(hostname) else 0.0

    # 12. num_subdomains
    if hostname:
        parts = hostname.split(".")
        # Standard domain like example.com has 2 parts (0 subdomains).
        # foo.example.com has 3 parts (1 subdomain).
        num_subdomains = float(max(0, len(parts) - 2))
    else:
        num_subdomains = 0.0

    # 13. suspicious_keywords_count
    suspicious_keywords_count = float(
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    )

    # 14. has_port
    has_port = 0.0
    if ":" in netloc:
        port_part = netloc.split(":")[-1]
        if port_part.isdigit() and port_part not in ("80", "443"):
            has_port = 1.0

    # 15. entropy
    entropy = float(calculate_entropy(cleaned_url))

    # 16. has_shortener
    has_shortener = 1.0 if hostname in SHORTENER_DOMAINS else 0.0

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_question_marks": num_question_marks,
        "num_equal_signs": num_equal_signs,
        "num_slashes": num_slashes,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "has_https": has_https,
        "has_ip": has_ip,
        "num_subdomains": num_subdomains,
        "suspicious_keywords_count": suspicious_keywords_count,
        "has_port": has_port,
        "entropy": entropy,
        "has_shortener": has_shortener,
    }


def url_to_feature_vector(url: str) -> np.ndarray:
    """Extract features and return as a 1D numpy array in fixed feature order."""
    features = extract_url_features(url)
    return np.array([features[name] for name in URL_FEATURE_NAMES], dtype=np.float32)
