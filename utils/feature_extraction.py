"""
Feature extraction utilities for URLs and fraud transactions.
"""

import re
import numpy as np
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "paypal", "password", "credential", "signin", "ebay",
    "amazon", "alert", "suspend", "urgent", "payment", "prize",
    "winner", "claim", "free", "reward", "validate", "auth",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".cf", ".gq", ".ga", ".xyz",
                   ".top", ".biz", ".info", ".cc", ".pw"]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "is.gd", "clck.ru", "rb.gy", "shorte.st",
]

LOCATION_MAP = {
    "Mumbai": 0, "Delhi": 1, "Bangalore": 2, "Chennai": 3,
    "Hyderabad": 4, "Kolkata": 5, "Pune": 6, "Ahmedabad": 7,
    "Jaipur": 8, "Lucknow": 9, "Unknown": 10,
    "Foreign-IP": 11, "VPN-Detected": 12,
    "Proxy-Server": 13, "Tor-Exit": 14,
}

DEVICE_MAP = {
    "Mobile": 0, "Desktop": 1, "Tablet": 2,
    "ATM": 3, "POS": 4, "Unknown-Device": 5, "Emulator": 6,
}


# ─────────────────────────────────────────────────────────────
# URL Feature Extraction
# ─────────────────────────────────────────────────────────────

def _has_ip_address(url: str) -> int:
    """Check if the URL uses an IP address instead of a domain."""
    pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.match(pattern, url) else 0


def _is_shortened(url: str) -> int:
    """Check if the URL uses a known URL shortener."""
    return 1 if any(s in url.lower() for s in URL_SHORTENERS) else 0


def _tld_suspicious(url: str) -> int:
    """Check if the URL uses a suspicious TLD."""
    url_lower = url.lower()
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            return 1
    return 0


def _get_domain(url: str) -> str:
    """Extract the domain from a URL."""
    try:
        parsed = urlparse(url if "//" in url else f"http://{url}")
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return url


def _get_path(url: str) -> str:
    """Extract the path from a URL."""
    try:
        parsed = urlparse(url if "//" in url else f"http://{url}")
        return parsed.path or "/"
    except Exception:
        return "/"


def extract_url_features(url: str) -> dict:
    """
    Extract features from a URL for malicious URL detection.

    Returns a dict with:
      url_length, dot_count, has_https, has_ip_address, special_char_count,
      suspicious_keyword_count, subdomain_count, path_length, digit_count,
      hyphen_count, is_shortened, tld_suspicious
    """
    url = str(url).strip()
    url_lower = url.lower()

    domain = _get_domain(url)
    path = _get_path(url)

    # Count subdomains (dots in domain minus 1 for TLD, minimum 0)
    subdomain_count = max(0, domain.count(".") - 1)

    features = {
        "url_length":               len(url),
        "dot_count":                url.count("."),
        "has_https":                1 if url_lower.startswith("https") else 0,
        "has_ip_address":           _has_ip_address(url),
        "special_char_count":       sum(url.count(c) for c in ["@", "!", "$", "&", "*", "^", "%", "~", "="]),
        "suspicious_keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),
        "subdomain_count":          subdomain_count,
        "path_length":              len(path),
        "digit_count":              sum(c.isdigit() for c in url),
        "hyphen_count":             url.count("-"),
        "is_shortened":             _is_shortened(url),
        "tld_suspicious":           _tld_suspicious(url),
    }
    return features


def get_suspicious_url_parts(url: str) -> list:
    """
    Return a list of suspicious segments/reasons for a URL.
    Used for explainability UI.
    """
    parts = []
    url_lower = url.lower()

    if _has_ip_address(url):
        parts.append("Uses IP address instead of domain name")

    if _tld_suspicious(url):
        for tld in SUSPICIOUS_TLDS:
            if tld in url_lower:
                parts.append(f"Suspicious TLD: {tld}")
                break

    kws_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if kws_found:
        parts.append(f"Suspicious keywords: {', '.join(kws_found[:5])}")

    domain = _get_domain(url)
    if domain.count(".") > 3:
        parts.append(f"Excessive subdomains ({domain.count('.')} dots)")

    if not url_lower.startswith("https"):
        parts.append("No HTTPS (unencrypted connection)")

    if _is_shortened(url):
        parts.append("URL shortener detected — destination hidden")

    special_count = sum(url.count(c) for c in ["@", "!", "$", "&", "~"])
    if special_count > 2:
        parts.append(f"Unusual special characters ({special_count} found)")

    if len(url) > 100:
        parts.append(f"Unusually long URL ({len(url)} chars)")

    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)
    if digit_ratio > 0.3:
        parts.append("High proportion of digits in URL")

    return parts if parts else ["No specific suspicious parts detected"]


def url_features_to_array(features: dict) -> np.ndarray:
    """Convert URL feature dict to ordered numpy array for model prediction."""
    ordered_keys = [
        "url_length", "dot_count", "has_https", "has_ip_address",
        "special_char_count", "suspicious_keyword_count", "subdomain_count",
        "path_length", "digit_count", "hyphen_count", "is_shortened", "tld_suspicious",
    ]
    return np.array([features.get(k, 0) for k in ordered_keys], dtype=float).reshape(1, -1)


# ─────────────────────────────────────────────────────────────
# Transaction Feature Extraction
# ─────────────────────────────────────────────────────────────

def _encode_location(location: str) -> int:
    """Encode location string to integer."""
    return LOCATION_MAP.get(location, len(LOCATION_MAP))


def _encode_device(device: str) -> int:
    """Encode device type string to integer."""
    return DEVICE_MAP.get(device, len(DEVICE_MAP))


def extract_transaction_features(
    amount: float,
    location: str,
    hour: int,
    device_type: str,
    freq: int,
) -> np.ndarray:
    """
    Extract features for fraud transaction detection.

    Returns a numpy array of shape (1, 5):
      [amount, hour, transaction_freq, location_enc, device_enc]
    """
    features = np.array([
        float(amount),
        float(hour),
        float(freq),
        float(_encode_location(location)),
        float(_encode_device(device_type)),
    ], dtype=float).reshape(1, -1)
    return features


def get_transaction_risk_factors(amount: float, location: str, hour: int,
                                  device_type: str, freq: int) -> list:
    """
    Return human-readable risk factors for a transaction.
    Used for fraud explainability.
    """
    factors = []

    if amount > 50000:
        factors.append(f"Very high transaction amount (₹{amount:,.0f})")
    elif amount > 20000:
        factors.append(f"High transaction amount (₹{amount:,.0f})")

    if hour in [0, 1, 2, 3, 22, 23]:
        factors.append(f"Unusual transaction hour ({hour}:00 — late night/early morning)")

    risky_locations = {"Unknown", "Foreign-IP", "VPN-Detected", "Proxy-Server", "Tor-Exit"}
    if location in risky_locations:
        factors.append(f"Suspicious origin location: {location}")

    risky_devices = {"Unknown-Device", "Emulator"}
    if device_type in risky_devices:
        factors.append(f"Suspicious device type: {device_type}")

    if freq > 10:
        factors.append(f"Abnormally high transaction frequency ({freq} transactions)")
    elif freq > 5:
        factors.append(f"Elevated transaction frequency ({freq} transactions)")

    return factors if factors else ["No specific risk factors detected"]
