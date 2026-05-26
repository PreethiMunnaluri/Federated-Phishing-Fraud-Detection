"""
Threat logging utilities for CyberShield AI.
Stores threats in logs/threats.json.
"""

import os
import json
import uuid
from datetime import datetime, timedelta
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
THREATS_FILE = os.path.join(LOGS_DIR, "threats.json")

os.makedirs(LOGS_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────

def _load_threats() -> list:
    """Load threats from JSON file."""
    if not os.path.exists(THREATS_FILE):
        return []
    try:
        with open(THREATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def _save_threats(threats: list):
    """Save threats list to JSON file."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(THREATS_FILE, "w", encoding="utf-8") as f:
        json.dump(threats, f, indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def log_threat(
    threat_type: str,
    details: dict,
    severity: str,
    username: str = "system",
):
    """
    Append a threat entry to logs/threats.json.

    Args:
        threat_type: e.g. 'phishing_email', 'malicious_url', 'sms_spam', 'fraud_transaction'
        details: dict of relevant data (text snippet, url, amount, etc.)
        severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        username: who triggered the scan
    """
    threats = _load_threats()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "threat_type": threat_type,
        "severity": severity.upper(),
        "details": details,
        "username": username,
    }
    threats.append(entry)
    _save_threats(threats)


def get_threats(limit: int = 100, threat_type: str = None) -> list:
    """
    Return recent threats, newest first.

    Args:
        limit: max number of entries to return
        threat_type: filter by type if provided
    """
    threats = _load_threats()
    if threat_type:
        threats = [t for t in threats if t.get("threat_type") == threat_type]
    # Sort newest first
    threats = sorted(threats, key=lambda x: x.get("timestamp", ""), reverse=True)
    return threats[:limit]


def get_threat_stats() -> dict:
    """
    Return aggregate statistics about logged threats.

    Returns dict:
        total, by_type{}, by_severity{}, recent_24h, by_hour{}
    """
    threats = _load_threats()
    now = datetime.utcnow()
    cutoff_24h = now - timedelta(hours=24)

    by_type = {}
    by_severity = {}
    by_hour = {h: 0 for h in range(24)}
    recent_24h = 0

    for t in threats:
        tt = t.get("threat_type", "unknown")
        by_type[tt] = by_type.get(tt, 0) + 1

        sv = t.get("severity", "MEDIUM")
        by_severity[sv] = by_severity.get(sv, 0) + 1

        ts_str = t.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            if ts >= cutoff_24h:
                recent_24h += 1
            by_hour[ts.hour] = by_hour.get(ts.hour, 0) + 1
        except (ValueError, AttributeError):
            pass

    return {
        "total": len(threats),
        "by_type": by_type,
        "by_severity": by_severity,
        "recent_24h": recent_24h,
        "by_hour": by_hour,
    }


def clear_old_threats(days: int = 30):
    """Remove threats older than N days."""
    threats = _load_threats()
    cutoff = datetime.utcnow() - timedelta(days=days)
    filtered = []
    for t in threats:
        ts_str = t.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            if ts >= cutoff:
                filtered.append(t)
        except (ValueError, AttributeError):
            filtered.append(t)  # keep if unparseable
    _save_threats(filtered)
    return len(threats) - len(filtered)


def get_threat_timeline(hours: int = 24) -> pd.DataFrame:
    """
    Return a DataFrame with hourly threat counts over the last N hours.

    Columns: hour_label, count, threat_type
    """
    threats = _load_threats()
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=hours)

    rows = []
    for t in threats:
        ts_str = t.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            if ts >= cutoff:
                rows.append({
                    "timestamp": ts,
                    "hour": ts.strftime("%Y-%m-%d %H:00"),
                    "threat_type": t.get("threat_type", "unknown"),
                    "severity": t.get("severity", "MEDIUM"),
                })
        except (ValueError, AttributeError):
            pass

    if not rows:
        return pd.DataFrame(columns=["hour", "count", "threat_type"])

    df = pd.DataFrame(rows)
    timeline = (
        df.groupby(["hour", "threat_type"])
        .size()
        .reset_index(name="count")
        .sort_values("hour")
    )
    return timeline
