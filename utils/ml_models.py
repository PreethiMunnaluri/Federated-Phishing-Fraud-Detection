"""
ML model loading, caching, and prediction interface.
Models are loaded once via @st.cache_resource.
Falls back to rule-based predictions if models are not found.
"""

import os
import sys
import subprocess
import numpy as np
import streamlit as st

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAVED_MODELS_DIR = os.path.join(PROJECT_ROOT, "saved_models")

# Make sure utils/ is importable
sys.path.insert(0, PROJECT_ROOT)

from utils.feature_extraction import (
    extract_url_features, url_features_to_array, get_suspicious_url_parts,
    extract_transaction_features, get_transaction_risk_factors,
    SUSPICIOUS_KEYWORDS,
)


# ─────────────────────────────────────────────────────────────
# Model loader
# ─────────────────────────────────────────────────────────────

def _try_load(path: str):
    """Load a joblib/pickle file, return None on failure."""
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        return None


def _auto_train():
    """Attempt to auto-train models by running the training script."""
    train_script = os.path.join(PROJECT_ROOT, "models", "train_models.py")
    if os.path.exists(train_script):
        try:
            subprocess.run(
                [sys.executable, train_script],
                timeout=300,
                capture_output=True,
            )
        except Exception:
            pass


@st.cache_resource(show_spinner=False)
def load_all_models() -> dict:
    """
    Load all trained models. If not found, attempt auto-training.
    Returns a dict with model objects (or None for missing ones).
    """
    def _path(name):
        return os.path.join(SAVED_MODELS_DIR, name)

    models = {
        "email_vectorizer": _try_load(_path("email_vectorizer.pkl")),
        "email_model":      _try_load(_path("email_model.pkl")),
        "url_model":        _try_load(_path("url_model.pkl")),
        "url_feature_names":_try_load(_path("url_feature_names.pkl")),
        "sms_vectorizer":   _try_load(_path("sms_vectorizer.pkl")),
        "sms_model":        _try_load(_path("sms_model.pkl")),
        "fraud_model":      _try_load(_path("fraud_model.pkl")),
        "fraud_encoders":   _try_load(_path("fraud_encoders.pkl")),
    }

    # If critical models missing, try auto-train once
    if models["email_model"] is None or models["url_model"] is None:
        _auto_train()
        models = {
            "email_vectorizer": _try_load(_path("email_vectorizer.pkl")),
            "email_model":      _try_load(_path("email_model.pkl")),
            "url_model":        _try_load(_path("url_model.pkl")),
            "url_feature_names":_try_load(_path("url_feature_names.pkl")),
            "sms_vectorizer":   _try_load(_path("sms_vectorizer.pkl")),
            "sms_model":        _try_load(_path("sms_model.pkl")),
            "fraud_model":      _try_load(_path("fraud_model.pkl")),
            "fraud_encoders":   _try_load(_path("fraud_encoders.pkl")),
        }

    return models


# ─────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────

def _risk_score_from_prob(prob: float) -> int:
    """Convert a 0-1 probability to a 0-100 risk score."""
    return int(round(prob * 100))


def _threat_level_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


def _rule_based_text_score(text: str) -> float:
    """Simple keyword-based heuristic, returns 0-1 probability of spam/phishing."""
    text_lower = text.lower()
    bad_keywords = [
        "urgent", "verify", "account", "suspended", "otp", "click here",
        "prize", "won", "claim", "free", "bank", "password", "reset",
        "blocked", "transaction", "fraud", "kyc", "update", "immediately",
    ]
    score = sum(1 for kw in bad_keywords if kw in text_lower)
    return min(score / 6.0, 1.0)


def _extract_suspicious_phrases(text: str) -> list:
    bad_keywords = [
        "urgent", "verify", "account suspended", "otp", "click here",
        "prize", "won", "claim", "free offer", "bank", "password reset",
        "account blocked", "transaction failed", "fraud alert",
        "kyc update", "update immediately", "call now", "wire transfer",
    ]
    return [kw for kw in bad_keywords if kw in text.lower()]


# ─────────────────────────────────────────────────────────────
# Email prediction
# ─────────────────────────────────────────────────────────────

def predict_email(text: str) -> dict:
    """
    Predict whether an email is phishing or safe.

    Returns:
        label: 'PHISHING' | 'SAFE'
        probability: float (0-1)
        risk_score: int (0-100)
        threat_level: str
        top_features: list of (word, importance) tuples
    """
    models = load_all_models()
    vectorizer = models.get("email_vectorizer")
    clf = models.get("email_model")

    top_features = []

    if vectorizer is not None and clf is not None:
        try:
            vec = vectorizer.transform([text])
            prob = clf.predict_proba(vec)[0][1]  # probability of phishing
            label = "PHISHING" if prob >= 0.5 else "SAFE"

            # Extract top contributing features
            feature_names = vectorizer.get_feature_names_out()
            importances = clf.feature_importances_
            vec_array = vec.toarray()[0]
            active_mask = vec_array > 0
            active_features = [
                (feature_names[i], importances[i] * vec_array[i])
                for i in range(len(feature_names))
                if active_mask[i]
            ]
            top_features = sorted(active_features, key=lambda x: x[1], reverse=True)[:10]
        except Exception:
            prob = _rule_based_text_score(text)
            label = "PHISHING" if prob >= 0.5 else "SAFE"
    else:
        prob = _rule_based_text_score(text)
        label = "PHISHING" if prob >= 0.5 else "SAFE"

    risk_score = _risk_score_from_prob(prob)
    return {
        "label": label,
        "probability": round(float(prob), 4),
        "risk_score": risk_score,
        "threat_level": _threat_level_from_score(risk_score),
        "top_features": top_features,
    }


# ─────────────────────────────────────────────────────────────
# URL prediction
# ─────────────────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Predict whether a URL is malicious, suspicious, or safe.

    Returns:
        label: 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE'
        probability: float
        risk_score: int
        threat_level: str
        suspicious_parts: list
        features: dict
    """
    models = load_all_models()
    clf = models.get("url_model")
    features = extract_url_features(url)
    suspicious_parts = get_suspicious_url_parts(url)
    X = url_features_to_array(features)

    if clf is not None:
        try:
            prob = clf.predict_proba(X)[0][1]
        except Exception:
            prob = _rule_based_url_score(features)
    else:
        prob = _rule_based_url_score(features)

    risk_score = _risk_score_from_prob(prob)
    if risk_score >= 70:
        label = "MALICIOUS"
    elif risk_score >= 40:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    return {
        "label": label,
        "probability": round(float(prob), 4),
        "risk_score": risk_score,
        "threat_level": _threat_level_from_score(risk_score),
        "suspicious_parts": suspicious_parts,
        "features": features,
    }


def _rule_based_url_score(features: dict) -> float:
    score = 0.0
    if features.get("has_ip_address"):      score += 0.35
    if features.get("tld_suspicious"):      score += 0.25
    if not features.get("has_https"):       score += 0.10
    score += min(features.get("suspicious_keyword_count", 0) * 0.07, 0.35)
    if features.get("subdomain_count", 0) > 3: score += 0.10
    if features.get("is_shortened"):        score += 0.15
    if features.get("url_length", 0) > 100:score += 0.05
    return min(score, 1.0)


# ─────────────────────────────────────────────────────────────
# SMS prediction
# ─────────────────────────────────────────────────────────────

def predict_sms(text: str) -> dict:
    """
    Predict whether an SMS is spam or ham.

    Returns:
        label: 'SPAM' | 'HAM'
        probability: float
        risk_score: int
        threat_level: str
        suspicious_phrases: list
    """
    models = load_all_models()
    vectorizer = models.get("sms_vectorizer")
    clf = models.get("sms_model")
    suspicious_phrases = _extract_suspicious_phrases(text)

    if vectorizer is not None and clf is not None:
        try:
            vec = vectorizer.transform([text])
            prob = clf.predict_proba(vec)[0][1]
        except Exception:
            prob = _rule_based_text_score(text)
    else:
        prob = _rule_based_text_score(text)

    label = "SPAM" if prob >= 0.5 else "HAM"
    risk_score = _risk_score_from_prob(prob)
    return {
        "label": label,
        "probability": round(float(prob), 4),
        "risk_score": risk_score,
        "threat_level": _threat_level_from_score(risk_score),
        "suspicious_phrases": suspicious_phrases,
    }


# ─────────────────────────────────────────────────────────────
# Fraud prediction
# ─────────────────────────────────────────────────────────────

def predict_fraud(
    amount: float,
    location: str,
    hour: int,
    device: str,
    freq: int,
) -> dict:
    """
    Predict whether a transaction is fraudulent.

    Returns:
        label: 'FRAUD' | 'NORMAL'
        probability: float
        risk_score: int
        threat_level: str
        risk_factors: list
    """
    models = load_all_models()
    fraud_bundle = models.get("fraud_model")
    fraud_encoders = models.get("fraud_encoders")
    risk_factors = get_transaction_risk_factors(amount, location, hour, device, freq)

    if fraud_bundle is not None:
        try:
            clf = fraud_bundle["classifier"]
            loc_enc = fraud_encoders["location_encoder"]
            dev_enc = fraud_encoders["device_encoder"]

            # Encode with fitted encoders; handle unseen values
            loc_classes = list(loc_enc.classes_)
            dev_classes = list(dev_enc.classes_)
            loc_val = loc_enc.transform([location])[0] if location in loc_classes else len(loc_classes)
            dev_val = dev_enc.transform([device])[0] if device in dev_classes else len(dev_classes)

            X = np.array([[amount, hour, freq, loc_val, dev_val]], dtype=float)
            prob = clf.predict_proba(X)[0][1]
        except Exception:
            prob = _rule_based_fraud_score(amount, location, hour, device, freq)
    else:
        prob = _rule_based_fraud_score(amount, location, hour, device, freq)

    label = "FRAUD" if prob >= 0.5 else "NORMAL"
    risk_score = _risk_score_from_prob(prob)
    return {
        "label": label,
        "probability": round(float(prob), 4),
        "risk_score": risk_score,
        "threat_level": _threat_level_from_score(risk_score),
        "risk_factors": risk_factors,
    }


def _rule_based_fraud_score(amount, location, hour, device, freq) -> float:
    score = 0.0
    if amount > 50000:   score += 0.35
    elif amount > 20000: score += 0.15
    risky_locs = {"Unknown", "Foreign-IP", "VPN-Detected", "Proxy-Server", "Tor-Exit"}
    if location in risky_locs: score += 0.30
    if hour in [0, 1, 2, 3, 22, 23]: score += 0.15
    risky_devs = {"Unknown-Device", "Emulator"}
    if device in risky_devs: score += 0.20
    if freq > 10: score += 0.20
    elif freq > 5: score += 0.08
    return min(score, 1.0)
