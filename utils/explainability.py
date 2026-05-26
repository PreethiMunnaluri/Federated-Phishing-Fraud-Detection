"""
Explainability utilities for CyberShield AI.
Uses model feature importances and optional SHAP values.
"""

import numpy as np
import re
from typing import Optional


# ─────────────────────────────────────────────────────────────
# Email explainability
# ─────────────────────────────────────────────────────────────

def explain_email_prediction(text: str, model, vectorizer) -> dict:
    """
    Explain an email phishing prediction using Random Forest feature importances.

    Returns:
        top_words: list of (word, importance, direction) tuples
                   direction: 'phishing' or 'safe'
        explanation: human-readable summary string
    """
    if model is None or vectorizer is None:
        return {
            "top_words": [],
            "explanation": "Model not available — no explanation generated.",
        }

    try:
        feature_names = vectorizer.get_feature_names_out()
        importances = model.feature_importances_

        vec = vectorizer.transform([text]).toarray()[0]
        active_indices = np.where(vec > 0)[0]

        scored = []
        for idx in active_indices:
            word = feature_names[idx]
            imp = importances[idx] * vec[idx]
            if imp > 0:
                scored.append((word, round(float(imp), 6), "phishing"))

        # Add top 'safe' indicators (high importance, NOT in text)
        all_imp = list(zip(feature_names, importances))
        top_global = sorted(all_imp, key=lambda x: x[1], reverse=True)[:50]
        for word, imp in top_global:
            if word not in [s[0] for s in scored] and imp > 0:
                scored.append((word, round(float(imp) * 0.1, 6), "context"))

        top_words = sorted(scored, key=lambda x: x[1], reverse=True)[:15]

        phishing_words = [w for w, i, d in top_words if d == "phishing"]
        if phishing_words:
            explanation = (
                f"The top indicators driving the phishing classification are: "
                f"{', '.join(phishing_words[:5])}. "
                f"These terms frequently appear in phishing emails in the training data."
            )
        else:
            explanation = "No strong phishing indicators found in this text."

        return {"top_words": top_words, "explanation": explanation}

    except Exception as e:
        return {"top_words": [], "explanation": f"Explanation failed: {str(e)}"}


# ─────────────────────────────────────────────────────────────
# URL explainability
# ─────────────────────────────────────────────────────────────

def explain_url_prediction(url: str, features: dict) -> dict:
    """
    Return feature importance for URL prediction with intuitive labels.

    Returns:
        feature_importance: list of (feature_name, value, importance_pct, risk_direction)
    """
    # Define importance weights for each feature (based on domain knowledge)
    importance_weights = {
        "has_ip_address":           0.25,
        "tld_suspicious":           0.20,
        "suspicious_keyword_count": 0.18,
        "has_https":                0.10,  # inverse — 0 = bad
        "subdomain_count":          0.08,
        "is_shortened":             0.07,
        "url_length":               0.04,
        "special_char_count":       0.04,
        "hyphen_count":             0.02,
        "digit_count":              0.01,
        "dot_count":                0.01,
    }

    readable_names = {
        "has_ip_address":           "IP Address in URL",
        "tld_suspicious":           "Suspicious TLD",
        "suspicious_keyword_count": "Suspicious Keywords",
        "has_https":                "Uses HTTPS",
        "subdomain_count":          "Subdomain Count",
        "is_shortened":             "URL Shortener",
        "url_length":               "URL Length",
        "special_char_count":       "Special Characters",
        "hyphen_count":             "Hyphens in URL",
        "digit_count":              "Digit Count",
        "dot_count":                "Dot Count",
    }

    result = []
    for key, weight in importance_weights.items():
        val = features.get(key, 0)
        # Determine risk direction
        if key == "has_https":
            risk = "safe" if val == 1 else "risky"
        elif key in ("url_length", "digit_count", "dot_count",
                     "special_char_count", "hyphen_count", "subdomain_count"):
            risk = "risky" if val > 3 else "neutral"
        else:
            risk = "risky" if val > 0 else "safe"

        result.append((
            readable_names.get(key, key),
            val,
            round(weight * 100, 1),
            risk,
        ))

    return {"feature_importance": result}


# ─────────────────────────────────────────────────────────────
# SMS explainability
# ─────────────────────────────────────────────────────────────

def explain_sms_prediction(text: str, model, vectorizer) -> dict:
    """
    Explain an SMS spam prediction. Same approach as email.
    """
    if model is None or vectorizer is None:
        return {"top_words": [], "explanation": "Model not available."}

    try:
        feature_names = vectorizer.get_feature_names_out()

        # For Logistic Regression: use coefficients
        if hasattr(model, "coef_"):
            coef = model.coef_[0]
            vec = vectorizer.transform([text]).toarray()[0]
            active_indices = np.where(vec > 0)[0]

            scored = []
            for idx in active_indices:
                word = feature_names[idx]
                contrib = coef[idx] * vec[idx]
                direction = "spam" if contrib > 0 else "ham"
                scored.append((word, round(float(abs(contrib)), 6), direction))

            top_words = sorted(scored, key=lambda x: x[1], reverse=True)[:15]
            spam_words = [w for w, i, d in top_words if d == "spam"]
            if spam_words:
                explanation = f"Key spam indicators: {', '.join(spam_words[:5])}."
            else:
                explanation = "This message appears to be legitimate (ham)."

        else:
            # Fallback to feature importances
            return explain_email_prediction(text, model, vectorizer)

        return {"top_words": top_words, "explanation": explanation}

    except Exception as e:
        return {"top_words": [], "explanation": f"Explanation failed: {str(e)}"}


# ─────────────────────────────────────────────────────────────
# Fraud explainability
# ─────────────────────────────────────────────────────────────

def explain_fraud_prediction(features: dict, model) -> dict:
    """
    Return feature importance for fraud prediction.

    features should have keys: amount, hour, transaction_freq, location_enc, device_enc
    """
    if model is None:
        return {"feature_importance": [], "explanation": "Model not available."}

    try:
        clf = model.get("classifier") if isinstance(model, dict) else model
        feature_names = ["Amount", "Hour of Day", "Transaction Frequency",
                         "Location", "Device Type"]

        feature_values = [
            features.get("amount", 0),
            features.get("hour", 0),
            features.get("transaction_freq", 0),
            features.get("location_enc", 0),
            features.get("device_enc", 0),
        ]

        if hasattr(clf, "feature_importances_"):
            importances = clf.feature_importances_
        else:
            importances = np.array([0.35, 0.15, 0.20, 0.18, 0.12])

        result = list(zip(feature_names, feature_values,
                          [round(float(i * 100), 1) for i in importances]))

        top_feature = feature_names[int(np.argmax(importances))]
        explanation = f"Most influential factor: {top_feature}. "
        if features.get("amount", 0) > 50000:
            explanation += "High transaction amount is a strong fraud indicator. "
        explanation += "Model uses ensemble of decision trees for fraud detection."

        return {
            "feature_importance": result,
            "explanation": explanation,
        }

    except Exception as e:
        return {"feature_importance": [], "explanation": f"Explanation failed: {str(e)}"}


# ─────────────────────────────────────────────────────────────
# SHAP values (with fallback)
# ─────────────────────────────────────────────────────────────

def get_shap_values(model, X: np.ndarray, feature_names: list) -> dict:
    """
    Compute SHAP values using TreeExplainer.
    Falls back to model.feature_importances_ if SHAP fails.

    Args:
        model:         Fitted sklearn tree-based model
        X:             Feature array (1 or more samples)
        feature_names: List of feature name strings

    Returns:
        shap_values:   2D array (samples x features)
        feature_names: list
    """
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        # For binary classification, shap_values is a list [class0, class1]
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # class 1 (threat)
        return {"shap_values": shap_values, "feature_names": feature_names}

    except Exception:
        # Fallback: use feature_importances_ broadcast across sample
        try:
            importances = model.feature_importances_
            # Expand to match X shape
            if len(X.shape) == 1:
                X = X.reshape(1, -1)
            pseudo_shap = np.tile(importances, (X.shape[0], 1)) * X
            return {"shap_values": pseudo_shap, "feature_names": feature_names}
        except Exception:
            n_features = len(feature_names)
            return {
                "shap_values": np.zeros((1, n_features)),
                "feature_names": feature_names,
            }
