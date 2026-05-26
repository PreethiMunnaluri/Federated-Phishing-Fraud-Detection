"""
Train all ML models and save as pickle files.
Run standalone: python models/train_models.py
"""

import os
import sys
import pickle
import numpy as np
import pandas as pd

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import re
import joblib

DATASETS_DIR = os.path.join(PROJECT_ROOT, "datasets")
SAVED_MODELS_DIR = os.path.join(PROJECT_ROOT, "saved_models")
os.makedirs(SAVED_MODELS_DIR, exist_ok=True)

# ─────────────────────────────────────────────────
# Shared URL feature extraction (mirrors utils/feature_extraction.py)
# ─────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "paypal", "password", "credential", "signin",
    "alert", "suspend", "urgent", "payment", "prize", "winner",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".cf", ".gq", ".ga", ".xyz", ".top", ".biz", ".info"]


def _has_ip(url: str) -> int:
    pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.match(pattern, url) else 0


def _is_shortened(url: str) -> int:
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.link"]
    return 1 if any(s in url for s in shorteners) else 0


def _tld_suspicious(url: str) -> int:
    return 1 if any(url.endswith(t) or f"{t}/" in url for t in SUSPICIOUS_TLDS) else 0


def extract_url_features_local(url: str) -> list:
    url = str(url).lower()
    parsed_domain = url.split("//")[-1].split("/")[0] if "//" in url else url.split("/")[0]
    path = "/" + "/".join(url.split("//")[-1].split("/")[1:]) if "//" in url else "/"

    features = [
        len(url),                                                                 # url_length
        url.count("."),                                                           # dot_count
        1 if url.startswith("https") else 0,                                     # has_https
        _has_ip(url),                                                             # has_ip_address
        sum(url.count(c) for c in ["@", "!", "$", "&", "*", "^", "%", "~"]),    # special_char_count
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url),                       # suspicious_keyword_count
        max(0, parsed_domain.count(".") - 1),                                     # subdomain_count
        len(path),                                                                # path_length
        sum(c.isdigit() for c in url),                                            # digit_count
        url.count("-"),                                                           # hyphen_count
        _is_shortened(url),                                                       # is_shortened
        _tld_suspicious(url),                                                     # tld_suspicious
    ]
    return features


FEATURE_NAMES = [
    "url_length", "dot_count", "has_https", "has_ip_address", "special_char_count",
    "suspicious_keyword_count", "subdomain_count", "path_length", "digit_count",
    "hyphen_count", "is_shortened", "tld_suspicious",
]


# ─────────────────────────────────────────────────
# 1. Email phishing model
# ─────────────────────────────────────────────────

def train_email_model():
    print("\n[1/4] Training Email Phishing Detection Model...")
    csv_path = os.path.join(DATASETS_DIR, "emails_combined.csv")
    if not os.path.exists(csv_path):
        print(f"  ERROR: {csv_path} not found. Run generate_datasets.py first.")
        return

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["text", "label"])
    X, y = df["text"].astype(str), df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"  Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    joblib.dump(vectorizer, os.path.join(SAVED_MODELS_DIR, "email_vectorizer.pkl"))
    joblib.dump(clf, os.path.join(SAVED_MODELS_DIR, "email_model.pkl"))
    print("  Saved: email_vectorizer.pkl, email_model.pkl")


# ─────────────────────────────────────────────────
# 2. URL detection model
# ─────────────────────────────────────────────────

def train_url_model():
    print("\n[2/4] Training URL Detection Model...")
    csv_path = os.path.join(DATASETS_DIR, "urls_combined.csv")
    if not os.path.exists(csv_path):
        print(f"  ERROR: {csv_path} not found. Run generate_datasets.py first.")
        return

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["url", "label"])

    features = df["url"].apply(extract_url_features_local).tolist()
    X = np.array(features)
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"  Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))

    joblib.dump(clf, os.path.join(SAVED_MODELS_DIR, "url_model.pkl"))
    joblib.dump(FEATURE_NAMES, os.path.join(SAVED_MODELS_DIR, "url_feature_names.pkl"))
    print("  Saved: url_model.pkl, url_feature_names.pkl")


# ─────────────────────────────────────────────────
# 3. SMS spam model
# ─────────────────────────────────────────────────

def train_sms_model():
    print("\n[3/4] Training SMS Spam Detection Model...")
    csv_path = os.path.join(DATASETS_DIR, "sms_combined.csv")
    if not os.path.exists(csv_path):
        print(f"  ERROR: {csv_path} not found. Run generate_datasets.py first.")
        return

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["text", "label"])
    X, y = df["text"].astype(str), df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), sublinear_tf=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = LogisticRegression(max_iter=1000, random_state=42, C=5.0)
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"  Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Ham", "Spam"]))

    joblib.dump(vectorizer, os.path.join(SAVED_MODELS_DIR, "sms_vectorizer.pkl"))
    joblib.dump(clf, os.path.join(SAVED_MODELS_DIR, "sms_model.pkl"))
    print("  Saved: sms_vectorizer.pkl, sms_model.pkl")


# ─────────────────────────────────────────────────
# 4. Fraud transaction model
# ─────────────────────────────────────────────────

def train_fraud_model():
    print("\n[4/4] Training Fraud Transaction Detection Model...")
    csv_path = os.path.join(DATASETS_DIR, "fraud_transactions.csv")
    if not os.path.exists(csv_path):
        print(f"  ERROR: {csv_path} not found. Run generate_datasets.py first.")
        return

    df = pd.read_csv(csv_path)
    df = df.dropna()

    # Encode categorical features
    loc_encoder = LabelEncoder()
    dev_encoder = LabelEncoder()
    df["location_enc"] = loc_encoder.fit_transform(df["location"])
    df["device_enc"] = dev_encoder.fit_transform(df["device_type"])

    feature_cols = ["amount", "hour", "transaction_freq", "location_enc", "device_enc"]
    X = df[feature_cols].values
    y = df["is_fraud"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Isolation Forest for anomaly scoring
    iso_forest = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
    iso_forest.fit(X_train)

    # Random Forest classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1,
                                  class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"  Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Fraud"]))

    encoders = {
        "location_encoder": loc_encoder,
        "device_encoder": dev_encoder,
        "location_classes": list(loc_encoder.classes_),
        "device_classes": list(dev_encoder.classes_),
        "feature_cols": feature_cols,
    }

    fraud_bundle = {
        "classifier": clf,
        "isolation_forest": iso_forest,
        "feature_cols": feature_cols,
    }

    joblib.dump(fraud_bundle, os.path.join(SAVED_MODELS_DIR, "fraud_model.pkl"))
    joblib.dump(encoders, os.path.join(SAVED_MODELS_DIR, "fraud_encoders.pkl"))
    print("  Saved: fraud_model.pkl, fraud_encoders.pkl")


# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("CyberShield AI - Model Training Pipeline")
    print("=" * 60)
    train_email_model()
    train_url_model()
    train_sms_model()
    train_fraud_model()
    print("\n" + "=" * 60)
    print("All models trained and saved successfully!")
    print(f"Models stored in: {SAVED_MODELS_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()
