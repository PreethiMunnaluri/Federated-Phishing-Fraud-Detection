"""
Federated learning simulation for CyberShield AI.
"""

import os
import json
import numpy as np
import random
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FL_HISTORY_FILE = os.path.join(PROJECT_ROOT, "logs", "fl_history.json")
os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)

CLIENTS = [
    "Client A (Bank)",
    "Client B (Telecom)",
    "Client C (E-commerce)",
    "Client D (Healthcare)",
]

# Simulated local dataset sizes per client
CLIENT_SAMPLES = {
    "Client A (Bank)":       4500,
    "Client B (Telecom)":    3200,
    "Client C (E-commerce)": 5800,
    "Client D (Healthcare)": 2100,
}

# Base accuracy per client (improves with rounds)
CLIENT_BASE_ACCURACY = {
    "Client A (Bank)":       0.78,
    "Client B (Telecom)":    0.74,
    "Client C (E-commerce)": 0.81,
    "Client D (Healthcare)": 0.70,
}

WEIGHT_DIM = 32  # Simulated weight vector dimension


# ─────────────────────────────────────────────────────────────
# FedAvg aggregation
# ─────────────────────────────────────────────────────────────

def fedavg(client_weights: list, client_samples: list) -> np.ndarray:
    """
    Federated Averaging (FedAvg) aggregation.
    Weighted average of client weight vectors by sample count.

    Args:
        client_weights: list of np.ndarray
        client_samples: list of int (sample counts)

    Returns:
        Aggregated global weight vector
    """
    total_samples = sum(client_samples)
    if total_samples == 0:
        return np.mean(client_weights, axis=0)

    aggregated = np.zeros_like(client_weights[0], dtype=float)
    for weights, n in zip(client_weights, client_samples):
        aggregated += (n / total_samples) * weights
    return aggregated


# ─────────────────────────────────────────────────────────────
# Differential privacy helpers (inline, lightweight)
# ─────────────────────────────────────────────────────────────

def _clip_weights(weights: np.ndarray, max_norm: float = 1.0) -> np.ndarray:
    norm = np.linalg.norm(weights)
    if norm > max_norm:
        weights = weights * (max_norm / norm)
    return weights


def _add_gaussian_noise_inline(weights: np.ndarray, epsilon: float, sensitivity: float = 1.0) -> np.ndarray:
    sigma = np.sqrt(2 * np.log(1.25 / 1e-5)) * sensitivity / max(epsilon, 0.01)
    noise = np.random.normal(0, sigma, size=weights.shape)
    return weights + noise


# ─────────────────────────────────────────────────────────────
# Simulation core
# ─────────────────────────────────────────────────────────────

def simulate_federated_round(
    round_num: int = 1,
    n_clients: int = 4,
    epsilon: float = 1.0,
) -> dict:
    """
    Simulate one round of federated learning.

    Each client "trains" on local data (simulated accuracy improvement),
    the server aggregates weights using FedAvg.

    Returns:
        round, client_results, global_accuracy, aggregated_weights, privacy_applied
    """
    rng = np.random.RandomState(round_num * 137)
    selected_clients = CLIENTS[:n_clients]

    client_results = []
    all_weights = []
    all_samples = []

    for client in selected_clients:
        n_samples = CLIENT_SAMPLES[client]
        base_acc = CLIENT_BASE_ACCURACY[client]

        # Accuracy improves with round number, with diminishing returns + noise
        improvement = 0.15 * (1 - np.exp(-0.3 * round_num))
        noise = rng.normal(0, 0.01)
        local_accuracy = min(base_acc + improvement + noise, 0.99)

        # Simulate weight vector (random unit-sphere direction, scaled by accuracy)
        raw_weights = rng.randn(WEIGHT_DIM).astype(float)
        weights = raw_weights / (np.linalg.norm(raw_weights) + 1e-8) * local_accuracy

        # Apply differential privacy
        if epsilon < 5.0:
            weights = _clip_weights(weights, max_norm=1.0)
            weights = _add_gaussian_noise_inline(weights, epsilon=epsilon)

        client_results.append({
            "client":         client,
            "local_accuracy": round(float(local_accuracy), 4),
            "samples":        n_samples,
            "weight":         weights.tolist(),
            "loss":           round(float(1.0 - local_accuracy + rng.uniform(0, 0.05)), 4),
        })
        all_weights.append(weights)
        all_samples.append(n_samples)

    # Server aggregation
    aggregated = fedavg(all_weights, all_samples)
    global_accuracy = float(np.mean([r["local_accuracy"] for r in client_results]))
    global_accuracy = round(global_accuracy + rng.uniform(0.005, 0.015), 4)

    return {
        "round":               round_num,
        "timestamp":           datetime.utcnow().isoformat() + "Z",
        "client_results":      client_results,
        "global_accuracy":     min(global_accuracy, 0.99),
        "aggregated_weights":  aggregated.tolist(),
        "privacy_applied":     epsilon < 5.0,
        "epsilon":             epsilon,
        "n_clients":           n_clients,
    }


# ─────────────────────────────────────────────────────────────
# FL History persistence
# ─────────────────────────────────────────────────────────────

def get_fl_history() -> list:
    """Return all simulated rounds from fl_history.json, newest first."""
    if not os.path.exists(FL_HISTORY_FILE):
        return []
    try:
        with open(FL_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def save_fl_round(round_data: dict):
    """Append a round result to fl_history.json."""
    history = get_fl_history()
    # Strip weight arrays to keep file manageable
    compact = {k: v for k, v in round_data.items() if k != "aggregated_weights"}
    compact["client_results"] = [
        {k2: v2 for k2, v2 in cr.items() if k2 != "weight"}
        for cr in round_data.get("client_results", [])
    ]
    history.append(compact)
    with open(FL_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


# ─────────────────────────────────────────────────────────────
# Trust scores & adversarial detection
# ─────────────────────────────────────────────────────────────

def get_client_trust_scores() -> dict:
    """
    Return a trust score (0-1) for each client based on historical performance.
    Higher = more trustworthy.
    """
    history = get_fl_history()
    if not history:
        # Default scores
        return {c: round(random.uniform(0.85, 0.98), 3) for c in CLIENTS}

    scores = {c: [] for c in CLIENTS}
    for round_data in history:
        for cr in round_data.get("client_results", []):
            client = cr.get("client")
            if client in scores:
                scores[client].append(cr.get("local_accuracy", 0.8))

    trust = {}
    for c in CLIENTS:
        if scores[c]:
            trust[c] = round(float(np.mean(scores[c])), 3)
        else:
            trust[c] = round(random.uniform(0.85, 0.98), 3)
    return trust


def simulate_adversarial_client(client_name: str) -> dict:
    """
    Simulate a poisoned model update from a client.
    Returns suspicious weight patterns (flipped / noisy).
    """
    rng = np.random.RandomState(hash(client_name) % (2 ** 31))
    # Adversarial: flipped signs + large magnitude noise
    bad_weights = -1 * rng.randn(WEIGHT_DIM) * 5.0
    return {
        "client":          client_name,
        "local_accuracy":  round(rng.uniform(0.3, 0.55), 4),
        "samples":         CLIENT_SAMPLES.get(client_name, 1000),
        "weight":          bad_weights.tolist(),
        "is_adversarial":  True,
        "anomaly_score":   round(float(np.linalg.norm(bad_weights)), 3),
    }


def detect_adversarial_updates(client_weights: list) -> list:
    """
    Detect potentially adversarial client updates using statistical analysis.

    Args:
        client_weights: list of {"client": str, "weight": list}

    Returns:
        list of {"client": str, "suspicion_score": float, "flagged": bool}
    """
    if not client_weights:
        return []

    weight_arrays = [np.array(cw["weight"]) for cw in client_weights]
    norms = [np.linalg.norm(w) for w in weight_arrays]
    mean_norm = np.mean(norms)
    std_norm = np.std(norms) + 1e-8

    results = []
    for cw, norm in zip(client_weights, norms):
        z_score = abs(norm - mean_norm) / std_norm
        # Also check cosine similarity with mean weight
        mean_weight = np.mean(weight_arrays, axis=0)
        cos_sim = np.dot(np.array(cw["weight"]), mean_weight) / (
            np.linalg.norm(cw["weight"]) * np.linalg.norm(mean_weight) + 1e-8
        )
        suspicion = min((z_score / 5.0 + max(0, -cos_sim) * 0.5), 1.0)
        results.append({
            "client":          cw["client"],
            "suspicion_score": round(float(suspicion), 3),
            "norm":            round(float(norm), 3),
            "cosine_sim":      round(float(cos_sim), 3),
            "flagged":         suspicion > 0.4,
        })
    return results
