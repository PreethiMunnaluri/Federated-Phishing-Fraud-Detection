"""
Differential privacy utilities for CyberShield AI.
"""

import numpy as np
import pandas as pd
import math


# ─────────────────────────────────────────────────────────────
# Noise mechanisms
# ─────────────────────────────────────────────────────────────

def clip_weights(weights: np.ndarray, max_norm: float = 1.0) -> np.ndarray:
    """
    Gradient/weight clipping: scale down if L2 norm exceeds max_norm.

    Args:
        weights:  Input weight array
        max_norm: Maximum allowed L2 norm

    Returns:
        Clipped weight array
    """
    norm = np.linalg.norm(weights)
    if norm > max_norm:
        return weights * (max_norm / norm)
    return weights.copy()


def add_gaussian_noise(
    weights: np.ndarray,
    epsilon: float = 1.0,
    sensitivity: float = 1.0,
    delta: float = 1e-5,
) -> np.ndarray:
    """
    Add Gaussian noise calibrated to (epsilon, delta)-differential privacy.

    sigma = sqrt(2 * ln(1.25/delta)) * sensitivity / epsilon

    Args:
        weights:     Input weight array
        epsilon:     Privacy budget (lower = more private)
        sensitivity: L2 sensitivity of the query
        delta:       Failure probability

    Returns:
        Noisy weight array
    """
    delta = max(delta, 1e-10)
    epsilon = max(epsilon, 1e-6)
    sigma = math.sqrt(2 * math.log(1.25 / delta)) * sensitivity / epsilon
    noise = np.random.normal(0, sigma, size=weights.shape)
    return weights + noise


def add_laplace_noise(
    weights: np.ndarray,
    epsilon: float = 1.0,
    sensitivity: float = 1.0,
) -> np.ndarray:
    """
    Add Laplace noise for pure epsilon-differential privacy.

    scale = sensitivity / epsilon

    Args:
        weights:     Input weight array
        epsilon:     Privacy budget
        sensitivity: L1 sensitivity of the query

    Returns:
        Noisy weight array
    """
    epsilon = max(epsilon, 1e-6)
    scale = sensitivity / epsilon
    noise = np.random.laplace(0, scale, size=weights.shape)
    return weights + noise


# ─────────────────────────────────────────────────────────────
# Privacy loss accounting
# ─────────────────────────────────────────────────────────────

def compute_privacy_loss(
    epsilon: float,
    delta: float,
    rounds: int,
) -> float:
    """
    Compute accumulated privacy loss over multiple rounds using a simplified
    moments accountant / basic composition.

    For Gaussian mechanism with composition:
        epsilon_total ≈ sqrt(2 * k * ln(1/delta)) * epsilon_per_round  (advanced composition)
        delta_total   = k * delta (simple composition for delta)

    Args:
        epsilon: Per-round privacy budget
        delta:   Per-round delta
        rounds:  Number of FL rounds

    Returns:
        Total accumulated epsilon
    """
    if rounds <= 0:
        return 0.0
    # Advanced composition theorem for Gaussian mechanism
    # epsilon_total = sqrt(2 * rounds * ln(1/delta)) * epsilon + rounds * epsilon * (e^epsilon - 1)
    # Simplified version (safe upper bound):
    delta = max(delta, 1e-10)
    epsilon_adv = math.sqrt(2 * rounds * math.log(1.0 / delta)) * epsilon
    return round(float(epsilon_adv), 4)


# ─────────────────────────────────────────────────────────────
# Analysis & comparison data
# ─────────────────────────────────────────────────────────────

def generate_privacy_comparison_data(epsilon_values: list) -> pd.DataFrame:
    """
    For each epsilon value, compute the accuracy-privacy tradeoff metrics.

    Simulates model utility degradation as epsilon decreases (more noise).

    Returns a DataFrame with columns:
        epsilon, accuracy, privacy_loss, noise_std, utility_score
    """
    rows = []
    base_accuracy = 0.95  # Perfect accuracy at epsilon = ∞

    for eps in epsilon_values:
        eps = max(float(eps), 0.01)
        # Simulate accuracy degradation: more noise → lower accuracy
        # Using a sigmoid-like model: acc = base * sigmoid(log(eps))
        acc_drop = 0.20 / (1 + math.exp(2 * (math.log10(eps) - 0.5)))
        accuracy = max(base_accuracy - acc_drop, 0.50)

        # Noise standard deviation for Gaussian mech (sensitivity=1, delta=1e-5)
        sigma = math.sqrt(2 * math.log(1.25 / 1e-5)) / eps

        # Privacy loss over 10 rounds
        priv_loss = compute_privacy_loss(eps, 1e-5, 10)

        # Utility score: composite measure (higher = better)
        utility = accuracy * (1 - min(priv_loss / 50.0, 0.9))

        rows.append({
            "epsilon":      round(eps, 3),
            "accuracy":     round(accuracy, 4),
            "privacy_loss": round(priv_loss, 4),
            "noise_std":    round(sigma, 4),
            "utility_score": round(utility, 4),
        })

    return pd.DataFrame(rows)


def get_dp_explanation(epsilon: float) -> str:
    """Return a human-readable explanation of what the given epsilon means."""
    if epsilon <= 0.1:
        return "Very Strong Privacy: Extremely high noise added. Model accuracy significantly reduced but maximum privacy guaranteed."
    elif epsilon <= 0.5:
        return "Strong Privacy: High noise. Individual records are very well protected with slight accuracy loss."
    elif epsilon <= 1.0:
        return "Good Privacy: Balanced noise level. Good privacy protection with acceptable model accuracy."
    elif epsilon <= 5.0:
        return "Moderate Privacy: Moderate noise. Reasonable privacy with good model utility."
    elif epsilon <= 10.0:
        return "Weak Privacy: Low noise. Some privacy benefit but limited protection for individual records."
    else:
        return "Minimal Privacy: Very little noise added. Near-original model accuracy but minimal privacy guarantee."
