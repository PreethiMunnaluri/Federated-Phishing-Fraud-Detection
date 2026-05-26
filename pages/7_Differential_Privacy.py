import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import time
from datetime import datetime

st.set_page_config(
    page_title="Differential Privacy | CyberShield AI",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    from utils.auth import require_login, get_current_user
    from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
    from utils.differential_privacy import (
        add_gaussian_noise, add_laplace_noise,
        compute_privacy_loss, generate_privacy_comparison_data
    )
    from utils.threat_logger import log_threat
except ImportError as e:
    def require_login(): pass
    def get_current_user(): return {"username": "demo_user"}
    def apply_custom_css(): pass
    def render_section_header(t, s=""): st.markdown(f"## {t}")
    def render_metric_card(l, v, d="", c="blue"): st.metric(l, v, d)

    def add_gaussian_noise(data, epsilon, sensitivity=1.0):
        sigma = sensitivity * np.sqrt(2 * np.log(1.25 / 1e-5)) / epsilon
        return data + np.random.normal(0, sigma, len(data))

    def add_laplace_noise(data, epsilon, sensitivity=1.0):
        scale = sensitivity / epsilon
        return data + np.random.laplace(0, scale, len(data))

    def compute_privacy_loss(epsilon, sensitivity, n_queries):
        return round(sensitivity / epsilon * np.sqrt(2 * np.log(1.25 / 1e-5) * n_queries), 4)

    def generate_privacy_comparison_data():
        eps_vals = np.linspace(0.01, 10, 100)
        accuracy = 100 * (1 - 0.3 * np.exp(-0.5 * eps_vals))
        privacy = 100 * np.exp(-0.3 * eps_vals)
        return {"epsilon": eps_vals.tolist(), "accuracy": accuracy.tolist(), "privacy": privacy.tolist()}

    def log_threat(t, d, sev): pass

apply_custom_css()
require_login()

# ─────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@300;400;600&display=swap');

body, .stApp { background: #0a0e1a !important; }

.dp-hero {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1428 50%, #0a1020 100%);
    border: 1px solid rgba(123,47,247,0.25);
    border-radius: 20px;
    padding: 40px;
    text-align: center;
    margin-bottom: 30px;
    position: relative;
    overflow: hidden;
}
.dp-hero::before {
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(123,47,247,0.10) 0%, transparent 60%);
}
.dp-hero h1 {
    font-family: 'Orbitron', monospace;
    font-size: 2.6rem;
    font-weight: 900;
    background: linear-gradient(90deg, #a78bfa, #7b2ff7, #c026d3);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0 0 10px 0;
}
.dp-hero p { font-family: 'Inter', sans-serif; color: rgba(200,180,255,0.75); font-size: 1.05rem; margin: 0; }

.insight-card {
    background: linear-gradient(145deg, #0d1428, #110a2a);
    border: 1px solid rgba(123,47,247,0.3);
    border-radius: 14px;
    padding: 20px 24px;
    margin: 10px 0;
    font-family: 'Inter', sans-serif;
}
.insight-card .title {
    color: #a78bfa;
    font-weight: 600;
    font-size: 1rem;
    margin-bottom: 6px;
}
.insight-card p { color: rgba(200,180,255,0.8); font-size: 0.9rem; margin: 0; }

.dp-metric {
    background: linear-gradient(145deg, #0d1428, #110a2a);
    border: 1px solid rgba(123,47,247,0.35);
    border-radius: 14px;
    padding: 20px;
    text-align: center;
}
.dp-metric .val { font-family: 'Orbitron', monospace; font-size: 2rem; color: #a78bfa; font-weight: 700; }
.dp-metric .lbl { font-family: 'Inter', sans-serif; color: rgba(200,180,255,0.6); font-size: 0.8rem; margin-top: 4px; }

.privacy-highlight {
    background: linear-gradient(135deg, #0d1428, #110a2a);
    border: 2px solid rgba(123,47,247,0.5);
    border-radius: 16px;
    padding: 24px;
    text-align: center;
    font-family: 'Orbitron', monospace;
    font-size: 1.05rem;
    color: #a78bfa;
    margin: 20px 0;
    letter-spacing: 0.5px;
}

.budget-bar {
    background: rgba(123,47,247,0.15);
    border: 1px solid rgba(123,47,247,0.3);
    border-radius: 10px;
    padding: 16px;
    margin: 8px 0;
}
</style>

<div class="dp-hero">
    <div style="display:inline-block;background:linear-gradient(135deg,#7b2ff7,#a78bfa);color:white;
                font-family:Orbitron,monospace;font-size:0.6rem;font-weight:700;padding:4px 14px;
                border-radius:20px;margin-bottom:15px;letter-spacing:2px;">🔒 PRIVACY TECH</div>
    <h1>🔒 Differential Privacy Simulation</h1>
    <p>Mathematical Proof-Based Privacy — Preventing Data Leakage Through Calibrated Noise Injection</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# INTRODUCTION
# ─────────────────────────────────────────
st.markdown("### 🎓 What is Differential Privacy?")
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("""
    <div class="insight-card">
        <div class="title">📐 Mathematical Guarantee</div>
        <p>DP provides a mathematically rigorous guarantee that 
        any single person's data has minimal impact on the output, 
        even if an adversary has access to all other data.</p>
    </div>
    """, unsafe_allow_html=True)
with col2:
    st.markdown("""
    <div class="insight-card">
        <div class="title">🎲 Noise Injection</div>
        <p>Carefully calibrated random noise is added to model 
        updates (Gaussian or Laplace) before they leave the client, 
        making individual records indistinguishable.</p>
    </div>
    """, unsafe_allow_html=True)
with col3:
    st.markdown("""
    <div class="insight-card">
        <div class="title">⚖️ Privacy-Utility Tradeoff</div>
        <p>Lower ε (epsilon) = stronger privacy but more noise = lower accuracy. 
        Differential privacy lets you tune this tradeoff with 
        mathematical precision.</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# INTERACTIVE DEMO
# ─────────────────────────────────────────
st.markdown("### 🎮 Interactive Noise Injection Demo")

col_ctrl, col_vis = st.columns([1, 2])

with col_ctrl:
    st.markdown("#### Configuration")
    epsilon = st.slider("🔒 Privacy Budget (ε)", 0.01, 10.0, 1.0, 0.01,
                        help="Lower ε = stronger privacy, more noise")
    sensitivity = st.slider("📡 Sensitivity (Δf)", 0.1, 5.0, 1.0, 0.1,
                            help="Maximum change any single record causes")
    mechanism = st.selectbox("⚙️ Noise Mechanism", ["Gaussian", "Laplace"])
    n_points = st.slider("📊 Data Points", 50, 500, 200, 50)
    n_queries = st.slider("🔢 Query Count", 1, 50, 10,
                          help="More queries consume more privacy budget")
    run_demo = st.button("🚀 Apply Noise & Visualize", type="primary", use_container_width=True)

with col_vis:
    np.random.seed(42)
    original_data = np.random.normal(50, 15, n_points)
    original_data = np.clip(original_data, 0, 100)

    try:
        if mechanism == "Gaussian":
            noisy_data = add_gaussian_noise(original_data, epsilon, sensitivity)
        else:
            noisy_data = add_laplace_noise(original_data, epsilon, sensitivity)
    except Exception:
        if mechanism == "Gaussian":
            sigma = sensitivity * np.sqrt(2 * np.log(1.25 / 1e-5)) / epsilon
            noisy_data = original_data + np.random.normal(0, sigma, n_points)
        else:
            scale = sensitivity / epsilon
            noisy_data = original_data + np.random.laplace(0, scale, n_points)

    fig_hist = go.Figure()
    fig_hist.add_trace(go.Histogram(
        x=original_data, name="Original Data", opacity=0.65,
        marker_color='#00ffb4', nbinsx=30,
        hovertemplate="Value: %{x}<br>Count: %{y}"
    ))
    fig_hist.add_trace(go.Histogram(
        x=noisy_data, name=f"Noisy Data ({mechanism})", opacity=0.65,
        marker_color='#a78bfa', nbinsx=30,
        hovertemplate="Value: %{x}<br>Count: %{y}"
    ))
    fig_hist.update_layout(
        barmode='overlay',
        title=f"Original vs {mechanism} Noisy Data Distribution (ε={epsilon:.2f})",
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,15,30,0.6)',
        font=dict(color='white'), height=340,
        legend=dict(bgcolor='rgba(0,0,0,0)', font=dict(color='white')),
        xaxis=dict(title="Value", gridcolor='rgba(255,255,255,0.05)'),
        yaxis=dict(title="Frequency", gridcolor='rgba(255,255,255,0.05)'),
        margin=dict(l=10, r=10, t=50, b=20)
    )
    st.plotly_chart(fig_hist, use_container_width=True)

# Privacy highlight text
privacy_text = "indistinguishable" if epsilon < 1 else "well-protected" if epsilon < 3 else "moderately protected"
privacy_icon = "🔒" if epsilon < 1 else "🛡️" if epsilon < 3 else "⚠️"
st.markdown(f"""
<div class="privacy-highlight">
    {privacy_icon} With ε={epsilon:.2f}, each individual's data contribution is 
    <strong style="color:#00ffb4">{privacy_text}</strong><br>
    <span style="font-size:0.75rem;color:rgba(200,180,255,0.6)">
        Raw data never leaves the client device — only calibrated noise is shared
    </span>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# PRIVACY-UTILITY TRADEOFF CHART
# ─────────────────────────────────────────
st.markdown("### 📈 Privacy-Utility Tradeoff")

try:
    cmp_data = generate_privacy_comparison_data()
    eps_vals = np.array(cmp_data["epsilon"])
    acc_vals = np.array(cmp_data["accuracy"])
    priv_vals = np.array(cmp_data["privacy"])
except Exception:
    eps_vals = np.linspace(0.01, 10, 100)
    acc_vals = 100 * (1 - 0.3 * np.exp(-0.5 * eps_vals))
    priv_vals = 100 * np.exp(-0.3 * eps_vals)

fig_tradeoff = go.Figure()
fig_tradeoff.add_trace(go.Scatter(
    x=eps_vals, y=acc_vals, name="Model Accuracy",
    line=dict(color='#00ffb4', width=3),
    fill='tozeroy', fillcolor='rgba(0,255,180,0.05)'
))
fig_tradeoff.add_trace(go.Scatter(
    x=eps_vals, y=priv_vals, name="Privacy Level",
    line=dict(color='#a78bfa', width=3),
    fill='tozeroy', fillcolor='rgba(167,139,250,0.05)'
))
# Mark current epsilon
current_acc = float(np.interp(epsilon, eps_vals, acc_vals))
current_priv = float(np.interp(epsilon, eps_vals, priv_vals))
fig_tradeoff.add_trace(go.Scatter(
    x=[epsilon, epsilon], y=[0, 100],
    mode='lines', name="Current ε",
    line=dict(color='#f7b42f', width=2, dash='dash')
))
fig_tradeoff.add_annotation(
    x=epsilon, y=max(current_acc, current_priv) + 5,
    text=f"ε={epsilon:.2f}", font=dict(color='#f7b42f', size=12),
    showarrow=False
)
fig_tradeoff.update_layout(
    title="Privacy-Utility Tradeoff Curve",
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,15,30,0.6)',
    font=dict(color='white'), height=380,
    xaxis=dict(title="ε (Privacy Budget)", gridcolor='rgba(255,255,255,0.05)'),
    yaxis=dict(title="Score (%)", range=[0, 105], gridcolor='rgba(255,255,255,0.05)', ticksuffix="%"),
    legend=dict(bgcolor='rgba(0,0,0,0)'),
    margin=dict(l=10, r=10, t=50, b=20)
)
st.plotly_chart(fig_tradeoff, use_container_width=True)

# ─────────────────────────────────────────
# NOISE VISUALIZATION (WEIGHTS)
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 🎛️ Model Weight Noise Visualization")

np.random.seed(123)
weight_indices = np.arange(50)
original_weights = np.sin(weight_indices * 0.3) * 0.5 + np.random.normal(0, 0.05, 50)

try:
    gaussian_noisy = add_gaussian_noise(original_weights, epsilon, sensitivity)
    laplace_noisy = add_laplace_noise(original_weights, epsilon, sensitivity)
except Exception:
    sigma = sensitivity * np.sqrt(2 * np.log(1.25 / 1e-5)) / epsilon
    scale = sensitivity / epsilon
    gaussian_noisy = original_weights + np.random.normal(0, sigma, 50)
    laplace_noisy = original_weights + np.random.laplace(0, scale, 50)

fig_weights = go.Figure()
fig_weights.add_trace(go.Scatter(
    x=weight_indices, y=original_weights, name="Original Weights",
    line=dict(color='#00ffb4', width=2.5), mode='lines'
))
fig_weights.add_trace(go.Scatter(
    x=weight_indices, y=gaussian_noisy, name="Gaussian Noisy",
    line=dict(color='#a78bfa', width=1.5, dash='dot'), mode='lines', opacity=0.85
))
fig_weights.add_trace(go.Scatter(
    x=weight_indices, y=laplace_noisy, name="Laplace Noisy",
    line=dict(color='#f72f7b', width=1.5, dash='dash'), mode='lines', opacity=0.85
))
fig_weights.update_layout(
    title=f"Original vs Noisy Model Weights (ε={epsilon:.2f}, Δf={sensitivity:.1f})",
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,15,30,0.6)',
    font=dict(color='white'), height=360,
    xaxis=dict(title="Weight Index", gridcolor='rgba(255,255,255,0.05)'),
    yaxis=dict(title="Weight Value", gridcolor='rgba(255,255,255,0.05)'),
    legend=dict(bgcolor='rgba(0,0,0,0)'),
    margin=dict(l=10, r=10, t=50, b=20)
)
st.plotly_chart(fig_weights, use_container_width=True)

# ─────────────────────────────────────────
# PRIVACY BUDGET TRACKER
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 📊 Privacy Budget Tracker")

try:
    privacy_loss = compute_privacy_loss(epsilon, sensitivity, n_queries)
except Exception:
    privacy_loss = round(sensitivity / epsilon * np.sqrt(2 * np.log(1.25 / 1e-5) * n_queries), 4)

budget_used_pct = min((privacy_loss / (epsilon * 2)) * 100, 100)
budget_remaining = max(epsilon * 2 - privacy_loss, 0)

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""<div class="dp-metric"><div class="val">{epsilon:.2f}</div>
                <div class="lbl">Total Budget (ε)</div></div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""<div class="dp-metric"><div class="val" style="color:#f7b42f">{privacy_loss:.4f}</div>
                <div class="lbl">Privacy Loss Used</div></div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""<div class="dp-metric"><div class="val" style="color:#00ffb4">{budget_remaining:.4f}</div>
                <div class="lbl">Budget Remaining</div></div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""<div class="dp-metric"><div class="val" style="color:#f72f7b">{n_queries}</div>
                <div class="lbl">Queries Made</div></div>""", unsafe_allow_html=True)

if budget_used_pct > 80:
    st.error(f"🚨 Privacy budget nearly exhausted! {budget_used_pct:.1f}% used. Consider increasing ε or reducing queries.")
elif budget_used_pct > 50:
    st.warning(f"⚠️ Privacy budget is {budget_used_pct:.1f}% used. Monitor usage carefully.")
else:
    st.success(f"✅ Privacy budget healthy: {budget_used_pct:.1f}% used, {budget_remaining:.4f} remaining.")

# Budget gauge
fig_budget = go.Figure(go.Indicator(
    mode="gauge+number",
    value=budget_used_pct,
    title={'text': "Privacy Budget Used (%)", 'font': {'color': 'white', 'size': 14}},
    number={'suffix': '%', 'font': {'color': 'white'}},
    gauge={
        'axis': {'range': [0, 100], 'tickcolor': 'white', 'tickfont': {'color': 'white'}},
        'bar': {'color': '#00ffb4' if budget_used_pct < 50 else '#f7b42f' if budget_used_pct < 80 else '#f72f7b'},
        'bgcolor': '#0a1628',
        'steps': [
            {'range': [0, 50], 'color': 'rgba(0,255,180,0.1)'},
            {'range': [50, 80], 'color': 'rgba(247,180,47,0.1)'},
            {'range': [80, 100], 'color': 'rgba(247,47,123,0.1)'},
        ],
        'threshold': {'line': {'color': 'white', 'width': 3}, 'thickness': 0.8, 'value': 80}
    }
))
fig_budget.update_layout(
    paper_bgcolor='rgba(0,0,0,0)', font=dict(color='white'), height=280,
    margin=dict(l=30, r=30, t=40, b=20)
)
st.plotly_chart(fig_budget, use_container_width=True)

# ─────────────────────────────────────────
# LAPLACE VS GAUSSIAN COMPARISON
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 🔬 Laplace vs Gaussian Noise Comparison")

eps_compare = np.array([0.1, 0.5, 1.0, 2.0, 5.0, 10.0])
gauss_noise_levels = np.array([sensitivity * np.sqrt(2 * np.log(1.25 / 1e-5)) / e for e in eps_compare])
laplace_noise_levels = np.array([sensitivity / e for e in eps_compare])

fig_compare = go.Figure()
fig_compare.add_trace(go.Bar(
    x=[str(e) for e in eps_compare], y=gauss_noise_levels, name="Gaussian σ",
    marker_color='#a78bfa', opacity=0.85
))
fig_compare.add_trace(go.Bar(
    x=[str(e) for e in eps_compare], y=laplace_noise_levels, name="Laplace scale b",
    marker_color='#00ffb4', opacity=0.85
))
fig_compare.update_layout(
    barmode='group',
    title=f"Noise Magnitude: Gaussian vs Laplace (Δf={sensitivity:.1f})",
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,15,30,0.6)',
    font=dict(color='white'), height=360,
    xaxis=dict(title="ε (Privacy Budget)", gridcolor='rgba(255,255,255,0.05)'),
    yaxis=dict(title="Noise Magnitude", gridcolor='rgba(255,255,255,0.05)'),
    legend=dict(bgcolor='rgba(0,0,0,0)'),
    margin=dict(l=10, r=10, t=50, b=20)
)
st.plotly_chart(fig_compare, use_container_width=True)

col1, col2 = st.columns(2)
with col1:
    with st.expander("📖 Gaussian Mechanism", expanded=False):
        st.markdown("""
        **Noise added:** `𝒩(0, σ²)` where `σ = √(2ln(1.25/δ)) · Δf / ε`
        
        - Best for (ε, δ)-DP (approximate DP)
        - Lighter tails → better utility at same ε
        - Used in most deep learning DP implementations
        - **TensorFlow Privacy** uses Gaussian mechanism
        """)
with col2:
    with st.expander("📖 Laplace Mechanism", expanded=False):
        st.markdown("""
        **Noise added:** `Lap(0, b)` where `b = Δf / ε`
        
        - Achieves pure ε-DP (no δ failure probability)
        - Heavier tails → more utility loss at low ε
        - Simpler analysis and interpretation
        - Best when you need **strict** privacy guarantees
        """)

# Key stats at bottom
st.markdown("---")
st.markdown("### 📋 Key Statistics")
k1, k2, k3 = st.columns(3)
with k1:
    noise_level = gauss_noise_levels[2] if mechanism == "Gaussian" else laplace_noise_levels[2]
    actual_noise = sensitivity * np.sqrt(2 * np.log(1.25 / 1e-5)) / epsilon if mechanism == "Gaussian" else sensitivity / epsilon
    st.metric("Noise Magnitude (σ or b)", f"{actual_noise:.4f}",
              f"{'↑ Strong privacy' if actual_noise > 1 else '↓ Weak privacy'}")
with k2:
    guarantee = f"({epsilon:.2f}, 1e-5)-DP" if mechanism == "Gaussian" else f"{epsilon:.2f}-DP"
    st.metric("Privacy Guarantee", guarantee)
with k3:
    acc_impact = min(actual_noise * 10, 30)
    st.metric("Estimated Accuracy Impact", f"-{acc_impact:.1f}%",
              delta=f"{'High noise penalty' if acc_impact > 15 else 'Acceptable trade-off'}",
              delta_color="inverse")
