import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import time
import json
from datetime import datetime

st.set_page_config(
    page_title="Adversarial Detection | CyberShield AI",
    page_icon="⚠️",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    from utils.auth import require_login, get_current_user
    from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
    from utils.federated import (
        detect_adversarial_updates, simulate_adversarial_client, CLIENTS
    )
    from utils.threat_logger import log_threat
except ImportError:
    def require_login(): pass
    def get_current_user(): return {"username": "demo_user"}
    def apply_custom_css(): pass
    def render_section_header(t, s=""): st.markdown(f"## {t}")
    def render_metric_card(l, v, d="", c="blue"): st.metric(l, v, d)

    CLIENTS = ["Client_1", "Client_2", "Client_3", "Client_4"]

    def detect_adversarial_updates(weights_dict):
        results = []
        for client, weights in weights_dict.items():
            w = np.array(weights)
            z = (w - np.mean(w)) / (np.std(w) + 1e-8)
            is_suspicious = np.max(np.abs(z)) > 3.0 or np.std(w) > 2.0
            results.append({
                "client": client,
                "is_suspicious": is_suspicious,
                "z_score_max": float(np.max(np.abs(z))),
                "std_dev": float(np.std(w)),
                "reason": "High z-score and weight variance" if is_suspicious else "Normal distribution"
            })
        return results

    def simulate_adversarial_client(client_id):
        # Return poisoned weights with anomalous distribution
        return np.random.normal(5.0, 4.0, 200).tolist()

    def log_threat(t, d, sev): pass

apply_custom_css()
require_login()

# ─────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@300;400;600&display=swap');

body, .stApp { background: #0a0a10 !important; }

.adv-hero {
    background: linear-gradient(135deg, #0a0a10 0%, #15050a 50%, #100a10 100%);
    border: 1px solid rgba(255,56,56,0.25);
    border-radius: 20px;
    padding: 40px;
    text-align: center;
    margin-bottom: 30px;
    position: relative;
    overflow: hidden;
}
.adv-hero::before {
    content: ''; position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(255,56,56,0.08) 0%, transparent 60%);
    border-radius: 20px;
}
.adv-hero h1 {
    font-family: 'Orbitron', monospace;
    font-size: 2.6rem; font-weight: 900;
    background: linear-gradient(90deg, #ff3838, #ff6b6b, #ff9999);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin: 0 0 10px 0;
}
.adv-hero p { font-family: 'Inter', sans-serif; color: rgba(255,180,180,0.75); font-size: 1.05rem; margin: 0; }

.trust-card-green {
    background: linear-gradient(145deg, #081a08, #0a200a);
    border: 2px solid rgba(0,255,136,0.4);
    border-radius: 16px;
    padding: 18px;
    text-align: center;
    box-shadow: 0 0 12px rgba(0,255,136,0.1);
}
.trust-card-yellow {
    background: linear-gradient(145deg, #1a1508, #201a0a);
    border: 2px solid rgba(247,180,47,0.4);
    border-radius: 16px;
    padding: 18px;
    text-align: center;
    box-shadow: 0 0 12px rgba(247,180,47,0.1);
}
.trust-card-red {
    background: linear-gradient(145deg, #1a0808, #200a0a);
    border: 2px solid rgba(255,56,56,0.4);
    border-radius: 16px;
    padding: 18px;
    text-align: center;
    box-shadow: 0 0 20px rgba(255,56,56,0.2);
}
.trust-val {
    font-family: 'Orbitron', monospace;
    font-size: 2rem; font-weight: 700;
}
.trust-lbl {
    font-family: 'Inter', sans-serif;
    font-size: 0.85rem; margin-top: 4px; color: rgba(255,200,200,0.7);
}
.trust-bar-bg {
    background: rgba(255,255,255,0.05);
    border-radius: 6px; height: 10px; margin-top: 8px;
}
.detection-card {
    background: linear-gradient(145deg, #15080a, #100508);
    border: 1px solid rgba(255,56,56,0.3);
    border-radius: 14px;
    padding: 18px 20px;
    margin: 10px 0;
    font-family: 'Inter', sans-serif;
    color: rgba(255,180,180,0.9);
}
.detection-card .title { color: #ff6b6b; font-weight: 600; font-size: 0.95rem; margin-bottom: 6px; }
.attack-card {
    background: linear-gradient(145deg, #120508, #0a0308);
    border-left: 4px solid #ff3838;
    border-radius: 0 12px 12px 0;
    padding: 16px 20px;
    margin: 10px 0;
    font-family: 'Inter', sans-serif;
}
.defense-badge {
    display: inline-block;
    padding: 5px 14px;
    border-radius: 20px;
    font-family: 'Orbitron', monospace;
    font-size: 0.7rem;
    font-weight: 700;
    margin: 4px;
}
.alert-box {
    background: linear-gradient(135deg, #1a0505, #150305);
    border: 2px solid #ff3838;
    border-radius: 14px;
    padding: 18px;
    font-family: 'Orbitron', monospace;
    color: #ff6b6b;
    font-size: 0.9rem;
    margin: 10px 0;
    box-shadow: 0 0 15px rgba(255,56,56,0.15);
    animation: border-pulse 2s infinite;
}
@keyframes border-pulse {
    0%, 100% { box-shadow: 0 0 10px rgba(255,56,56,0.15); }
    50% { box-shadow: 0 0 25px rgba(255,56,56,0.35); }
}
</style>

<div class="adv-hero">
    <div style="display:inline-block;background:linear-gradient(135deg,#ff3838,#ff6b6b);color:white;
                font-family:Orbitron,monospace;font-size:0.6rem;font-weight:700;padding:4px 14px;
                border-radius:20px;margin-bottom:15px;letter-spacing:2px;">⚠️ SECURITY</div>
    <h1>⚠️ Adversarial Attack Detection</h1>
    <p>Byzantine Fault Tolerance — Detecting & Neutralising Malicious Clients in Federated Learning</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# INTRODUCTION
# ─────────────────────────────────────────
st.markdown("### 🎓 Byzantine Fault Tolerance in Federated Learning")
c1, c2, c3 = st.columns(3)
intros = [
    ("🦠", "#ff6b6b", "Byzantine Attack", "A subset of clients in FL can be compromised and send malicious gradient updates designed to degrade or backdoor the global model."),
    ("🔍", "#f7b42f", "Anomaly Detection", "By analyzing the statistical distribution of client weight updates, we can identify outliers that deviate significantly from the norm."),
    ("🛡️", "#00ff88", "Robust Aggregation", "Algorithms like Krum, Median, and Trimmed Mean can exclude malicious updates while still learning from honest clients."),
]
for col, (icon, color, title, desc) in zip([c1, c2, c3], intros):
    col.markdown(f"""
    <div style="background:linear-gradient(145deg,#120508,#0f0308);border:1px solid rgba(255,56,56,0.2);
                border-radius:14px;padding:18px;font-family:Inter,sans-serif;">
        <div style="font-size:2rem;margin-bottom:8px;">{icon}</div>
        <strong style="color:{color};font-family:Orbitron,monospace;font-size:0.85rem;">{title}</strong><br>
        <span style="color:rgba(255,180,180,0.75);font-size:0.87rem;">{desc}</span>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────
if "trust_scores" not in st.session_state:
    st.session_state.trust_scores = {c: float(np.random.randint(75, 95)) for c in CLIENTS}
if "poisoned_clients" not in st.session_state:
    st.session_state.poisoned_clients = []
if "excluded_clients" not in st.session_state:
    st.session_state.excluded_clients = []
if "trust_history" not in st.session_state:
    # Generate 10 rounds of history
    st.session_state.trust_history = {
        c: [float(np.random.randint(70, 95)) for _ in range(10)]
        for c in CLIENTS
    }
if "client_weights" not in st.session_state:
    st.session_state.client_weights = {
        c: np.random.normal(0, 0.5, 200).tolist() for c in CLIENTS
    }
if "detection_results" not in st.session_state:
    st.session_state.detection_results = []

# ─────────────────────────────────────────
# CLIENT TRUST DASHBOARD
# ─────────────────────────────────────────
st.markdown("### 🖥️ Client Trust Dashboard")

trust_cols = st.columns(len(CLIENTS))
for i, (client, col) in enumerate(zip(CLIENTS, trust_cols)):
    score = st.session_state.trust_scores[client]
    is_poisoned = client in st.session_state.poisoned_clients
    is_excluded = client in st.session_state.excluded_clients

    if is_excluded:
        card_class = "trust-card-red"
        score_color = "#ff3838"
        status = "🚫 EXCLUDED"
    elif is_poisoned or score < 50:
        card_class = "trust-card-red"
        score_color = "#ff3838"
        status = "🔴 MALICIOUS"
    elif score < 70:
        card_class = "trust-card-yellow"
        score_color = "#f7b42f"
        status = "🟡 SUSPICIOUS"
    else:
        card_class = "trust-card-green"
        score_color = "#00ff88"
        status = "🟢 TRUSTED"

    bar_pct = int(score)
    bar_color = "#ff3838" if score < 50 else "#f7b42f" if score < 70 else "#00ff88"
    col.markdown(f"""
    <div class="{card_class}">
        <div style="font-family:Orbitron,monospace;font-size:0.75rem;color:rgba(255,200,200,0.8);">
            {client.replace('_', ' ')}
        </div>
        <div class="trust-val" style="color:{score_color};">{score:.0f}</div>
        <div style="font-size:0.65rem;color:rgba(255,255,255,0.5)">Trust Score</div>
        <div class="trust-bar-bg">
            <div style="width:{bar_pct}%;height:100%;background:{bar_color};border-radius:6px;
                        transition:width 0.5s;box-shadow:0 0 8px {bar_color}44;"></div>
        </div>
        <div style="margin-top:8px;font-size:0.75rem;font-family:Orbitron,monospace;">{status}</div>
    </div>
    """, unsafe_allow_html=True)

# Trust score history chart
st.markdown("#### 📈 Trust Score History")
fig_trust = go.Figure()
colors_trust = ['#00ff88', '#00c6ff', '#a78bfa', '#f7b42f', '#f72f7b', '#34d399']
for i, client in enumerate(CLIENTS):
    history = st.session_state.trust_history[client]
    is_poisoned = client in st.session_state.poisoned_clients
    line_style = dict(color='#ff3838', width=3, dash='dash') if is_poisoned else \
                 dict(color=colors_trust[i], width=2)
    fig_trust.add_trace(go.Scatter(
        x=list(range(1, len(history) + 1)), y=history,
        name=client.replace("_", " "),
        mode='lines+markers', line=line_style,
        marker=dict(size=7)
    ))
fig_trust.add_hline(y=70, line=dict(color='#f7b42f', dash='dot', width=1.5),
                    annotation_text="Suspicious threshold (70)",
                    annotation_font_color='#f7b42f')
fig_trust.add_hline(y=50, line=dict(color='#ff3838', dash='dot', width=1.5),
                    annotation_text="Malicious threshold (50)",
                    annotation_font_color='#ff3838')
fig_trust.update_layout(
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,5,10,0.6)',
    font=dict(color='white'), height=320,
    xaxis=dict(title="Round", gridcolor='rgba(255,255,255,0.05)', dtick=1),
    yaxis=dict(title="Trust Score", range=[0, 100], gridcolor='rgba(255,255,255,0.05)'),
    legend=dict(bgcolor='rgba(0,0,0,0)'),
    margin=dict(l=10, r=10, t=20, b=20)
)
st.plotly_chart(fig_trust, use_container_width=True)

st.markdown("---")

# ─────────────────────────────────────────
# SIMULATION CONTROLS
# ─────────────────────────────────────────
st.markdown("### 🎮 Simulation Controls")
col_poison, col_detect, col_action = st.columns(3)

with col_poison:
    st.markdown("#### 💀 Poison a Client")
    client_to_poison = st.selectbox("Select Client", CLIENTS, key="poison_select")
    attack_type = st.selectbox("Attack Type", ["Label Flipping", "Gradient Poisoning", "Backdoor"])

    if st.button("💉 Simulate Poisoned Client", type="primary", use_container_width=True, key="poison_btn"):
        with st.spinner(f"Injecting {attack_type} attack into {client_to_poison}..."):
            time.sleep(0.4)
            try:
                poisoned_weights = simulate_adversarial_client(client_to_poison)
            except Exception:
                poisoned_weights = np.random.normal(6.0, 5.0, 200).tolist()

            st.session_state.client_weights[client_to_poison] = poisoned_weights
            st.session_state.trust_scores[client_to_poison] = float(np.random.randint(15, 40))
            if client_to_poison not in st.session_state.poisoned_clients:
                st.session_state.poisoned_clients.append(client_to_poison)

            # Update trust history
            st.session_state.trust_history[client_to_poison].append(
                st.session_state.trust_scores[client_to_poison]
            )

        st.error(f"⚠️ {client_to_poison} poisoned with {attack_type}! Trust score dropped to {st.session_state.trust_scores[client_to_poison]:.0f}")
        try:
            log_threat("ADVERSARIAL_ATTACK", f"{attack_type} on {client_to_poison}", "HIGH")
        except Exception:
            pass
        st.rerun()

with col_detect:
    st.markdown("#### 🔍 Run Detection")

    if st.button("🔬 Analyze All Clients", type="primary", use_container_width=True, key="detect_btn"):
        with st.spinner("Running anomaly detection algorithms..."):
            time.sleep(0.6)
            try:
                results = detect_adversarial_updates(st.session_state.client_weights)
            except Exception:
                results = []
                for c, w in st.session_state.client_weights.items():
                    w_arr = np.array(w)
                    z = np.abs((w_arr - np.mean(w_arr)) / (np.std(w_arr) + 1e-8))
                    is_sus = np.max(z) > 3.0 or np.std(w_arr) > 2.0
                    results.append({
                        "client": c, "is_suspicious": is_sus,
                        "z_score_max": float(np.max(z)), "std_dev": float(np.std(w_arr)),
                        "reason": "High z-score detected" if is_sus else "Normal weight distribution"
                    })
            st.session_state.detection_results = results

        st.success("✅ Detection complete!")
        st.rerun()

    if st.button("🔄 Reset All Clients", use_container_width=True, key="reset_btn"):
        st.session_state.trust_scores = {c: float(np.random.randint(75, 95)) for c in CLIENTS}
        st.session_state.poisoned_clients = []
        st.session_state.excluded_clients = []
        st.session_state.client_weights = {c: np.random.normal(0, 0.5, 200).tolist() for c in CLIENTS}
        st.session_state.detection_results = []
        st.session_state.trust_history = {c: [float(np.random.randint(70, 95)) for _ in range(10)] for c in CLIENTS}
        st.success("✅ All clients reset to trusted state.")
        st.rerun()

with col_action:
    st.markdown("#### 🛡️ Security Actions")
    if st.session_state.poisoned_clients:
        suspicious = st.multiselect(
            "Select clients to exclude",
            options=CLIENTS,
            default=st.session_state.poisoned_clients,
            key="exclude_select"
        )
        if st.button("🚫 Exclude Suspicious Clients", type="secondary", use_container_width=True, key="exclude_btn"):
            for c in suspicious:
                if c not in st.session_state.excluded_clients:
                    st.session_state.excluded_clients.append(c)
            st.success(f"✅ {len(suspicious)} client(s) excluded from federation!")
            try:
                log_threat("CLIENT_EXCLUDED", f"Excluded: {', '.join(suspicious)}", "HIGH")
            except Exception:
                pass
            st.rerun()

        if st.button("🔄 Isolate & Re-train", type="secondary", use_container_width=True, key="retrain_btn"):
            with st.spinner("Re-training without poisoned clients..."):
                time.sleep(0.8)
            active = [c for c in CLIENTS if c not in st.session_state.excluded_clients]
            new_acc = 0.85 + 0.05 * len(active) / len(CLIENTS)
            st.success(f"✅ Re-trained with {len(active)} clean clients. New accuracy: {new_acc*100:.1f}%")
    else:
        st.info("ℹ️ No poisoned clients detected. Use 'Poison a Client' to simulate an attack.")

st.markdown("---")

# ─────────────────────────────────────────
# DETECTION RESULTS
# ─────────────────────────────────────────
if st.session_state.detection_results:
    st.markdown("### 🔬 Detection Analysis Results")

    col_l, col_r = st.columns(2)

    with col_l:
        # Weight distribution overlapping histograms
        st.markdown("#### 📊 Weight Distribution Analysis")
        fig_dist = go.Figure()
        dist_colors = ['#00ff88', '#00c6ff', '#a78bfa', '#f7b42f', '#f72f7b', '#34d399']
        for i, client in enumerate(CLIENTS):
            weights = st.session_state.client_weights[client]
            is_poisoned = client in st.session_state.poisoned_clients
            fig_dist.add_trace(go.Histogram(
                x=weights, name=client.replace("_", " "),
                opacity=0.55,
                marker_color='#ff3838' if is_poisoned else dist_colors[i],
                nbinsx=40
            ))
        fig_dist.update_layout(
            barmode='overlay',
            title="Client Weight Distributions (Red = Poisoned)",
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,5,10,0.6)',
            font=dict(color='white'), height=340,
            xaxis=dict(title="Weight Value", gridcolor='rgba(255,255,255,0.05)'),
            yaxis=dict(title="Count", gridcolor='rgba(255,255,255,0.05)'),
            legend=dict(bgcolor='rgba(0,0,0,0)'),
            margin=dict(l=10, r=10, t=50, b=20)
        )
        st.plotly_chart(fig_dist, use_container_width=True)

    with col_r:
        # Z-score and cosine similarity
        st.markdown("#### 📐 Z-Score Analysis")
        clients_list = [r["client"].replace("_", " ") for r in st.session_state.detection_results]
        z_scores = [r.get("z_score_max", 0) for r in st.session_state.detection_results]
        std_devs = [r.get("std_dev", 0) for r in st.session_state.detection_results]
        bar_cols = ['#ff3838' if r.get("is_suspicious") else '#00ff88'
                    for r in st.session_state.detection_results]

        fig_z = go.Figure()
        fig_z.add_trace(go.Bar(
            x=clients_list, y=z_scores, name="Max Z-Score",
            marker_color=bar_cols, opacity=0.85,
            text=[f"{z:.2f}" for z in z_scores], textposition='outside',
            textfont=dict(color='white', size=11)
        ))
        fig_z.add_hline(y=3.0, line=dict(color='#f7b42f', dash='dash', width=2),
                        annotation_text="Anomaly Threshold (z=3)",
                        annotation_font_color='#f7b42f')
        fig_z.update_layout(
            title="Max Z-Score per Client (>3 = Anomaly)",
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,5,10,0.6)',
            font=dict(color='white'), height=340,
            yaxis=dict(title="Max |Z-Score|", gridcolor='rgba(255,255,255,0.05)'),
            margin=dict(l=10, r=10, t=50, b=30)
        )
        st.plotly_chart(fig_z, use_container_width=True)

    # Detection summary cards
    st.markdown("#### 🚨 Flagged Clients")
    any_flagged = False
    for result in st.session_state.detection_results:
        client = result["client"]
        is_sus = result.get("is_suspicious", False)
        z = result.get("z_score_max", 0)
        std = result.get("std_dev", 0)
        reason = result.get("reason", "")

        if is_sus:
            any_flagged = True
            st.markdown(f"""
            <div class="alert-box">
                🚨 {client.replace('_', ' ')} — SUSPICIOUS DETECTED<br>
                <span style="font-size:0.75rem;font-family:Inter,sans-serif;color:#ff9999;">
                    Max Z-Score: {z:.3f} &nbsp;|&nbsp; Std Dev: {std:.4f} &nbsp;|&nbsp; Reason: {reason}
                </span>
            </div>
            """, unsafe_allow_html=True)

    if not any_flagged:
        st.success("✅ No adversarial clients detected. All weight distributions are within normal parameters.")

    # Cosine similarity matrix
    st.markdown("#### 🔗 Cosine Similarity Matrix")
    n_clients = len(CLIENTS)
    sim_matrix = np.zeros((n_clients, n_clients))
    for i, ci in enumerate(CLIENTS):
        wi = np.array(st.session_state.client_weights[ci])
        for j, cj in enumerate(CLIENTS):
            wj = np.array(st.session_state.client_weights[cj])
            min_len = min(len(wi), len(wj))
            wi_s, wj_s = wi[:min_len], wj[:min_len]
            denom = (np.linalg.norm(wi_s) * np.linalg.norm(wj_s))
            sim_matrix[i][j] = float(np.dot(wi_s, wj_s) / denom) if denom > 0 else 1.0

    fig_sim = px.imshow(
        sim_matrix,
        x=[c.replace("_", " ") for c in CLIENTS],
        y=[c.replace("_", " ") for c in CLIENTS],
        color_continuous_scale=[[0, "#ff3838"], [0.5, "#f7b42f"], [1, "#00ff88"]],
        title="Cosine Similarity Between Client Updates (Low = Suspicious)",
        text_auto=".2f",
        zmin=-1, zmax=1
    )
    fig_sim.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', font=dict(color='white'), height=350,
        margin=dict(l=10, r=10, t=50, b=20)
    )
    st.plotly_chart(fig_sim, use_container_width=True)

st.markdown("---")

# ─────────────────────────────────────────
# ATTACK TYPE EXPLANATIONS
# ─────────────────────────────────────────
st.markdown("### 🦠 Attack Type Explanations")
col1, col2, col3 = st.columns(3)

with col1:
    with st.expander("🏷️ Label Flipping Attack", expanded=True):
        st.markdown("""
        <div class="attack-card">
            <strong style="color:#ff6b6b;">Mechanism</strong><br>
            The attacker flips labels in their training data (e.g., 'phishing' → 'legitimate') 
            so the global model learns wrong associations.<br><br>
            <strong style="color:#ff6b6b;">Impact</strong><br>
            Reduces detection accuracy for specific threat classes the attacker wants to evade.<br><br>
            <strong style="color:#f7b42f;">Detection</strong><br>
            High divergence in weight vectors for specific output neurons.
        </div>
        """, unsafe_allow_html=True)

with col2:
    with st.expander("🧪 Gradient Poisoning", expanded=True):
        st.markdown("""
        <div class="attack-card">
            <strong style="color:#ff6b6b;">Mechanism</strong><br>
            Attacker directly crafts malicious gradient updates that, when aggregated, 
            push the global model toward desired (malicious) behavior.<br><br>
            <strong style="color:#ff6b6b;">Impact</strong><br>
            Can cause catastrophic forgetting or targeted misclassification.<br><br>
            <strong style="color:#f7b42f;">Detection</strong><br>
            Statistical anomalies in gradient norm and distribution.
        </div>
        """, unsafe_allow_html=True)

with col3:
    with st.expander("🚪 Backdoor Attack", expanded=True):
        st.markdown("""
        <div class="attack-card">
            <strong style="color:#ff6b6b;">Mechanism</strong><br>
            Attacker embeds a hidden trigger pattern (e.g., specific pixel) into their data. 
            The model classifies normally except when trigger is present.<br><br>
            <strong style="color:#ff6b6b;">Impact</strong><br>
            Stealthy — model passes validation but fails on triggered inputs.<br><br>
            <strong style="color:#f7b42f;">Detection</strong><br>
            Weight distribution analysis in final layers.
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# DEFENSE MECHANISMS CHART
# ─────────────────────────────────────────
st.markdown("### 🛡️ Defense Mechanism Comparison")

defense_mechanisms = ["FedAvg (baseline)", "Krum Aggregation", "Median Aggregation",
                      "Trimmed Mean", "FLTrust", "RFA (Robust FL)"]
robustness_scores = [45, 78, 82, 76, 88, 91]
accuracy_retention = [97, 89, 85, 88, 91, 90]
computational_cost = [10, 65, 45, 35, 75, 80]

fig_defense = go.Figure()
fig_defense.add_trace(go.Bar(
    name="Byzantine Robustness (%)",
    x=defense_mechanisms, y=robustness_scores,
    marker_color='#00ff88', opacity=0.85
))
fig_defense.add_trace(go.Bar(
    name="Accuracy Retention (%)",
    x=defense_mechanisms, y=accuracy_retention,
    marker_color='#00c6ff', opacity=0.85
))
fig_defense.add_trace(go.Bar(
    name="Computational Cost (relative)",
    x=defense_mechanisms, y=computational_cost,
    marker_color='#f72f7b', opacity=0.85
))
fig_defense.update_layout(
    barmode='group', title="Defense Mechanism Performance Comparison",
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,5,10,0.6)',
    font=dict(color='white'), height=380,
    yaxis=dict(title="Score", range=[0, 105], gridcolor='rgba(255,255,255,0.05)'),
    legend=dict(bgcolor='rgba(0,0,0,0)'),
    margin=dict(l=10, r=10, t=50, b=20)
)
st.plotly_chart(fig_defense, use_container_width=True)

# Defense mechanism descriptions
col1, col2 = st.columns(2)
with col1:
    st.markdown("""
    **Krum Aggregation**: Selects the single client update that is closest to its `n-f-2` neighbors 
    (where f is the number of Byzantine clients). Provides strong Byzantine resistance but 
    requires knowing f in advance.
    
    **Median Aggregation**: Takes the coordinate-wise median of all client updates. 
    More robust than averaging but loses information from extreme honest updates.
    """)
with col2:
    st.markdown("""
    **FLTrust**: Server maintains a small clean dataset to generate a reference gradient, 
    then reweights client updates based on cosine similarity to this reference.
    
    **RFA (Robust Federated Aggregation)**: Uses geometric median for aggregation, 
    providing optimal robustness guarantees under the Byzantine threat model.
    """)

# Real-time alert check
if st.session_state.poisoned_clients:
    excluded = st.session_state.excluded_clients
    active_poisoned = [c for c in st.session_state.poisoned_clients if c not in excluded]
    if active_poisoned:
        st.markdown("---")
        st.markdown(f"""
        <div class="alert-box" style="text-align:center;">
            🚨 REAL-TIME ALERT: {len(active_poisoned)} ACTIVE MALICIOUS CLIENT(S) DETECTED<br>
            <span style="font-size:0.8rem;font-family:Inter,sans-serif;color:#ff9999;">
                {', '.join(active_poisoned)} — Run detection and exclude these clients immediately!
            </span>
        </div>
        """, unsafe_allow_html=True)
