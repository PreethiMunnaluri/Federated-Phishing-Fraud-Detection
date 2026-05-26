import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import time
import json
import os
from datetime import datetime

st.set_page_config(
    page_title="Federated Learning | CyberShield AI",
    page_icon="🔗",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    from utils.auth import require_login, get_current_user
    from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
    from utils.federated import (
        simulate_federated_round, get_fl_history, save_fl_round,
        detect_adversarial_updates, simulate_adversarial_client, CLIENTS
    )
    from utils.differential_privacy import add_gaussian_noise, add_laplace_noise, compute_privacy_loss
    from utils.threat_logger import log_threat
except ImportError as e:
    st.error(f"Import error: {e}. Some utils may not be available yet.")
    # Fallback stubs so the page can still render
    def require_login(): pass
    def get_current_user(): return {"username": "demo_user"}
    def apply_custom_css(): pass
    def render_section_header(t, s=""): st.markdown(f"## {t}")
    def render_metric_card(l, v, d="", c="blue"): st.metric(l, v, d)
    def simulate_federated_round(n, e, dp): 
        clients = [f"Client_{i}" for i in range(1, n+1)]
        accs = {c: round(np.random.uniform(0.82, 0.97), 4) for c in clients}
        weights = {c: np.random.dirichlet(np.ones(5)).tolist() for c in clients}
        global_acc = round(float(np.mean(list(accs.values()))), 4)
        return {"client_accuracies": accs, "global_accuracy": global_acc, 
                "client_weights": weights, "privacy_loss": round(1/e, 4) if dp else 0.0,
                "round_num": 1, "timestamp": datetime.now().isoformat()}
    def get_fl_history(): return []
    def save_fl_round(r): pass
    def detect_adversarial_updates(w): return []
    def simulate_adversarial_client(cid): return np.random.normal(5, 3, 100).tolist()
    CLIENTS = [f"Client_{i}" for i in range(1, 5)]
    def add_gaussian_noise(d, e, s): return d
    def compute_privacy_loss(e, s, n): return round(s/e * np.sqrt(2*np.log(1.25/1e-5)*n), 4)
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

.fl-hero {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1b2a 40%, #0a1628 100%);
    border: 1px solid rgba(0,255,180,0.15);
    border-radius: 20px;
    padding: 40px;
    text-align: center;
    margin-bottom: 30px;
    position: relative;
    overflow: hidden;
}
.fl-hero::before {
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(0,255,180,0.08) 0%, transparent 60%);
}
.fl-hero h1 {
    font-family: 'Orbitron', monospace;
    font-size: 2.8rem;
    font-weight: 900;
    background: linear-gradient(90deg, #00ffb4, #00c6ff, #7b2ff7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0 0 10px 0;
    animation: pulse-glow 3s ease-in-out infinite alternate;
}
@keyframes pulse-glow {
    from { filter: drop-shadow(0 0 8px rgba(0,255,180,0.4)); }
    to   { filter: drop-shadow(0 0 20px rgba(0,198,255,0.7)); }
}
.fl-hero p {
    font-family: 'Inter', sans-serif;
    color: rgba(200,220,255,0.75);
    font-size: 1.05rem;
    margin: 0;
}
.badge {
    display: inline-block;
    background: linear-gradient(135deg, #00ffb4, #00c6ff);
    color: #0a0e1a;
    font-family: 'Orbitron', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 4px 12px;
    border-radius: 20px;
    margin-bottom: 15px;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.config-card {
    background: linear-gradient(145deg, #0d1b2e, #111827);
    border: 1px solid rgba(0,255,180,0.2);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 20px;
}
.step-card {
    background: linear-gradient(145deg, #0d1b2e, #0f2040);
    border-left: 4px solid #00ffb4;
    border-radius: 12px;
    padding: 18px 22px;
    margin: 10px 0;
    font-family: 'Inter', sans-serif;
    color: rgba(200,220,255,0.9);
}
.round-card {
    background: linear-gradient(145deg, #0d1b2e, #111827);
    border: 1px solid rgba(0,198,255,0.25);
    border-radius: 12px;
    padding: 16px 20px;
    margin: 8px 0;
    font-family: 'Inter', sans-serif;
}
.formula-box {
    background: linear-gradient(135deg, #0a1628, #0d2040);
    border: 1px solid rgba(123,47,247,0.4);
    border-radius: 14px;
    padding: 24px;
    text-align: center;
    font-family: 'Orbitron', monospace;
    color: #a78bfa;
    font-size: 1.15rem;
    letter-spacing: 1px;
    margin: 20px 0;
}
.metric-glow {
    background: linear-gradient(145deg, #0d1b2e, #0a1628);
    border: 1px solid rgba(0,255,180,0.3);
    border-radius: 14px;
    padding: 20px;
    text-align: center;
}
.metric-glow .val {
    font-family: 'Orbitron', monospace;
    font-size: 2rem;
    color: #00ffb4;
    font-weight: 700;
}
.metric-glow .lbl {
    font-family: 'Inter', sans-serif;
    color: rgba(180,200,240,0.7);
    font-size: 0.8rem;
    margin-top: 4px;
}
</style>

<div class="fl-hero">
    <div class="badge">⚡ CORE INNOVATION</div>
    <h1>🔗 Federated Learning Simulation</h1>
    <p>Privacy-Preserving Distributed AI Training — No Raw Data Ever Leaves the Client Device</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# HOW IT WORKS SECTION
# ─────────────────────────────────────────
st.markdown("### 📡 How Federated Learning Works")

col1, col2 = st.columns([3, 2])
with col1:
    # Network diagram using Plotly
    fig_net = go.Figure()
    # Server node
    fig_net.add_trace(go.Scatter(
        x=[0], y=[0], mode='markers+text',
        marker=dict(size=50, color='#00ffb4', symbol='diamond',
                    line=dict(color='#00c6ff', width=3)),
        text=["🖥️ Central<br>Server"], textposition="middle center",
        textfont=dict(size=10, color='white'),
        name="Server", hoverinfo='skip'
    ))
    # Client nodes
    client_positions = [(-2.5, 1.8), (2.5, 1.8), (-2.5, -1.8), (2.5, -1.8)]
    client_colors = ['#7b2ff7', '#f72f7b', '#2ff7b4', '#f7b42f']
    client_labels = ['Client 1<br>(Hospital A)', 'Client 2<br>(Bank)', 
                     'Client 3<br>(ISP)', 'Client 4<br>(Enterprise)']
    for i, ((x, y), color, label) in enumerate(zip(client_positions, client_colors, client_labels)):
        fig_net.add_trace(go.Scatter(
            x=[x], y=[y], mode='markers+text',
            marker=dict(size=38, color=color, symbol='circle',
                        line=dict(color='white', width=2)),
            text=[f"💻 {label}"], textposition="middle center",
            textfont=dict(size=9, color='white'),
            name=f"Client {i+1}", hoverinfo='skip'
        ))
        # Arrows (upload - dashed)
        fig_net.add_annotation(
            ax=x, ay=y, x=0, y=0, xref='x', yref='y', axref='x', ayref='y',
            arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor='#00c6ff',
            opacity=0.7
        )
        # Download arrow offset
        fig_net.add_annotation(
            ax=x*0.05, ay=y*0.05, x=x*0.9, y=y*0.9,
            xref='x', yref='y', axref='x', ayref='y',
            arrowhead=2, arrowsize=1.2, arrowwidth=1.5, arrowcolor='#00ffb4',
            opacity=0.6
        )

    fig_net.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        showlegend=False, height=380,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-4, 4]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-3, 3]),
        margin=dict(l=10, r=10, t=20, b=10),
        annotations=fig_net.layout.annotations + (
            go.layout.Annotation(x=1.2, y=1.0, text="📤 Gradients Only", 
                                 showarrow=False, font=dict(color='#00c6ff', size=10)),
            go.layout.Annotation(x=-1.2, y=-0.7, text="📥 Global Model", 
                                 showarrow=False, font=dict(color='#00ffb4', size=10)),
        )
    )
    st.plotly_chart(fig_net, use_container_width=True)

with col2:
    st.markdown("""
    <div class="step-card">
        <strong style="color:#00ffb4">① Local Training</strong><br>
        Each client trains on its own private dataset (phishing emails, fraud logs, etc.)
    </div>
    <div class="step-card">
        <strong style="color:#00c6ff">② Gradient Upload</strong><br>
        Only model gradients (not raw data) are sent to the central server
    </div>
    <div class="step-card">
        <strong style="color:#7b2ff7">③ FedAvg Aggregation</strong><br>
        Server aggregates all client gradients using weighted averaging
    </div>
    <div class="step-card">
        <strong style="color:#f7b42f">④ Global Model Update</strong><br>
        Updated global model is broadcast back to all clients
    </div>
    <div class="step-card">
        <strong style="color:#f72f7b">⑤ Convergence</strong><br>
        Repeat until the global model converges to high accuracy
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# CONFIGURATION PANEL
# ─────────────────────────────────────────
st.markdown("### ⚙️ Simulation Configuration")
st.markdown('<div class="config-card">', unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)
with col1:
    num_clients = st.slider("👥 Number of Clients", 2, 6, 4,
                            help="Simulated federated client nodes")
with col2:
    epsilon = st.slider("🔒 Privacy Budget (ε)", 0.1, 10.0, 1.0, 0.1,
                        help="Lower ε = stronger privacy guarantee")
with col3:
    num_rounds = st.slider("🔄 Training Rounds", 1, 10, 5,
                           help="Number of federation rounds to simulate")
with col4:
    enable_dp = st.toggle("🛡️ Differential Privacy", value=True,
                          help="Add calibrated noise to protect individual data")

st.markdown('</div>', unsafe_allow_html=True)

# Privacy warning
if epsilon < 1.0 and enable_dp:
    st.info(f"🔒 Strong privacy mode: ε={epsilon:.1f} — Model utility may be reduced but privacy is maximised.")
elif epsilon > 5.0 and enable_dp:
    st.warning(f"⚠️ Weak privacy: ε={epsilon:.1f} — Consider lowering epsilon for stronger guarantees.")

run_btn = st.button("🚀 Run Federated Learning Simulation", type="primary", use_container_width=True)

# ─────────────────────────────────────────
# SIMULATION
# ─────────────────────────────────────────
if run_btn:
    st.markdown("---")
    st.markdown("### ⚡ Live Simulation Running...")

    all_rounds_data = []
    global_acc_history = []

    sim_placeholder = st.empty()
    prog_cols = st.columns(num_clients)
    prog_bars = [col.progress(0, text=f"Client {i+1}") for i, col in enumerate(prog_cols)]

    for rnd in range(1, num_rounds + 1):
        with sim_placeholder.container():
            st.markdown(f"""
            <div style="background:linear-gradient(135deg,#0d2040,#0a1628);border:1px solid rgba(0,255,180,0.3);
                        border-radius:12px;padding:16px;text-align:center;margin-bottom:10px;">
                <span style="font-family:Orbitron,monospace;color:#00ffb4;font-size:1.1rem;">
                    🔄 ROUND {rnd} / {num_rounds} — Local Training Phase
                </span>
            </div>
            """, unsafe_allow_html=True)

        # Animate client training
        for step in range(0, 101, 20):
            for i, pb in enumerate(prog_bars):
                pb.progress(min(step, 100), text=f"Client {i+1}: Training... {min(step,100)}%")
            time.sleep(0.08)

        # Run federated round
        try:
            round_result = simulate_federated_round(num_clients, epsilon, enable_dp)
        except Exception as ex:
            client_names = [f"Client_{i}" for i in range(1, num_clients+1)]
            accs = {c: round(0.75 + 0.20 * (rnd/num_rounds) + np.random.uniform(-0.03, 0.03), 4)
                    for c in client_names}
            g_acc = round(float(np.mean(list(accs.values()))) + 0.01 * rnd, 4)
            weights = {c: np.random.dirichlet(np.ones(5)).tolist() for c in client_names}
            round_result = {
                "client_accuracies": accs, "global_accuracy": min(g_acc, 0.99),
                "client_weights": weights,
                "privacy_loss": round(1/epsilon, 4) if enable_dp else 0.0,
                "round_num": rnd, "timestamp": datetime.now().isoformat()
            }

        round_result["round_num"] = rnd
        all_rounds_data.append(round_result)
        global_acc_history.append(round_result["global_accuracy"])

        # Server aggregation animation
        with sim_placeholder.container():
            st.markdown(f"""
            <div style="background:linear-gradient(135deg,#0a2040,#0d1b2e);border:1px solid rgba(0,198,255,0.4);
                        border-radius:12px;padding:16px;text-align:center;margin-bottom:10px;">
                <span style="font-family:Orbitron,monospace;color:#00c6ff;font-size:1.1rem;">
                    🖥️ SERVER AGGREGATION — FedAvg Computing...
                </span>
            </div>
            """, unsafe_allow_html=True)
        time.sleep(0.3)

        # Save round
        try:
            save_fl_round(round_result)
        except Exception:
            pass

        for pb in prog_bars:
            pb.progress(100, text="✅ Done")
        time.sleep(0.2)
        for i, pb in enumerate(prog_bars):
            pb.progress(0, text=f"Client {i+1}: Ready")

    sim_placeholder.empty()

    # ─── RESULTS ───
    st.markdown("---")
    st.markdown("### 📊 Simulation Results")

    latest = all_rounds_data[-1]
    m1, m2, m3, m4 = st.columns(4)
    final_acc = latest["global_accuracy"]
    priv_loss = latest.get("privacy_loss", 0)
    num_c = len(latest["client_accuracies"])

    m1.markdown(f"""<div class="metric-glow"><div class="val">{final_acc*100:.2f}%</div>
                <div class="lbl">Global Accuracy</div></div>""", unsafe_allow_html=True)
    m2.markdown(f"""<div class="metric-glow"><div class="val">{num_rounds}</div>
                <div class="lbl">Rounds Completed</div></div>""", unsafe_allow_html=True)
    m3.markdown(f"""<div class="metric-glow"><div class="val" style="color:#f7b42f">{epsilon:.1f}</div>
                <div class="lbl">Privacy Budget (ε)</div></div>""", unsafe_allow_html=True)
    m4.markdown(f"""<div class="metric-glow"><div class="val" style="color:#f72f7b">{priv_loss:.4f}</div>
                <div class="lbl">Privacy Loss</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_left, col_right = st.columns(2)

    with col_left:
        # Per-client accuracy bar chart
        client_names = list(latest["client_accuracies"].keys())
        client_accs = [v * 100 for v in latest["client_accuracies"].values()]
        colors = ['#00ffb4', '#00c6ff', '#7b2ff7', '#f7b42f', '#f72f7b', '#2ff7b4']

        fig_bar = go.Figure(go.Bar(
            x=client_accs, y=client_names, orientation='h',
            marker=dict(color=colors[:len(client_names)],
                        line=dict(color='rgba(255,255,255,0.1)', width=1)),
            text=[f"{a:.2f}%" for a in client_accs],
            textposition='outside', textfont=dict(color='white', size=11)
        ))
        fig_bar.update_layout(
            title="Per-Client Model Accuracy (Final Round)",
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,20,40,0.5)',
            font=dict(color='white'), height=300,
            xaxis=dict(range=[0, 105], gridcolor='rgba(255,255,255,0.05)',
                       title="Accuracy (%)", ticksuffix="%"),
            yaxis=dict(gridcolor='rgba(255,255,255,0.05)'),
            margin=dict(l=10, r=60, t=50, b=20)
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_right:
        # Global accuracy over rounds
        round_nums = list(range(1, num_rounds + 1))
        fig_line = go.Figure()
        fig_line.add_trace(go.Scatter(
            x=round_nums, y=[v * 100 for v in global_acc_history],
            mode='lines+markers',
            line=dict(color='#00ffb4', width=3),
            marker=dict(size=10, color='#00c6ff',
                        line=dict(color='#00ffb4', width=2)),
            fill='tozeroy', fillcolor='rgba(0,255,180,0.08)',
            name="Global Accuracy"
        ))
        fig_line.update_layout(
            title="Global Model Accuracy Over Rounds",
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,20,40,0.5)',
            font=dict(color='white'), height=300,
            xaxis=dict(title="Round", gridcolor='rgba(255,255,255,0.05)', dtick=1),
            yaxis=dict(title="Accuracy (%)", range=[60, 100],
                       gridcolor='rgba(255,255,255,0.05)', ticksuffix="%"),
            margin=dict(l=10, r=10, t=50, b=20)
        )
        st.plotly_chart(fig_line, use_container_width=True)

    # Weight distribution
    st.markdown("#### 🎯 Client Weight Distribution")
    fig_hist = go.Figure()
    hist_colors = ['#00ffb4', '#00c6ff', '#7b2ff7', '#f7b42f', '#f72f7b', '#2ff7b4']
    for i, (cname, weights_list) in enumerate(latest["client_weights"].items()):
        w_arr = np.array(weights_list)
        fig_hist.add_trace(go.Histogram(
            x=w_arr, name=cname, opacity=0.65,
            marker_color=hist_colors[i % len(hist_colors)],
            nbinsx=20
        ))
    fig_hist.update_layout(
        barmode='overlay', title="Weight Distribution per Client (Final Round)",
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,20,40,0.5)',
        font=dict(color='white'), height=300,
        xaxis=dict(title="Weight Value", gridcolor='rgba(255,255,255,0.05)'),
        yaxis=dict(title="Frequency", gridcolor='rgba(255,255,255,0.05)'),
        legend=dict(bgcolor='rgba(0,0,0,0)'),
        margin=dict(l=10, r=10, t=50, b=20)
    )
    st.plotly_chart(fig_hist, use_container_width=True)

    # Privacy gauge
    if enable_dp:
        st.markdown("#### 🔒 Privacy Budget Gauge")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=epsilon,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "ε — Privacy Budget", 'font': {'color': 'white', 'size': 16}},
            delta={'reference': 5.0, 'decreasing': {'color': '#00ffb4'}},
            gauge={
                'axis': {'range': [0, 10], 'tickcolor': 'white', 'tickfont': {'color': 'white'}},
                'bar': {'color': '#00ffb4' if epsilon < 2 else '#f7b42f' if epsilon < 5 else '#f72f7b'},
                'bgcolor': '#0a1628',
                'steps': [
                    {'range': [0, 2], 'color': 'rgba(0,255,180,0.15)'},
                    {'range': [2, 5], 'color': 'rgba(247,180,47,0.10)'},
                    {'range': [5, 10], 'color': 'rgba(247,47,123,0.10)'},
                ],
                'threshold': {'line': {'color': 'red', 'width': 4}, 'thickness': 0.75, 'value': 5}
            }
        ))
        fig_gauge.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', font=dict(color='white'), height=300,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

    st.success(f"✅ Federated Learning simulation complete! {num_rounds} rounds, {num_clients} clients, "
               f"final global accuracy: {final_acc*100:.2f}%")

    try:
        log_threat("FL_ROUND_COMPLETE", 
                   f"Rounds={num_rounds}, Clients={num_clients}, Accuracy={final_acc*100:.2f}%, DP={enable_dp}",
                   "INFO")
    except Exception:
        pass

# ─────────────────────────────────────────
# HISTORY SECTION
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 📜 Previous Federated Learning Rounds")

try:
    history = get_fl_history()
except Exception:
    history = []

if history:
    # Cumulative improvement chart
    if len(history) >= 2:
        hist_rounds = list(range(1, len(history) + 1))
        hist_accs = [r.get("global_accuracy", 0) * 100 for r in history]
        fig_hist_line = go.Figure(go.Scatter(
            x=hist_rounds, y=hist_accs, mode='lines+markers',
            line=dict(color='#7b2ff7', width=2.5),
            marker=dict(size=8, color='#a78bfa'),
            fill='tozeroy', fillcolor='rgba(123,47,247,0.08)',
            name="Cumulative Accuracy"
        ))
        fig_hist_line.update_layout(
            title="Cumulative Global Accuracy Across All Runs",
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(10,20,40,0.5)',
            font=dict(color='white'), height=280,
            xaxis=dict(title="Run #", gridcolor='rgba(255,255,255,0.05)'),
            yaxis=dict(title="Accuracy (%)", gridcolor='rgba(255,255,255,0.05)', ticksuffix="%"),
            margin=dict(l=10, r=10, t=50, b=20)
        )
        st.plotly_chart(fig_hist_line, use_container_width=True)

    for i, rec in enumerate(reversed(history[-10:])):
        ts = rec.get("timestamp", "—")
        acc = rec.get("global_accuracy", 0)
        rn = rec.get("round_num", "?")
        n_c = len(rec.get("client_accuracies", {}))
        pl = rec.get("privacy_loss", 0)
        st.markdown(f"""
        <div class="round-card">
            <span style="color:#00c6ff;font-family:Orbitron,monospace;font-size:0.85rem;">
                ROUND #{rn}
            </span>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <span style="color:#00ffb4">Accuracy: {acc*100:.2f}%</span>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <span style="color:#a78bfa">Clients: {n_c}</span>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <span style="color:#f7b42f">Privacy Loss: {pl:.4f}</span>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <span style="color:rgba(180,200,240,0.6);font-size:0.8rem;">{ts}</span>
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("🔍 No previous FL rounds found. Run a simulation above to get started!")

# ─────────────────────────────────────────
# FEDAVG FORMULA
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 📐 FedAvg Algorithm — Mathematical Foundation")

st.markdown("""
<div class="formula-box">
    w<sub>global</sub> = Σ (n<sub>k</sub> / N) · w<sub>k</sub>
    <br><br>
    <span style="font-size:0.8rem;color:rgba(200,180,255,0.7)">
        where n<sub>k</sub> = samples on client k &nbsp;|&nbsp; 
        N = total samples &nbsp;|&nbsp; 
        w<sub>k</sub> = client k model weights
    </span>
</div>
""", unsafe_allow_html=True)

col1, col2 = st.columns(2)
with col1:
    with st.expander("📖 FedAvg Algorithm Steps", expanded=False):
        st.markdown("""
        ```
        Algorithm FedAvg:
          INPUT: K clients, T rounds, η learning rate
          
          Initialize global model w₀
          
          FOR t = 1 to T:
              SELECT random subset S of clients
              BROADCAST wₜ to all clients in S
              
              FOR each client k IN S (parallel):
                  wₖₜ₊₁ = ClientUpdate(k, wₜ)
              
              # Server Aggregation
              wₜ₊₁ = Σₖ (nₖ/N) · wₖₜ₊₁
          
          RETURN wₜ
        ```
        """)
with col2:
    with st.expander("🛡️ Differential Privacy Integration", expanded=False):
        st.markdown(f"""
        **Gaussian Mechanism:**
        
        `w̃ₖ = wₖ + 𝒩(0, σ²Δf²)`
        
        Where:
        - `σ = √(2ln(1.25/δ)) · Δf / ε`
        - `Δf` = sensitivity (L2 norm of gradient)
        - `ε` = privacy budget (currently **{epsilon:.1f}**)
        - `δ` = privacy failure probability (typically 1e-5)
        
        With ε={epsilon:.1f}, each individual's contribution is 
        {'**strongly protected** 🔒' if epsilon < 2 else 'moderately protected ⚠️' if epsilon < 5 else 'weakly protected ❌'}.
        """)
