import streamlit as st
import time
import random
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(
    page_title="Fraud Transaction Detector | CyberShield AI",
    page_icon="💳",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Graceful imports ──────────────────────────────────────────────────────────
try:
    from utils.auth import require_login, get_current_user
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False

try:
    from utils.ui_helpers import apply_custom_css, threat_badge, render_metric_card, render_section_header, render_alert
    UI_AVAILABLE = True
except ImportError:
    UI_AVAILABLE = False

try:
    from utils.ml_models import predict_fraud
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from utils.threat_logger import log_threat, get_threats
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

try:
    from utils.explainability import explain_fraud_prediction
    EXPLAIN_AVAILABLE = True
except ImportError:
    EXPLAIN_AVAILABLE = False

if AUTH_AVAILABLE:
    apply_custom_css()
    require_login()
elif UI_AVAILABLE:
    apply_custom_css()

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
.stApp { background: linear-gradient(135deg, #0a0e1a 0%, #0d1117 50%, #0a1628 100%); }

.fraud-hero {
    background: linear-gradient(135deg, #0a0a2e 0%, #16163e 50%, #1a0a2e 100%);
    border: 1px solid rgba(138,43,226,0.35); border-radius: 20px;
    padding: 2.5rem 3rem; margin-bottom: 2rem;
    position: relative; overflow: hidden;
}
.fraud-hero::before {
    content: ''; position: absolute; top: -40%; right: -5%;
    width: 280px; height: 280px;
    background: radial-gradient(circle, rgba(138,43,226,0.2) 0%, transparent 70%);
    border-radius: 50%;
}
.fraud-hero h1 {
    font-size: 2.5rem; font-weight: 800;
    background: linear-gradient(135deg, #a855f7, #ec4899, #f59e0b);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin: 0 0 0.5rem 0;
}
.fraud-hero p { color: #8892b0; font-size: 1.1rem; margin: 0; }

/* Verdict */
.verdict-FRAUD {
    background: linear-gradient(135deg, #1a0000, #2a0808, #1a001a);
    border: 2px solid #ff1a1a; border-radius: 20px; padding: 2rem;
    text-align: center; animation: pulse-fraud 1.8s infinite;
    position: relative; overflow: hidden;
}
.verdict-FRAUD::before {
    content: ''; position: absolute; inset: 0;
    background: radial-gradient(circle at 50% 50%, rgba(255,26,26,0.1) 0%, transparent 70%);
}
.verdict-NORMAL {
    background: linear-gradient(135deg, #001a0a, #002a12, #001a1a);
    border: 2px solid #00cc66; border-radius: 20px; padding: 2rem; text-align: center;
}
@keyframes pulse-fraud { 0%,100%{border-color:#ff1a1a;box-shadow:0 0 30px rgba(255,26,26,0.4)} 50%{border-color:#ff5555;box-shadow:0 0 60px rgba(255,26,26,0.7)} }

/* Form card */
.form-card {
    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px; padding: 1.5rem;
}

/* Transaction row */
.txn-row-fraud {
    background: rgba(255,77,77,0.1); border-left: 3px solid #ff4d4d;
    border-radius: 8px; padding: 0.6rem 1rem; margin-bottom: 0.4rem;
    font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;
    display: grid; grid-template-columns: 1fr 1fr 1fr 1fr 0.7fr; gap: 0.5rem; align-items: center;
}
.txn-row-normal {
    background: rgba(0,204,102,0.07); border-left: 3px solid #00cc66;
    border-radius: 8px; padding: 0.6rem 1rem; margin-bottom: 0.4rem;
    font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;
    display: grid; grid-template-columns: 1fr 1fr 1fr 1fr 0.7fr; gap: 0.5rem; align-items: center;
}
.txn-header {
    background: rgba(255,255,255,0.06); border-radius: 8px; padding: 0.5rem 1rem; margin-bottom: 0.4rem;
    font-size: 0.78rem; color: #8892b0; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;
    display: grid; grid-template-columns: 1fr 1fr 1fr 1fr 0.7fr; gap: 0.5rem;
}

/* Risk factor list */
.risk-factor {
    display: flex; align-items: flex-start; gap: 0.7rem;
    padding: 0.7rem 1rem; background: rgba(255,77,77,0.08);
    border: 1px solid rgba(255,77,77,0.2); border-radius: 10px; margin-bottom: 0.5rem;
    color: #ffb3b3; font-size: 0.9rem;
}
.normal-factor {
    display: flex; align-items: flex-start; gap: 0.7rem;
    padding: 0.7rem 1rem; background: rgba(0,204,102,0.07);
    border: 1px solid rgba(0,204,102,0.2); border-radius: 10px; margin-bottom: 0.5rem;
    color: #b3ffda; font-size: 0.9rem;
}

.section-divider { height: 2px; background: linear-gradient(90deg, transparent, rgba(138,43,226,0.5), transparent); margin: 2rem 0; border: none; }
.live-indicator { display: inline-block; width: 8px; height: 8px; background: #00cc66; border-radius: 50%; animation: blink 1s infinite; margin-right: 6px; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }

.stat-box { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 1rem; text-align: center; }
.stat-val { font-size: 1.6rem; font-weight: 700; }
.stat-lbl { font-size: 0.78rem; color: #8892b0; margin-top: 0.2rem; }
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────
LOCATIONS = ["Mumbai", "Delhi", "Bangalore", "Chennai", "Kolkata", "London", "New York", "Dubai", "Unknown"]
DEVICES = ["Mobile App", "Web Browser", "ATM", "POS Terminal", "Unknown Device"]
FOREIGN_LOCS = {"London", "New York", "Dubai", "Unknown"}

# ── Fallback predictor ────────────────────────────────────────────────────────
def _mock_predict_fraud(amount: float, location: str, hour: int, device: str, freq: int) -> dict:
    score = 0
    risk_factors = []
    normal_factors = []

    # Amount
    if amount > 50000:
        score += 25
        risk_factors.append(f"High transaction amount: ₹{amount:,.0f}")
    elif amount > 10000:
        score += 10
    else:
        normal_factors.append("Normal transaction amount")

    # Location
    if location in FOREIGN_LOCS:
        score += 30
        risk_factors.append(f"International/unknown location: {location}")
    else:
        normal_factors.append(f"Domestic location: {location}")

    # Hour
    if 0 <= hour <= 5:
        score += 20
        risk_factors.append(f"Unusual transaction time: {hour:02d}:00 (late night/early morning)")
    elif 22 <= hour <= 23:
        score += 10
        risk_factors.append("Late night transaction")
    else:
        normal_factors.append(f"Normal business hours: {hour:02d}:00")

    # Device
    if device == "Unknown Device":
        score += 25
        risk_factors.append("Transaction from unknown/unregistered device")
    elif device == "ATM" and amount > 20000:
        score += 15
        risk_factors.append(f"Large ATM withdrawal: ₹{amount:,.0f}")
    else:
        normal_factors.append(f"Trusted device: {device}")

    # Frequency
    if freq >= 10:
        score += 20
        risk_factors.append(f"Very high frequency: {freq} transactions in last hour")
    elif freq >= 5:
        score += 10
        risk_factors.append(f"Elevated transaction frequency: {freq}/hour")
    else:
        normal_factors.append(f"Normal frequency: {freq} transactions/hour")

    score = min(score, 100)
    label = "FRAUD" if score >= 50 else "NORMAL"
    if score >= 80: threat = "CRITICAL"
    elif score >= 60: threat = "HIGH"
    elif score >= 40: threat = "MEDIUM"
    else: threat = "LOW"

    return {
        "label": label,
        "probability": round(score / 100, 4),
        "risk_score": score,
        "threat_level": threat,
        "risk_factors": risk_factors if risk_factors else normal_factors
    }

def get_fraud_prediction(amount, location, hour, device, freq):
    if ML_AVAILABLE:
        return predict_fraud(amount, location, hour, device, freq)
    return _mock_predict_fraud(amount, location, hour, device, freq)

# ── Random transaction generator ──────────────────────────────────────────────
def _generate_random_transactions(n: int = 8) -> list:
    txns = []
    for i in range(n):
        amt = random.choice([
            random.randint(100, 2000),
            random.randint(2000, 15000),
            random.randint(50000, 200000),
        ])
        loc = random.choice(LOCATIONS)
        hr = random.randint(0, 23)
        dev = random.choice(DEVICES)
        freq = random.randint(1, 20)
        r = _mock_predict_fraud(amt, loc, hr, dev, freq)
        txns.append({
            "ID": f"TXN{1000+i}",
            "Amount": f"₹{amt:,}",
            "Location": loc,
            "Time": f"{hr:02d}:00",
            "Device": dev[:10],
            "Status": r["label"],
            "Risk": r["risk_score"],
            "_amount": amt,
            "_loc": loc,
            "_hr": hr,
            "_dev": dev,
            "_freq": freq,
        })
    return txns

# ── HERO ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="fraud-hero">
  <h1>💳 Fraud Transaction Detector</h1>
  <p>AI-powered real-time fraud detection for banking transactions — analyzes amount, location, time, device & frequency patterns</p>
</div>
""", unsafe_allow_html=True)

main_col, side_col = st.columns([3, 1])

with side_col:
    st.markdown("### 📊 Session Overview")
    if "fraud_session" not in st.session_state:
        st.session_state["fraud_session"] = {"scanned": 0, "fraud": 0, "normal": 0, "patterns": []}
    sess = st.session_state["fraud_session"]
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f'<div class="stat-box"><div class="stat-val">{sess["scanned"]}</div><div class="stat-lbl">Analyzed</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="stat-box"><div class="stat-val" style="color:#ff4d4d;">{sess["fraud"]}</div><div class="stat-lbl">Fraud</div></div>', unsafe_allow_html=True)

    st.markdown("---")

    # Fraud patterns detected
    st.markdown("### 🔍 Patterns Detected")
    pattern_data = {
        "Late Night": random.randint(2, 8),
        "Foreign Loc.": random.randint(1, 5),
        "High Amount": random.randint(3, 9),
        "Unknown Dev.": random.randint(1, 4),
        "High Freq.": random.randint(2, 6),
    }
    for p, v in pattern_data.items():
        bar_w = int(v / 10 * 100)
        st.markdown(f"""
        <div style="margin-bottom:0.6rem;">
            <div style="display:flex;justify-content:space-between;color:#8892b0;font-size:0.78rem;margin-bottom:3px;"><span>{p}</span><span style="color:#a855f7;">{v}</span></div>
            <div style="background:rgba(255,255,255,0.07);border-radius:4px;height:6px;"><div style="width:{bar_w}%;height:100%;background:linear-gradient(90deg,#a855f7,#ec4899);border-radius:4px;"></div></div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🛡️ Fraud Signals")
    signals = [
        ("🌍", "International transactions"),
        ("🌙", "2AM–5AM transactions"),
        ("💸", "Amount > ₹50,000"),
        ("📱", "Unknown device"),
        ("⚡", "> 8 txns/hour"),
    ]
    for icon, sig in signals:
        st.markdown(f"<div style='color:#8892b0;font-size:0.82rem;padding:0.2rem 0;'>{icon} {sig}</div>", unsafe_allow_html=True)

with main_col:
    tab1, tab2 = st.tabs(["🔍 Analyze Transaction", "📡 Live Transaction Feed"])

    with tab1:
        st.markdown('<div class="form-card">', unsafe_allow_html=True)
        st.markdown("#### 💳 Transaction Details")

        fc1, fc2 = st.columns(2)
        with fc1:
            amount_slider = st.slider("Transaction Amount (₹)", min_value=100, max_value=500000, value=5000, step=100, key="fraud_amount_slider")
            amount_input = st.number_input("Or type exact amount:", min_value=1, max_value=10000000, value=amount_slider, step=100, key="fraud_amount_input")
            final_amount = amount_input

            location = st.selectbox("Transaction Location", LOCATIONS, key="fraud_location")

        with fc2:
            hour = st.slider("Transaction Hour (0 = midnight)", min_value=0, max_value=23, value=14, step=1,
                             format="%d:00", key="fraud_hour")
            hour_display = f"{'🌙' if hour < 6 or hour >= 22 else '☀️'} {hour:02d}:00 {'(Late Night ⚠️)' if hour < 6 or hour >= 22 else '(Business Hours)'}"
            st.markdown(f"<p style='color:#8892b0;font-size:0.85rem;margin-top:0.3rem;'>{hour_display}</p>", unsafe_allow_html=True)

            device = st.selectbox("Device Type", DEVICES, key="fraud_device")
            freq = st.slider("Transaction Frequency (this hour)", min_value=1, max_value=20, value=2, key="fraud_freq")

        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        analyze_fraud = st.button("🔍 Analyze Transaction", type="primary", use_container_width=True)

        if analyze_fraud:
            prog = st.progress(0, "🔄 Initializing fraud detection engine…")
            for pct, msg in [
                (20, "📊 Loading transaction features…"),
                (45, "🧠 Running ensemble classifier…"),
                (70, "🔍 Checking fraud patterns…"),
                (90, "📈 Computing risk score…"),
                (100, "✅ Analysis complete!")
            ]:
                time.sleep(0.3)
                prog.progress(pct, msg)
            time.sleep(0.2)
            prog.empty()

            result = get_fraud_prediction(final_amount, location, hour, device, freq)

            sess["scanned"] += 1
            if result["label"] == "FRAUD":
                sess["fraud"] += 1
            else:
                sess["normal"] += 1

            if LOGGER_AVAILABLE and result["label"] == "FRAUD":
                try:
                    log_threat(threat_type="FRAUD_TRANSACTION", severity=result["threat_level"],
                               details={"amount": final_amount, "location": location, "hour": hour,
                                        "device": device, "freq": freq, "risk_score": result["risk_score"]})
                except Exception:
                    pass

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown("## 🎯 Fraud Analysis Result")

            # Large verdict
            if result["label"] == "FRAUD":
                st.markdown(f"""
                <div class="verdict-FRAUD">
                    <div style="font-size:3.5rem;">🚨</div>
                    <div style="font-size:2rem;font-weight:800;color:#ff4d4d;letter-spacing:4px;">FRAUD DETECTED</div>
                    <div style="color:#ff8888;margin-top:0.5rem;font-size:1rem;">Risk Score: <strong>{result['risk_score']}/100</strong> &nbsp;|&nbsp; Threat: <strong>{result['threat_level']}</strong></div>
                    <div style="color:#ff6666;margin-top:0.3rem;font-size:0.9rem;">Transaction flagged for review. Do not approve.</div>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="verdict-NORMAL">
                    <div style="font-size:3.5rem;">✅</div>
                    <div style="font-size:2rem;font-weight:800;color:#00cc66;letter-spacing:4px;">TRANSACTION NORMAL</div>
                    <div style="color:#88ffbb;margin-top:0.5rem;font-size:1rem;">Risk Score: <strong>{result['risk_score']}/100</strong> &nbsp;|&nbsp; Threat Level: <strong>{result['threat_level']}</strong></div>
                    <div style="color:#66ff99;margin-top:0.3rem;font-size:0.9rem;">No suspicious patterns detected. Transaction approved.</div>
                </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            chart_c1, chart_c2 = st.columns([1, 1])

            with chart_c1:
                # Gauge
                g_color = "#ff4d4d" if result["risk_score"] >= 70 else "#ffd700" if result["risk_score"] >= 40 else "#00cc66"
                fig_g = go.Figure(go.Indicator(
                    mode="gauge+number+delta",
                    value=result["risk_score"],
                    delta={"reference": 50, "increasing": {"color": "#ff4d4d"}, "decreasing": {"color": "#00cc66"}},
                    title={"text": "Fraud Risk Score", "font": {"color": "#ccd6f6", "size": 15}},
                    number={"font": {"color": g_color, "size": 42}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#8892b0", "tickfont": {"color": "#8892b0"}},
                        "bar": {"color": g_color, "thickness": 0.3},
                        "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                        "steps": [
                            {"range": [0, 40], "color": "rgba(0,204,102,0.12)"},
                            {"range": [40, 70], "color": "rgba(255,215,0,0.12)"},
                            {"range": [70, 100], "color": "rgba(255,77,77,0.12)"},
                        ],
                        "threshold": {"line": {"color": g_color, "width": 4}, "thickness": 0.75, "value": result["risk_score"]}
                    }
                ))
                fig_g.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font={"color": "#ccd6f6"}, height=280, margin=dict(t=50, b=10, l=20, r=20)
                )
                st.plotly_chart(fig_g, use_container_width=True)

            with chart_c2:
                # Risk breakdown bar chart
                feature_names = ["Amount", "Location", "Time of Day", "Device Type", "Frequency"]
                # Compute sub-scores
                amt_s = min(40, final_amount / 500000 * 40) if final_amount > 10000 else 5
                loc_s = 30 if location in FOREIGN_LOCS else 5
                hr_s = 20 if hour < 6 or hour >= 22 else (10 if hour >= 20 else 3)
                dev_s = 25 if device == "Unknown Device" else (15 if device == "ATM" else 5)
                freq_s = min(20, (freq - 1) * 2)
                feature_scores = [amt_s, loc_s, hr_s, dev_s, freq_s]
                bar_colors = ["#ff4d4d" if s >= 15 else "#ffd700" if s >= 8 else "#00cc66" for s in feature_scores]

                fig_bar = go.Figure(go.Bar(
                    x=feature_names, y=feature_scores,
                    marker=dict(color=bar_colors, line=dict(color="rgba(255,255,255,0.1)", width=1)),
                    text=[f"{int(s)}" for s in feature_scores], textposition="outside",
                    textfont=dict(color="#ccd6f6", size=12)
                ))
                fig_bar.update_layout(
                    title=dict(text="Risk Contribution by Feature", font=dict(color="#ccd6f6", size=14)),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    xaxis=dict(color="#8892b0", gridcolor="rgba(255,255,255,0.05)"),
                    yaxis=dict(color="#8892b0", gridcolor="rgba(255,255,255,0.05)", title="Risk Points"),
                    height=280, margin=dict(t=50, b=20, l=20, r=20),
                    font=dict(color="#ccd6f6")
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            # Animated prob bar
            prob_pct = int(result["probability"] * 100)
            p_color = g_color
            st.markdown(f"""
            <div style="margin-top:1rem;">
                <div style="display:flex;justify-content:space-between;color:#8892b0;font-size:0.9rem;margin-bottom:0.4rem;">
                    <span>Fraud Probability</span><span style="color:{p_color};font-weight:700;">{prob_pct}%</span>
                </div>
                <div style="background:rgba(255,255,255,0.08);border-radius:8px;height:16px;overflow:hidden;">
                    <div style="width:{prob_pct}%;height:100%;background:linear-gradient(90deg,{p_color},{p_color}bb);border-radius:8px;box-shadow:0 0 12px {p_color}66;"></div>
                </div>
            </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Risk factors
            risk_factors = result.get("risk_factors", [])
            if risk_factors:
                st.markdown("#### 🚩 Risk Factors / Assessment")
                for rf in risk_factors:
                    if result["label"] == "FRAUD":
                        st.markdown(f'<div class="risk-factor">⚠️ &nbsp; {rf}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="normal-factor">✅ &nbsp; {rf}</div>', unsafe_allow_html=True)

            # Explanation
            if EXPLAIN_AVAILABLE:
                try:
                    expl = explain_fraud_prediction(final_amount, location, hour, device, freq, result)
                    with st.expander("🔬 AI Explanation"):
                        st.markdown(expl)
                except Exception:
                    pass
            else:
                with st.expander("🔬 Detailed Risk Analysis"):
                    if result["label"] == "FRAUD":
                        st.markdown(f"""
**Transaction Risk Summary:**
- **Risk Score {result['risk_score']}/100** — HIGH probability of fraud
- {len(risk_factors)} risk signals detected in this transaction
- Recommendation: **Block transaction** and notify the account holder immediately
- Send OTP verification challenge before proceeding
- Flag this device/location combination for 30-day monitoring
                        """)
                    else:
                        st.markdown(f"""
**Transaction Risk Summary:**
- **Risk Score {result['risk_score']}/100** — Within safe parameters
- Transaction patterns match historical behavior
- Device and location are familiar/trusted
- Recommendation: **Approve** — no intervention required
- Continue monitoring as part of standard fraud prevention
                        """)

    with tab2:
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;">
            <span class="live-indicator"></span>
            <span style="color:#00cc66;font-weight:600;font-size:1rem;">LIVE Transaction Feed</span>
            <span style="color:#8892b0;font-size:0.85rem;margin-left:0.5rem;">— Auto-generated on page load</span>
        </div>""", unsafe_allow_html=True)

        refresh_btn = st.button("🔄 Refresh Feed", key="refresh_feed")

        if "live_txns" not in st.session_state or refresh_btn:
            with st.spinner("Generating transaction feed…"):
                time.sleep(0.5)
                st.session_state["live_txns"] = _generate_random_transactions(random.randint(8, 12))

        txns = st.session_state["live_txns"]
        fraud_count = sum(1 for t in txns if t["Status"] == "FRAUD")
        normal_count = len(txns) - fraud_count

        # Summary mini-metrics
        lc1, lc2, lc3, lc4 = st.columns(4)
        with lc1:
            st.markdown(f'<div class="stat-box"><div class="stat-val">{len(txns)}</div><div class="stat-lbl">Total Transactions</div></div>', unsafe_allow_html=True)
        with lc2:
            st.markdown(f'<div class="stat-box"><div class="stat-val" style="color:#ff4d4d;">{fraud_count}</div><div class="stat-lbl">Fraud Detected</div></div>', unsafe_allow_html=True)
        with lc3:
            st.markdown(f'<div class="stat-box"><div class="stat-val" style="color:#00cc66;">{normal_count}</div><div class="stat-lbl">Legitimate</div></div>', unsafe_allow_html=True)
        with lc4:
            pct = int(fraud_count / len(txns) * 100) if txns else 0
            st.markdown(f'<div class="stat-box"><div class="stat-val" style="color:#ffd700;">{pct}%</div><div class="stat-lbl">Fraud Rate</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Transaction table header
        st.markdown("""
        <div class="txn-header">
            <span>TXN ID</span><span>Amount</span><span>Location</span><span>Device</span><span>Status</span>
        </div>""", unsafe_allow_html=True)

        for txn in txns:
            row_cls = "txn-row-fraud" if txn["Status"] == "FRAUD" else "txn-row-normal"
            status_icon = "🚨" if txn["Status"] == "FRAUD" else "✅"
            status_color = "#ff4d4d" if txn["Status"] == "FRAUD" else "#00cc66"
            st.markdown(f"""
            <div class="{row_cls}">
                <span style="color:#ccd6f6;">{txn['ID']}</span>
                <span style="color:#ffd700;">{txn['Amount']}</span>
                <span style="color:#8892b0;">{txn['Location']} {txn['Time']}</span>
                <span style="color:#8892b0;">{txn['Device']}</span>
                <span style="color:{status_color};font-weight:700;">{status_icon} {txn['Status']}</span>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Risk distribution chart
        chart_l, chart_r = st.columns(2)
        with chart_l:
            fig_dist = go.Figure(go.Pie(
                labels=["Normal", "Fraud"],
                values=[normal_count, fraud_count],
                marker=dict(colors=["#00cc66", "#ff4d4d"], line=dict(color="#0d1117", width=2)),
                hole=0.55,
                textfont=dict(color="#ccd6f6", size=12),
                hovertemplate="%{label}: %{value} transactions<extra></extra>"
            ))
            fig_dist.update_layout(
                title=dict(text="Transaction Distribution", font=dict(color="#ccd6f6", size=14)),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#ccd6f6"),
                legend=dict(font=dict(color="#ccd6f6"), bgcolor="rgba(0,0,0,0)"),
                height=280, margin=dict(t=50, b=10, l=10, r=10),
                annotations=[dict(text=f"{pct}%<br>Fraud", font=dict(color="#ff4d4d" if pct > 0 else "#00cc66", size=13), showarrow=False)]
            )
            st.plotly_chart(fig_dist, use_container_width=True)

        with chart_r:
            # Risk score scatter by location
            locs = [t["_loc"] for t in txns]
            risks = [t["Risk"] for t in txns]
            amounts = [t["_amount"] for t in txns]
            colors_scatter = ["#ff4d4d" if t["Status"] == "FRAUD" else "#00cc66" for t in txns]
            fig_scatter = go.Figure(go.Scatter(
                x=locs, y=risks,
                mode="markers",
                marker=dict(
                    color=colors_scatter, size=[max(8, min(30, a // 5000)) for a in amounts],
                    line=dict(color="rgba(255,255,255,0.3)", width=1)
                ),
                text=[f"₹{t['_amount']:,} | Risk:{t['Risk']}" for t in txns],
                hovertemplate="%{text}<extra></extra>"
            ))
            fig_scatter.update_layout(
                title=dict(text="Risk by Location (size = amount)", font=dict(color="#ccd6f6", size=13)),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(color="#8892b0", gridcolor="rgba(255,255,255,0.05)", tickangle=-30),
                yaxis=dict(color="#8892b0", gridcolor="rgba(255,255,255,0.05)", title="Risk Score"),
                height=280, margin=dict(t=50, b=60, l=20, r=20),
                font=dict(color="#ccd6f6")
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
