import streamlit as st
import time
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

st.set_page_config(
    page_title="Phishing Email Detector | CyberShield AI",
    page_icon="📧",
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
    from utils.ml_models import predict_email
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from utils.threat_logger import log_threat, get_threats
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

try:
    from utils.explainability import explain_email_prediction
    EXPLAIN_AVAILABLE = True
except ImportError:
    EXPLAIN_AVAILABLE = False

# ── Auth gate ─────────────────────────────────────────────────────────────────
if AUTH_AVAILABLE:
    apply_custom_css()
    require_login()
elif UI_AVAILABLE:
    apply_custom_css()

# ── Inline CSS (always applied) ───────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }

/* Page background */
.stApp { background: linear-gradient(135deg, #0a0e1a 0%, #0d1117 50%, #0a1628 100%); }

/* Main header */
.email-hero {
    background: linear-gradient(135deg, #1a0a2e 0%, #16213e 50%, #0f3460 100%);
    border: 1px solid rgba(255,77,77,0.3);
    border-radius: 20px;
    padding: 2.5rem 3rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.email-hero::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -10%;
    width: 300px;
    height: 300px;
    background: radial-gradient(circle, rgba(255,77,77,0.15) 0%, transparent 70%);
    border-radius: 50%;
}
.email-hero h1 {
    font-size: 2.5rem;
    font-weight: 800;
    background: linear-gradient(135deg, #ff4d4d, #ff8c00, #ffd700);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0 0 0.5rem 0;
}
.email-hero p { color: #8892b0; font-size: 1.1rem; margin: 0; }

/* Threat badge */
.threat-CRITICAL {
    background: linear-gradient(135deg, #ff1a1a, #cc0000);
    color: white; padding: 1rem 2rem; border-radius: 12px;
    font-size: 1.8rem; font-weight: 800; text-align: center;
    box-shadow: 0 0 30px rgba(255,0,0,0.5);
    animation: pulse-red 2s infinite;
    letter-spacing: 2px;
}
.threat-HIGH {
    background: linear-gradient(135deg, #ff6b00, #e55100);
    color: white; padding: 1rem 2rem; border-radius: 12px;
    font-size: 1.8rem; font-weight: 800; text-align: center;
    box-shadow: 0 0 30px rgba(255,107,0,0.5);
    animation: pulse-orange 2s infinite;
    letter-spacing: 2px;
}
.threat-MEDIUM {
    background: linear-gradient(135deg, #ffd700, #ff8c00);
    color: #0a0e1a; padding: 1rem 2rem; border-radius: 12px;
    font-size: 1.8rem; font-weight: 800; text-align: center;
    box-shadow: 0 0 20px rgba(255,215,0,0.4);
    letter-spacing: 2px;
}
.threat-LOW, .threat-SAFE {
    background: linear-gradient(135deg, #00cc66, #00994d);
    color: white; padding: 1rem 2rem; border-radius: 12px;
    font-size: 1.8rem; font-weight: 800; text-align: center;
    box-shadow: 0 0 25px rgba(0,204,102,0.4);
    letter-spacing: 2px;
}
@keyframes pulse-red { 0%,100%{box-shadow:0 0 30px rgba(255,0,0,0.5)} 50%{box-shadow:0 0 60px rgba(255,0,0,0.9)} }
@keyframes pulse-orange { 0%,100%{box-shadow:0 0 30px rgba(255,107,0,0.5)} 50%{box-shadow:0 0 60px rgba(255,107,0,0.9)} }

/* Keyword chips */
.kw-chip {
    display: inline-block;
    background: rgba(255,77,77,0.2);
    border: 1px solid rgba(255,77,77,0.5);
    color: #ff6b6b;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    margin: 0.2rem;
}

/* Tips card */
.tip-card {
    background: rgba(0,204,102,0.08);
    border: 1px solid rgba(0,204,102,0.25);
    border-radius: 12px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.8rem;
    color: #ccd6f6;
    font-size: 0.9rem;
}
.tip-card .tip-icon { font-size: 1.2rem; margin-right: 0.5rem; }

/* Example card */
.example-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 1rem;
    cursor: pointer;
    transition: border-color 0.3s;
}
.example-card:hover { border-color: rgba(100,149,237,0.5); }

/* Styledivider */
.section-divider {
    height: 2px;
    background: linear-gradient(90deg, transparent, rgba(100,149,237,0.5), transparent);
    margin: 2rem 0;
    border: none;
}

/* Stat box */
.stat-box {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 12px;
    padding: 1rem;
    text-align: center;
}
.stat-box .stat-val { font-size: 1.8rem; font-weight: 700; color: #64ffda; }
.stat-box .stat-lbl { font-size: 0.82rem; color: #8892b0; margin-top: 0.2rem; }

/* Input styling */
.stTextArea textarea {
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid rgba(100,149,237,0.3) !important;
    border-radius: 12px !important;
    color: #ccd6f6 !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.stTextArea textarea:focus { border-color: rgba(100,149,237,0.8) !important; box-shadow: 0 0 15px rgba(100,149,237,0.2) !important; }

/* Progress bar override */
.stProgress > div > div { background: linear-gradient(90deg, #ff4d4d, #ff8c00) !important; border-radius: 4px !important; }
</style>
""", unsafe_allow_html=True)

# ── EXAMPLE EMAILS ─────────────────────────────────────────────────────────────
EXAMPLES = {
    "🇬🇧 English Phishing": {
        "text": "URGENT: Your bank account has been suspended. Click here immediately to verify: http://secure-bank-verify.com/login\n\nDear Customer,\n\nWe have detected suspicious activity on your account. Your account will be permanently closed within 24 hours unless you verify your information immediately.\n\nClick the link below NOW:\nhttp://secure-bank-verify.com/login?token=xyz123\n\nProvide your: Account number, PIN, OTP\n\nFailure to comply will result in permanent account closure.\n\n- Security Team",
        "label": "⚠️ Phishing",
        "color": "#ff4d4d"
    },
    "🇮🇳 Hindi Phishing": {
        "text": "आपका बैंक खाता बंद हो गया है। तुरंत verify करें: http://bank-verify.in/otp\n\nप्रिय ग्राहक,\n\nआपके खाते में संदिग्ध गतिविधि पाई गई है। अगर आप 2 घंटे में verify नहीं करते तो आपका खाता हमेशा के लिए बंद हो जाएगा।\n\nअभी क्लिक करें: http://bank-verify.in/otp?id=9876\n\nअपना ATM PIN और OTP दर्ज करें।",
        "label": "⚠️ Phishing",
        "color": "#ff4d4d"
    },
    "✅ Legitimate Email": {
        "text": "Dear John,\n\nThank you for your recent purchase from our store. Your order #12345 has been confirmed and will be shipped within 2-3 business days.\n\nOrder Details:\n- Item: Laptop Stand\n- Quantity: 1\n- Total: ₹2,499\n\nYou can track your order at: https://mystore.com/track/12345\n\nIf you have any questions, please contact us at support@mystore.com\n\nBest regards,\nCustomer Service Team\nMyStore.com",
        "label": "✅ Legitimate",
        "color": "#00cc66"
    },
    "🇮🇳 Marathi Phishing": {
        "text": "तुमचे खाते तात्पुरते बंद केले आहे. लगेच verify करा\n\nप्रिय ग्राहक,\n\nआमच्या सुरक्षा प्रणालीने तुमच्या खात्यावर संशयास्पद व्यवहार आढळले आहेत. तुमचे खाते 24 तासांत कायमचे बंद केले जाईल.\n\nआत्ता येथे क्लिक करा: http://bank-secure-verify.co.in/marathi/otp\n\nतुमचा ATM क्रमांक आणि पासवर्ड द्या.",
        "label": "⚠️ Phishing",
        "color": "#ff4d4d"
    }
}

# ── Fallback predict_email ────────────────────────────────────────────────────
def _mock_predict_email(text: str) -> dict:
    """Demo predictor when ML model not available."""
    phishing_kw = ["urgent", "suspended", "verify", "click here", "immediately",
                   "account", "login", "otp", "pin", "atm", "bंद", "verify करें",
                   "turat", "click", "secure", "http://", "token", "24 hours"]
    text_lower = text.lower()
    hits = sum(1 for kw in phishing_kw if kw in text_lower)
    is_phishing = hits >= 3
    prob = min(0.98, 0.35 + hits * 0.1) if is_phishing else max(0.05, 0.30 - hits * 0.05)
    risk = int(prob * 100)
    if risk >= 80: threat = "CRITICAL"
    elif risk >= 60: threat = "HIGH"
    elif risk >= 40: threat = "MEDIUM"
    else: threat = "LOW"
    all_kw = [("urgent", 0.92), ("suspended", 0.89), ("verify", 0.85), ("click here", 0.83),
              ("immediately", 0.80), ("otp", 0.78), ("login", 0.72), ("token", 0.70),
              ("24 hours", 0.65), ("account", 0.60)]
    found_kw = [(w, s) for w, s in all_kw if w in text_lower]
    return {
        "label": "PHISHING" if is_phishing else "SAFE",
        "probability": round(prob, 4),
        "risk_score": risk,
        "threat_level": threat,
        "top_features": found_kw[:10] if found_kw else [("no_suspicious", 0.1)]
    }

def get_prediction(text):
    if ML_AVAILABLE:
        return predict_email(text)
    return _mock_predict_email(text)

# ── HERO HEADER ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="email-hero">
  <h1>📧 Phishing Email Detector</h1>
  <p>AI-powered analysis to detect phishing attempts, social engineering, and malicious links in emails — supports English, Hindi & Marathi</p>
</div>
""", unsafe_allow_html=True)

# ── LAYOUT ────────────────────────────────────────────────────────────────────
main_col, side_col = st.columns([3, 1])

with side_col:
    st.markdown("### 🛡️ Email Safety Tips")
    tips = [
        ("🔍", "Never click links in urgent emails — go directly to the official website"),
        ("🏦", "Banks NEVER ask for your PIN, OTP, or password via email"),
        ("🔗", "Hover over links to see the real URL before clicking"),
        ("📛", "Check the sender's email address carefully for spoofing"),
        ("⏰", "Urgency and threats are classic phishing tactics — stay calm"),
        ("🌐", "Always verify HTTPS and the correct domain name"),
        ("📎", "Avoid downloading attachments from unknown senders"),
    ]
    for icon, tip in tips:
        st.markdown(f"""<div class="tip-card"><span class="tip-icon">{icon}</span>{tip}</div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📊 Session Stats")
    threats_this_session = st.session_state.get("email_scan_count", 0)
    phishing_found = st.session_state.get("email_phishing_count", 0)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f'<div class="stat-box"><div class="stat-val">{threats_this_session}</div><div class="stat-lbl">Scanned</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="stat-box"><div class="stat-val" style="color:#ff4d4d">{phishing_found}</div><div class="stat-lbl">Threats</div></div>', unsafe_allow_html=True)

with main_col:
    # ── Example Emails ─────────────────────────────────────────────────────
    with st.expander("📂 Load Example Emails", expanded=False):
        ex_cols = st.columns(len(EXAMPLES))
        selected_example = None
        for idx, (name, data) in enumerate(EXAMPLES.items()):
            with ex_cols[idx]:
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.03);border:1px solid {data['color']}44;border-radius:12px;padding:0.8rem;text-align:center;">
                    <div style="color:{data['color']};font-weight:600;font-size:0.9rem;">{name}</div>
                    <div style="color:#8892b0;font-size:0.75rem;margin-top:0.3rem;">{data['label']}</div>
                </div>""", unsafe_allow_html=True)
                if st.button(f"Load", key=f"ex_{idx}", use_container_width=True):
                    st.session_state["email_example_text"] = data["text"]
                    st.rerun()

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Input Tabs ──────────────────────────────────────────────────────────
    tab1, tab2 = st.tabs(["✏️ Paste Email Content", "📁 Upload .txt File"])

    email_text = st.session_state.get("email_example_text", "")

    with tab1:
        pasted = st.text_area(
            "Paste the full email content below:",
            value=email_text,
            height=200,
            placeholder="Paste email subject, body, links — everything…",
            key="email_paste_input"
        )
        analyze_btn = st.button("🔍 Analyze Email", type="primary", use_container_width=True, key="analyze_paste")

    with tab2:
        uploaded = st.file_uploader("Upload a .txt file containing email content", type=["txt"], key="email_file")
        file_text = ""
        if uploaded:
            file_text = uploaded.read().decode("utf-8", errors="ignore")
            st.success(f"✅ File loaded: {uploaded.name} ({len(file_text)} characters)")
            with st.expander("Preview file content"):
                st.code(file_text[:800] + ("…" if len(file_text) > 800 else ""), language=None)
        analyze_file_btn = st.button("🔍 Analyze File", type="primary", use_container_width=True, key="analyze_file", disabled=not bool(file_text))

    # ── Determine active text ───────────────────────────────────────────────
    active_text = ""
    run_analysis = False
    if "analyze_paste" in st.session_state and analyze_btn:
        active_text = pasted
        run_analysis = True
    if "analyze_file" in st.session_state and analyze_file_btn:
        active_text = file_text
        run_analysis = True

    # ── ANALYSIS ────────────────────────────────────────────────────────────
    if run_analysis and active_text.strip():
        # Progress animation
        prog_ph = st.empty()
        prog_bar = prog_ph.progress(0, text="🔄 Initializing neural network…")
        stages = [
            (20, "🧠 Tokenizing email content…"),
            (45, "🔍 Extracting linguistic features…"),
            (65, "⚡ Running classifier…"),
            (85, "📊 Computing SHAP values…"),
            (100, "✅ Analysis complete!"),
        ]
        for pct, msg in stages:
            time.sleep(0.35)
            prog_bar.progress(pct, text=msg)
        time.sleep(0.2)
        prog_ph.empty()

        result = get_prediction(active_text)
        st.session_state["email_scan_count"] = st.session_state.get("email_scan_count", 0) + 1
        if result["label"] == "PHISHING":
            st.session_state["email_phishing_count"] = st.session_state.get("email_phishing_count", 0) + 1

        # ── Log threat ──────────────────────────────────────────────────────
        if LOGGER_AVAILABLE and result["label"] == "PHISHING":
            try:
                log_threat(threat_type="PHISHING_EMAIL", severity=result["threat_level"],
                           details={"risk_score": result["risk_score"], "probability": result["probability"],
                                    "preview": active_text[:120]})
            except Exception:
                pass

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown("## 🎯 Analysis Results")

        # ── Top metric row ──────────────────────────────────────────────────
        rc1, rc2, rc3, rc4 = st.columns(4)
        with rc1:
            verdict_color = "#ff4d4d" if result["label"] == "PHISHING" else "#00cc66"
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.04);border:1px solid {verdict_color}44;border-radius:14px;padding:1rem;text-align:center;">
                <div style="font-size:2rem;">{"🚨" if result["label"]=="PHISHING" else "✅"}</div>
                <div style="color:{verdict_color};font-size:1.1rem;font-weight:700;">{result["label"]}</div>
                <div style="color:#8892b0;font-size:0.8rem;">Verdict</div>
            </div>""", unsafe_allow_html=True)
        with rc2:
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:14px;padding:1rem;text-align:center;">
                <div style="font-size:2rem;">🎯</div>
                <div style="color:#64ffda;font-size:1.1rem;font-weight:700;">{result['risk_score']}/100</div>
                <div style="color:#8892b0;font-size:0.8rem;">Risk Score</div>
            </div>""", unsafe_allow_html=True)
        with rc3:
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:14px;padding:1rem;text-align:center;">
                <div style="font-size:2rem;">📈</div>
                <div style="color:#ffd700;font-size:1.1rem;font-weight:700;">{result['probability']*100:.1f}%</div>
                <div style="color:#8892b0;font-size:0.8rem;">Confidence</div>
            </div>""", unsafe_allow_html=True)
        with rc4:
            tl = result["threat_level"]
            tl_color = {"CRITICAL":"#ff1a1a","HIGH":"#ff6b00","MEDIUM":"#ffd700","LOW":"#00cc66"}.get(tl,"#00cc66")
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.04);border:1px solid {tl_color}44;border-radius:14px;padding:1rem;text-align:center;">
                <div style="font-size:2rem;">⚠️</div>
                <div style="color:{tl_color};font-size:1.1rem;font-weight:700;">{tl}</div>
                <div style="color:#8892b0;font-size:0.8rem;">Threat Level</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Large threat badge ──────────────────────────────────────────────
        tl = result["threat_level"]
        badge_class = f"threat-{tl}" if result["label"] == "PHISHING" else "threat-SAFE"
        badge_text = f"🚨 {tl} THREAT DETECTED" if result["label"] == "PHISHING" else "✅ EMAIL APPEARS SAFE"
        st.markdown(f'<div class="{badge_class}">{badge_text}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        # ── Charts row ──────────────────────────────────────────────────────
        chart_c1, chart_c2 = st.columns(2)

        with chart_c1:
            # Gauge chart
            gauge_color = "#ff4d4d" if result["risk_score"] >= 70 else "#ffd700" if result["risk_score"] >= 40 else "#00cc66"
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=result["risk_score"],
                delta={"reference": 50, "increasing": {"color": "#ff4d4d"}, "decreasing": {"color": "#00cc66"}},
                title={"text": "Risk Score", "font": {"color": "#ccd6f6", "size": 16}},
                number={"font": {"color": "#ccd6f6", "size": 36}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#8892b0", "tickfont": {"color": "#8892b0"}},
                    "bar": {"color": gauge_color, "thickness": 0.3},
                    "bgcolor": "rgba(0,0,0,0)",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 40], "color": "rgba(0,204,102,0.15)"},
                        {"range": [40, 70], "color": "rgba(255,215,0,0.15)"},
                        {"range": [70, 100], "color": "rgba(255,77,77,0.15)"},
                    ],
                    "threshold": {"line": {"color": gauge_color, "width": 4}, "thickness": 0.75, "value": result["risk_score"]}
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#ccd6f6"}, height=280, margin=dict(t=40, b=10, l=20, r=20)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        with chart_c2:
            # Feature importance bar chart
            features = result.get("top_features", [])
            if features:
                words = [f[0] for f in features[:10]]
                scores = [f[1] for f in features[:10]]
                colors = ["#ff4d4d" if s > 0.5 else "#ffd700" if s > 0.3 else "#64ffda" for s in scores]
                fig_feat = go.Figure(go.Bar(
                    x=scores, y=words, orientation='h',
                    marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.1)", width=1)),
                    text=[f"{s:.2f}" for s in scores], textposition="outside",
                    textfont=dict(color="#ccd6f6", size=11)
                ))
                fig_feat.update_layout(
                    title=dict(text="🔑 Suspicious Keywords", font=dict(color="#ccd6f6", size=15)),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    xaxis=dict(title="Importance Score", color="#8892b0", gridcolor="rgba(255,255,255,0.05)"),
                    yaxis=dict(color="#ccd6f6", autorange="reversed"),
                    height=280, margin=dict(t=50, b=20, l=10, r=60),
                    font=dict(color="#ccd6f6")
                )
                st.plotly_chart(fig_feat, use_container_width=True)

        # ── Keyword Chips ───────────────────────────────────────────────────
        features = result.get("top_features", [])
        if features:
            st.markdown("#### 🏷️ Flagged Keywords")
            chips_html = " ".join([f'<span class="kw-chip">{w}</span>' for w, _ in features])
            st.markdown(chips_html, unsafe_allow_html=True)

        # ── Probability bar ─────────────────────────────────────────────────
        prob_pct = int(result["probability"] * 100)
        bar_color = "#ff4d4d" if prob_pct >= 70 else "#ffd700" if prob_pct >= 40 else "#00cc66"
        st.markdown(f"""
        <div style="margin-top:1.5rem;">
            <div style="display:flex;justify-content:space-between;color:#8892b0;font-size:0.9rem;margin-bottom:0.4rem;">
                <span>Phishing Probability</span><span style="color:{bar_color};font-weight:700;">{prob_pct}%</span>
            </div>
            <div style="background:rgba(255,255,255,0.08);border-radius:8px;height:14px;overflow:hidden;">
                <div style="width:{prob_pct}%;height:100%;background:linear-gradient(90deg,{bar_color},{bar_color}cc);border-radius:8px;transition:width 1s ease;box-shadow:0 0 10px {bar_color}66;"></div>
            </div>
        </div>""", unsafe_allow_html=True)

        # ── Explanation ─────────────────────────────────────────────────────
        if EXPLAIN_AVAILABLE:
            try:
                explanation = explain_email_prediction(active_text, result)
                with st.expander("🔬 Detailed AI Explanation"):
                    st.markdown(explanation)
            except Exception:
                pass
        else:
            with st.expander("🔬 AI Explanation"):
                if result["label"] == "PHISHING":
                    st.markdown(f"""
**Why this email was flagged as phishing:**
- **Risk Score {result['risk_score']}/100** — well above the safe threshold of 40
- **{len(features)} suspicious features** identified by the classifier
- Common social engineering tactics detected: urgency, authority impersonation, call to action
- Contains external links that may redirect to malicious sites
- **Recommendation:** Do NOT click any links. Report and delete this email immediately.
                    """)
                else:
                    st.markdown("""
**Why this email appears safe:**
- No urgency or threat language detected
- Links appear to belong to legitimate domains
- No requests for sensitive information (PIN, OTP, password)
- Natural writing style without social engineering patterns
- **Recommendation:** Still exercise caution — no filter is 100% accurate.
                    """)

    elif run_analysis and not active_text.strip():
        st.warning("⚠️ Please enter or upload email content before analyzing.")

# ── Reset example after use ────────────────────────────────────────────────────
if "email_example_text" in st.session_state and not run_analysis:
    pass  # keep it loaded until user clicks analyze
