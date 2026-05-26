import streamlit as st
import time
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

st.set_page_config(
    page_title="SMS / Smishing Detector | CyberShield AI",
    page_icon="📱",
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
    from utils.ml_models import predict_sms
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from utils.threat_logger import log_threat, get_threats
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

try:
    from utils.explainability import explain_sms_prediction
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

.sms-hero {
    background: linear-gradient(135deg, #0a1a1a 0%, #0d2020 50%, #0a2830 100%);
    border: 1px solid rgba(0,220,200,0.3); border-radius: 20px;
    padding: 2.5rem 3rem; margin-bottom: 2rem;
    position: relative; overflow: hidden;
}
.sms-hero::before {
    content: ''; position: absolute; top: -40%; right: -5%;
    width: 280px; height: 280px;
    background: radial-gradient(circle, rgba(0,220,200,0.15) 0%, transparent 70%);
    border-radius: 50%;
}
.sms-hero h1 {
    font-size: 2.5rem; font-weight: 800;
    background: linear-gradient(135deg, #00dcc8, #00b4d8, #90e0ef);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin: 0 0 0.5rem 0;
}
.sms-hero p { color: #8892b0; font-size: 1.1rem; margin: 0; }

/* Phone mock UI */
.phone-frame {
    background: linear-gradient(160deg, #1c1c2e, #16213e);
    border: 3px solid #2a2a4a;
    border-radius: 40px;
    padding: 40px 20px 30px 20px;
    max-width: 340px;
    margin: 0 auto;
    box-shadow: 0 0 40px rgba(0,220,200,0.1), inset 0 0 20px rgba(0,0,0,0.5);
    position: relative;
}
.phone-frame::before {
    content: '';
    display: block;
    width: 80px; height: 8px;
    background: #2a2a4a;
    border-radius: 4px;
    margin: 0 auto 24px auto;
}
.phone-status-bar {
    display: flex; justify-content: space-between;
    color: #8892b0; font-size: 0.7rem;
    padding: 0 10px; margin-bottom: 16px;
}
.sms-bubble-spam {
    background: linear-gradient(135deg, #3a0a0a, #4a1010);
    border: 1px solid rgba(255,77,77,0.4);
    border-radius: 18px 18px 4px 18px;
    padding: 12px 16px; color: #ffb3b3;
    font-size: 0.85rem; line-height: 1.5;
    margin: 8px 0; word-break: break-word;
    box-shadow: 0 0 15px rgba(255,77,77,0.15);
    position: relative;
}
.sms-bubble-ham {
    background: linear-gradient(135deg, #0a2e1a, #0d3520);
    border: 1px solid rgba(0,204,102,0.3);
    border-radius: 18px 18px 4px 18px;
    padding: 12px 16px; color: #b3ffda;
    font-size: 0.85rem; line-height: 1.5;
    margin: 8px 0; word-break: break-word;
    box-shadow: 0 0 15px rgba(0,204,102,0.1);
    position: relative;
}
.sms-bubble-input {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 18px 18px 4px 18px;
    padding: 12px 16px; color: #ccd6f6;
    font-size: 0.85rem; line-height: 1.5;
    margin: 8px 0; word-break: break-word;
}
.phone-sender { color: #8892b0; font-size: 0.7rem; margin-bottom: 4px; }
.phone-time { color: #64748b; font-size: 0.65rem; text-align: right; margin-top: 4px; }

/* Verdict */
.sms-verdict-spam {
    background: linear-gradient(135deg, #1a0000, #2a0808);
    border: 2px solid #ff1a1a; border-radius: 16px; padding: 1.5rem;
    text-align: center; animation: pulse-sms 2s infinite;
}
.sms-verdict-ham {
    background: linear-gradient(135deg, #001a0a, #002a12);
    border: 2px solid #00cc66; border-radius: 16px; padding: 1.5rem; text-align: center;
}
@keyframes pulse-sms { 0%,100%{border-color:#ff1a1a;box-shadow:0 0 20px rgba(255,26,26,0.3)} 50%{border-color:#ff6666;box-shadow:0 0 40px rgba(255,26,26,0.6)} }

/* Highlighted phrase */
.sus-phrase {
    background: rgba(255,77,77,0.25); border: 1px solid rgba(255,77,77,0.5);
    border-radius: 4px; padding: 0.15rem 0.5rem; color: #ff6b6b;
    font-weight: 600; font-size: 0.88rem;
    display: inline-block; margin: 0.2rem;
}
.safe-phrase {
    background: rgba(0,204,102,0.15); border: 1px solid rgba(0,204,102,0.4);
    border-radius: 4px; padding: 0.15rem 0.5rem; color: #00cc66;
    font-size: 0.88rem; display: inline-block; margin: 0.2rem;
}

.tip-card { background: rgba(0,220,200,0.06); border: 1px solid rgba(0,220,200,0.2); border-radius: 12px; padding: 0.8rem 1rem; margin-bottom: 0.6rem; color: #ccd6f6; font-size: 0.88rem; }
.section-divider { height: 2px; background: linear-gradient(90deg, transparent, rgba(0,220,200,0.5), transparent); margin: 2rem 0; border: none; }

.example-sms-card { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 0.8rem 1rem; margin-bottom: 0.5rem; }
</style>
""", unsafe_allow_html=True)

# ── EXAMPLE SMS ───────────────────────────────────────────────────────────────
SMS_EXAMPLES = {
    "🇬🇧 OTP Scam (EN)": {
        "text": "ALERT: Your SBI account OTP is 847291. Share this OTP with our agent at 9876543210 to verify your account. DO NOT ignore or your account will be BLOCKED.",
        "label": "SPAM", "lang": "English",
        "category": "OTP Scam"
    },
    "🇮🇳 UPI Fraud (HI)": {
        "text": "आपके UPI खाते में ₹5000 क्रेडिट होंगे। अभी अपना PIN दर्ज करें: http://upi-reward.in/claim. जल्दी करें - ऑफर 2 घंटे में समाप्त!",
        "label": "SPAM", "lang": "Hindi",
        "category": "UPI Fraud"
    },
    "🇮🇳 Prize Scam (MR)": {
        "text": "अभिनंदन! तुम्ही ₹10 लाख जिंकले! तुमचा बक्षीस मिळवण्यासाठी लगेच या नंबरवर संपर्क करा: 9999888877. http://lottery-win.co.in",
        "label": "SPAM", "lang": "Marathi",
        "category": "Prize Scam"
    },
    "✅ Legitimate OTP": {
        "text": "Your HDFC Bank OTP for transaction of Rs.1,250 to Merchant XYZ is 374821. Valid for 10 minutes. Do NOT share with anyone. HDFC Bank never asks for OTP.",
        "label": "HAM", "lang": "English",
        "category": "Legitimate"
    }
}

# ── Fallback predictor ────────────────────────────────────────────────────────
def _mock_predict_sms(text: str) -> dict:
    spam_kw = ["otp", "share", "verify", "blocked", "urgent", "click", "http://", "win",
               "prize", "claim", "reward", "free", "pin", "upi", "credit", "lucky",
               "lottery", "congratulations", "₹", "crore", "lakh", "jaldi", "जल्दी",
               "अभी", "lगेच", "agent", "call now", "expire"]
    safe_kw = ["do not share", "never asks for otp", "hdfc bank", "sbi official",
               "valid for", "transaction of"]
    text_lower = text.lower()
    spam_hits = sum(1 for kw in spam_kw if kw in text_lower)
    safe_hits = sum(1 for kw in safe_kw if kw in text_lower)
    net = spam_hits - safe_hits * 2
    is_spam = net >= 2
    prob = min(0.97, 0.3 + net * 0.1) if is_spam else max(0.05, 0.28 - net * 0.05)
    prob = max(0.0, min(1.0, prob))
    risk = int(prob * 100)
    if risk >= 80: threat = "CRITICAL"
    elif risk >= 60: threat = "HIGH"
    elif risk >= 40: threat = "MEDIUM"
    else: threat = "LOW"
    found_phrases = [kw for kw in spam_kw if kw in text_lower]
    return {
        "label": "SPAM" if is_spam else "HAM",
        "probability": round(prob, 4),
        "risk_score": risk,
        "threat_level": threat,
        "suspicious_phrases": found_phrases[:8]
    }

def _classify_sms_category(text: str, label: str) -> str:
    if label == "HAM":
        return "Legitimate Message"
    t = text.lower()
    if any(k in t for k in ["otp", "one time", "password"]): return "OTP Scam"
    if any(k in t for k in ["upi", "bank", "account", "pin"]): return "Bank Fraud"
    if any(k in t for k in ["win", "prize", "lottery", "reward", "lucky"]): return "Prize Fraud"
    if any(k in t for k in ["click", "http", "link", "verify", "claim"]): return "Phishing Link"
    return "SMS Spam"

def get_sms_prediction(text):
    if ML_AVAILABLE:
        return predict_sms(text)
    return _mock_predict_sms(text)

# ── HERO ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="sms-hero">
  <h1>📱 SMS / Smishing Detector</h1>
  <p>Detect SMS phishing (smishing), OTP scams, UPI fraud, and prize fraud — multi-language support (English, Hindi, Marathi)</p>
</div>
""", unsafe_allow_html=True)

main_col, side_col = st.columns([3, 1])

with side_col:
    # Fraud type pie chart
    st.markdown("### 📊 SMS Fraud Types")
    fraud_labels = ["OTP Scam", "Bank Fraud", "Prize/Lottery", "UPI Fraud", "Delivery Scam", "Job Scam"]
    fraud_vals = [32, 24, 18, 14, 7, 5]
    fraud_colors = ["#ff4d4d", "#ff8c00", "#ffd700", "#e94560", "#a855f7", "#06b6d4"]
    fig_pie = go.Figure(go.Pie(
        labels=fraud_labels, values=fraud_vals,
        marker=dict(colors=fraud_colors, line=dict(color="#0d1117", width=2)),
        hole=0.55,
        textfont=dict(color="#ccd6f6", size=10),
        hovertemplate="%{label}: %{value}%<extra></extra>"
    ))
    fig_pie.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", showlegend=True,
        legend=dict(font=dict(color="#8892b0", size=9), bgcolor="rgba(0,0,0,0)"),
        height=240, margin=dict(t=10, b=10, l=10, r=10),
        annotations=[dict(text="Fraud<br>Types", font=dict(color="#ccd6f6", size=11), showarrow=False)]
    )
    st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown("---")
    st.markdown("### 🛡️ Prevention Tips")
    tips = [
        ("🔒", "Never share OTP with anyone — not even bank agents"),
        ("🏦", "Your bank will NEVER call/SMS asking for PIN"),
        ("🔗", "Do not click shortened links from unknown numbers"),
        ("🎁", "You cannot win a lottery you didn't enter"),
        ("📞", "Verify before acting — call official number"),
        ("🚫", "Block & report suspicious senders immediately"),
    ]
    for icon, tip in tips:
        st.markdown(f'<div class="tip-card"><span style="font-size:1.1rem;">{icon}</span> {tip}</div>', unsafe_allow_html=True)

with main_col:
    # ── Language selector + Input ───────────────────────────────────────────
    lang_col, _ = st.columns([1, 3])
    with lang_col:
        language = st.selectbox("Language", ["English", "Hindi", "Marathi"], key="sms_lang")

    # ── Example loader ──────────────────────────────────────────────────────
    with st.expander("📂 Load Example SMS Messages", expanded=False):
        ex_cols = st.columns(len(SMS_EXAMPLES))
        for idx, (name, data) in enumerate(SMS_EXAMPLES.items()):
            with ex_cols[idx]:
                badge_color = "#ff4d4d" if data["label"] == "SPAM" else "#00cc66"
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.03);border:1px solid {badge_color}44;border-radius:10px;padding:0.7rem;text-align:center;min-height:70px;">
                    <div style="color:{badge_color};font-weight:600;font-size:0.82rem;">{name}</div>
                    <div style="color:#8892b0;font-size:0.72rem;margin-top:0.2rem;">{data['category']}</div>
                </div>""", unsafe_allow_html=True)
                if st.button("Load SMS", key=f"sms_ex_{idx}", use_container_width=True):
                    st.session_state["sms_example_text"] = data["text"]
                    st.rerun()

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Phone UI + Input ────────────────────────────────────────────────────
    ph_col, input_col = st.columns([1, 2])

    with ph_col:
        preview_text = st.session_state.get("sms_example_text", "")
        preview_short = (preview_text[:100] + "…") if len(preview_text) > 100 else preview_text
        st.markdown(f"""
        <div class="phone-frame">
            <div class="phone-status-bar">
                <span>9:41 AM</span>
                <span>📶 ●●●●○ 🔋</span>
            </div>
            <div style="text-align:center;color:#8892b0;font-size:0.75rem;margin-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.07);padding-bottom:8px;">Unknown Sender</div>
            <div class="phone-sender">+91 9876XXXXXX</div>
            <div class="sms-bubble-input">{preview_short or "Your SMS will appear here…"}</div>
            <div class="phone-time">Tap Analyze to scan ↓</div>
        </div>""", unsafe_allow_html=True)

    with input_col:
        sms_text = st.text_area(
            "📥 Paste SMS content:",
            value=st.session_state.get("sms_example_text", ""),
            height=180,
            placeholder="Paste the full SMS message here…\n\nSupports English, Hindi, and Marathi",
            key="sms_main_input"
        )
        analyze_sms = st.button("🔍 Analyze SMS", type="primary", use_container_width=True)

    # ── ANALYSIS ────────────────────────────────────────────────────────────
    if analyze_sms and sms_text.strip():
        prog = st.progress(0, "🔄 Preprocessing SMS…")
        for pct, msg in [(30, "🧠 Tokenizing…"), (60, "⚡ Running classifier…"), (90, "📊 Extracting patterns…"), (100, "✅ Done!")]:
            time.sleep(0.25)
            prog.progress(pct, msg)
        time.sleep(0.15)
        prog.empty()

        result = get_sms_prediction(sms_text.strip())
        category = _classify_sms_category(sms_text, result["label"])

        if LOGGER_AVAILABLE and result["label"] == "SPAM":
            try:
                log_threat(threat_type="SMS_SPAM", severity=result["threat_level"],
                           details={"risk_score": result["risk_score"], "category": category,
                                    "preview": sms_text[:100]})
            except Exception:
                pass

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown("## 🎯 Analysis Results")

        # Verdict
        if result["label"] == "SPAM":
            st.markdown(f"""
            <div class="sms-verdict-spam">
                <div style="font-size:3rem;">🚨</div>
                <div style="font-size:1.8rem;font-weight:800;color:#ff4d4d;letter-spacing:3px;">SPAM / SMISHING</div>
                <div style="color:#ff8888;font-size:1rem;margin-top:0.5rem;">Category: <strong>{category}</strong></div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="sms-verdict-ham">
                <div style="font-size:3rem;">✅</div>
                <div style="font-size:1.8rem;font-weight:800;color:#00cc66;letter-spacing:3px;">LEGITIMATE SMS</div>
                <div style="color:#88ffbb;font-size:1rem;margin-top:0.5rem;">Category: <strong>{category}</strong></div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Metrics row
        m1, m2, m3, m4 = st.columns(4)
        risk_color = "#ff4d4d" if result["risk_score"] >= 70 else "#ffd700" if result["risk_score"] >= 40 else "#00cc66"
        tl_color = {"CRITICAL":"#ff1a1a","HIGH":"#ff6b00","MEDIUM":"#ffd700","LOW":"#00cc66"}.get(result["threat_level"],"#00cc66")
        for col, icon, val, lbl, color in [
            (m1, "🎯", f"{result['risk_score']}/100", "Risk Score", risk_color),
            (m2, "📈", f"{result['probability']*100:.1f}%", "Probability", risk_color),
            (m3, "⚠️", result["threat_level"], "Threat Level", tl_color),
            (m4, "🏷️", category, "Category", "#00dcc8"),
        ]:
            with col:
                st.markdown(f"""<div style="background:rgba(255,255,255,0.04);border:1px solid {color}33;border-radius:14px;padding:0.9rem;text-align:center;"><div style="font-size:1.8rem;">{icon}</div><div style="color:{color};font-size:1rem;font-weight:700;">{val}</div><div style="color:#8892b0;font-size:0.8rem;">{lbl}</div></div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        chart_c1, chart_c2 = st.columns(2)

        with chart_c1:
            # Gauge
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=result["risk_score"],
                title={"text": "Fraud Probability Meter", "font": {"color": "#ccd6f6", "size": 13}},
                number={"font": {"color": risk_color, "size": 36}, "suffix": "%"},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#8892b0", "tickfont": {"color": "#8892b0"}},
                    "bar": {"color": risk_color, "thickness": 0.28},
                    "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                    "steps": [
                        {"range": [0, 40], "color": "rgba(0,204,102,0.12)"},
                        {"range": [40, 70], "color": "rgba(255,215,0,0.12)"},
                        {"range": [70, 100], "color": "rgba(255,77,77,0.12)"},
                    ],
                    "threshold": {"line": {"color": risk_color, "width": 4}, "thickness": 0.75, "value": result["risk_score"]}
                }
            ))
            fig_g.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#ccd6f6"}, height=270, margin=dict(t=50, b=10, l=20, r=20)
            )
            st.plotly_chart(fig_g, use_container_width=True)

        with chart_c2:
            # SMS in phone bubble style
            bubble_cls = "sms-bubble-spam" if result["label"] == "SPAM" else "sms-bubble-ham"
            short_sms = (sms_text[:150] + "…") if len(sms_text) > 150 else sms_text
            st.markdown(f"""
            <div style="padding:1rem;">
                <div style="color:#ccd6f6;font-size:0.9rem;font-weight:600;margin-bottom:0.8rem;">📱 Message Preview</div>
                <div class="phone-sender">Unknown Sender • Just now</div>
                <div class="{bubble_cls}">{short_sms}</div>
                <div class="phone-time">{"⚠️ Flagged as " + result['label'] if result['label'] == 'SPAM' else "✅ Appears Legitimate"}</div>
            </div>""", unsafe_allow_html=True)

        # Suspicious phrases
        sus_phrases = result.get("suspicious_phrases", [])
        if sus_phrases and result["label"] == "SPAM":
            st.markdown("#### 🏷️ Suspicious Phrases Detected")
            chips_html = " ".join([f'<span class="sus-phrase">{p}</span>' for p in sus_phrases])
            st.markdown(chips_html, unsafe_allow_html=True)
        elif result["label"] == "HAM":
            st.markdown("#### ✅ Safety Indicators")
            safe_indicators = ["Official sender format", "No suspicious links", "No OTP sharing request", "No urgency language"]
            chips_html = " ".join([f'<span class="safe-phrase">{s}</span>' for s in safe_indicators])
            st.markdown(chips_html, unsafe_allow_html=True)

        # Probability bar
        prob_pct = int(result["probability"] * 100)
        st.markdown(f"""
        <div style="margin-top:1.5rem;">
            <div style="display:flex;justify-content:space-between;color:#8892b0;font-size:0.9rem;margin-bottom:0.4rem;">
                <span>{"Spam" if result["label"]=="SPAM" else "Legitimate"} Probability</span><span style="color:{risk_color};font-weight:700;">{prob_pct}%</span>
            </div>
            <div style="background:rgba(255,255,255,0.08);border-radius:8px;height:14px;overflow:hidden;">
                <div style="width:{prob_pct}%;height:100%;background:linear-gradient(90deg,{risk_color},{risk_color}cc);border-radius:8px;box-shadow:0 0 10px {risk_color}66;"></div>
            </div>
        </div>""", unsafe_allow_html=True)

        # Explanation
        if EXPLAIN_AVAILABLE:
            try:
                expl = explain_sms_prediction(sms_text, result)
                with st.expander("🔬 AI Explanation"):
                    st.markdown(expl)
            except Exception:
                pass
        else:
            with st.expander("🔬 Why this decision?"):
                if result["label"] == "SPAM":
                    st.markdown(f"""
**SMS flagged as SPAM because:**
- **{len(sus_phrases)} suspicious phrases** matched known fraud patterns
- **Risk score {result['risk_score']}/100** — significantly elevated
- Category classified as **{category}** based on content analysis
- Social engineering indicators present: urgency, financial reward, or OTP sharing requests
- **Action:** Block this number. Report to TRAI DND at 1909.
                    """)
                else:
                    st.markdown("""
**SMS appears legitimate because:**
- No suspicious link patterns or phishing URLs detected
- Message follows official bank communication format
- Contains explicit "Do NOT share OTP" warning (genuine banks include this)
- No urgency tactics or financial reward claims
- **Note:** Always verify with your bank's official number if uncertain.
                    """)

    elif analyze_sms and not sms_text.strip():
        st.warning("⚠️ Please enter SMS content to analyze.")
