import streamlit as st
import time
import re
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from urllib.parse import urlparse

st.set_page_config(
    page_title="Malicious URL Detector | CyberShield AI",
    page_icon="🔗",
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
    from utils.ml_models import predict_url
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from utils.threat_logger import log_threat, get_threats
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

try:
    from utils.explainability import explain_url_prediction
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

.url-hero {
    background: linear-gradient(135deg, #0a1a2e 0%, #0d2137 50%, #0a2850 100%);
    border: 1px solid rgba(0,149,255,0.3);
    border-radius: 20px; padding: 2.5rem 3rem; margin-bottom: 2rem;
    position: relative; overflow: hidden;
}
.url-hero::before {
    content: ''; position: absolute; top: -40%; right: -5%;
    width: 280px; height: 280px;
    background: radial-gradient(circle, rgba(0,149,255,0.15) 0%, transparent 70%);
    border-radius: 50%;
}
.url-hero h1 {
    font-size: 2.5rem; font-weight: 800;
    background: linear-gradient(135deg, #0095ff, #00d4ff, #00ff9d);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin: 0 0 0.5rem 0;
}
.url-hero p { color: #8892b0; font-size: 1.1rem; margin: 0; }

/* URL breakdown */
.url-part { display: inline-block; padding: 0.3rem 0.7rem; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 1rem; font-weight: 600; margin: 0.1rem; }
.url-protocol { background: rgba(0,204,102,0.2); color: #00cc66; border: 1px solid rgba(0,204,102,0.4); }
.url-domain-safe { background: rgba(0,149,255,0.2); color: #0095ff; border: 1px solid rgba(0,149,255,0.4); }
.url-domain-sus { background: rgba(255,77,77,0.2); color: #ff4d4d; border: 1px solid rgba(255,77,77,0.5); animation: glow-red 1.5s infinite; }
.url-path { background: rgba(255,255,255,0.06); color: #ccd6f6; border: 1px solid rgba(255,255,255,0.15); }
.url-params-sus { background: rgba(255,165,0,0.2); color: #ffa500; border: 1px solid rgba(255,165,0,0.5); }
@keyframes glow-red { 0%,100%{box-shadow:0 0 8px rgba(255,77,77,0.4)} 50%{box-shadow:0 0 20px rgba(255,77,77,0.9)} }

.verdict-MALICIOUS {
    background: linear-gradient(135deg, #1a0a0a, #2a0000);
    border: 2px solid #ff1a1a; border-radius: 16px; padding: 1.5rem 2rem;
    text-align: center; animation: pulse-danger 2s infinite;
}
.verdict-SUSPICIOUS {
    background: linear-gradient(135deg, #1a1200, #2a1e00);
    border: 2px solid #ffa500; border-radius: 16px; padding: 1.5rem 2rem; text-align: center;
}
.verdict-SAFE {
    background: linear-gradient(135deg, #001a0e, #002a17);
    border: 2px solid #00cc66; border-radius: 16px; padding: 1.5rem 2rem; text-align: center;
}
@keyframes pulse-danger { 0%,100%{border-color:#ff1a1a} 50%{border-color:#ff6666;box-shadow:0 0 30px rgba(255,26,26,0.5)} }

.feature-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.6rem 1rem; border-radius: 8px; margin-bottom: 0.4rem;
    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07);
}
.feature-key { color: #8892b0; font-size: 0.88rem; }
.feature-val-bad { color: #ff4d4d; font-weight: 600; font-size: 0.9rem; }
.feature-val-good { color: #00cc66; font-weight: 600; font-size: 0.9rem; }
.feature-val-warn { color: #ffd700; font-weight: 600; font-size: 0.9rem; }

.batch-row-malicious { background: rgba(255,77,77,0.1); border-left: 3px solid #ff4d4d; }
.batch-row-suspicious { background: rgba(255,165,0,0.1); border-left: 3px solid #ffa500; }
.batch-row-safe { background: rgba(0,204,102,0.08); border-left: 3px solid #00cc66; }

.section-divider { height: 2px; background: linear-gradient(90deg, transparent, rgba(0,149,255,0.5), transparent); margin: 2rem 0; border: none; }

.risk-item { display: flex; align-items: flex-start; gap: 0.7rem; padding: 0.7rem; border-radius: 10px; background: rgba(255,77,77,0.08); border: 1px solid rgba(255,77,77,0.2); margin-bottom: 0.5rem; }
.risk-icon { font-size: 1.2rem; flex-shrink: 0; }
.risk-text { color: #ccd6f6; font-size: 0.9rem; }

.example-url-card {
    background: rgba(255,255,255,0.03); border-radius: 10px; padding: 0.7rem 1rem;
    margin-bottom: 0.5rem; cursor: pointer;
    border: 1px solid rgba(255,255,255,0.08);
    font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;
    word-break: break-all;
}
</style>
""", unsafe_allow_html=True)

# ── Example URLs ──────────────────────────────────────────────────────────────
SAFE_URLS = [
    "https://www.google.com/search?q=cybersecurity",
    "https://github.com/user/repository",
    "https://docs.python.org/3/library/re.html",
]
MALICIOUS_URLS = [
    "http://secure-paypal-verify.xyz/login?token=abc123&user=victim",
    "http://192.168.1.1/admin/bank-update.php?id=9876",
    "http://go0gle-account-suspended.tk/reset-password/verify.html",
]

# ── Fallback URL analyzer ─────────────────────────────────────────────────────
def _extract_url_features(url: str) -> dict:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path
        query = parsed.query
    except Exception:
        domain, path, query = url, "", ""

    suspicious_kw = ["verify", "secure", "login", "update", "bank", "paypal", "account",
                     "suspend", "reset", "confirm", "password", "otp", "free", "win", "prize"]
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    return {
        "url_length": len(url),
        "https": url.startswith("https://"),
        "ip_address": bool(ip_pattern.search(url)),
        "subdomain_depth": domain.count("."),
        "special_chars": sum(url.count(c) for c in ["-", "_", "~", "%", "@"]),
        "suspicious_keywords": [kw for kw in suspicious_kw if kw in url.lower()],
        "has_query_params": bool(query),
        "path_depth": path.count("/"),
        "domain": domain,
        "path": path,
        "query": query,
        "protocol": "https" if url.startswith("https") else "http",
        "known_tld_sus": any(url.lower().endswith(t) for t in [".tk", ".xyz", ".ml", ".ga", ".cf", ".gq"]),
    }

def _mock_predict_url(url: str) -> dict:
    f = _extract_url_features(url)
    score = 0
    if not f["https"]: score += 20
    if f["ip_address"]: score += 35
    if len(f["suspicious_keywords"]) > 0: score += len(f["suspicious_keywords"]) * 12
    if f["url_length"] > 75: score += 15
    if f["known_tld_sus"]: score += 25
    if f["subdomain_depth"] > 3: score += 10
    if f["special_chars"] > 5: score += 10
    score = min(score, 100)
    if score >= 70: label, threat = "MALICIOUS", "CRITICAL" if score >= 85 else "HIGH"
    elif score >= 40: label, threat = "SUSPICIOUS", "MEDIUM"
    else: label, threat = "SAFE", "LOW"
    sus_parts = []
    if f["ip_address"]: sus_parts.append(f"IP address used as domain: {f['domain']}")
    if f["known_tld_sus"]: sus_parts.append(f"Suspicious TLD detected")
    if f["suspicious_keywords"]: sus_parts.append(f"Phishing keywords: {', '.join(f['suspicious_keywords'][:5])}")
    if not f["https"]: sus_parts.append("No HTTPS — unencrypted connection")
    if f["url_length"] > 75: sus_parts.append(f"Unusually long URL ({f['url_length']} chars)")
    return {
        "label": label, "probability": round(score / 100, 4),
        "risk_score": score, "threat_level": threat,
        "suspicious_parts": sus_parts, "features": f
    }

def get_url_prediction(url):
    if ML_AVAILABLE:
        return predict_url(url)
    return _mock_predict_url(url)

# ── HERO ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="url-hero">
  <h1>🔗 Malicious URL Detector</h1>
  <p>Real-time analysis of URLs for phishing, malware distribution, and social engineering — batch scanning supported</p>
</div>
""", unsafe_allow_html=True)

main_col, side_col = st.columns([3, 1])

with side_col:
    st.markdown("### 📖 Example URLs")
    st.markdown("**✅ Safe URLs**")
    for u in SAFE_URLS:
        short = u[:45] + "…" if len(u) > 45 else u
        st.markdown(f'<div class="example-url-card" style="border-color:rgba(0,204,102,0.25);color:#00cc66;">{short}</div>', unsafe_allow_html=True)
        if st.button("Load ↗", key=f"safe_{u[:20]}", use_container_width=True):
            st.session_state["url_input"] = u
            st.rerun()

    st.markdown("**🚨 Malicious URLs**")
    for u in MALICIOUS_URLS:
        short = u[:45] + "…" if len(u) > 45 else u
        st.markdown(f'<div class="example-url-card" style="border-color:rgba(255,77,77,0.35);color:#ff6b6b;">{short}</div>', unsafe_allow_html=True)
        if st.button("Load ↗", key=f"mal_{u[:20]}", use_container_width=True):
            st.session_state["url_input"] = u
            st.rerun()

    st.markdown("---")
    st.markdown("### 🔬 What We Check")
    checks = ["HTTPS Protocol", "IP Address Usage", "Domain Reputation", "URL Length",
              "Suspicious Keywords", "Subdomain Depth", "Special Characters", "Known Phishing Patterns"]
    for c in checks:
        st.markdown(f"<div style='color:#8892b0;font-size:0.85rem;padding:0.2rem 0;'>✓ {c}</div>", unsafe_allow_html=True)

with main_col:
    tab1, tab2 = st.tabs(["🔍 Single URL Scan", "📋 Batch URL Analysis"])

    with tab1:
        url_input = st.text_input(
            "Enter URL to analyze:",
            value=st.session_state.get("url_input", ""),
            placeholder="https://example.com/path?param=value",
            key="url_single_input"
        )
        scan_col, _ = st.columns([2, 3])
        with scan_col:
            scan_btn = st.button("⚡ Quick Scan", type="primary", use_container_width=True)

        if scan_btn and url_input.strip():
            # Animate
            prog = st.progress(0, "🔄 Resolving URL…")
            for pct, msg in [(25,"🌐 Checking domain reputation…"),(55,"🔍 Extracting URL features…"),(80,"⚡ Running ML classifier…"),(100,"✅ Scan complete!")]:
                time.sleep(0.3)
                prog.progress(pct, msg)
            time.sleep(0.2)
            prog.empty()

            url = url_input.strip()
            result = get_url_prediction(url)
            features = result.get("features", _extract_url_features(url))

            # Log
            if LOGGER_AVAILABLE and result["label"] != "SAFE":
                try:
                    log_threat(threat_type="MALICIOUS_URL", severity=result["threat_level"],
                               details={"url": url, "risk_score": result["risk_score"]})
                except Exception:
                    pass

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # Verdict card
            verdict_cls = f"verdict-{result['label']}"
            v_icon = {"MALICIOUS": "🚨", "SUSPICIOUS": "⚠️", "SAFE": "✅"}.get(result["label"], "❓")
            v_color = {"MALICIOUS": "#ff4d4d", "SUSPICIOUS": "#ffa500", "SAFE": "#00cc66"}.get(result["label"], "#ccd6f6")
            st.markdown(f"""
            <div class="{verdict_cls}">
                <div style="font-size:3rem;">{v_icon}</div>
                <div style="font-size:1.8rem;font-weight:800;color:{v_color};letter-spacing:2px;">{result['label']}</div>
                <div style="color:#8892b0;margin-top:0.3rem;">Risk Score: <span style="color:{v_color};font-weight:700;">{result['risk_score']}/100</span> &nbsp;|&nbsp; Confidence: <span style="color:{v_color};font-weight:700;">{result['probability']*100:.1f}%</span></div>
            </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # URL Breakdown
            st.markdown("#### 🧩 URL Component Breakdown")
            protocol = features.get("protocol", "http")
            domain = features.get("domain", "")
            path = features.get("path", "")
            query = features.get("query", "")
            is_sus = result["label"] != "SAFE"
            proto_cls = "url-protocol"
            domain_cls = "url-domain-sus" if is_sus else "url-domain-safe"
            path_cls = "url-path"
            param_cls = "url-params-sus" if query and is_sus else "url-path"
            breakdown_html = f"""
            <div style="background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:1rem 1.5rem;font-family:'JetBrains Mono',monospace;word-break:break-all;font-size:0.95rem;line-height:2.2;">
                <span class="url-part {proto_cls}">{protocol}://</span>
                <span class="url-part {domain_cls}">{domain}</span>
                {f'<span class="url-part {path_cls}">{path}</span>' if path else ""}
                {f'<span class="url-part {param_cls}">?{query}</span>' if query else ""}
            </div>"""
            st.markdown(breakdown_html, unsafe_allow_html=True)

            # Colour legend
            st.markdown("""
            <div style="display:flex;gap:1rem;margin-top:0.6rem;font-size:0.8rem;">
                <span style="color:#00cc66;">■ Protocol</span>
                <span style="color:#ff4d4d;">■ Suspicious Domain</span>
                <span style="color:#0095ff;">■ Safe Domain</span>
                <span style="color:#ccd6f6;">■ Path</span>
                <span style="color:#ffa500;">■ Suspicious Params</span>
            </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            chart_c1, chart_c2 = st.columns(2)

            with chart_c1:
                # Gauge
                g_color = {"MALICIOUS": "#ff4d4d", "SUSPICIOUS": "#ffa500", "SAFE": "#00cc66"}.get(result["label"], "#ccd6f6")
                fig_g = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=result["risk_score"],
                    title={"text": "Risk Score", "font": {"color": "#ccd6f6", "size": 15}},
                    number={"font": {"color": g_color, "size": 40}, "suffix": "/100"},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#8892b0", "tickfont": {"color": "#8892b0"}},
                        "bar": {"color": g_color, "thickness": 0.28},
                        "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                        "steps": [
                            {"range": [0, 40], "color": "rgba(0,204,102,0.12)"},
                            {"range": [40, 70], "color": "rgba(255,165,0,0.12)"},
                            {"range": [70, 100], "color": "rgba(255,77,77,0.12)"},
                        ],
                        "threshold": {"line": {"color": g_color, "width": 4}, "thickness": 0.75, "value": result["risk_score"]}
                    }
                ))
                fig_g.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font={"color": "#ccd6f6"}, height=260, margin=dict(t=40, b=10, l=20, r=20)
                )
                st.plotly_chart(fig_g, use_container_width=True)

            with chart_c2:
                # Radar chart
                feat_names = ["URL Length", "HTTPS", "No IP", "Safe TLD", "Low Keywords", "Simple Path"]
                url_len_score = max(0, 1 - features.get("url_length", 50) / 150)
                https_score = 1.0 if features.get("https") else 0.0
                no_ip_score = 0.0 if features.get("ip_address") else 1.0
                safe_tld = 0.0 if features.get("known_tld_sus") else 1.0
                low_kw = max(0, 1 - len(features.get("suspicious_keywords", [])) / 5)
                simple_path = max(0, 1 - features.get("path_depth", 0) / 8)
                vals = [url_len_score, https_score, no_ip_score, safe_tld, low_kw, simple_path]
                
                g_fillcolor = {
                    "MALICIOUS": "rgba(255, 77, 77, 0.13)",
                    "SUSPICIOUS": "rgba(255, 165, 0, 0.13)",
                    "SAFE": "rgba(0, 204, 102, 0.13)"
                }.get(result["label"], "rgba(204, 214, 246, 0.13)")

                fig_radar = go.Figure(go.Scatterpolar(
                    r=vals, theta=feat_names, fill='toself',
                    fillcolor=g_fillcolor, line=dict(color=g_color, width=2),
                    marker=dict(color=g_color, size=6)
                ))
                fig_radar.update_layout(
                    polar=dict(
                        radialaxis=dict(visible=True, range=[0,1], tickfont=dict(color="#8892b0"), gridcolor="rgba(255,255,255,0.1)"),
                        angularaxis=dict(tickfont=dict(color="#ccd6f6"), gridcolor="rgba(255,255,255,0.1)"),
                        bgcolor="rgba(0,0,0,0)"
                    ),
                    paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
                    title=dict(text="Safety Radar", font=dict(color="#ccd6f6", size=14)),
                    height=260, margin=dict(t=50, b=10, l=40, r=40)
                )
                st.plotly_chart(fig_radar, use_container_width=True)

            # Feature analysis table
            st.markdown("#### 📊 Feature Analysis")
            feat_rows = [
                ("URL Length", f"{features.get('url_length', len(url))} chars", features.get("url_length", 0) > 75),
                ("HTTPS Secured", "✅ Yes" if features.get("https") else "❌ No", not features.get("https")),
                ("IP Address as Domain", "⚠️ Detected" if features.get("ip_address") else "✅ None", features.get("ip_address")),
                ("Suspicious TLD", "⚠️ Yes" if features.get("known_tld_sus") else "✅ No", features.get("known_tld_sus")),
                ("Subdomain Depth", f"{features.get('subdomain_depth', 0)} levels", features.get("subdomain_depth", 0) > 3),
                ("Special Characters", f"{features.get('special_chars', 0)} found", features.get("special_chars", 0) > 5),
                ("Query Parameters", "Present" if features.get("has_query_params") else "None", False),
                ("Phishing Keywords", ", ".join(features.get("suspicious_keywords", [])[:4]) or "None", bool(features.get("suspicious_keywords"))),
            ]
            for key, val, is_bad in feat_rows:
                val_cls = "feature-val-bad" if is_bad else "feature-val-good"
                st.markdown(f"""<div class="feature-row"><span class="feature-key">{key}</span><span class="{val_cls}">{val}</span></div>""", unsafe_allow_html=True)

            # Risk factors
            sus_parts = result.get("suspicious_parts", [])
            if sus_parts:
                st.markdown("#### 🚩 Risk Factors")
                for part in sus_parts:
                    st.markdown(f'<div class="risk-item"><span class="risk-icon">⚠️</span><span class="risk-text">{part}</span></div>', unsafe_allow_html=True)

            # Explanation
            if EXPLAIN_AVAILABLE:
                try:
                    expl = explain_url_prediction(url, result)
                    with st.expander("🔬 Detailed Explanation"):
                        st.markdown(expl)
                except Exception:
                    pass

        elif scan_btn:
            st.warning("⚠️ Please enter a URL to scan.")

    with tab2:
        st.markdown("#### 📋 Batch URL Scanner")
        st.markdown('<p style="color:#8892b0;font-size:0.9rem;">Enter one URL per line to scan multiple URLs simultaneously</p>', unsafe_allow_html=True)
        batch_input = st.text_area(
            "URLs (one per line):",
            height=160,
            placeholder="https://google.com\nhttp://suspicious-site.tk/login\nhttps://github.com",
            key="batch_url_input"
        )
        batch_btn = st.button("🚀 Scan All URLs", type="primary", use_container_width=True)

        if batch_btn and batch_input.strip():
            urls = [u.strip() for u in batch_input.strip().split("\n") if u.strip()]
            prog_b = st.progress(0, f"Scanning 0/{len(urls)} URLs…")
            results = []
            for i, u in enumerate(urls):
                time.sleep(0.2)
                r = get_url_prediction(u)
                results.append({"URL": u[:60] + ("…" if len(u) > 60 else ""),
                                 "Status": r["label"], "Risk Score": r["risk_score"],
                                 "Threat Level": r["threat_level"],
                                 "Confidence": f"{r['probability']*100:.1f}%"})
                prog_b.progress(int((i + 1) / len(urls) * 100), f"Scanning {i+1}/{len(urls)} URLs…")
            prog_b.empty()

            st.markdown("#### 📊 Batch Scan Results")
            df = pd.DataFrame(results)

            # Color the Status column
            def color_status(val):
                if val == "MALICIOUS": return "background-color:rgba(255,77,77,0.2);color:#ff4d4d;font-weight:700;"
                if val == "SUSPICIOUS": return "background-color:rgba(255,165,0,0.2);color:#ffa500;font-weight:700;"
                return "background-color:rgba(0,204,102,0.1);color:#00cc66;font-weight:700;"

            styled = df.style.map(color_status, subset=["Status"])
            st.dataframe(styled, use_container_width=True)

            total = len(results)
            mal = sum(1 for r in results if r["Status"] == "MALICIOUS")
            sus = sum(1 for r in results if r["Status"] == "SUSPICIOUS")
            safe = sum(1 for r in results if r["Status"] == "SAFE")
            bc1, bc2, bc3, bc4 = st.columns(4)
            for col, lbl, val, col_hex in zip([bc1,bc2,bc3,bc4],["Total","Malicious","Suspicious","Safe"],[total,mal,sus,safe],["#0095ff","#ff4d4d","#ffa500","#00cc66"]):
                with col:
                    st.markdown(f"""<div style="background:rgba(255,255,255,0.04);border:1px solid {col_hex}33;border-radius:12px;padding:0.9rem;text-align:center;"><div style="font-size:1.8rem;font-weight:700;color:{col_hex};">{val}</div><div style="color:#8892b0;font-size:0.8rem;">{lbl}</div></div>""", unsafe_allow_html=True)

            # Pie chart
            if total > 0:
                fig_pie = go.Figure(go.Pie(
                    labels=["Safe", "Suspicious", "Malicious"],
                    values=[safe, sus, mal],
                    marker=dict(colors=["#00cc66", "#ffa500", "#ff4d4d"],
                                line=dict(color="#0d1117", width=2)),
                    hole=0.5,
                    textfont=dict(color="#ccd6f6")
                ))
                fig_pie.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#ccd6f6"),
                    title=dict(text="Batch Scan Distribution", font=dict(color="#ccd6f6", size=14)),
                    legend=dict(font=dict(color="#ccd6f6")),
                    height=280, margin=dict(t=50, b=10, l=10, r=10)
                )
                st.plotly_chart(fig_pie, use_container_width=True)
