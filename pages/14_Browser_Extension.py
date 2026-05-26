"""
Browser Extension Page - CyberShield AI.
A sandbox web browser and interactive extension popup simulation showcasing live threat blocklists and AI scanner API integration.
"""

import streamlit as st
import sys
import os
import pandas as pd
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

st.set_page_config(
    page_title="Browser Extension - CyberShield AI",
    page_icon="🧩",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils.auth import require_login
from utils.ui_helpers import apply_custom_css, render_section_header
from utils.ml_models import predict_url

# Apply styles and login check
apply_custom_css()
require_login()

# Title layout
st.markdown('<h1 style="margin:0;font-size:2rem;">🧩 AI Browser Extension Simulation</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#8a9bb5; margin-top:2px; font-size:0.9rem;">High-fidelity sandbox browser showcasing real-time URL interceptors and endpoint isolation shields</p>', unsafe_allow_html=True)
st.markdown("---")

# Informative Introduction Card
st.markdown(
    """
    <div style="background: rgba(0, 212, 255, 0.05); border: 1px solid rgba(0, 212, 255, 0.2); border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        💡 <b>OPERATIONAL BLUEPRINT:</b> This module simulates how the <b>CyberShield AI Web Protection Engine</b> 
        functions when deployed as a lightweight browser extension (e.g., Chrome/Firefox). Enter any address in the mock URL search bar below 
        to trigger the real-time ML classifiers. The engine interceptor will instantly display active threat popup warnings 
        and block access if malicious features are detected.
    </div>
    """,
    unsafe_allow_html=True
)

# Sandbox defaults
PRESET_URLS = {
    "Safe Website": "https://www.google.com/search?q=cybersecurity+framework",
    "Suspicious Domain": "http://verify-bank-security-portal.cc/login.php",
    "Direct IP Phishing": "http://192.168.1.105/paypal/update-account/secured-verify.html",
    "Safe Repo": "https://github.com/google/differential-privacy"
}

# Layout split
col_browser, col_details = st.columns([5, 3])

# Set initial URL state
if "browser_url" not in st.session_state:
    st.session_state.browser_url = "https://www.google.com/search?q=cybersecurity+framework"

with col_details:
    st.markdown('<div class="cyber-card" style="padding:15px; border-radius:8px; border: 1px solid rgba(0,212,255,0.15);">', unsafe_allow_html=True)
    st.subheader("🛠️ Active Sandbox Controls")
    st.markdown("Click a preset below to instantly route the sandbox browser to that address coordinates:")
    
    for label, url in PRESET_URLS.items():
        if st.button(f"🔗 {label}", key=f"btn_{label}", use_container_width=True):
            st.session_state.browser_url = url
            st.rerun()
            
    st.markdown("<hr style='margin:15px 0;'>", unsafe_allow_html=True)
    st.markdown("### 🔍 Model API Response Indicators")
    
    # Run active URL through real ML models
    url_scan = predict_url(st.session_state.browser_url)
    label = url_scan.get("label", "SAFE")
    score = url_scan.get("risk_score", 0)
    threat_level = url_scan.get("threat_level", "LOW")
    features = url_scan.get("features", {})
    
    # Render indicators based on result
    if label == "MALICIOUS":
        st.error(f"🔴 ALERT: MALICIOUS ENDPOINT FOUND")
        st.markdown(f"**Threat Severity**: `CRITICAL` (Risk Index: {score}%)")
    elif label == "SUSPICIOUS":
        st.warning(f"🟡 ALERT: SUSPICIOUS ACTIVITY FLAG")
        st.markdown(f"**Threat Severity**: `HIGH` (Risk Index: {score}%)")
    else:
        st.success(f"🟢 SAFE ENDPOINT VERIFIED")
        st.markdown(f"**Threat Severity**: `LOW` (Risk Index: {score}%)")
        
    st.markdown("#### Feature Extraction Vectors:")
    df_feats = pd.DataFrame([
        {"Feature": "URL Length", "Value": len(st.session_state.browser_url)},
        {"Feature": "Has HTTPS Encryption", "Value": "Yes" if "https://" in st.session_state.browser_url else "No (Vulnerable)"},
        {"Feature": "IP Address Usage", "Value": "Yes" if features.get("has_ip_address", False) else "No"},
        {"Feature": "Dot Split Count", "Value": features.get("dot_count", 0)},
        {"Feature": "Special Characters", "Value": features.get("special_char_count", 0)},
        {"Feature": "Suspicious Keywords Flagged", "Value": features.get("suspicious_keyword_count", 0)}
    ])
    st.dataframe(df_feats, hide_index=True, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_browser:
    # Outer Web Browser Wrapper
    st.markdown(
        """
        <style>
        .browser-mockup {
            border: 3px solid #1e293b;
            border-radius: 8px 8px 6px 6px;
            background: #0f172a;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }
        .browser-header {
            background: #1e293b;
            padding: 8px 15px;
            display: flex;
            align-items: center;
            border-bottom: 2px solid #334155;
        }
        .browser-dots {
            display: flex;
            gap: 6px;
            margin-right: 15px;
        }
        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        .dot-red { background: #ef4444; }
        .dot-yellow { background: #eab308; }
        .dot-green { background: #22c55e; }
        </style>
        """,
        unsafe_allow_html=True
    )
    
    # HTML Header frame
    st.markdown(
        """
        <div class="browser-mockup">
            <div class="browser-header">
                <div class="browser-dots">
                    <span class="dot dot-red"></span>
                    <span class="dot dot-yellow"></span>
                    <span class="dot dot-green"></span>
                </div>
                <div style="color:#94a3b8; font-family:sans-serif; font-size:0.75rem; background:#0f172a; padding: 4px 12px; border-radius: 4px; border:1px solid #334155; width:100%; max-width:550px; font-family:monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                    🔒 SECURED CONTEXT // INTERCEPTOR ACTIVE
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Streamlit search address bar input inside container
    browser_url_input = st.text_input(
        "Browser URL Address", 
        value=st.session_state.browser_url,
        key="url_bar",
        placeholder="Enter address coordinates (e.g. http://login-verify-bank.com)",
        label_visibility="collapsed"
    )
    
    if browser_url_input != st.session_state.browser_url:
        st.session_state.browser_url = browser_url_input
        st.rerun()

    # Browser Web Content Box
    st.markdown('<div style="background:#020617; border: 1px solid #1e293b; padding:25px; min-height:350px; border-radius: 0 0 4px 4px;">', unsafe_allow_html=True)
    
    if label in ["MALICIOUS", "SUSPICIOUS"]:
        # Block warning frame
        st.markdown(
            f"""
            <div style="background: rgba(239, 68, 68, 0.08); border: 2px solid #ef4444; border-radius: 8px; padding: 25px; text-align: center; color: #f8fafc; font-family: sans-serif; margin-top:20px;">
                <span style="font-size:3.5rem;">🚨</span>
                <h3 style="color:#ef4444; font-family:monospace; margin-top:10px; font-size:1.4rem;">CYBERSHIELD ENDPOINT ISOLATION BLOCK</h3>
                <p style="margin-top:10px; font-size:0.95rem; color:#cbd5e1; line-height:1.5;">
                    The webpage at <b>{st.session_state.browser_url}</b> was automatically blocked by your local AI Extension. 
                    Credential-harvesting patterns and phishing indicators were identified by the random forest classifiers.
                </p>
                <hr style="border-top:1px solid rgba(239, 68, 68, 0.2); margin:15px 0;">
                <div style="font-family:monospace; font-size:0.8rem; color:#94a3b8; display: flex; justify-content: space-around;">
                    <span><b>RISK INDEX:</b> {score}%</span>
                    <span><b>THREAT CLASS:</b> {label}</span>
                    <span><b>PROTECTION:</b> EXTENSION SHIELD v1.0</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        # Mocking Safe Websites inside browser mockup
        if "google.com" in st.session_state.browser_url:
            st.markdown(
                f"""
                <div style="font-family: sans-serif; text-align:center; padding:30px; color:#e2e8f0;">
                    <h1 style="font-size:2.8rem; font-family: 'Product Sans', sans-serif;"><span style="color:#4285F4;">G</span><span style="color:#EA4335;">o</span><span style="color:#FBBC05;">o</span><span style="color:#4285F4;">g</span><span style="color:#34A853;">l</span><span style="color:#EA4335;">e</span></h1>
                    <div style="background:#1e293b; border: 1px solid #334155; border-radius: 20px; padding: 6px 15px; max-width: 450px; margin: 15px auto 0; text-align:left; color:#94a3b8; font-size:0.85rem;">
                        🔍 cybersecurity framework
                    </div>
                    <p style="font-size:0.75rem; color:#64748b; margin-top:20px;">Google Sandbox Search Results // Secured with local HTTPS certificates.</p>
                </div>
                """,
                unsafe_allow_html=True
            )
        elif "github.com" in st.session_state.browser_url:
            st.markdown(
                f"""
                <div style="font-family: sans-serif; color:#e2e8f0; padding:10px;">
                    <h3 style="margin:0; color:#38bdf8;">🐙 GitHub Sandbox Repo</h3>
                    <p style="color:#94a3b8; font-size:0.85rem; margin-top:3px;">google / differential-privacy</p>
                    <hr style="border-top:1px solid #1e293b; margin:10px 0;">
                    <div style="background:#0f172a; padding:10px; border-radius:6px; border:1px solid #1e293b; font-family:monospace; font-size:0.8rem; color:#00ff88;">
                        $ git clone https://github.com/google/differential-privacy.git<br>
                        Cloning into 'differential-privacy'... done.<br>
                        Checking out files: 100% completed.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div style="font-family: sans-serif; color:#e2e8f0; text-align:center; padding:30px;">
                    <span style="font-size:2.5rem;">🌐</span>
                    <h3 style="color:#38bdf8; margin-top:10px;">Safe Webpage Loaded Successfully</h3>
                    <p style="font-size:0.85rem; color:#cbd5e1; margin-top:8px;">
                        The address <b>{st.session_state.browser_url}</b> holds normal parameter features. 
                        No malicious keywords, excessive dots, or anomalies were detected.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("<br><hr>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="text-align: center; color: #4a5568; font-size: 0.8rem; font-family: monospace;">
        SANDBOX ENDPOINT INTERCEPTION SHELL // CYBERSHIELD BROWSER SHIELD v1.0.0
    </div>
    """,
    unsafe_allow_html=True
)
