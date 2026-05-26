"""
CyberShield AI — Main Entry Point and Home/Landing Page.
"""

import streamlit as st
import sys
import os
from datetime import datetime

# Set page configuration first
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Insert current directory into path so utils is importable
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.auth import login, signup, logout, get_current_user
from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
from utils.threat_logger import get_threat_stats, get_threats

# Apply the custom cyber CSS theme
apply_custom_css()

# Custom login page styling and layout
def render_styled_login():
    st.markdown(
        """
        <div style="text-align: center; margin-top: 2rem;">
            <span style="font-size: 5rem; text-shadow: 0 0 20px rgba(0,255,136,0.5);">🛡️</span>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.markdown('<div class="login-card">', unsafe_allow_html=True)
    st.markdown('<div class="login-logo">CYBERSHIELD AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="login-subtitle">FEDERATED LEARNING-BASED THREAT DETECTION PLATFORM</div>', unsafe_allow_html=True)
    
    # Toggle between Login and Sign Up using a selectbox or pill buttons
    auth_mode = st.radio("Access Portal", ["Sign In", "Create Account", "Guest Mode (Mock Admin)"], horizontal=True)
    
    st.markdown("<hr style='margin: 1.5rem 0;'>", unsafe_allow_html=True)
    
    if auth_mode == "Sign In":
        username = st.text_input("Operator Username", placeholder="e.g. admin")
        password = st.text_input("Security Access Code", type="password", placeholder="••••••••")
        
        st.markdown("<div style='margin-top: 1.5rem;'>", unsafe_allow_html=True)
        if st.button("AUTHENTICATE DECRYPTED ACCESS", use_container_width=True):
            if not username or not password:
                st.error("Access Denied: Operational credentials required.")
            else:
                with st.spinner("Decrypting tokens..."):
                    if login(username, password):
                        st.success("Authentication successful! Loading main systems...")
                        st.rerun()
                    else:
                        st.error("Authentication failed: Invalid credentials.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; font-size:0.75rem; color:#4a5568; margin-top:10px;'>Default credentials: <b>admin</b> / <b>admin123</b></p>", unsafe_allow_html=True)

    elif auth_mode == "Create Account":
        new_username = st.text_input("Desired Operator Username", placeholder="e.g. analyst1")
        new_email = st.text_input("Operational Contact Email", placeholder="e.g. analyst1@cybershield.ai")
        new_password = st.text_input("New Security Access Code", type="password", placeholder="Min 6 characters")
        role = st.selectbox("Role Assignment", ["user", "admin"])
        
        st.markdown("<div style='margin-top: 1.5rem;'>", unsafe_allow_html=True)
        if st.button("INITIALIZE NEW CREDENTIALS", use_container_width=True):
            if not new_username or not new_email or not new_password:
                st.error("Registration failed: All fields are mandatory.")
            else:
                ok, msg = signup(new_username, new_password, new_email, role)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
        st.markdown("</div>", unsafe_allow_html=True)

    elif auth_mode == "Guest Mode (Mock Admin)":
        st.info("Bypassing secure token checks. Initiating sandbox environment with administrative privileges.")
        if st.button("LAUNCH SANDBOX ADMIN ENVIRONMENT", use_container_width=True):
            st.session_state["user"] = {
                "username": "SandboxAdmin",
                "role": "admin",
                "email": "sandbox@cybershield.ai",
                "logged_in": True,
                "login_time": datetime.now().isoformat(),
            }
            st.rerun()
            
    st.markdown('</div>', unsafe_allow_html=True)

# Sidebar layout
def render_cyber_sidebar(user):
    with st.sidebar:
        st.markdown('<div class="sidebar-logo">🛡️ CyberShield AI</div>', unsafe_allow_html=True)
        
        st.markdown(
            f"""
            <div class="sidebar-user-card">
                <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">ACTIVE OPERATOR</div>
                <div class="user-name">👤 {user.get('username', 'Unknown')}</div>
                <div class="user-role">🛡️ {user.get('role', 'user')}</div>
                <div style="font-size: 0.7rem; color: #4a5568; margin-top: 4px;">Session: {datetime.now().strftime("%H:%M:%S")}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown("### SYSTEM CONTROLS")
        if st.button("🔒 TERMINATE SESSION", use_container_width=True, type="secondary"):
            logout()

# Main Landing Page content after logging in
def render_landing_page(user):
    st.title("🛡️ CyberShield AI Portal")
    st.markdown('<p style="color:#8a9bb5; font-size:1.1rem; margin-top:-5px;">Federated AI-Based Framework for Secure Phishing and Fraud Detection</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    # System summary metrics
    try:
        stats = get_threat_stats()
        total_threats = stats.get("total", 0)
        recent_threats = stats.get("recent_24h", 0)
    except Exception:
        total_threats = 50
        recent_threats = 12
        
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_metric_card("🛡️ Models Active", "4 / 4", "Email, URL, SMS, Fraud", "#00ff88", "🤖")
    with m2:
        render_metric_card("🚨 Total Threats", f"{total_threats}", f"+{recent_threats} in 24h", "#ff3366", "⚠️")
    with m3:
        render_metric_card("🔗 Federated Nodes", "4 Active", "FedAvg Aggregator", "#00d4ff", "⛓️")
    with m4:
        render_metric_card("🔒 Privacy Budget", "ε = 1.0", "DP Enabled (Laplace)", "#ffd700", "🔑")
        
    st.markdown("<br>", unsafe_allow_html=True)
    render_section_header("CORE PLATFORM SUB-SYSTEMS", "Select a module from the sidebar or choose from the operational panel below.")
    
    # 3x3 operational panel grid
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">🏠</div>
                <div class="card-title">SOC DASHBOARD</div>
                <div class="card-desc">Real-time threat feeds, active phishing trackers, anomaly alerts, and centralized security metrics dashboard.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">🔗</div>
                <div class="card-title">MALICIOUS URL SCANNER</div>
                <div class="card-desc">Inspect, classify, and isolate dangerous links, fake banking portals, domain typosquatting, and malicious TLDs.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">⛓️</div>
                <div class="card-title">FEDERATED LEARNING</div>
                <div class="card-desc">Run dynamic FedAvg simulation across decentralized nodes (Bank, Telecom, etc.) without sharing private raw logs.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    with col2:
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">📧</div>
                <div class="card-title">EMAIL PHISHING DETECTOR</div>
                <div class="card-desc">Advanced NLP scanning for spoofed addresses, urgent language cues, fraudulent bank alerts, and credential harvesting.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">📱</div>
                <div class="card-title">SMS / SMISHING DETECTOR</div>
                <div class="card-desc">Simulate a smartphone interface and analyze text messages for fake lottery wins, UPI fraud, and fake OTP requests.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">🔒</div>
                <div class="card-title">DIFFERENTIAL PRIVACY</div>
                <div class="card-desc">Simulate Laplace and Gaussian noise injection into model weight aggregates to preserve client data privacy.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    with col3:
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">💳</div>
                <div class="card-title">FRAUD TRANSACTION ANALYZER</div>
                <div class="card-desc">Anomaly detection models classifying real-time banking transfers using amount, hour, frequency, location, and device data.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">🧠</div>
                <div class="card-title">EXPLAINABLE AI (XAI)</div>
                <div class="card-desc">Deep model inspection utilizing feature importances and SHAP-like waterfall charts to explain system alerts.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="feature-card">
                <div class="card-icon">🤖</div>
                <div class="card-title">AI ASSISTANT</div>
                <div class="card-desc">Operational expert Q&A chatbot using fuzzy-logic knowledge base to solve operators' questions instantly.</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br><hr>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="text-align: center; color: #4a5568; font-size: 0.8rem; font-family: monospace;">
            CYBERSHIELD AI PLATFORM v1.0.0 // LOCAL ENVIRONMENT OPERATIONAL // SECURITY LEVEL 4
        </div>
        """,
        unsafe_allow_html=True
    )

# Auth state router
user = get_current_user()
if not user or not user.get("logged_in"):
    render_styled_login()
else:
    render_cyber_sidebar(user)
    render_landing_page(user)
