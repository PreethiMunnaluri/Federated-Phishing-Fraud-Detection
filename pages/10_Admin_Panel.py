"""
Admin Panel Page - CyberShield AI.
Secure administrator console for operator management, threat audits, and system configuration.
"""

import streamlit as st
import pandas as pd
import json
import os
import sys
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

st.set_page_config(
    page_title="Admin Panel - CyberShield AI",
    page_icon="⚙️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils.auth import require_login, is_admin, get_all_users, signup, get_current_user
from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
from utils.threat_logger import get_threat_stats, get_threats, clear_old_threats, _save_threats

# Apply the custom cyber CSS theme
apply_custom_css()

# Enforce secure login
require_login()

# Enforce admin credentials check
if not is_admin():
    st.error("🚨 ACCESS DENIED: ADMINISTRATIVE security clearance is required to view this panel.")
    st.info(f"Active Operator '{get_current_user().get('username')}' has insufficient credentials.")
    if st.button("⬅️ RETURN TO MAIN PLATFORM"):
        st.switch_page("app.py")
    st.stop()

# Header layout
col_title, col_time = st.columns([7, 3])
with col_title:
    st.markdown('<h1 style="margin:0;font-size:2rem;">⚙️ Admin Control Console</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#8a9bb5; margin-top:2px; font-size:0.9rem;">Cryptographically verified operator management, audits, and network controllers</p>', unsafe_allow_html=True)
with col_time:
    now = datetime.now()
    st.markdown(
        f'<div style="text-align:right;padding-top:10px;color:#00ff88;font-family:monospace;font-size:0.9rem;">'
        f'ADMIN MODE // AUTHENTICATED: {now.strftime("%H:%M:%S")}</div>',
        unsafe_allow_html=True
    )

st.markdown("---")

# Load real metrics
try:
    stats = get_threat_stats()
    total_logs = stats.get("total", 0)
    users = get_all_users()
    total_users = len(users)
except Exception:
    total_logs = 0
    total_users = 1
    users = []

# Admin Metrics Panel
c1, c2, c3, c4 = st.columns(4)
with c1:
    render_metric_card("👥 Registered Operators", f"{total_users}", "Auth-enabled keys", "#00ff88", "🔑")
with c2:
    render_metric_card("🚨 Audit Threat Logs", f"{total_logs}", "Stored in threats.json", "#ff3366", "📂")
with c3:
    render_metric_card("⚡ System Clearance", "LEVEL 4", "Maximum Decoupled", "#00d4ff", "🔒")
with c4:
    render_metric_card("💾 Database Integrity", "100%", "Decentralized Audit", "#ffd700", "🛡️")

st.markdown("<br>", unsafe_allow_html=True)

# Tabs structure
tab_users, tab_logs, tab_sys = st.tabs([
    "👥 OPERATOR DATABASE", 
    "📂 AUDIT TRAIL LOGS", 
    "🛡️ CORE SYSTEM SETTINGS"
])

# 1. User Management Tab
with tab_users:
    render_section_header("ACTIVE SECURITY OPERATORS", "Manage system analysts, administrators, and guest tokens")
    
    col_u_left, col_u_right = st.columns([5, 4])
    
    with col_u_left:
        st.subheader("🔑 Registry of Registered Keys")
        if users:
            # Build clean pandas table
            df_users = pd.DataFrame(users)
            df_users.rename(columns={
                "username": "OPERATOR ID",
                "email": "SECURE EMAIL",
                "role": "SECURITY ROLE",
                "created_at": "KEY INITIALIZED AT"
            }, inplace=True)
            
            # Format datetime
            df_users["KEY INITIALIZED AT"] = df_users["KEY INITIALIZED AT"].apply(
                lambda x: str(x).replace("T", " ")[:19]
            )
            
            # Display Table with style
            st.markdown('<div class="table-container">', unsafe_allow_html=True)
            st.dataframe(df_users, use_container_width=True, hide_index=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.warning("No registered operators found in sandbox registry.")
            
    with col_u_right:
        st.subheader("➕ Authorize New Operator Node")
        with st.form("new_operator_form"):
            new_uname = st.text_input("Operator Username / ID", placeholder="e.g. secure_analyst_2")
            new_email = st.text_input("Operational Contact Email", placeholder="e.g. analyst2@cybershield.ai")
            new_password = st.text_input("Security Access Code (Password)", type="password", placeholder="Min 6 characters")
            new_role = st.selectbox("Assigned Security Clearance", ["user", "admin"])
            
            submitted = st.form_submit_button("INITIALIZE OPERATOR INTERFACE", use_container_width=True)
            if submitted:
                if not new_uname or not new_email or not new_password:
                    st.error("Operator initialization failed: All fields are mandatory.")
                else:
                    success, msg = signup(new_uname, new_password, new_email, new_role)
                    if success:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

# 2. Audit Trail Logs Tab
with tab_logs:
    render_section_header("LOG FILE SECURITY AUDITING", "Monitor threat databases and execute database purges")
    
    col_l_left, col_l_right = st.columns([5, 3])
    
    with col_l_left:
        st.subheader("📜 Live Event Feed (threats.json)")
        try:
            recent_threats = get_threats(limit=250)
            if recent_threats:
                st.json(recent_threats)
            else:
                st.info("The threat database is currently empty. Run scans to populate logs.")
        except Exception as e:
            st.error(f"Error accessing threat ledger file: {e}")
            
    with col_l_right:
        st.subheader("🧹 Database Maintenance Tools")
        st.warning("⚠️ CRITICAL ACTION: Purging threat logs deletes historical anomaly and scanning databases. This action is irreversible.")
        
        purge_choice = st.selectbox(
            "Select Purge Target Range", 
            ["Keep All (Cancel)", "Older than 30 Days", "Older than 7 Days", "Delete ALL Stored Threat Logs"]
        )
        
        if st.button("EXECUTE LOG PURGE ACTIONS", type="primary", use_container_width=True):
            if purge_choice == "Keep All (Cancel)":
                st.info("Log purge canceled by administrator request.")
            elif purge_choice == "Older than 30 Days":
                cleared = clear_old_threats(30)
                st.success(f"Purge completed successfully! Cleared {cleared} threat record(s) older than 30 days.")
                st.rerun()
            elif purge_choice == "Older than 7 Days":
                cleared = clear_old_threats(7)
                st.success(f"Purge completed successfully! Cleared {cleared} threat record(s) older than 7 days.")
                st.rerun()
            elif purge_choice == "Delete ALL Stored Threat Logs":
                try:
                    # Direct clear of the JSON file
                    _save_threats([])
                    st.success("Successfully purged ALL security threat registers inside threats.json!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to truncate threat database: {e}")

# 3. Core System Settings Tab
with tab_sys:
    render_section_header("PLATFORM ENGINE CONTROLLERS", "System-wide settings and threat database warm-up routines")
    
    col_s_left, col_s_right = st.columns(2)
    
    with col_s_left:
        st.subheader("🤖 Local AI Engine Settings")
        st.toggle("Differential Privacy (DP) Noise Aggregation", value=True, disabled=True, help="Enforces local Laplace differential privacy bounds during federated rounds.")
        st.toggle("SHA-256 Block Log Verification", value=True, disabled=True, help="Automatically stores threat telemetry signatures to the blockchain simulator.")
        st.toggle("Adversarial Byzantine Filtering", value=True, disabled=True, help="Flags abnormal client model weights dynamically during client consensus phases.")
        st.slider("Anomaly RF Threshold Limit (%)", min_value=50, max_value=99, value=85, help="Alert boundary for suspicious transaction and scan classifiers.")
        st.success("🟢 Cybersecurity AI Core Engine status: STABLE")
        
    with col_s_right:
        st.subheader("⚡ Sandbox Test Suite Tools")
        st.info("Use these triggers to instantly reload sandbox databases, synthetic threat logs, or trained model files.")
        
        if st.button("🚀 SEED SYNTHETIC THREAT FEED (50 LOGS)", use_container_width=True):
            with st.spinner("Seeding threats..."):
                try:
                    import subprocess
                    script_path = os.path.join(PROJECT_ROOT, "generate_threats.py")
                    result = subprocess.run(["python", script_path], capture_output=True, text=True, check=True)
                    st.success("Successfully seeded threats.json with 50 diverse historical cyber threats!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error executing threat generator: {e}")
                    
        if st.button("🧬 GENERATE CSV DATASETS (500 ROWS)", use_container_width=True):
            with st.spinner("Writing synthetic records..."):
                try:
                    import subprocess
                    script_path = os.path.join(PROJECT_ROOT, "datasets", "generate_datasets.py")
                    result = subprocess.run(["python", script_path], capture_output=True, text=True, check=True)
                    st.success("Datasets fully generated and saved in datasets/ folder!")
                except Exception as e:
                    st.error(f"Error executing datasets generation script: {e}")

        if st.button("🤖 RETRAIN & PICKLE ALL FOUR AI MODELS", use_container_width=True):
            with st.spinner("Training scikit-learn models..."):
                try:
                    import subprocess
                    script_path = os.path.join(PROJECT_ROOT, "models", "train_models.py")
                    result = subprocess.run(["python", script_path], capture_output=True, text=True, check=True)
                    st.success("Models fully retrained and pickled into saved_models/ folder!")
                except Exception as e:
                    st.error(f"Error executing models training: {e}")

st.markdown("<br><hr>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="text-align: center; color: #4a5568; font-size: 0.8rem; font-family: monospace;">
        SECURE ADMINISTRATIVE PANEL // CYBERSHIELD CONTROL SHELL v1.0.0
    </div>
    """,
    unsafe_allow_html=True
)
