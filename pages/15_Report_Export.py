"""
Report Export Page - CyberShield AI.
Interactive control console allowing security analysts to filter, analyze, and programmatically export PDF and CSV reports.
"""

import streamlit as st
import pandas as pd
import sys
import os
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

st.set_page_config(
    page_title="Report Export Console - CyberShield AI",
    page_icon="📥",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils.auth import require_login
from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
from utils.threat_logger import get_threats, get_threat_stats
from utils.report_generator import export_threats_pdf, export_threats_csv

# Apply styles and login check
apply_custom_css()
require_login()

# Title layout
st.markdown('<h1 style="margin:0;font-size:2rem;">📥 Secure Report Exporter</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#8a9bb5; margin-top:2px; font-size:0.9rem;">Programmatic document builder compiling audit logs and local classifier diagnostics</p>', unsafe_allow_html=True)
st.markdown("---")

# Informational Header Card
st.markdown(
    """
    <div style="background: rgba(0, 255, 136, 0.04); border: 1px solid rgba(0, 255, 136, 0.2); border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        📊 <b>COMPLIANCE & AUDIT ASSURANCE:</b> Exporters conform to cryptographically validated ledger standards. 
        Filter records based on vector channels and severity levels to instantly generate professional operational report layouts.
    </div>
    """,
    unsafe_allow_html=True
)

# Fetch stats and alerts
try:
    stats = get_threat_stats()
    threats = get_threats(limit=500)
except Exception:
    stats = {"total": 0, "recent_24h": 0}
    threats = []

# Exporter Layout Columns
col_controls, col_preview = st.columns([1, 2])

with col_controls:
    st.markdown('<div class="cyber-card" style="padding:18px; border-radius:8px; border: 1px solid rgba(0,255,136,0.15); min-height:500px;">', unsafe_allow_html=True)
    st.subheader("⚙️ Filter Directives")
    
    # Severity filters
    all_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    selected_severities = st.multiselect(
        "Select Severity Coordinates", 
        all_severities, 
        default=all_severities
    )
    
    # Vector filters
    all_vectors = ["phishing_email", "malicious_url", "sms_spam", "fraud_transaction"]
    selected_vectors = st.multiselect(
        "Select Channel Vectors", 
        all_vectors, 
        default=all_vectors
    )
    
    # Limit filter
    max_records = st.slider("Record Query Limit", min_value=10, max_value=500, value=100)
    
    st.markdown("<hr style='margin:18px 0;'>", unsafe_allow_html=True)
    st.subheader("📥 Export Outputs")
    
    # Filtering logic
    filtered_threats = [
        t for t in threats 
        if t.get("severity") in selected_severities 
        and t.get("threat_type") in selected_vectors
    ][:max_records]
    
    if filtered_threats:
        # 1. Export PDF button
        try:
            pdf_bytes = export_threats_pdf(filtered_threats)
            st.download_button(
                label="📄 COMPILE & DOWNLOAD PDF REPORT",
                data=pdf_bytes,
                file_name=f"CyberShield_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )
        except Exception as e:
            st.error(f"Error compiling PDF exporter: {e}")
            
        # 2. Export CSV button
        try:
            # We can compile CSV bytes of the specific filtered set
            output_csv_lines = ["id,timestamp,threat_type,severity,username,details"]
            for t in filtered_threats:
                details_str = str(t.get('details', '')).replace('"', "'")
                row = f"{t.get('id')},{t.get('timestamp')},{t.get('threat_type')},{t.get('severity')},{t.get('username')},\"{details_str}\""
                output_csv_lines.append(row)
            csv_bytes = "\n".join(output_csv_lines).encode("utf-8")
            
            st.markdown("<div style='margin-top:10px;'>", unsafe_allow_html=True)
            st.download_button(
                label="📊 COMPILE & DOWNLOAD CSV AUDIT",
                data=csv_bytes,
                file_name=f"CyberShield_Threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
            st.markdown("</div>", unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error compiling CSV exporter: {e}")
            
    else:
        st.warning("⚠️ Export actions disabled: Filter coordinates returned empty records.")
        
    st.markdown('</div>', unsafe_allow_html=True)

with col_preview:
    render_section_header("DOCUMENT PREVIEW ENGINE", "Active compilation matrix of operational datasets matching query bounds")
    
    if filtered_threats:
        # Format table preview nicely
        preview_data = []
        for i, t in enumerate(filtered_threats, 1):
            details = t.get("details", {})
            detail_summary = ""
            if "text" in details:
                detail_summary = details["text"]
            elif "url" in details:
                detail_summary = details["url"]
            elif "amount" in details:
                detail_summary = f"Amt: ₹{details['amount']} | Loc: {details.get('location')}"
                
            if len(detail_summary) > 55:
                detail_summary = detail_summary[:52] + "..."
                
            preview_data.append({
                "INDEX": i,
                "TIMESTAMP": t.get("timestamp", "")[:19].replace("T", " "),
                "VECTOR": t.get("threat_type", "").upper().replace("_", " "),
                "SEVERITY": t.get("severity", ""),
                "OPERATOR": t.get("username", "system"),
                "DIAGNOSTIC DETAIL": detail_summary
            })
            
        df_preview = pd.DataFrame(preview_data)
        
        # Display statistics metrics
        m1, m2, m3 = st.columns(3)
        with m1:
            render_metric_card("Filtered Records", f"{len(filtered_threats)} Rows", "Active matching total", "#00ff88", "📋")
        with m2:
            high_risk_count = sum(1 for t in filtered_threats if t.get("severity") in ["HIGH", "CRITICAL"])
            render_metric_card("High/Critical Index", f"{high_risk_count}", "Elevated priority alerts", "#ff3366", "🚨")
        with m3:
            render_metric_card("File Security", "LEVEL 4 CLEAR", "Authenticated Access", "#00d4ff", "🔒")
            
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### Document Rows Preview:")
        st.dataframe(df_preview, use_container_width=True, hide_index=True)
        
    else:
        st.info("💡 Awaiting coordinate bounds. Configure search selectors in the left-hand console panel to preview active log matrices.")

st.markdown("<br><hr>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="text-align: center; color: #4a5568; font-size: 0.8rem; font-family: monospace;">
        SECURE COMPLIANCE ENGINE // DOCUMENT GENERATION PANEL v1.0.0
    </div>
    """,
    unsafe_allow_html=True
)
