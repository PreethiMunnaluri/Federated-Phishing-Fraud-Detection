"""
UI helpers and CSS for CyberShield AI – dark cybersecurity theme.
"""

import streamlit as st


# ──────────────────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────────────────

CYBER_CSS = """
<style>
/* ── Google Font ── */
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap');

/* ── Root variables ── */
:root {
    --bg-primary:   #0a0e1a;
    --bg-secondary: #0d1526;
    --bg-card:      #111827;
    --bg-glass:     rgba(17, 24, 39, 0.85);
    --accent-green: #00ff88;
    --accent-cyan:  #00d4ff;
    --accent-blue:  #0066ff;
    --accent-red:   #ff3366;
    --accent-orange:#ff9500;
    --accent-yellow:#ffd700;
    --text-primary: #e2e8f0;
    --text-secondary:#94a3b8;
    --text-muted:   #4a5568;
    --border-color: rgba(0,255,136,0.2);
    --glow-green:   0 0 20px rgba(0,255,136,0.3);
    --glow-cyan:    0 0 20px rgba(0,212,255,0.3);
}

/* ── Global reset ── */
*, *::before, *::after { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"],
[data-testid="stApp"] {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
    font-family: 'Rajdhani', sans-serif;
}

/* ── Animated background grid ── */
[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
        linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
    animation: gridPulse 8s ease-in-out infinite;
}

@keyframes gridPulse {
    0%, 100% { opacity: 0.5; }
    50%       { opacity: 1; }
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #060a14 0%, #0a0e1a 50%, #060d1f 100%) !important;
    border-right: 1px solid var(--border-color) !important;
}
[data-testid="stSidebar"]::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan), var(--accent-blue));
    animation: borderFlow 3s linear infinite;
}
@keyframes borderFlow {
    0%   { background-position: 0% 0%; }
    100% { background-position: 200% 0%; }
}
[data-testid="stSidebar"] .stMarkdown,
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] div {
    color: var(--text-primary) !important;
}

/* ── Main content area ── */
.main .block-container {
    padding: 1.5rem 2rem !important;
    max-width: 1400px !important;
    position: relative;
    z-index: 1;
}

/* ── Headers ── */
h1, h2, h3 {
    font-family: 'Orbitron', monospace !important;
    color: var(--accent-green) !important;
    letter-spacing: 2px;
}
h1 { text-shadow: var(--glow-green); font-size: 2rem !important; }
h2 { color: var(--accent-cyan) !important; font-size: 1.4rem !important; text-shadow: var(--glow-cyan); }
h3 { color: var(--text-primary) !important; font-size: 1.1rem !important; }

/* ── Streamlit buttons ── */
.stButton > button {
    background: linear-gradient(135deg, rgba(0,255,136,0.15), rgba(0,212,255,0.15)) !important;
    color: var(--accent-green) !important;
    border: 1px solid var(--accent-green) !important;
    border-radius: 6px !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
    letter-spacing: 1px !important;
    transition: all 0.3s ease !important;
    padding: 0.5rem 1.5rem !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, rgba(0,255,136,0.3), rgba(0,212,255,0.3)) !important;
    box-shadow: var(--glow-green) !important;
    transform: translateY(-2px) !important;
}
.stButton > button:active {
    transform: translateY(0) !important;
}

/* ── Danger / red button variant ── */
.stButton > button[kind="secondary"] {
    border-color: var(--accent-red) !important;
    color: var(--accent-red) !important;
    background: rgba(255,51,102,0.1) !important;
}
.stButton > button[kind="secondary"]:hover {
    box-shadow: 0 0 20px rgba(255,51,102,0.3) !important;
}

/* ── Text inputs ── */
.stTextInput > div > div > input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"] > div {
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1px solid rgba(0,255,136,0.3) !important;
    border-radius: 6px !important;
    font-family: 'Rajdhani', sans-serif !important;
    transition: border-color 0.3s, box-shadow 0.3s !important;
}
.stTextInput > div > div > input:focus,
.stTextArea textarea:focus {
    border-color: var(--accent-cyan) !important;
    box-shadow: var(--glow-cyan) !important;
    outline: none !important;
}

/* ── Labels ── */
label, .stTextInput label, .stSelectbox label,
.stTextArea label, .stSlider label {
    color: var(--accent-cyan) !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 600 !important;
    letter-spacing: 1px !important;
    font-size: 0.9rem !important;
}

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 10px !important;
    padding: 1rem !important;
    box-shadow: var(--glow-green) !important;
    transition: transform 0.3s, box-shadow 0.3s !important;
}
[data-testid="metric-container"]:hover {
    transform: translateY(-4px) !important;
    box-shadow: 0 0 30px rgba(0,255,136,0.4) !important;
}
[data-testid="stMetricLabel"] {
    color: var(--accent-cyan) !important;
    font-family: 'Rajdhani' !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
}
[data-testid="stMetricValue"] {
    color: var(--accent-green) !important;
    font-family: 'Orbitron', monospace !important;
    font-size: 2rem !important;
}
[data-testid="stMetricDelta"] { color: var(--accent-cyan) !important; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--bg-secondary) !important;
    border-bottom: 2px solid var(--border-color) !important;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    color: var(--text-secondary) !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
    letter-spacing: 1px !important;
    border-radius: 6px 6px 0 0 !important;
    transition: all 0.3s !important;
}
.stTabs [aria-selected="true"] {
    color: var(--accent-green) !important;
    background: rgba(0,255,136,0.1) !important;
    border-bottom: 2px solid var(--accent-green) !important;
}

/* ── Expanders ── */
.streamlit-expanderHeader {
    background: var(--bg-card) !important;
    color: var(--accent-cyan) !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 600 !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 6px !important;
}

/* ── Dataframe / tables ── */
.dataframe, [data-testid="stDataFrame"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
}
thead tr th {
    background: rgba(0,255,136,0.1) !important;
    color: var(--accent-green) !important;
    font-family: 'Orbitron' !important;
    font-size: 0.75rem !important;
    letter-spacing: 1px !important;
}
tbody tr:hover { background: rgba(0,212,255,0.05) !important; }

/* ── Plotly charts ── */
.js-plotly-plot { border-radius: 10px !important; }

/* ── Sliders ── */
[data-testid="stSlider"] > div > div > div {
    background: var(--accent-green) !important;
}

/* ── Radio buttons ── */
.stRadio label { color: var(--text-primary) !important; }
.stRadio [role="radio"] { border-color: var(--accent-green) !important; }

/* ── Checkboxes ── */
.stCheckbox label { color: var(--text-primary) !important; }

/* ── Alerts (Streamlit native) ── */
[data-testid="stAlert"] {
    border-radius: 8px !important;
    font-family: 'Rajdhani', sans-serif !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-secondary); }
::-webkit-scrollbar-thumb { background: rgba(0,255,136,0.4); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-green); }

/* ── Spinner ── */
.stSpinner > div { border-top-color: var(--accent-green) !important; }

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: var(--bg-card) !important;
    border: 2px dashed var(--border-color) !important;
    border-radius: 10px !important;
    transition: border-color 0.3s !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: var(--accent-cyan) !important;
}

/* ── Sidebar nav items ── */
.sidebar-nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 15px;
    margin: 4px 0;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s ease;
    color: var(--text-secondary);
    font-family: 'Rajdhani', sans-serif;
    font-weight: 500;
    font-size: 0.95rem;
    border: 1px solid transparent;
}
.sidebar-nav-item:hover {
    background: rgba(0,255,136,0.08);
    border-color: rgba(0,255,136,0.2);
    color: var(--accent-green);
}
.sidebar-nav-item.active {
    background: rgba(0,255,136,0.12);
    border-color: rgba(0,255,136,0.4);
    color: var(--accent-green);
}

/* ── Glass card ── */
.glass-card {
    background: var(--bg-glass);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(0,255,136,0.2);
    border-radius: 12px;
    padding: 1.5rem;
    margin: 0.5rem 0;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
    position: relative;
    overflow: hidden;
}
.glass-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent-green), var(--accent-cyan), transparent);
    animation: shimmer 3s infinite linear;
    background-size: 200% 100%;
}
@keyframes shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
}
.glass-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 32px rgba(0,255,136,0.15);
}

/* ── Metric custom card ── */
.metric-card {
    background: linear-gradient(135deg, var(--bg-card), #0f1a2e);
    border: 1px solid rgba(0,255,136,0.25);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}
.metric-card:hover {
    border-color: var(--accent-green);
    box-shadow: var(--glow-green);
    transform: translateY(-3px);
}
.metric-card .metric-icon { font-size: 2rem; margin-bottom: 0.3rem; }
.metric-card .metric-value {
    font-family: 'Orbitron', monospace;
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent-green);
    text-shadow: var(--glow-green);
    line-height: 1.2;
}
.metric-card .metric-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.85rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-top: 0.2rem;
}
.metric-card .metric-subtitle {
    font-size: 0.78rem;
    color: var(--accent-cyan);
    margin-top: 0.1rem;
}

/* ── Feature / nav card ── */
.feature-card {
    background: linear-gradient(135deg, #111827, #0d1526);
    border: 1px solid rgba(0,255,136,0.2);
    border-radius: 14px;
    padding: 1.5rem;
    text-align: center;
    cursor: pointer;
    transition: all 0.35s ease;
    position: relative;
    overflow: hidden;
    min-height: 160px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}
.feature-card::after {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(0,255,136,0.05), rgba(0,212,255,0.05));
    opacity: 0;
    transition: opacity 0.3s;
}
.feature-card:hover::after { opacity: 1; }
.feature-card:hover {
    border-color: var(--accent-cyan);
    box-shadow: 0 0 30px rgba(0,212,255,0.2), 0 8px 32px rgba(0,0,0,0.4);
    transform: translateY(-6px) scale(1.02);
}
.feature-card .card-icon { font-size: 2.5rem; margin-bottom: 0.7rem; }
.feature-card .card-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.85rem;
    color: var(--accent-green);
    font-weight: 700;
    letter-spacing: 1px;
    margin-bottom: 0.4rem;
}
.feature-card .card-desc {
    font-size: 0.82rem;
    color: var(--text-secondary);
    line-height: 1.4;
}

/* ── Badges / severity indicators ── */
.badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 20px;
    font-size: 0.78rem;
    font-weight: 700;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}
.badge-low      { background: rgba(0,255,136,0.15); color: #00ff88; border: 1px solid #00ff88; }
.badge-medium   { background: rgba(255,215,0,0.15);  color: #ffd700; border: 1px solid #ffd700; }
.badge-high     { background: rgba(255,149,0,0.15);  color: #ff9500; border: 1px solid #ff9500; }
.badge-critical { background: rgba(255,51,102,0.15); color: #ff3366; border: 1px solid #ff3366; }

/* ── Alert boxes ── */
.cyber-alert {
    padding: 1rem 1.2rem;
    border-radius: 8px;
    margin: 0.5rem 0;
    display: flex;
    align-items: flex-start;
    gap: 0.7rem;
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.95rem;
    border-left: 4px solid;
}
.cyber-alert-success {
    background: rgba(0,255,136,0.08);
    border-color: var(--accent-green);
    color: var(--accent-green);
}
.cyber-alert-warning {
    background: rgba(255,215,0,0.08);
    border-color: var(--accent-yellow);
    color: var(--accent-yellow);
}
.cyber-alert-danger {
    background: rgba(255,51,102,0.08);
    border-color: var(--accent-red);
    color: var(--accent-red);
}
.cyber-alert-info {
    background: rgba(0,212,255,0.08);
    border-color: var(--accent-cyan);
    color: var(--accent-cyan);
}

/* ── Section header ── */
.section-header {
    border-bottom: 1px solid rgba(0,255,136,0.2);
    padding-bottom: 0.7rem;
    margin-bottom: 1.2rem;
}
.section-header .sh-title {
    font-family: 'Orbitron', monospace;
    font-size: 1.1rem;
    color: var(--accent-green);
    text-shadow: var(--glow-green);
    letter-spacing: 2px;
}
.section-header .sh-subtitle {
    font-size: 0.88rem;
    color: var(--text-secondary);
    margin-top: 0.2rem;
}

/* ── Risk gauge ── */
.risk-gauge-container {
    background: var(--bg-card);
    border: 1px solid rgba(0,255,136,0.2);
    border-radius: 12px;
    padding: 1rem;
    text-align: center;
}
.risk-score-text {
    font-family: 'Orbitron', monospace;
    font-size: 3rem;
    font-weight: 900;
    text-shadow: var(--glow-green);
}

/* ── Spinner custom ── */
.cyber-spinner {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 1rem;
    color: var(--accent-cyan);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9rem;
}
.cyber-spinner::before {
    content: '';
    width: 20px;
    height: 20px;
    border: 3px solid rgba(0,212,255,0.2);
    border-top-color: var(--accent-cyan);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Login card ── */
.login-card {
    max-width: 440px;
    margin: 3rem auto;
    background: rgba(13,21,38,0.95);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(0,255,136,0.3);
    border-radius: 20px;
    padding: 2.5rem;
    box-shadow: 0 0 60px rgba(0,255,136,0.1), 0 0 120px rgba(0,212,255,0.05);
    position: relative;
    overflow: hidden;
}
.login-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan), var(--accent-blue));
    animation: borderFlow 2s linear infinite;
    background-size: 200%;
}
.login-logo {
    font-family: 'Orbitron', monospace;
    font-size: 1.8rem;
    font-weight: 900;
    color: var(--accent-green);
    text-shadow: var(--glow-green);
    text-align: center;
    margin-bottom: 0.3rem;
}
.login-subtitle {
    text-align: center;
    font-size: 0.82rem;
    color: var(--text-secondary);
    letter-spacing: 1px;
    margin-bottom: 2rem;
}

/* ── Sidebar logo ── */
.sidebar-logo {
    font-family: 'Orbitron', monospace;
    font-size: 1.1rem;
    font-weight: 900;
    color: var(--accent-green);
    text-shadow: var(--glow-green);
    padding: 0.5rem 0;
}
.sidebar-user-card {
    background: rgba(0,255,136,0.05);
    border: 1px solid rgba(0,255,136,0.15);
    border-radius: 10px;
    padding: 0.8rem 1rem;
    margin: 0.8rem 0;
    font-size: 0.85rem;
}
.sidebar-user-card .user-name {
    color: var(--accent-cyan);
    font-weight: 700;
    font-size: 0.95rem;
}
.sidebar-user-card .user-role {
    color: var(--accent-green);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── Progress bars ── */
.stProgress > div > div > div > div {
    background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan)) !important;
}

/* ── Number input ── */
[data-testid="stNumberInput"] input {
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1px solid rgba(0,255,136,0.3) !important;
    border-radius: 6px !important;
}

/* ── Select box ── */
[data-testid="stSelectbox"] > div > div {
    background: var(--bg-card) !important;
    border: 1px solid rgba(0,255,136,0.3) !important;
    border-radius: 6px !important;
    color: var(--text-primary) !important;
}

/* ── Multiselect ── */
[data-testid="stMultiSelect"] > div > div {
    background: var(--bg-card) !important;
    border: 1px solid rgba(0,255,136,0.3) !important;
}

/* ── Tooltip ── */
[data-testid="stTooltipIcon"] { color: var(--accent-cyan) !important; }

/* ── Divider ── */
hr {
    border: none !important;
    border-top: 1px solid rgba(0,255,136,0.15) !important;
    margin: 1rem 0 !important;
}

/* ── Success / info / warning / error streamlit ── */
[data-testid="stAlert"][kind="success"] {
    background: rgba(0,255,136,0.08) !important;
    border-color: var(--accent-green) !important;
    color: var(--accent-green) !important;
}
[data-testid="stAlert"][kind="error"] {
    background: rgba(255,51,102,0.08) !important;
    border-color: var(--accent-red) !important;
    color: var(--accent-red) !important;
}
[data-testid="stAlert"][kind="info"] {
    background: rgba(0,212,255,0.08) !important;
    border-color: var(--accent-cyan) !important;
    color: var(--accent-cyan) !important;
}
[data-testid="stAlert"][kind="warning"] {
    background: rgba(255,215,0,0.08) !important;
    border-color: var(--accent-yellow) !important;
    color: var(--accent-yellow) !important;
}

/* Pulse animation for critical threats */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.5; }
}
.pulse { animation: pulse 2s ease-in-out infinite; }

/* Typing cursor animation */
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
.cursor::after { content: '|'; animation: blink 1s infinite; color: var(--accent-green); }
</style>
"""


def apply_custom_css():
    """Inject the comprehensive cybersecurity CSS theme."""
    st.markdown(CYBER_CSS, unsafe_allow_html=True)


def threat_badge(level: str) -> str:
    """
    Return an HTML badge for a threat level.
    level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    """
    level = level.upper()
    icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
    classes = {"LOW": "badge-low", "MEDIUM": "badge-medium", "HIGH": "badge-high", "CRITICAL": "badge-critical"}
    icon = icons.get(level, "⚪")
    cls = classes.get(level, "badge-low")
    return f'<span class="badge {cls}">{icon} {level}</span>'


def render_metric_card(title: str, value, subtitle: str = "", color: str = "#00ff88", icon: str = "🔐"):
    """Render a styled metric card."""
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-icon">{icon}</div>
            <div class="metric-value" style="color:{color}; text-shadow: 0 0 20px {color}55;">{value}</div>
            <div class="metric-title">{title}</div>
            {"<div class='metric-subtitle'>" + subtitle + "</div>" if subtitle else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_section_header(title: str, subtitle: str = "", icon: str = "🛡️"):
    """Render a styled section header."""
    st.markdown(
        f"""
        <div class="section-header">
            <div class="sh-title">{icon} {title}</div>
            {"<div class='sh-subtitle'>" + subtitle + "</div>" if subtitle else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_alert(message: str, alert_type: str = "warning"):
    """
    Render a custom cyber alert box.
    alert_type: 'success', 'warning', 'danger', 'info'
    """
    icons = {"success": "✅", "warning": "⚠️", "danger": "🚨", "info": "ℹ️"}
    icon = icons.get(alert_type, "ℹ️")
    css_class = f"cyber-alert cyber-alert-{alert_type}"
    st.markdown(
        f'<div class="{css_class}"><span>{icon}</span><span>{message}</span></div>',
        unsafe_allow_html=True,
    )


def render_cyber_spinner(text: str = "Analyzing..."):
    """Render a cyber-themed loading indicator."""
    st.markdown(
        f'<div class="cyber-spinner">{text}</div>',
        unsafe_allow_html=True,
    )
