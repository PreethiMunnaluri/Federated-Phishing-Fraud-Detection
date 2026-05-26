import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import json
import hashlib
import time
import os
from datetime import datetime, timezone

st.set_page_config(
    page_title="Blockchain Verification | CyberShield AI",
    page_icon="⛓️",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    from utils.auth import require_login, get_current_user
    from utils.ui_helpers import apply_custom_css, render_section_header, render_metric_card
    from utils.threat_logger import log_threat
except ImportError:
    def require_login(): pass
    def get_current_user(): return {"username": "demo_user"}
    def apply_custom_css(): pass
    def render_section_header(t, s=""): st.markdown(f"## {t}")
    def render_metric_card(l, v, d="", c="blue"): st.metric(l, v, d)
    def log_threat(t, d, sev): pass

apply_custom_css()
require_login()

# ─────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&family=Inter:wght@300;400;600&display=swap');

body, .stApp { background: #080c14 !important; }

.bc-hero {
    background: linear-gradient(135deg, #080c14 0%, #0a1020 50%, #08100a 100%);
    border: 1px solid rgba(247,180,47,0.2);
    border-radius: 20px;
    padding: 40px;
    text-align: center;
    margin-bottom: 30px;
    position: relative;
    overflow: hidden;
}
.bc-hero::before {
    content: ''; position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(247,180,47,0.07) 0%, transparent 60%);
    border-radius: 20px;
}
.bc-hero h1 {
    font-family: 'Orbitron', monospace;
    font-size: 2.6rem; font-weight: 900;
    background: linear-gradient(90deg, #f7b42f, #ffd700, #f7b42f);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin: 0 0 10px 0;
}
.bc-hero p { font-family: 'Inter', sans-serif; color: rgba(247,220,150,0.75); font-size: 1.05rem; margin: 0; }

.block-container {
    display: flex;
    overflow-x: auto;
    padding: 20px 0;
    gap: 0;
    align-items: center;
}
.block-card {
    min-width: 200px;
    background: linear-gradient(145deg, #0d1520, #0a1015);
    border: 2px solid rgba(247,180,47,0.35);
    border-radius: 14px;
    padding: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: rgba(247,220,150,0.9);
    flex-shrink: 0;
    position: relative;
    transition: all 0.3s;
}
.block-card.latest {
    border-color: #00ff88;
    box-shadow: 0 0 20px rgba(0,255,136,0.3), 0 0 40px rgba(0,255,136,0.1);
}
.block-card.tampered {
    border-color: #ff3838;
    box-shadow: 0 0 20px rgba(255,56,56,0.4);
    background: linear-gradient(145deg, #200808, #150505);
}
.block-header {
    color: #f7b42f;
    font-family: 'Orbitron', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    margin-bottom: 10px;
    border-bottom: 1px solid rgba(247,180,47,0.2);
    padding-bottom: 6px;
}
.block-hash { color: #00ff88; font-size: 0.65rem; word-break: break-all; }
.block-prev { color: rgba(247,180,47,0.6); font-size: 0.65rem; word-break: break-all; }
.chain-arrow {
    color: #f7b42f;
    font-size: 1.8rem;
    padding: 0 8px;
    flex-shrink: 0;
    align-self: center;
}
.bc-metric {
    background: linear-gradient(145deg, #0d1520, #0a1015);
    border: 1px solid rgba(247,180,47,0.3);
    border-radius: 14px;
    padding: 18px;
    text-align: center;
}
.bc-metric .val { font-family: 'Orbitron', monospace; font-size: 1.9rem; color: #f7b42f; font-weight: 700; }
.bc-metric .lbl { font-family: 'Inter', sans-serif; color: rgba(247,220,150,0.6); font-size: 0.8rem; margin-top: 4px; }

.hash-anim {
    background: #0a1a0a;
    border: 1px solid #00ff88;
    border-radius: 10px;
    padding: 14px 18px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    color: #00ff88;
    word-break: break-all;
    letter-spacing: 0.5px;
}
.tamper-alert {
    background: linear-gradient(135deg, #200808, #150505);
    border: 2px solid #ff3838;
    border-radius: 14px;
    padding: 20px;
    font-family: 'Orbitron', monospace;
    color: #ff6b6b;
    text-align: center;
    font-size: 1rem;
    box-shadow: 0 0 20px rgba(255,56,56,0.2);
    margin: 12px 0;
}
.verify-success {
    background: linear-gradient(135deg, #081508, #0a200a);
    border: 2px solid #00ff88;
    border-radius: 14px;
    padding: 20px;
    font-family: 'Orbitron', monospace;
    color: #00ff88;
    text-align: center;
    font-size: 1rem;
    box-shadow: 0 0 20px rgba(0,255,136,0.2);
    margin: 12px 0;
}
</style>

<div class="bc-hero">
    <div style="display:inline-block;background:linear-gradient(135deg,#f7b42f,#ffd700);color:#080c14;
                font-family:Orbitron,monospace;font-size:0.6rem;font-weight:700;padding:4px 14px;
                border-radius:20px;margin-bottom:15px;letter-spacing:2px;">⛓️ BLOCKCHAIN</div>
    <h1>⛓️ Blockchain Verification</h1>
    <p>Immutable Audit Trail — Verifying FL Model Updates Are Cryptographically Untampered</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# BLOCKCHAIN STORAGE
# ─────────────────────────────────────────
BLOCKCHAIN_FILE = "logs/blockchain.json"
os.makedirs("logs", exist_ok=True)

def compute_hash(block_data: dict) -> str:
    block_str = json.dumps({k: v for k, v in block_data.items() if k != "hash"}, sort_keys=True)
    return hashlib.sha256(block_str.encode()).hexdigest()

def create_genesis_blocks() -> list:
    blocks = []
    prev_hash = "0" * 64
    for i in range(5):
        ts = datetime.now(timezone.utc).isoformat()
        block = {
            "index": i,
            "timestamp": ts,
            "round_num": i,
            "client_count": 4,
            "accuracy": round(0.78 + i * 0.03, 4),
            "nonce": int(np.random.randint(1000, 9999)),
            "previous_hash": prev_hash,
        }
        block["hash"] = compute_hash(block)
        prev_hash = block["hash"]
        blocks.append(block)
    return blocks

def load_blockchain() -> list:
    if os.path.exists(BLOCKCHAIN_FILE):
        try:
            with open(BLOCKCHAIN_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    genesis = create_genesis_blocks()
    save_blockchain(genesis)
    return genesis

def save_blockchain(chain: list):
    os.makedirs("logs", exist_ok=True)
    with open(BLOCKCHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

def verify_chain(chain: list) -> tuple[bool, int]:
    for i in range(1, len(chain)):
        current = chain[i]
        prev = chain[i - 1]
        expected_hash = compute_hash({k: v for k, v in current.items() if k != "hash"})
        if current["hash"] != expected_hash:
            return False, i
        if current["previous_hash"] != prev["hash"]:
            return False, i
    return True, -1

# Initialize blockchain
if "blockchain" not in st.session_state:
    st.session_state.blockchain = load_blockchain()
if "tampered_idx" not in st.session_state:
    st.session_state.tampered_idx = -1

chain = st.session_state.blockchain

# ─────────────────────────────────────────
# EXPLANATION
# ─────────────────────────────────────────
st.markdown("### 🔍 Why Blockchain for Federated Learning?")
col1, col2, col3 = st.columns(3)
explanations = [
    ("🔒", "#f7b42f", "Immutability", "Once a FL round's model weights are committed to the blockchain, they cannot be altered without breaking the cryptographic chain."),
    ("✅", "#00ff88", "Verification", "Any participant can independently verify that the global model was computed correctly from client updates."),
    ("📋", "#a78bfa", "Audit Trail", "Every federated learning round is permanently recorded with its timestamp, accuracy, and client count."),
]
for col, (icon, color, title, desc) in zip([col1, col2, col3], explanations):
    col.markdown(f"""
    <div style="background:linear-gradient(145deg,#0d1520,#0a1015);border:1px solid rgba(247,180,47,0.2);
                border-radius:14px;padding:20px;font-family:Inter,sans-serif;">
        <div style="font-size:2rem;margin-bottom:8px;">{icon}</div>
        <strong style="color:{color};font-family:Orbitron,monospace;font-size:0.9rem;">{title}</strong><br>
        <span style="color:rgba(247,220,150,0.75);font-size:0.88rem;">{desc}</span>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# BLOCKCHAIN VISUALIZATION
# ─────────────────────────────────────────
st.markdown("### ⛓️ Block Chain Explorer")

# Build HTML for the blockchain visualization
blocks_html = '<div style="display:flex;overflow-x:auto;padding:20px 0;gap:0;align-items:center;">'
is_valid, broken_at = verify_chain(chain)

for i, block in enumerate(chain):
    is_latest = (i == len(chain) - 1)
    is_tampered_blk = (i == st.session_state.tampered_idx or (not is_valid and i == broken_at))

    card_class = "block-card latest" if is_latest and not is_tampered_blk else \
                 "block-card tampered" if is_tampered_blk else "block-card"
    header_color = "#00ff88" if is_latest and not is_tampered_blk else \
                   "#ff3838" if is_tampered_blk else "#f7b42f"

    short_hash = block["hash"][:16] + "..."
    short_prev = block["previous_hash"][:16] + "..."

    blocks_html += f"""
    <div class="{card_class}">
        <div class="block-header" style="color:{header_color};">
            {'🔴 BLOCK #' if is_tampered_blk else '🟢 BLOCK #' if is_latest else '📦 BLOCK #'}{block['index']}
        </div>
        <div><span style="color:rgba(247,220,150,0.5)">Round:</span> {block.get('round_num', '?')}</div>
        <div><span style="color:rgba(247,220,150,0.5)">Accuracy:</span> {block.get('accuracy', 0)*100:.2f}%</div>
        <div><span style="color:rgba(247,220,150,0.5)">Clients:</span> {block.get('client_count', '?')}</div>
        <div><span style="color:rgba(247,220,150,0.5)">Nonce:</span> {block.get('nonce', '?')}</div>
        <div style="margin-top:8px;">
            <span style="color:rgba(247,220,150,0.5)">Hash:</span><br>
            <span class="block-hash" style="color:{'#ff6b6b' if is_tampered_blk else '#00ff88'}">{short_hash}</span>
        </div>
        <div style="margin-top:6px;">
            <span style="color:rgba(247,220,150,0.5)">Prev:</span><br>
            <span class="block-prev">{short_prev}</span>
        </div>
        <div style="margin-top:6px;color:rgba(247,220,150,0.5);font-size:0.62rem;">
            {block['timestamp'][:19]}
        </div>
    </div>
    """
    if i < len(chain) - 1:
        arrow_color = "#ff3838" if (not is_valid and i >= broken_at - 1) else "#f7b42f"
        blocks_html += f'<div class="chain-arrow" style="color:{arrow_color};">→</div>'

blocks_html += '</div>'
st.markdown(blocks_html, unsafe_allow_html=True)

# Chain status
if is_valid and st.session_state.tampered_idx == -1:
    st.markdown("""
    <div class="verify-success">
        ✅ CHAIN INTEGRITY VERIFIED — All blocks cryptographically valid
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div class="tamper-alert">
        🚨 CHAIN INTEGRITY VIOLATION DETECTED — Block #{broken_at if not is_valid else st.session_state.tampered_idx} has been tampered!
        <br><span style="font-size:0.8rem;color:#ff9999;font-family:Inter,sans-serif;font-style:italic;">
        The cryptographic hash chain is broken. This FL round cannot be trusted.
        </span>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# METRICS ROW
# ─────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
latest_block = chain[-1]
m1.markdown(f"""<div class="bc-metric"><div class="val">{len(chain)}</div><div class="lbl">Total Blocks</div></div>""", unsafe_allow_html=True)
m2.markdown(f"""<div class="bc-metric"><div class="val" style="color:#00ff88">{'✅' if is_valid else '❌'}</div><div class="lbl">Chain Status</div></div>""", unsafe_allow_html=True)
m3.markdown(f"""<div class="bc-metric"><div class="val">{latest_block.get('accuracy', 0)*100:.1f}%</div><div class="lbl">Latest Accuracy</div></div>""", unsafe_allow_html=True)
m4.markdown(f"""<div class="bc-metric"><div class="val">{latest_block.get('round_num', '?')}</div><div class="lbl">Latest FL Round</div></div>""", unsafe_allow_html=True)

st.markdown("---")

# ─────────────────────────────────────────
# BLOCK ACTIONS
# ─────────────────────────────────────────
st.markdown("### ⚡ Blockchain Actions")
col_a, col_b, col_c = st.columns(3)

with col_a:
    st.markdown("#### ➕ Add New Block")
    new_acc = st.slider("New Round Accuracy", 0.80, 0.99, 0.95, 0.01, key="new_acc")
    new_clients = st.number_input("Client Count", 2, 6, 4, key="new_clients")
    if st.button("⛓️ Verify & Add Block", type="primary", use_container_width=True, key="add_block"):
        with st.spinner("Computing SHA-256 hash..."):
            # Animate hash computation
            placeholder = st.empty()
            chars = "0123456789abcdef"
            for _ in range(12):
                fake_hash = ''.join(np.random.choice(list(chars), 64))
                placeholder.markdown(f'<div class="hash-anim">Computing: {fake_hash}</div>',
                                     unsafe_allow_html=True)
                time.sleep(0.07)

            new_block = {
                "index": len(chain),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "round_num": len(chain),
                "client_count": int(new_clients),
                "accuracy": float(new_acc),
                "nonce": int(np.random.randint(1000, 99999)),
                "previous_hash": chain[-1]["hash"],
            }
            new_block["hash"] = compute_hash(new_block)
            chain.append(new_block)
            st.session_state.blockchain = chain
            save_blockchain(chain)
            st.session_state.tampered_idx = -1
            placeholder.markdown(f'<div class="hash-anim">✅ Hash: {new_block["hash"]}</div>',
                                  unsafe_allow_html=True)

        try:
            log_threat("BLOCK_ADDED", f"Block #{new_block['index']} added, accuracy={new_acc}", "INFO")
        except Exception:
            pass
        st.success(f"✅ Block #{new_block['index']} added to chain!")
        st.rerun()

with col_b:
    st.markdown("#### 🔍 Verify Chain")
    if st.button("✅ Verify Entire Chain", type="secondary", use_container_width=True, key="verify_chain"):
        with st.spinner("Verifying all block hashes..."):
            time.sleep(0.5)
            valid, err_idx = verify_chain(chain)
        if valid:
            st.success(f"✅ All {len(chain)} blocks verified! Chain is intact.")
        else:
            st.error(f"❌ Integrity violation at block #{err_idx}!")

    if st.button("🔄 Reset to Genesis", use_container_width=True, key="reset_chain"):
        st.session_state.blockchain = create_genesis_blocks()
        st.session_state.tampered_idx = -1
        save_blockchain(st.session_state.blockchain)
        st.success("✅ Chain reset to 5 genesis blocks.")
        st.rerun()

with col_c:
    st.markdown("#### 🚨 Tamper Detection Demo")
    tamper_idx = st.selectbox(
        "Select block to tamper",
        options=list(range(len(chain))),
        format_func=lambda x: f"Block #{x} (Round {chain[x].get('round_num', x)})",
        key="tamper_select"
    )
    if st.button("💀 Simulate Tampering", type="secondary", use_container_width=True, key="tamper_btn"):
        with st.spinner("Simulating attacker modifying block data..."):
            time.sleep(0.4)
            # Modify block data (without recomputing hash - breaks the chain)
            chain[tamper_idx]["accuracy"] = 0.99  # Attacker inflates accuracy
            chain[tamper_idx]["client_count"] = 99  # False client count
            st.session_state.blockchain = chain
            st.session_state.tampered_idx = tamper_idx
            # Don't save - keep in memory only

        st.error(f"💀 Block #{tamper_idx} tampered! Hash mismatch detected.")
        st.warning("⚠️ The cryptographic chain is now BROKEN. FL model update is invalid!")
        st.rerun()

st.markdown("---")

# ─────────────────────────────────────────
# BLOCK EXPLORER TABLE
# ─────────────────────────────────────────
st.markdown("### 🔎 Block Explorer")
table_data = []
for block in chain:
    valid_blk = compute_hash({k: v for k, v in block.items() if k != "hash"}) == block["hash"]
    table_data.append({
        "Block #": block["index"],
        "FL Round": block.get("round_num", "?"),
        "Accuracy": f"{block.get('accuracy', 0)*100:.2f}%",
        "Clients": block.get("client_count", "?"),
        "Nonce": block.get("nonce", "?"),
        "Timestamp": block["timestamp"][:19],
        "Hash (first 24)": block["hash"][:24] + "...",
        "Status": "✅ Valid" if valid_blk else "❌ TAMPERED",
    })

import pandas as pd
df = pd.DataFrame(table_data)
st.dataframe(
    df,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Status": st.column_config.TextColumn("Status", width="small"),
        "Hash (first 24)": st.column_config.TextColumn("Hash", width="medium"),
    }
)

# ─────────────────────────────────────────
# HASH VISUALIZATION
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 🔐 Hash Visualization")
selected_block_idx = st.selectbox(
    "Select a block to inspect",
    options=list(range(len(chain))),
    format_func=lambda x: f"Block #{x}",
    key="hash_inspect"
)
selected_block = chain[selected_block_idx]
col1, col2 = st.columns(2)
with col1:
    st.markdown("**Block Data (Input to SHA-256)**")
    block_display = {k: v for k, v in selected_block.items() if k != "hash"}
    st.json(block_display)
with col2:
    st.markdown("**SHA-256 Hash Output**")
    real_hash = compute_hash(block_display)
    stored_hash = selected_block["hash"]
    match = real_hash == stored_hash
    st.markdown(f"""
    <div class="hash-anim" style="{'border-color:#ff3838;color:#ff6b6b' if not match else ''}">
        Computed: {real_hash}<br><br>
        Stored:   {stored_hash}<br><br>
        {'✅ MATCH — Block is valid' if match else '❌ MISMATCH — Block has been tampered!'}
    </div>
    """, unsafe_allow_html=True)

# ─────────────────────────────────────────
# ACCURACY CHART OVER CHAIN
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("### 📊 Model Accuracy Across Blockchain")
bc_indices = [b["index"] for b in chain]
bc_accs = [b.get("accuracy", 0) * 100 for b in chain]
fig_bc = go.Figure(go.Scatter(
    x=bc_indices, y=bc_accs, mode='lines+markers',
    line=dict(color='#f7b42f', width=3),
    marker=dict(size=12, color='#ffd700', line=dict(color='#f7b42f', width=2)),
    fill='tozeroy', fillcolor='rgba(247,180,47,0.07)',
    name="Global Accuracy"
))
fig_bc.update_layout(
    title="Federated Learning Global Accuracy — Blockchain Record",
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(8,12,20,0.6)',
    font=dict(color='white'), height=320,
    xaxis=dict(title="Block Index", gridcolor='rgba(255,255,255,0.05)', dtick=1),
    yaxis=dict(title="Accuracy (%)", range=[70, 100], gridcolor='rgba(255,255,255,0.05)', ticksuffix="%"),
    margin=dict(l=10, r=10, t=50, b=20)
)
st.plotly_chart(fig_bc, use_container_width=True)
