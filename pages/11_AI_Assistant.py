"""
AI Assistant Page - CyberShield AI.
Local cybersecurity operations expert Q&A chatbot using fuzzy-matching rule base.
"""

import streamlit as st
import sys
import os
import time
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

st.set_page_config(
    page_title="AI Expert Assistant - CyberShield AI",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils.auth import require_login
from utils.ui_helpers import apply_custom_css, render_section_header

# Apply styles and login check
apply_custom_css()
require_login()

# Pre-defined Cybersecurity Q&A knowledge base (30 detailed Q&As)
KNOWLEDGE_BASE = [
    {
        "keywords": ["federated learning", "what is fl", "explain fl", "federated learning framework"],
        "question": "What is Federated Learning (FL)?",
        "answer": "Federated Learning is a decentralized machine learning paradigm where models are trained locally on client devices or nodes (like separate banks or phones). Instead of sharing private raw log files to a central server, only the model's updated weight matrices are shared and aggregated. This preserves privacy and complies with data sovereignty regulations."
    },
    {
        "keywords": ["fedavg", "federated averaging", "aggregation algorithm", "fl aggregation"],
        "question": "How does the Federated Averaging (FedAvg) algorithm work?",
        "answer": "FedAvg is the standard aggregation algorithm in Federated Learning. The central server initializes the global model weights. In each round, clients download this model, perform local SGD (Stochastic Gradient Descent) on their private datasets, and send the updated weights back. The server averages these weights weighted by the number of local samples: $w_{t+1} = \\sum \\frac{n_k}{n} w_{t+1}^k$."
    },
    {
        "keywords": ["differential privacy", "what is dp", "explain differential privacy", "dp"],
        "question": "What is Differential Privacy (DP)?",
        "answer": "Differential Privacy is a mathematical framework that guarantees that the output of an algorithm doesn't reveal whether a single individual's record was present in the dataset. It works by adding calibrated noise (usually Laplace or Gaussian) to queries or model weight aggregates, ensuring privacy leakage is mathematically bounded."
    },
    {
        "keywords": ["epsilon", "privacy budget", "what is epsilon"],
        "question": "What is the Privacy Budget (Epsilon / ε)?",
        "answer": "In Differential Privacy, Epsilon ($\epsilon$) represents the strength of the privacy guarantee. A lower $\epsilon$ value adds more noise, providing stronger privacy guarantees but decreasing model utility/accuracy. A higher $\epsilon$ adds less noise, yielding better utility but higher potential information leakage risk."
    },
    {
        "keywords": ["laplace", "gaussian", "laplace vs gaussian", "noise types"],
        "question": "What is the difference between Laplace and Gaussian noise in DP?",
        "answer": "Laplace noise is used in pure Differential Privacy ($\epsilon$-DP) and is calibrated using the L1 sensitivity of the function. Gaussian noise is used in approximate/relaxed Differential Privacy ($\epsilon$, $\delta$)-DP, calibrated via L2 sensitivity. Gaussian noise is often preferred for high-dimensional gradient additions in deep learning models."
    },
    {
        "keywords": ["moments accountant", "privacy accountant", "tracking privacy loss"],
        "question": "What is the Moments Accountant in Differential Privacy?",
        "answer": "The Moments Accountant is an advanced method used to track the cumulative privacy loss ($\epsilon$, $\delta$) across multiple rounds of iterative algorithm execution (like federated epochs). It yields much tighter bounds than standard composition theorems, allowing for higher utility models without exceeding the target privacy budget."
    },
    {
        "keywords": ["gradient clipping", "clip weights", "why clip", "clipping"],
        "question": "Why do we use weight clipping in Differential Privacy?",
        "answer": "We clip weights (or gradients) to bound the maximum influence a single data record can have on the update. Calibrated DP noise addition relies directly on the 'sensitivity' of the updates. By clipping updates to a maximum L2/L1 threshold, we enforce a strict sensitivity limit, preventing extreme values from overriding the noise scale."
    },
    {
        "keywords": ["explainable ai", "xai", "what is xai", "model explanation"],
        "question": "What is Explainable AI (XAI)?",
        "answer": "Explainable AI consists of tools and frameworks designed to make machine learning predictions transparent and interpretable to humans. In cybersecurity, XAI helps security analysts understand why a specific email, URL, or transaction was flagged as high-risk, boosting trust and simplifying operational audits."
    },
    {
        "keywords": ["shap", "shapley values", "shap explainer"],
        "question": "What are SHAP (Shapley Additive exPlanations) values?",
        "answer": "SHAP is a game-theory-based framework explaining model outputs by assigning a contribution value to each feature. In our platform, SHAP explains individual alert events (e.g., showing that an email was labeled phishing primarily due to the phrases 'urgent alert' (+0.35) and 'verify account' (+0.28))."
    },
    {
        "keywords": ["feature importance", "important features", "random forest importance"],
        "question": "How are global feature importances calculated?",
        "answer": "Global feature importances estimate the overall impact of features across the entire dataset. In our Random Forest model, this is determined by calculating the mean decrease in impurity (MDI) or Gini importance, indicating which features (like URL length or keyword frequency) split the nodes most cleanly during training."
    },
    {
        "keywords": ["blockchain", "blockchain security", "distributed ledger"],
        "question": "How does Blockchain enhance cybersecurity in this framework?",
        "answer": "Blockchain creates a tamper-evident audit ledger for security threat alerts. By hashing threat event parameters and embedding them into chronologically chained SHA-256 blocks, it ensures that logs inside the system cannot be retroactively edited, deleted, or falsified by attackers trying to cover their tracks."
    },
    {
        "keywords": ["tampering", "tamper detection", "tamper blockchain"],
        "question": "How does the blockchain ledger detect tampering?",
        "answer": "Each block contains the hash of the previous block ($PrevHash$) and its own metadata hash. If any parameter inside block $N$ is altered, its block hash changes. Since block $N+1$ holds the original $PrevHash$, the cryptographic validation check instantly fails, breaking the chain validation logic."
    },
    {
        "keywords": ["adversarial ml", "poisoning attack", "poisoned weights"],
        "question": "What is an adversarial poisoning attack in FL?",
        "answer": "An adversarial poisoning attack involves compromised clients participating in Federated Learning. These clients attempt to corrupt the global model by uploading malicious weight sets (containing Trojan backdoors or false labels) designed to lower global accuracy or create bypass vulnerabilities."
    },
    {
        "keywords": ["byzantine", "byzantine detection", "malicious clients"],
        "question": "What is Byzantine Threat Detection in Federated Learning?",
        "answer": "Byzantine detection identifies rogue, poisoned, or malfunctioning nodes in a federated circle. The central server calculates the variance, cosine similarities, or Z-scores of incoming client weight vectors. Outlying updates with highly aberrant patterns are flagged and isolated before they can corrupt the global model aggregation."
    },
    {
        "keywords": ["phishing email", "detect phishing", "phishing characteristics"],
        "question": "What are the common indicators of a phishing email?",
        "answer": "Indicators include: 1) Urgent or threatening language ('Immediate suspension!', 'Verify now'). 2) Request for credentials, OTPs, or financial transactions. 3) Spoofed headers or mismatching domain names. 4) Hyperlinks routing to unrecognized, IP-based, or newly registered domains."
    },
    {
        "keywords": ["malicious url", "url phishing", "suspicious url"],
        "question": "What features make a URL suspicious?",
        "answer": "Suspicious URL indicators: 1) Typosquatting (e.g., `g00gle.com` or `secure-paypal.com`). 2) High number of subdomains or dots. 3) Absence of standard HTTPS encryption. 4) Embedding IP addresses directly. 5) Use of unusual TLDs (e.g., `.cc`, `.xyz`, `.top`)."
    },
    {
        "keywords": ["smishing", "sms spam", "sms fraud"],
        "question": "What is Smishing (SMS phishing)?",
        "answer": "Smishing is phishing carried out via SMS text messages. Attackers send fraudulent alerts simulating banks or courier companies claiming you won a lottery, your account is blocked, or a UPI transfer failed. The texts typically contain urgent links, malicious numbers, or demands for immediate callbacks."
    },
    {
        "keywords": ["transaction fraud", "fraud indicators", "financial anomaly"],
        "question": "What are key indicators of a fraudulent transaction?",
        "answer": "Key indicators: 1) Highly unusual transfer amounts relative to past user averages. 2) Transactions originating from multiple locations within short timeframes (impossible travel). 3) Transfer hour (e.g., large transactions at 3:00 AM). 4) Unrecognized device configurations or extreme transaction frequencies."
    },
    {
        "keywords": ["isolation forest", "anomaly detection algorithm"],
        "question": "How does the Isolation Forest algorithm work?",
        "answer": "Isolation Forest is an unsupervised learning algorithm that detects anomalies by isolating points in a multi-dimensional feature space. It recursively partitions features with random splits. Because anomalies have unique patterns, they require fewer splits to isolate, resulting in much shorter path lengths in the trees."
    },
    {
        "keywords": ["random forest", "rf classifier"],
        "question": "Why did we select Random Forest for Phishing detection?",
        "answer": "Random Forest is an ensemble classifier that operates by constructing multiple decision trees during training. It is highly robust against overfitting, handles both categorical and numerical features efficiently, produces clean probabilities, and yields stable Gini feature importances for explaining predictions."
    },
    {
        "keywords": ["tf-idf", "vectorizer", "term frequency"],
        "question": "What is TF-IDF vectorization?",
        "answer": "TF-IDF (Term Frequency-Inverse Document Frequency) is a numerical statistic indicating how important a word is to a document in a corpus. It increases proportionally with the word's frequency in the document, but is scaled down by its frequency in the overall corpus, helping NLP models filter out common stopwords (like 'the', 'is') and focus on phishing indicators."
    },
    {
        "keywords": ["threat severity", "low medium high", "critical"],
        "question": "How are threat severity rankings defined?",
        "answer": "1) LOW: Minor risk, standard safe messages. 2) MEDIUM: Suspicious flags but lacking conclusive features. 3) HIGH: Highly likely threat with active indicators. 4) CRITICAL: Conclusive anomaly or blacklisted phishing threat (alerting immediate SOC response)."
    },
    {
        "keywords": ["secure phone", "smishing prevention"],
        "question": "How can I secure my smartphone against smishing attacks?",
        "answer": "1) Never tap on links received in SMS text messages from unknown or short-code contacts. 2) Enable built-in caller ID and spam protection apps. 3) Never share OTPs or secure credentials over text or calls. 4) Cross-check bank alerts inside your official mobile banking application."
    },
    {
        "keywords": ["typosquatting", "domain spoofing"],
        "question": "What is typosquatting?",
        "answer": "Typosquatting (URL hijacking) is a social engineering attack where malicious actors register domains closely mimicking famous brands (e.g., `amzon.com` or `paypa1.com`). Attackers count on users making typos when typing addresses, hoping to direct them to fake credential-harvesting clones."
    },
    {
        "keywords": ["browser extension", "web extension"],
        "question": "How does an AI browser protection extension function?",
        "answer": "An AI browser extension intercepts outgoing HTTP connections. When you load a site, it extracts URL metadata, checks blocklists, and runs local AI classifiers. If a suspicious pattern is flagged, it blocks the page and displays an alert warning, isolating the user from potential threat exposure."
    },
    {
        "keywords": ["soc console", "security operations center"],
        "question": "What is the purpose of a Security Operations Center (SOC)?",
        "answer": "A SOC is a centralized unit responsible for monitoring, detecting, analyzing, and responding to cybersecurity incidents. In our platform, the SOC console consolidates threat analytics, active scanners, blockchain logs, and model performance metrics into a single real-time operations room."
    },
    {
        "keywords": ["rbac", "access control"],
        "question": "What is Role-Based Access Control (RBAC)?",
        "answer": "RBAC is a security model restricting system access based on an individual's operational role. In CyberShield AI, standard 'user' operators can perform scans and view explanations, while 'admin' operators possess clearances to add nodes, clear logs, and modify neural weights."
    },
    {
        "keywords": ["bcrypt", "password security"],
        "question": "Why is bcrypt used for password hashing?",
        "answer": "bcrypt uses an adaptive salt and a key derivation hashing function based on the Blowfish cipher. It is designed to be slow and computationally heavy, protecting credentials against brute-force attacks and GPU-accelerated rainbow table hacks."
    },
    {
        "keywords": ["local ai", "privacy tradeoff"],
        "question": "What is the security benefit of local offline AI processing?",
        "answer": "Local processing eliminates the requirement of sending sensitive personal data (emails, SMS transcripts, ledger files) to external third-party cloud APIs. This keeps all personal records entirely inside your perimeter, reducing data breach exposure risks and ensuring GDPR compliance."
    },
    {
        "keywords": ["cybershield", "cybershield platform"],
        "question": "What is CyberShield AI?",
        "answer": "CyberShield AI is an advanced federated security framework protecting decentralized systems from phishing and fraud. By combining local scikit-learn models, differential privacy noise injection, blockchain audit chains, and SHAP explainability, it represents a premium threat-mitigation platform."
    }
]

# Quick presets list for click-to-ask
QUICK_PRESETS = [
    "What is Federated Learning (FL)?",
    "What is Differential Privacy (DP)?",
    "What are SHAP values?",
    "What is Byzantine Threat Detection in Federated Learning?",
    "What is Smishing (SMS phishing)?",
    "What are key indicators of a fraudulent transaction?"
]

# Title layout
st.markdown('<h1 style="margin:0;font-size:2rem;">🤖 Operational AI Assistant</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#8a9bb5; margin-top:2px; font-size:0.9rem;">CyberShield Cybersecurity Operations Expert Chatbot Panel</p>', unsafe_allow_html=True)
st.markdown("---")

# Session state initialization
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = [
        {
            "role": "assistant",
            "content": "Awaiting operations input. I am pre-loaded with local knowledge regarding Federated Learning, Differential Privacy, SHAP Explanations, Blockchain Ledgers, and Anomaly Models. How can I support your threat response coordinates today, Operator?"
        }
    ]

# Search matching logic
def get_bot_response(user_text: str) -> str:
    user_text_lower = user_text.lower().strip()
    
    # Simple keyword match
    best_match = None
    max_matches = 0
    
    for qa in KNOWLEDGE_BASE:
        matches = sum(1 for kw in qa["keywords"] if kw in user_text_lower)
        if matches > max_matches:
            max_matches = matches
            best_match = qa
            
    if best_match and max_matches > 0:
        return best_match["answer"]
    
    # Fallback to AI-like security advice
    return (
        "Command syntax unrecognized in local offline database. \n\n"
        "💡 **Operation Advice**: If inquiring about Federated Learning, Differential Privacy, "
        "or explainability, please try standard phrases such as: *'Explain FL'*, *'What is Differential Privacy'*, "
        "or *'Explain SHAP values'*. \n\n"
        "For manual threat resolution, ensure standard firewalls and multi-factor credentials are active."
    )

# Page Layout columns
col_chat, col_presets = st.columns([5, 2])

with col_presets:
    st.markdown('<div class="cyber-card" style="padding:15px; border-radius:8px; border: 1px solid rgba(0,255,136,0.15);">', unsafe_allow_html=True)
    st.subheader("💡 Suggested Operator Inquiries")
    st.markdown("Click one of the standard templates below to load it into the operations chatbot input console:")
    
    preset_clicked = None
    for idx, preset in enumerate(QUICK_PRESETS):
        if st.button(preset, key=f"preset_{idx}", use_container_width=True):
            preset_clicked = preset
            
    st.markdown("<hr style='margin:15px 0;'>", unsafe_allow_html=True)
    st.info("🤖 **Offline Mode Active**: This chatbot runs completely locally inside the sandboxed database, guarding credentials and scanning logs from leaks.")
    st.markdown('</div>', unsafe_allow_html=True)

with col_chat:
    # Outer container for scrollable chat window
    chat_container = st.container()
    
    # User Input box at bottom
    with st.form("chat_input_form", clear_on_submit=True):
        col_in, col_btn = st.columns([6, 1])
        with col_in:
            user_input = st.text_input(
                "Enter Inquiry Coordinate", 
                value=preset_clicked if preset_clicked else "",
                placeholder="Ask about Federated Learning, DP, Blockchain, or Threat scanners...",
                label_visibility="collapsed"
            )
        with col_btn:
            submit_btn = st.form_submit_button("SEND", use_container_width=True)
            
    if submit_btn and user_input:
        # Append User message
        st.session_state["chat_history"].append({"role": "user", "content": user_input})
        # Generate Bot response
        bot_reply = get_bot_response(user_input)
        # Append Bot message
        st.session_state["chat_history"].append({"role": "assistant", "content": bot_reply})
        st.rerun()

    # Render Chat Bubble Layout inside the container
    with chat_container:
        st.markdown('<div class="chat-viewport" style="max-height: 550px; overflow-y: auto; padding-right:10px;">', unsafe_allow_html=True)
        
        for msg in st.session_state["chat_history"]:
            if msg["role"] == "user":
                st.markdown(
                    f"""
                    <div style="display: flex; justify-content: flex-end; margin-bottom: 12px;">
                        <div style="background: rgba(0, 212, 255, 0.15); border: 1px solid rgba(0, 212, 255, 0.3); border-radius: 12px 12px 0 12px; padding: 10px 16px; max-width: 75%; color: #e2e8f0; font-family: sans-serif;">
                            <b style="color:#00d4ff; font-family:monospace; font-size:0.75rem; display:block; margin-bottom:4px;">👤 OPERATOR</b>
                            {msg['content']}
                        </div>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""
                    <div style="display: flex; justify-content: flex-start; margin-bottom: 12px;">
                        <div style="background: rgba(0, 255, 136, 0.08); border: 1px solid rgba(0, 255, 136, 0.25); border-radius: 12px 12px 12px 0; padding: 10px 16px; max-width: 75%; color: #e2e8f0; font-family: sans-serif;">
                            <b style="color:#00ff88; font-family:monospace; font-size:0.75rem; display:block; margin-bottom:4px;">🤖 CYBERSHIELD AI</b>
                            {msg['content']}
                        </div>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )
        
        st.markdown('</div>', unsafe_allow_html=True)

# Clean chat history trigger
st.markdown("<br>", unsafe_allow_html=True)
if st.button("🗑️ PURGE CHAT HISTORY MEMORY", use_container_width=True):
    st.session_state["chat_history"] = [
        {
            "role": "assistant",
            "content": "Session memory cleared. Systems ready for new threat queries."
        }
    ]
    st.rerun()

st.markdown("<br><hr>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="text-align: center; color: #4a5568; font-size: 0.8rem; font-family: monospace;">
        OFFLINE SYSTEM INTERACTION PANEL // EXPERT AI INTEGRATION v1.0.0
    </div>
    """,
    unsafe_allow_html=True
)
