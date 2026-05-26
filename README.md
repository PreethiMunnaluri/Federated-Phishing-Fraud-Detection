# 🛡️ CyberShield AI: Federated Secure Threat & Fraud Detection Platform

> **A Decentralized, Explainable AI-Based Framework for Collaborative Phishing, Smishing, Malicious URL, and Financial Fraud Detection.**

---

## 🌌 Project Overview
**CyberShield AI** is an advanced, high-fidelity local prototype simulating an enterprise-grade AI threat intelligence platform. Built entirely with **Python**, **Streamlit**, and **scikit-learn**, it demonstrates the practical application of cutting-edge AI and cryptographic technologies in modern cybersecurity.

This system is designed specifically for **academic showcases, final-year engineering projects, hackathons, and professional portfolio demonstrations**, showcasing the intersection of decentralized learning, math-based privacy bounds, threat explanation, and secure auditable ledgers.

---

## 🛠️ Cutting-Edge Features & Modules

| Sub-System | Core Technology | Operational Concept |
| :--- | :--- | :--- |
| **SOC Operations Center** | Streamlit + Plotly | Aggregated security metrics, real-time threat alert tick ticker, hourly alert volume trendlines, and vector distributions. |
| **Decentralized Training** | In-Memory FedAvg | Simulated model compilation across four isolated nodes (Bank, Telecom, E-commerce, Healthcare) without central raw database exposure. |
| **Differential Privacy (DP)** | Laplace & Gaussian Noise | Noise calibration matching strict $\epsilon$ bounds, illustrating the exact mathematical privacy-utility tradeoff curves. |
| **Explainable AI (XAI)** | SHAP & RF Importance | Global feature importances and individual event attribution explanations, demonstrating why alerts are triggered. |
| **Cryptographic Ledger** | SHA-256 Blockchain | Auto-mines secure telemetry blocks for threat records, ensuring tamper-evident, auditable event timelines. |
| **Adversarial Mitigation** | Byzantine Node Filtering | Z-score anomaly vectors and cosine variance analysis isolating compromised client nodes uploading poisoned model weights. |
| **Local AI Scanner suite** | Random Forest / TF-IDF | Multi-language NLP scanners detecting Phishing emails, URL segments, SMS spam, and financial transaction anomalies. |
| **Interactive Sandbox** | Mock Web Interceptor | Real-time web browser simulation with a slide-out protection extension scanning pages and blocking malicious domains. |
| **Compliance Export** | ReportLab PDF / Pandas | Programmatic compile-to-PDF threat report builder with tabular statistics and Pandas audit-to-CSV download modules. |
| **Expert Expert Assistant** | Fuzzy Matching Chatbot | Sandbox cyber operational advisor chatbot loaded with a robust 30 Q&A expert database. |

---

## 🗂️ Platform Blueprint (File Structure)

```
edai_endsem/
├── app.py                          # Main system entry point, Custom CSS & login portal
├── requirements.txt                # System dependency limits
├── README.md                       # Operations documentation manual
│
├── assets/
│   └── style.css                   # Custom CSS variables, cyber neon cards, animations
│
├── datasets/
│   ├── generate_datasets.py        # Synthetic dataset builder (multilingual)
│   └── *.csv                       # Generated operational data files (emails, URLs, SMS, trans)
│
├── models/
│   └── train_models.py             # Core script compiling and pickling all 4 ML models
│
├── saved_models/
│   ├── email_model.pkl             # Random Forest Email Classifier
│   ├── email_vectorizer.pkl        # TF-IDF text parser
│   ├── url_model.pkl               # RF URL Feature Classifier
│   ├── sms_model.pkl               # Logistic Regression SMS model
│   ├── sms_vectorizer.pkl          # TF-IDF SMS parser
│   └── fraud_model.pkl             # Isolation Forest Anomaly model
│
├── logs/
│   ├── threats.json                # Live operational threat database log
│   └── blockchain.json             # Cryptographically verified ledger blocks
│
├── utils/
│   ├── auth.py                     # Operator database controller (users.json + bcrypt)
│   ├── ui_helpers.py               # Custom UI card renderers, risk badges, alerts
│   ├── ml_models.py                # Unified model cache interfaces + rules fallbacks
│   ├── feature_extraction.py       # Conversions for URL features & trans vectors
│   ├── federated.py                # In-memory FedAvg aggregator & client metrics
│   ├── differential_privacy.py     # Noise calibration algorithms & Moments Accountant
│   ├── explainability.py           # SHAP interpretations & Gini export arrays
│   ├── threat_logger.py            # Log writers & database aggregators
│   └── report_generator.py         # Programmatic ReportLab PDF and Pandas CSV exports
│
└── pages/                          # Multi-page panel dashboard routers
    ├── 1_Dashboard.py              # Central SOC Command Room
    ├── 2_Phishing_Email.py         # Email threat scanner
    ├── 3_URL_Detection.py          # Domain structure scanner
    ├── 4_SMS_Detection.py          # Mobile smishing chatbot simulator
    ├── 5_Fraud_Transaction.py      # Bank anomaly slider analyzer
    ├── 6_Federated_Learning.py     # FedAvg convergence chart visualizer
    ├── 7_Differential_Privacy.py   # Mathematical privacy budget analyzer
    ├── 8_Explainable_AI.py         # SHAP waterfall charts
    ├── 9_Threat_Analytics.py       # Time trends & geospatial breakdown
    ├── 10_Admin_Panel.py           # Admin console: keys, logs maintenance, seed data
    ├── 11_AI_Assistant.py          # Interactive cybersecurity chatbot
    ├── 12_Blockchain_Sim.py        # Ledger block chain tampering viewer
    ├── 13_Adversarial_Detection.py # Byzantine poisoned weights detector
    ├── 14_Browser_Extension.py     # Sandbox browser protection simulation
    └── 15_Report_Export.py         # Compliance reports manager
```

---

## ⚡ Step-by-Step Installation & Setup

Follow these simple coordinates to boot the CyberShield AI framework completely offline on your local machine:

### 1. Extract and Navigate
Download the files and open your terminal (Command Prompt/PowerShell on Windows, or bash/zsh on Unix/Linux):
```bash
cd c:\Users\preet\Desktop\VIT\TY_SEM6\edai_endsem
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / MacOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Required Dependencies
All dependencies are standard, locally compiled, and require **zero** cloud registrations:
```bash
pip install -r requirements.txt
```

### 4. Warm-Up & Data Seeding
Before launching the UI, execute the sandbox training suite scripts in order to seed datasets, train your local machine learning models, and populate threat databases.
*(Alternatively, you can trigger these actions directly from the Admin Panel settings once logged in).*

```bash
# A. Generate the multilingual training datasets
python datasets/generate_datasets.py

# B. Train and save (pickle) all four ML models
python models/train_models.py

# C. Seed the historical threat logging database (threats.json)
python generate_threats.py
```

### 5. Launch the Platform!
Start the Streamlit portal:
```bash
streamlit run app.py
```

Streamlit will automatically open the platform portal inside your default web browser at:
`http://localhost:8501`

---

## 🛡️ Administrative Security & Authentication

By default, CyberShield AI operates under a **Role-Based Access Control (RBAC)** security design:
* **Default Admin Credentials**:
  * **Username**: `admin`
  * **Password**: `admin123`
  * **Assigned Role**: `admin` (Clears logs, manages user registrations, adjusts RF sensitivities)
* **Standard Operators**:
  * You can create a custom user account directly on the entry login portal or add them from the Admin Panel. Regular operator accounts have access to all scanners and advanced simulations, but are strictly gated from the system purges and node settings.

---

## 🔒 Privacy & Decentralization Mathematical Assertions

This framework models state-of-the-art protections:
1. **Federated Learning consensus**:
   $$\text{Weights Average: } W_{global} = \sum_{k=1}^K \frac{n_k}{N} W_{local}^{(k)}$$
2. **Laplace Noise DP protection**:
   $$\text{Mechanism: } \mathcal{M}(x) = f(x) + \text{Lap}\left(0, \frac{\Delta f}{\epsilon}\right)$$
   Ensuring mathematical protection limits where lower $\epsilon$ budgets guarantee absolute privacy bounds.

---

## 🎓 Showcase Strategy & Presentation Guide

When showcasing CyberShield AI to evaluators or interviewers, follow this proven demo structure:
1. **Authentication Portal**: Show the premium glassmorphism login. Explain that passwords are encrypted locally using `bcrypt` and stored securely in `users.json`.
2. **SOC Command Dashboard**: Direct their attention to the active scrolling news ticker displaying real-time threat telemetry. Explain the hourly incident trend graphs and vector donuts.
3. **Run a Phishing Scan**: Paste a suspicious email or URL (e.g. from the preset library) and trigger the scanner. Show the **Explainable AI (XAI)** tab displaying a visual SHAP breakdown detailing exactly which features triggered the high-risk alert.
4. **Decentralized Collaborative Learning**: Navigate to the Federated Learning screen. Adjust the epsilon and sensitivity parameters and show how noise affects global model accuracy. Explain that **Differential Privacy** adds calculated Laplace noise to weight packets so that private raw documents are mathematically impossible to reverse-engineer.
5. **Blockchain Audit Trail**: Navigate to the Blockchain Simulator. TAMPER with one of the historical alerts in the input box, show how the SHA-256 block hashes immediately turn RED, failing validation audits due to broken links.
6. **Byzantine Adversarial Defense**: Show the Adversarial Defense page, showing how outlying client coordinates are filtered out dynamically via Z-scores to secure the global model from poisoned updates.
7. **Compliance Reporting**: Filter alerts down to high-priority items and export a **programmatic PDF threat report** to show presentation-ready compliance exports.

---

```
SYSTEM READY // ALL NODES SECURED // LOCAL SHIELD OPERATIONAL
```
