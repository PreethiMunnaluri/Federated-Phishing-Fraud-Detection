# 🛡️ CyberShield AI

> **A local cybersecurity threat intelligence platform for phishing, SMS scams, malicious URLs, financial fraud, and secure federated learning.**

## Overview

CyberShield AI is a Python-based Streamlit application that simulates an advanced Security Operations Center (SOC). It combines:

- AI-driven threat detection for emails, URLs, SMS, and financial transactions
- Federated learning simulation with privacy-preserving aggregation
- Differential privacy noise visualization
- Explainable AI (XAI) analysis for model decisions
- Blockchain-style tamper-evident threat audit trails
- Adversarial node detection and risk analytics
- Report export to PDF and CSV

This repository is ideal for academic demonstrations, end-semester engineering projects, cybersecurity portfolios, and prototype evaluation.

## Key Features

- **SOC Dashboard**: Central command hub for visualizing threat metrics and alerts
- **Phishing Email Detection**: TF-IDF + Random Forest-based email scam classifier
- **Malicious URL Detection**: URL feature analysis and phishing risk scoring
- **SMS/Smishing Classifier**: Multilingual SMS scam detection
- **Fraud Transaction Analyzer**: Anomaly detection for financial suspicious activity
- **Federated Learning Simulation**: FedAvg across multiple isolated client nodes
- **Differential Privacy Module**: Laplace/Gaussian noise and privacy budget tradeoffs
- **Explainable AI**: SHAP-style explanations for model outputs
- **Blockchain Audit Simulator**: Tamper-evident threat logging with SHA-256 blocks
- **Adversarial Detection**: Rogue federated node filtering and poisoning defense
- **Report Export**: Generate compliance-ready PDF and CSV threat reports
- **Offline AI Assistant**: Chatbot-style security guidance without internet access

## Repository Structure

```
edai_endsem/
├── app.py                          # Main Streamlit launch point and login portal
├── requirements.txt                # Python dependencies
├── README.md                       # Project documentation
├── assets/
│   └── style.css                   # Custom app styling
├── datasets/
│   ├── generate_datasets.py        # Synthetic dataset generation script
│   └── *.csv                       # Example dataset files
├── generate_threats.py             # Initial threat log seeder
├── models/
│   └── train_models.py             # Model training and serialization
├── saved_models/                   # Pickled ML models and vectorizers
├── logs/                           # Threat and blockchain log files
├── pages/                          # Streamlit feature pages
└── utils/                          # Helper modules for auth, ML, privacy, reporting
```

## Installation

### 1. Clone the repository

```bash
cd c:\Users\preet\Desktop\VIT\TY_SEM6\edai_endsem
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate data and train models

```bash
python datasets/generate_datasets.py
python models/train_models.py
python generate_threats.py
```

### 5. Start the app

```bash
streamlit run app.py
```

Open the browser at the URL shown by Streamlit, typically `http://localhost:8501`.

## Default Access

- Username: `admin`
- Password: `admin123`

Use the Admin Panel to create additional user accounts and assign roles.

## Pages and Functionality

| Page | Purpose |
| --- | --- |
| `1_Dashboard.py` | Central SOC dashboard and status overview |
| `2_Phishing_Email.py` | Email phishing detection |
| `3_URL_Detection.py` | Malicious URL scanner |
| `4_SMS_Detection.py` | SMS and smishing detection |
| `5_Fraud_Transaction.py` | Financial fraud transaction analysis |
| `6_Federated_Learning.py` | Federated learning simulation |
| `7_Differential_Privacy.py` | Differential privacy visualization |
| `8_Explainable_AI.py` | Explainable AI and feature importance |
| `9_Threat_Analytics.py` | Threat analytics and telemetry charts |
| `10_Admin_Panel.py` | Administrative controls and management |
| `11_AI_Assistant.py` | Offline cybersecurity assistant chatbot |
| `12_Blockchain_Sim.py` | Blockchain-style audit trail simulator |
| `13_Adversarial_Detection.py` | Rogue node detection and poisoning defense |
| `14_Browser_Extension.py` | Browser security sandbox simulation |
| `15_Report_Export.py` | PDF/CSV compliance report generation |

## Core Utility Modules

- `utils/auth.py`: authentication and user registration
- `utils/ml_models.py`: model loading and prediction helpers
- `utils/feature_extraction.py`: feature generation for URLs and transactions
- `utils/federated.py`: federated aggregation and node simulation
- `utils/differential_privacy.py`: noise mechanisms and privacy budget logic
- `utils/explainability.py`: model explanation utilities
- `utils/threat_logger.py`: threat log storage and analytics
- `utils/report_generator.py`: report export generation
- `utils/ui_helpers.py`: layout and UI helper functions

## Usage Notes

- This project is a local prototype for demonstration and learning.
- Data is synthetic and intended for educational testing.
- For reliable demonstrations, regenerate datasets and retrain models after code changes.
- The Admin Panel controls user roles, log cleanup, and model management.

## Suggested Demo Flow

1. Log in as admin.
2. Show the SOC Dashboard metrics.
3. Run an email or URL scan and highlight the threat result.
4. Open Explainable AI to show why a decision was made.
5. Demonstrate Federated Learning and Differential Privacy.
6. Show Blockchain Simulator tamper detection.
7. Export a PDF report from the Report Export page.

## Dependencies

Required packages are listed in `requirements.txt`

## License

Use this project freely for academic, portfolio, and research purposes. Please credit the original author in any public demonstrations.
