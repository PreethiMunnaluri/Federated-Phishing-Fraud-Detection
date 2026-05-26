CyberShield AI: Functional Specifications & Feature Guide
This guide describes each of the 14 integrated pages and modules of the CyberShield AI platform. It explains what each feature does in simple terms, provides realistic example inputs, and outlines the expected outputs.

📬 1. Phishing Email Detector (2_Phishing_Email.py)
🔹 What It Does
This scanner analyzes the text of incoming email messages to decide if they are safe or if they are phishing attempts designed to steal credentials, money, or sensitive accounts. It uses a trained Random Forest Machine Learning Classifier paired with TF-IDF keyword vectorization.

Example Input (i/p):
text

Subject: URGENT: Action Required on Your Bank Account!
We detected suspicious login activity on your net banking. Please click here immediately to verify your account credentials: http://secure-verify-account.xyz/login. Failure to do so within 24 hours will result in permanent suspension.
Expected Output (o/p):
Verdict: 🚨 PHISHING (High/Critical Threat Level)
Confidence: 98.4%
Risk Score: 98/100
Flagged Indicators: "URGENT", "verify account credentials", "permanent suspension"
XAI Highlight: Highlighted key phrases contributing to the prediction, like "verify" and "suspicious login".
🔗 2. Malicious URL Detector (3_URL_Detection.py)
🔹 What It Does
This scanner inspects website URLs in real time to check for phishing domains, fake links, unencrypted protocols, and typosquatting scams. It features both a single URL quick-scan tool and a batch scan tool that processes list files.

Example Input (i/p):
text

http://192.168.1.1/secure-login/paypal.com/signin.php?token=xyz987
Expected Output (o/p):
Verdict: 🚨 MALICIOUS (Critical Threat Level)
Confidence: 91.0%
Risk Score: 91/100
URL Component Breakdown:
Protocol: http (Warning: Unencrypted)
Domain: 192.168.1.1 (Warning: Raw IP domain)
Path: /secure-login/paypal.com/signin.php (Warning: Impersonates a safe brand)
Radar Chart: Visual representation showing spikes in "IP Address Usage", "No HTTPS", and "Known Phishing Keywords".
💬 3. SMS Scam Classifier (4_SMS_Detection.py)
🔹 What It Does
It analyzes mobile text messages to identify spam, OTP scams, fake delivery notifications, lottery frauds, and UPI bank authorization scams. It operates in multiple languages (English, Hindi, Marathi) using a Logistic Regression Classifier.

Example Input (i/p):
text

CONGRATULATIONS! You have won a cash prize of Rs. 5,00,000 from KBC Lottery! Click here to claim your reward via UPI now: http://kbc-claims.tk/otp
Expected Output (o/p):
Verdict: 🚨 SPAM / FRAUD (High Threat Level)
Confidence: 97.2%
Risk Score: 97/100
Risk Indicators: "CONGRATULATIONS", "won a cash prize", "claim your reward"
Action Advice: Warns the operator never to click the link or share credit card/UPI PINs.
💳 4. Fraud Transaction Scanner (5_Fraud_Transaction.py)
🔹 What It Does
Monitors credit/debit card and online banking transactions to identify potential credit card theft or unauthorized transactions. It runs a combined Isolation Forest (Anomaly Detection) and Random Forest (Classifier) model.

Example Input (i/p):
Amount: ₹1,25,000
Location: Foreign-IP (VPN-Detected)
Time of Day: 3:45 AM
Device Type: Emulator (Unknown-Device)
Transaction Frequency: 18 transactions in the last hour
Expected Output (o/p):
Verdict: 🚨 FRAUD (Critical Threat Level)
Confidence: 99.1%
Risk Score: 99/100
Risk Factors:
Unusually high transaction amount (₹1.25L vs average of ₹3K)
Suspicious transaction timing (late night 03:45)
Velocity limit exceeded (18 actions/hour)
Device fingerprint anomaly (emulator)
🤝 5. Federated Learning Simulation (6_Federated_Learning.py)
🔹 What It Does
Simulates a collaborative AI network where multiple corporate nodes (e.g., Bank A, Telecom B, E-Commerce C) train a threat detection model together without sharing their private database files with each other. It shows how the server aggregates local updates using the FedAvg algorithm.

Example Input (i/p):
Operator sets the active round count to 5 rounds.
Operator selects clients: Client A (Bank) and Client B (Telecom).
Differential Privacy noise level: epsilon = 1.5
Expected Output (o/p):
Aggregation Flow: Standard outputs showcasing each client training locally, sending model weights to the central server, and the server averaging weights into a global model.
Convergence Curve: A real-time line chart showing global accuracy climbing from 72.4% (Round 1) to 94.8% (Round 5).
🛡️ 6. Differential Privacy Calibration (7_Differential_Privacy.py)
🔹 What It Does
Demonstrates mathematical privacy protection. It adds calibrated Gaussian or Laplace noise to model parameters during training. This prevents hackers from reconstructing private database rows from the public model, showcasing the trade-off between privacy and accuracy.

Example Input (i/p):
Operator sets Privacy Budget: Epsilon = 0.5 (Strong Privacy / High Noise)
Sensitivity Level: 1.0
Expected Output (o/p):
Privacy Trade-off Chart: Interactive visual showing that while Epsilon 0.5 keeps user data perfectly safe, accuracy slightly dips to 84%, whereas Epsilon 5.0 raises accuracy to 96% but risks data leakage.
Noise Distribution: A bell curve visualization showing the exact mathematical noise vectors added.
🔬 7. Explainable AI Console (8_Explainable_AI.py)
🔹 What It Does
Removes the "black box" nature of AI. It shows exactly why a machine learning model made a certain decision. It computes SHAP-style attribution values showing how each input feature pushed the score higher (dangerous) or lower (safe).

Example Input (i/p):
Load transaction details: Amount = ₹85,000, Time = 2:00 AM, Location = Safe Home IP.
Expected Output (o/p):
SHAP Waterfall/Force Chart: A visual chart showing:
High Amount: +42% contribution to fraud score (pushed toward fraud)
Time (Late Night): +18% contribution to fraud score (pushed toward fraud)
Location (Safe Home IP): -30% contribution to fraud score (pushed toward safe)
Global Feature Importances: Bar chart indicating "Amount" and "Location" are the overall strongest signals.
📊 8. SOC Threat Analytics Dashboard (9_Threat_Analytics.py)
🔹 What It Does
Acts as a central Security Operations Center (SOC) room. It aggregates threat telemetry logs and displays real-time visual feeds, geographical heatmaps, and trend projections.

Example Input (i/p):
Telemetry logs containing 250 recently detected attacks (phishing, transactions, SMS scams).
Expected Output (o/p):
Geo-Distribution Map: Map of India highlighting active threat epicenters (e.g. Bangalore, Mumbai).
Trend Charts: Trend lines showing the rise or fall of attack types over time.
Day-of-Week × Hour Heatmap: A color-coded grid revealing peak attack times (e.g., Friday night).
Confusion Matrices: Detailed accuracy tables for each of the active classifiers.
⛓️ 9. Blockchain Audit Simulator (12_Blockchain_Sim.py)
🔹 What It Does
Ensures audit logs are tamper-proof. Every time a threat is detected, the incident details are compiled into a block with a unique cryptographic hash and linked to the previous block. If anyone tries to modify log history, the hashes break, revealing the fraud.

Example Input (i/p):
Threat incident details: ID = 105, Type = Phishing Email, Operator = admin.
User clicks "Forge Block #3" to try to change the sender detail.
Expected Output (o/p):
Block Ledger View: Shows active blocks in a green glow, displaying Prev Hash: 0000a89d... and Current Hash: 0000cf42....
Glow Warning: Instantly changes the affected block to flashing Crimson Red, indicating: "CHAIN INVALID: Hash mismatch detected at Block #3. Security Alert!"
🕵️ 10. Byzantine Adversarial Detector (13_Adversarial_Detection.py)
🔹 What It Does
Defends the collaborative federated network against rogue/hacked nodes. If a client attempts to upload poisoned weights (designed to degrade model performance or create backdoors), this module compares their update signature against standard client norms and flags them.

Example Input (i/p):
4 active nodes. One node (Client C) submits corrupted or poisoned update matrices containing extreme gradient scale offsets.
Expected Output (o/p):
Suspicion Index:
Client A: 4% (Normal)
Client C (Rogue): 98% (Poisoned gradients detected!)
Network Action: Automatically isolates/quarantines Client C, dropping its aggregation weights to 0 to keep the global model unpolluted.
👑 11. Secure Admin Panel (10_Admin_Panel.py)
🔹 What It Does
An administrative control room that restricts access using role-based access control (RBAC). It displays current operators and provides controls to manage logs, wipe datasets, and adjust global hyperparameters.

Example Input (i/p):
Administrative user requests to purge logs older than 30 days.
Expected Output (o/p):
User Grid: Lists all registered operators and their roles (admin, analyst).
Database Status: Confirms threat logs are truncated and older records removed successfully, printing a success confirmation banner.
🤖 12. Offline AI Security Assistant Chatbot (11_AI_Assistant.py)
🔹 What It Does
An offline chatbot loaded with advanced cybersecurity rules and Q&A capabilities. It answers questions about phishing, federated learning, and security guidelines without requiring internet access.

Example Input (i/p):
User asks: "What is federated learning?"
Expected Output (o/p):
Bot Bubble: Renders a clear response explaining that federated learning is a decentralized machine learning technique where nodes train models locally on their own devices and share weights instead of raw datasets.
🌐 13. Chrome Web Protection Sandbox (14_Browser_Extension.py)
🔹 What It Does
Simulates a browser security extension. The user can type any URL into a mock browser bar. If the URL is malicious, the sandbox intercepts the request, blocks the page, and displays a secure threat warning.

Example Input (i/p):
User types http://login-verify-chase.xyz/update into the address bar and hits enter.
Expected Output (o/p):
Web Frame Warning: The browser viewport goes dark and displays a bright crimson warning banner: "WARNING: Access Blocked by CyberShield AI Sandbox! Typosquatting / Credential Harvester detected."
📄 14. Secure Compliance Document Generator (15_Report_Export.py)
🔹 What It Does
Allows compliance analysts to filter detected threats and export them to PDF reports or CSV audit sheets.

Example Input (i/p):
Filter criteria: Severity = HIGH/CRITICAL, Channel = phishing_email, Limit = 50 rows.
Expected Output (o/p):
Document Preview: Renders a live table showing matching incidents.
Action Button Output: Generates downloadable PDF reports with formatted cover pages, metrics summaries, tables, and timestamps. Also creates matching CSV downloads.