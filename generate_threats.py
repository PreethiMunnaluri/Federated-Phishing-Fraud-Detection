"""
Script to generate the initial threats.json with 50 pre-populated entries.
"""
import json
import uuid
import random
import os
from datetime import datetime, timedelta

random.seed(42)

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

NOW = datetime.utcnow()

THREAT_TYPES = [
    "phishing_email",
    "malicious_url",
    "sms_spam",
    "fraud_transaction",
]

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHTS = [0.2, 0.35, 0.3, 0.15]

USERS = ["admin", "analyst1", "analyst2", "system", "scanner_bot", "preet"]

PHISHING_DETAILS = [
    {"snippet": "URGENT: Your SBI account suspended. Verify at http://sbi-secure.tk", "risk_score": 91, "model": "email_rf"},
    {"snippet": "Congratulations! You won ₹50000. Claim: http://prize-winner.ml", "risk_score": 95, "model": "email_rf"},
    {"snippet": "HDFC Bank: Unauthorized login. Reset now: http://hdfc-reset.cf", "risk_score": 88, "model": "email_rf"},
    {"snippet": "Your OTP 847291. Share to verify your Axis account.", "risk_score": 82, "model": "email_rf"},
    {"snippet": "Income Tax refund ₹12400 pending. Click: http://incometax.ml/refund", "risk_score": 90, "model": "email_rf"},
    {"snippet": "PayPal alert: suspicious activity. Confirm: http://paypal-verify.info", "risk_score": 87, "model": "email_rf"},
    {"snippet": "Amazon order cancelled. Claim refund: http://amzn-refund.tk/12345", "risk_score": 79, "model": "email_rf"},
    {"snippet": "तुरंत! आपका ICICI खाता बंद होगा। http://icici-kyc.gq/verify", "risk_score": 93, "model": "email_rf"},
    {"snippet": "Netflix billing failed. Update: http://netflix-pay.cf/update", "risk_score": 85, "model": "email_rf"},
    {"snippet": "Microsoft security alert. Virus detected. Call 1-800-555-0199.", "risk_score": 78, "model": "email_rf"},
]

URL_DETAILS = [
    {"url": "http://192.168.1.100/login/verify?id=847291", "risk_score": 96, "suspicious_parts": ["IP address", "suspicious keyword: verify"]},
    {"url": "http://secure-bank-login.tk/account/update", "risk_score": 94, "suspicious_parts": ["Suspicious TLD: .tk", "keywords: secure, bank, login"]},
    {"url": "http://paypal-verify.login.xyz/confirm", "risk_score": 91, "suspicious_parts": ["Suspicious TLD: .xyz", "keywords: verify, login"]},
    {"url": "http://login.hdfc.bank-update.cf/kyc", "risk_score": 89, "suspicious_parts": ["Suspicious TLD: .cf", "excessive subdomains"]},
    {"url": "http://prize-winner-847291.ml/claim?ref=user", "risk_score": 97, "suspicious_parts": ["Suspicious TLD: .ml", "keywords: prize, winner"]},
    {"url": "http://10.0.2.15/phishing/credential/harvest", "risk_score": 98, "suspicious_parts": ["IP address", "keywords: phishing, credential"]},
    {"url": "http://amznrefund.secure-payment.gq/claim", "risk_score": 88, "suspicious_parts": ["Suspicious TLD: .gq", "keywords: secure, payment"]},
    {"url": "http://bit.ly/3xK9mLp", "risk_score": 62, "suspicious_parts": ["URL shortener: bit.ly"]},
    {"url": "http://update-epfo-kyc.cf/pf/claim?uan=1234567", "risk_score": 92, "suspicious_parts": ["Suspicious TLD: .cf", "keywords: update, kyc"]},
    {"url": "http://aXb7Kp9mNqR.top/a1b2/c3d4/e5f6", "risk_score": 86, "suspicious_parts": ["Suspicious TLD: .top", "random characters in domain"]},
]

SMS_DETAILS = [
    {"snippet": "FREE! You won ₹25000! Claim: Call +91-9876543210 or SMS WIN to 56789.", "risk_score": 94},
    {"snippet": "URGENT: Your a/c will be blocked. Send OTP 982341 to verify.", "risk_score": 91},
    {"snippet": "Your UPI won ₹10000. Verify: http://upi-winner.tk", "risk_score": 96},
    {"snippet": "Police case registered. Pay ₹5000 fine immediately.", "risk_score": 89},
    {"snippet": "तुरंत! आपका UPI खाता बंद होगा। OTP 762819 दें।", "risk_score": 93},
    {"snippet": "Aadhaar linked crime. Call CBI officer +91-9123456789", "risk_score": 97},
    {"snippet": "Loan offer ₹50000 instant. No documents. Click: http://loan.cf", "risk_score": 88},
    {"snippet": "मोफत! ₹15000 जिंकले! +91-8765432109 ला call करा.", "risk_score": 92},
    {"snippet": "SIM upgrade required. Update now: http://sim-update.tk/387261", "risk_score": 85},
    {"snippet": "Lottery winner! ₹100000 prize. Pay ₹500 processing fee.", "risk_score": 95},
]

FRAUD_DETAILS = [
    {"amount": 487500.00, "location": "Tor-Exit", "hour": 2, "device": "Emulator", "freq": 23, "risk_score": 98},
    {"amount": 125000.00, "location": "Foreign-IP", "hour": 3, "device": "Unknown-Device", "freq": 17, "risk_score": 95},
    {"amount": 78900.00, "location": "VPN-Detected", "hour": 1, "device": "Emulator", "freq": 15, "risk_score": 92},
    {"amount": 250000.00, "location": "Proxy-Server", "hour": 23, "device": "Unknown-Device", "freq": 28, "risk_score": 97},
    {"amount": 35600.00, "location": "Unknown", "hour": 0, "device": "Emulator", "freq": 12, "risk_score": 87},
    {"amount": 92100.00, "location": "Foreign-IP", "hour": 2, "device": "Unknown-Device", "freq": 19, "risk_score": 93},
    {"amount": 175000.00, "location": "Tor-Exit", "hour": 22, "device": "Emulator", "freq": 31, "risk_score": 99},
    {"amount": 67800.00, "location": "VPN-Detected", "hour": 1, "device": "Unknown-Device", "freq": 16, "risk_score": 90},
    {"amount": 425000.00, "location": "Foreign-IP", "hour": 3, "device": "Emulator", "freq": 22, "risk_score": 96},
    {"amount": 53200.00, "location": "Proxy-Server", "hour": 0, "device": "Unknown-Device", "freq": 13, "risk_score": 88},
]

all_details = {
    "phishing_email":    PHISHING_DETAILS,
    "malicious_url":     URL_DETAILS,
    "sms_spam":          SMS_DETAILS,
    "fraud_transaction": FRAUD_DETAILS,
}

threats = []

# Spread 50 entries over last 7 days
for i in range(50):
    hours_ago = random.uniform(0, 168)  # 0-168 hours = 7 days
    ts = NOW - timedelta(hours=hours_ago)

    threat_type = THREAT_TYPES[i % len(THREAT_TYPES)]
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]

    details_pool = all_details[threat_type]
    details = details_pool[i % len(details_pool)].copy()

    threats.append({
        "id":          str(uuid.uuid4())[:8],
        "timestamp":   ts.strftime("%Y-%m-%dT%H:%M:%S") + "Z",
        "threat_type": threat_type,
        "severity":    severity,
        "details":     details,
        "username":    random.choice(USERS),
    })

# Sort by timestamp
threats.sort(key=lambda x: x["timestamp"])

output_path = os.path.join(LOGS_DIR, "threats.json")
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(threats, f, indent=2, ensure_ascii=False)

print(f"Generated {len(threats)} threat entries -> {output_path}")
