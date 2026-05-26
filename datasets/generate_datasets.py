"""
Synthetic dataset generator for CyberShield AI platform.
Run standalone: python datasets/generate_datasets.py
"""

import random
import pandas as pd
import numpy as np
import os
import sys

random.seed(42)
np.random.seed(42)

# Ensure output is in the datasets/ folder relative to this file
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = SCRIPT_DIR


# ──────────────────────────────────────────────────────────────────────────────
# Email templates
# ──────────────────────────────────────────────────────────────────────────────

PHISHING_TEMPLATES = [
    # English phishing
    "URGENT: Your {bank} account has been suspended. Verify immediately at http://secure-{bank}-login.tk/verify?id={id}",
    "Congratulations! You have WON a prize of ₹{amount}! Click here to claim: http://prize-winner-{id}.xyz/claim",
    "Dear Customer, your OTP is {otp}. Share this to verify your account. Do NOT ignore this message.",
    "ACTION REQUIRED: Unauthorized login detected on your {bank} account. Reset password NOW: http://banklogin-reset.cf/{id}",
    "Your {bank} account will be BLOCKED in 24 hours. Update your KYC: http://kyc-update.ml/form?ref={id}",
    "ALERT: Rs.{amount} debit from your account. Not you? Call {phone} or click http://dispute.{bank}-fraud.gq/block",
    "PayPal: We noticed suspicious activity. Confirm your identity: http://paypal-verify.info/secure/{id}",
    "Your Amazon order #{id} has been cancelled. Refund your ₹{amount}: http://amazon-refund.tk/claim?order={id}",
    "FREE RECHARGE! Get ₹{amount} talk time FREE. Limited offer. Claim now: http://free-recharge-{id}.cf",
    "Income Tax Department: You have a refund of ₹{amount}. Claim here: http://incometax-refund.ml/{id}",
    "Hi, I'm a Nigerian prince. I have $5,000,000 stuck. Help me and get 30%. Reply with your bank details.",
    "Your Netflix subscription failed. Update billing to continue: http://netflix-billing.tk/update?id={id}",
    "EPFO: Your PF amount ₹{amount} is ready. KYC needed: http://epfo-kyc.cf/claim?uan={id}",
    "Microsoft Security Alert: Virus detected on your PC. Call +1-800-{phone} immediately to fix.",
    "Lottery Winner! Ticket #{id} selected. Claim $50,000 prize. Fees of $200 required. Contact us.",
    # Hindi phishing
    "तुरंत! आपका {bank} खाता बंद हो जाएगा। अभी सत्यापित करें: http://bank-verify.ml/{id}",
    "बधाई हो! आप ₹{amount} जीत गए! दावा करने के लिए क्लिक करें: http://prize-{id}.tk/claim",
    "आपका OTP {otp} है। इसे किसी के साथ साझा न करें। अभी verify करें।",
    "ALERT: आपके खाते से ₹{amount} की अनधिकृत निकासी हुई। तुरंत संपर्क करें: http://fraud-help.cf",
    "SBI: आपका ATM कार्ड ब्लॉक हो जाएगा। अपडेट करें: http://sbi-update.ml/card?id={id}",
    # Marathi phishing
    "तातडीचे: तुमचे {bank} खाते बंद होईल. आत्ता verify करा: http://bank-verify-marathi.tk/{id}",
    "अभिनंदन! तुम्ही ₹{amount} जिंकले! दावा करा: http://prize-marathi.cf/{id}",
    "तुमचा OTP {otp} आहे. हे कोणाशीही शेअर करू नका. लगेच verify करा.",
    "इशारा: तुमच्या खात्यातून ₹{amount} काढले गेले. तक्रार करा: http://fraud-marathi.ml/{id}",
    "ICICI: तुमचे खाते freeze होईल. KYC अपडेट करा: http://icici-kyc.gq/form?id={id}",
]

SAFE_EMAIL_TEMPLATES = [
    "Hi team, please find the meeting agenda for tomorrow's standup attached. We'll discuss the Q{q} roadmap.",
    "Your order #{id} has been shipped. Expected delivery: {date}. Track at our official website.",
    "Monthly Newsletter: Top stories in tech this week - AI advances, new product launches, industry trends.",
    "Reminder: Your subscription renews on {date}. No action needed if you wish to continue.",
    "Team, the sprint review is scheduled for Friday at 3 PM. Please update your tickets before then.",
    "Welcome to our platform! Your account has been created. Username: {user}. Visit our help center to get started.",
    "Quarterly report Q{q} is now available. Revenue up 12%. Full report in the attached PDF.",
    "Hi {name}, your interview is confirmed for {date} at 10 AM. Please bring your ID and portfolio.",
    "GitHub: New pull request in {repo} - 'Fix login bug' by developer. Please review when you get a chance.",
    "Your invoice #INV-{id} is ready. Amount due: ₹{amount}. Payment due by {date}.",
    "Conference registration confirmed. You're attending TechSummit {year}. Badge pickup at Gate A.",
    "Project update: Milestone 3 completed ahead of schedule. Next milestone due in 2 weeks.",
    "Happy Birthday! As a valued customer, enjoy 10% off your next purchase with code BDAY{id}.",
    "Webinar reminder: 'Machine Learning in Healthcare' starts in 1 hour. Join link in calendar invite.",
    "Your password was changed successfully. If you didn't make this change, contact support immediately.",
    "आपकी मीटिंग कल सुबह 10 बजे है। कृपया समय पर आएं। एजेंडा अटैच है।",
    "टीम को सूचित किया जाता है कि इस शुक्रवार को कोई काम नहीं होगा। छुट्टी का आनंद लें।",
    "आपका ऑर्डर #{id} डिलीवर हो गया है। कृपया रेटिंग दें।",
    "सभी कर्मचारियों को सूचित किया जाता है कि वार्षिक परीक्षा {date} को होगी।",
    "तुमची मीटिंग उद्या आहे. कृपया वेळेवर या. अजेंडा संलग्न आहे.",
]

PHISHING_SUBJECTS = [
    "URGENT: Account Suspended!", "You Won ₹{amount}!", "OTP Verification Required",
    "Security Alert", "Action Required Immediately", "Account Blocked",
    "Claim Your Prize", "Unauthorized Transaction Detected", "Update KYC Now",
    "Password Reset Required", "तुरंत कार्रवाई करें", "खाता बंद होगा",
    "Free Recharge Offer", "Verify Your Identity", "Final Warning",
]

SAFE_SUBJECTS = [
    "Meeting Agenda", "Order Shipped", "Monthly Newsletter", "Subscription Reminder",
    "Sprint Review", "Welcome!", "Quarterly Report", "Interview Confirmed",
    "New Pull Request", "Invoice Ready", "Conference Registration", "Project Update",
    "Birthday Offer", "Webinar Reminder", "Password Changed",
]

BANKS = ["SBI", "HDFC", "ICICI", "Axis", "PNB", "Kotak", "Yes Bank", "Canara"]
NAMES = ["Rahul", "Priya", "Amit", "Sneha", "Rajesh", "Anita", "Vivek", "Pooja"]
REPOS = ["frontend-app", "api-service", "ml-pipeline", "data-warehouse", "auth-service"]


def _ph_vars():
    return {
        "bank": random.choice(BANKS),
        "amount": random.randint(500, 50000),
        "id": random.randint(100000, 999999),
        "otp": random.randint(100000, 999999),
        "phone": f"{random.randint(100,999)}-{random.randint(1000,9999)}",
    }


def _safe_vars():
    return {
        "id": random.randint(1000, 99999),
        "amount": random.randint(500, 50000),
        "date": f"202{random.randint(4,6)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
        "user": random.choice(NAMES).lower() + str(random.randint(10, 99)),
        "name": random.choice(NAMES),
        "q": random.randint(1, 4),
        "repo": random.choice(REPOS),
        "year": random.randint(2024, 2026),
    }


def generate_phishing_emails(n=500):
    rows = []
    for i in range(n):
        tmpl = random.choice(PHISHING_TEMPLATES)
        try:
            text = tmpl.format(**_ph_vars())
        except KeyError:
            text = tmpl
        rows.append({"id": i + 1, "text": text, "label": 1})
    return pd.DataFrame(rows)


def generate_safe_emails(n=500):
    rows = []
    for i in range(n):
        tmpl = random.choice(SAFE_EMAIL_TEMPLATES)
        try:
            text = tmpl.format(**_safe_vars())
        except KeyError:
            text = tmpl
        rows.append({"id": i + 1, "text": text, "label": 0})
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────────────────────────────────────
# URL datasets
# ──────────────────────────────────────────────────────────────────────────────

PHISHING_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm",
                     "bank", "paypal", "password", "credential", "signin", "ebay",
                     "amazon", "alert", "suspend", "urgent", "payment"]
BAD_TLDS = [".tk", ".ml", ".cf", ".gq", ".ga", ".xyz", ".top", ".info", ".biz"]
GOOD_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
    "amazon.com", "netflix.com", "youtube.com", "linkedin.com",
    "microsoft.com", "apple.com", "twitter.com", "reddit.com",
    "bbc.com", "cnn.com", "nytimes.com", "medium.com",
    "python.org", "numpy.org", "pandas.pydata.org", "scikit-learn.org",
    "streamlit.io", "plotly.com", "kaggle.com", "huggingface.co",
    "arxiv.org", "nature.com", "springer.com", "ieee.org",
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
]
GOOD_PATHS = [
    "/docs", "/about", "/contact", "/blog", "/news", "/article/12345",
    "/products", "/services", "/help", "/faq", "/pricing",
    "/search?q=python", "/api/v2/data", "/images/photo.jpg",
    "/en/wiki/Machine_learning", "/repo/project-name",
]


def generate_malicious_urls(n=500):
    rows = []
    for i in range(n):
        strategy = random.choice(["ip", "subdomain", "keyword", "random_chars", "bad_tld"])
        if strategy == "ip":
            ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            path = f"/{random.choice(PHISHING_KEYWORDS)}/{''.join(random.choices('abcdef1234567890', k=8))}"
            url = f"http://{ip}{path}"
        elif strategy == "subdomain":
            kw = random.choice(PHISHING_KEYWORDS)
            sub = ".".join([kw, random.choice(["secure", "verify", "login", "update"]),
                            "".join(random.choices("abcdefghij", k=5))])
            tld = random.choice(BAD_TLDS)
            url = f"http://{sub}{tld}/account/{random.randint(1000,9999)}"
        elif strategy == "keyword":
            kw1 = random.choice(PHISHING_KEYWORDS)
            kw2 = random.choice(PHISHING_KEYWORDS)
            tld = random.choice(BAD_TLDS)
            url = f"http://{kw1}-{kw2}.{random.choice(BANKS).lower()}{tld}/verify?id={random.randint(10000,99999)}"
        elif strategy == "random_chars":
            domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(12, 20)))
            tld = random.choice(BAD_TLDS)
            path = "/".join(["".join(random.choices("abcdef0123456789", k=8)) for _ in range(3)])
            url = f"http://{domain}{tld}/{path}"
        else:  # bad_tld
            kw = random.choice(PHISHING_KEYWORDS)
            tld = random.choice(BAD_TLDS)
            url = f"https://{kw}-portal.{random.choice(['support', 'help', 'service'])}{tld}/login?redirect=home"
        rows.append({"id": i + 1, "url": url, "label": 1})
    return pd.DataFrame(rows)


def generate_safe_urls(n=500):
    rows = []
    for i in range(n):
        domain = random.choice(GOOD_DOMAINS)
        path = random.choice(GOOD_PATHS)
        use_https = random.random() > 0.1
        protocol = "https" if use_https else "http"
        url = f"{protocol}://{domain}{path}"
        rows.append({"id": i + 1, "url": url, "label": 0})
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────────────────────────────────────
# SMS spam datasets
# ──────────────────────────────────────────────────────────────────────────────

SMS_SPAM_TEMPLATES = [
    # English
    "FREE msg: You've won ₹{amount}! Claim within 24hrs. Call {phone} or SMS WIN to 56789.",
    "URGENT: Your bank a/c will be blocked. Send OTP {otp} to our executive immediately.",
    "Congratulations! Your UPI ID won ₹{amount}. Verify at http://upi-winner.tk to receive.",
    "Dear customer, ₹{amount} credited to your account as cashback. Verify: http://cashback.ml/{id}",
    "LOTTERY: You've been selected as a winner! Prize: ₹{amount}. Pay ₹500 processing fee to claim.",
    "Your CIBIL score is low. Get instant loan ₹{amount}. No documents. Click: http://loan-app.cf",
    "SIM card upgrade required. Your {sim} SIM will deactivate. Update: http://sim-update.tk/{id}",
    "Job offer! Earn ₹{amount}/day from home. No experience needed. Register: http://earn-home.ml",
    "Police Case registered against you. Pay ₹{amount} fine immediately to avoid arrest: {phone}",
    "Aadhaar linked with crime. Call CBI officer at {phone} immediately. Ignore at your risk.",
    # Hindi
    "मुफ्त! आपने ₹{amount} जीते! 24 घंटे में दावा करें। कॉल करें {phone}",
    "तुरंत: आपका UPI खाता बंद हो जाएगा। OTP {otp} दें।",
    "बधाई! ₹{amount} आपके खाते में भेजे जाएंगे। अभी verify करें: http://upi.ml",
    "लोन ऑफर: ₹{amount} तुरंत मिलेगा। कोई दस्तावेज़ नहीं। अभी apply करें।",
    "आपका आधार कार्ड crime से लिंक है। तुरंत call करें {phone}",
    # Marathi
    "मोफत! तुम्ही ₹{amount} जिंकले! 24 तासात दावा करा. कॉल करा {phone}",
    "तातडीचे: तुमचे UPI खाते बंद होईल. OTP {otp} द्या.",
    "अभिनंदन! ₹{amount} तुमच्या खात्यात जमा होतील. verify करा: http://upi.ml",
    "लोन ऑफर: ₹{amount} लगेच मिळेल. कोणतेही कागदपत्र नाही. आत्ता apply करा.",
    "तुमचे आधार कार्ड गुन्ह्याशी जोडले आहे. लगेच call करा {phone}",
]

SMS_HAM_TEMPLATES = [
    "Your OTP for login is {otp}. Valid for 10 minutes. Do NOT share with anyone.",
    "Transaction of ₹{amount} done at {merchant}. Available bal: ₹{bal}.",
    "Meeting at 3 PM today. Conference room B. Please bring your laptop.",
    "Your order #{id} has been delivered. Rate your experience on the app.",
    "Reminder: EMI of ₹{amount} due on {date}. Auto-debit will happen.",
    "Your flight AI-{id} departs at 6:30 AM from Terminal 2. Check-in open.",
    "Exam results declared. Log in to portal to check your score.",
    "Happy Birthday {name}! Wishing you a wonderful day.",
    "Library book return due on {date}. Please return to avoid fine.",
    "Doctor appointment confirmed for {date} at 11 AM with Dr. {name}.",
    "आपका OTP {otp} है। 10 मिनट में expire होगा। किसी को न बताएं।",
    "₹{amount} का लेनदेन {merchant} पर हुआ। बैलेंस: ₹{bal}",
    "आज 3 बजे मीटिंग है। कॉन्फ्रेंस रूम B में। लैपटॉप लेकर आएं।",
    "तुमचा OTP {otp} आहे. 10 मिनिटात expire होईल. कोणालाही सांगू नका.",
    "₹{amount} चा व्यवहार {merchant} येथे झाला. शिल्लक: ₹{bal}",
]

MERCHANTS = ["BigBazaar", "DMart", "Reliance", "Amazon", "Flipkart", "Zomato", "Swiggy", "Petrol Pump"]


def _sms_spam_vars():
    return {
        "amount": random.randint(500, 100000),
        "phone": f"+91-{random.randint(7000000000, 9999999999)}",
        "otp": random.randint(100000, 999999),
        "id": random.randint(1000, 99999),
        "sim": random.choice(["Jio", "Airtel", "Vi", "BSNL"]),
    }


def _sms_ham_vars():
    return {
        "otp": random.randint(100000, 999999),
        "amount": random.randint(100, 50000),
        "bal": random.randint(1000, 200000),
        "merchant": random.choice(MERCHANTS),
        "date": f"{random.randint(1,28):02d}-{random.randint(1,12):02d}-2025",
        "id": random.randint(100, 9999),
        "name": random.choice(NAMES),
    }


def generate_sms_spam(n=500):
    rows = []
    for i in range(n):
        tmpl = random.choice(SMS_SPAM_TEMPLATES)
        try:
            text = tmpl.format(**_sms_spam_vars())
        except KeyError:
            text = tmpl
        rows.append({"id": i + 1, "text": text, "label": 1})
    return pd.DataFrame(rows)


def generate_sms_ham(n=500):
    rows = []
    for i in range(n):
        tmpl = random.choice(SMS_HAM_TEMPLATES)
        try:
            text = tmpl.format(**_sms_ham_vars())
        except KeyError:
            text = tmpl
        rows.append({"id": i + 1, "text": text, "label": 0})
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Fraud transactions
# ──────────────────────────────────────────────────────────────────────────────

LOCATIONS = ["Mumbai", "Delhi", "Bangalore", "Chennai", "Hyderabad",
             "Kolkata", "Pune", "Ahmedabad", "Jaipur", "Lucknow",
             "Unknown", "Foreign-IP", "VPN-Detected", "Proxy-Server", "Tor-Exit"]
DEVICES = ["Mobile", "Desktop", "Tablet", "ATM", "POS", "Unknown-Device", "Emulator"]


def generate_fraud_transactions(n=1000):
    rows = []
    for i in range(n):
        is_fraud = 1 if i < n // 4 else 0  # 25% fraud
        if is_fraud:
            amount = random.uniform(10000, 500000)
            hour = random.choice([0, 1, 2, 3, 23, 22])
            location = random.choice(["Unknown", "Foreign-IP", "VPN-Detected", "Proxy-Server", "Tor-Exit"])
            device = random.choice(["Unknown-Device", "Emulator"])
            freq = random.randint(15, 50)
        else:
            amount = random.uniform(50, 9000)
            hour = random.randint(8, 20)
            location = random.choice(["Mumbai", "Delhi", "Bangalore", "Chennai", "Hyderabad",
                                      "Kolkata", "Pune", "Ahmedabad", "Jaipur", "Lucknow"])
            device = random.choice(["Mobile", "Desktop", "Tablet", "ATM", "POS"])
            freq = random.randint(1, 5)
        rows.append({
            "id": i + 1,
            "amount": round(amount, 2),
            "location": location,
            "hour": hour,
            "device_type": device,
            "transaction_freq": freq,
            "is_fraud": is_fraud,
        })
    random.shuffle(rows)
    for idx, row in enumerate(rows):
        row["id"] = idx + 1
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("Generating synthetic datasets...")

    print("  -> phishing_emails.csv")
    df_phish = generate_phishing_emails(500)
    df_phish.to_csv(os.path.join(OUT_DIR, "phishing_emails.csv"), index=False)

    print("  -> safe_emails.csv")
    df_safe = generate_safe_emails(500)
    df_safe.to_csv(os.path.join(OUT_DIR, "safe_emails.csv"), index=False)

    print("  -> emails_combined.csv")
    df_email_combined = pd.concat([df_phish, df_safe], ignore_index=True)
    df_email_combined["id"] = range(1, len(df_email_combined) + 1)
    df_email_combined = df_email_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    df_email_combined.to_csv(os.path.join(OUT_DIR, "emails_combined.csv"), index=False)

    print("  -> malicious_urls.csv")
    df_mal_url = generate_malicious_urls(500)
    df_mal_url.to_csv(os.path.join(OUT_DIR, "malicious_urls.csv"), index=False)

    print("  -> safe_urls.csv")
    df_safe_url = generate_safe_urls(500)
    df_safe_url.to_csv(os.path.join(OUT_DIR, "safe_urls.csv"), index=False)

    print("  -> urls_combined.csv")
    df_url_combined = pd.concat([df_mal_url, df_safe_url], ignore_index=True)
    df_url_combined["id"] = range(1, len(df_url_combined) + 1)
    df_url_combined = df_url_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    df_url_combined.to_csv(os.path.join(OUT_DIR, "urls_combined.csv"), index=False)

    print("  -> sms_spam.csv")
    df_sms_spam = generate_sms_spam(500)
    df_sms_spam.to_csv(os.path.join(OUT_DIR, "sms_spam.csv"), index=False)

    print("  -> sms_ham.csv")
    df_sms_ham = generate_sms_ham(500)
    df_sms_ham.to_csv(os.path.join(OUT_DIR, "sms_ham.csv"), index=False)

    print("  -> sms_combined.csv")
    df_sms_combined = pd.concat([df_sms_spam, df_sms_ham], ignore_index=True)
    df_sms_combined["id"] = range(1, len(df_sms_combined) + 1)
    df_sms_combined = df_sms_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    df_sms_combined.to_csv(os.path.join(OUT_DIR, "sms_combined.csv"), index=False)

    print("  -> fraud_transactions.csv")
    df_fraud = generate_fraud_transactions(1000)
    df_fraud.to_csv(os.path.join(OUT_DIR, "fraud_transactions.csv"), index=False)

    print(f"\nAll datasets saved to: {OUT_DIR}")
    print("Summary:")
    print(f"  phishing_emails.csv : {len(df_phish)} rows")
    print(f"  safe_emails.csv     : {len(df_safe)} rows")
    print(f"  emails_combined.csv : {len(df_email_combined)} rows")
    print(f"  malicious_urls.csv  : {len(df_mal_url)} rows")
    print(f"  safe_urls.csv       : {len(df_safe_url)} rows")
    print(f"  urls_combined.csv   : {len(df_url_combined)} rows")
    print(f"  sms_spam.csv        : {len(df_sms_spam)} rows")
    print(f"  sms_ham.csv         : {len(df_sms_ham)} rows")
    print(f"  sms_combined.csv    : {len(df_sms_combined)} rows")
    print(f"  fraud_transactions  : {len(df_fraud)} rows  (fraud={df_fraud['is_fraud'].sum()})")


if __name__ == "__main__":
    main()
