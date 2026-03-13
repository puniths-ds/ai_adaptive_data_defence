from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import os
import joblib
import json
import pandas as pd
from datetime import datetime, timedelta
import hashlib
import secrets
from werkzeug.security import check_password_hash, generate_password_hash
from honeypot import get_honeypot_data
import re

# -------------------------------------------------
# SQL INJECTION DETECTION
# -------------------------------------------------

SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)",
    r"(--|#|/\*|\*/)",                        # Comment sequences
    r"(\bOR\b.{0,10}\d+\s*=+\s*\d+)",        # OR 1=1, OR 1==1 (with any spacing/==)
    r"(\bAND\b.{0,10}\d+\s*=+\s*\d+)",       # AND 1=1, AND 1==1
    r"('\s*(OR|AND)\s*')",                     # ' OR ' / ' AND '
    r"(\bOR\b.{0,10}('|\").*(=+).*('|\"))",   # OR 'a'='a'
    r"(';|\";\s*--|'--)",                      # Quote + comment
    r"(\bxp_\w+)",
    r"(\bWAITFOR\b|\bSLEEP\b)",
    r"(\bINFORMATION_SCHEMA\b)",
    r"(CHAR\s*\(|ASCII\s*\(|CONCAT\s*\()",
    r"(\b0x[0-9a-fA-F]+\b)",
    r"(\d+\s*=+\s*\d+)",                      # ← catches bare: 1=1, 1==1, 2==2
    r"('.*')",                                 # ← any single-quoted string like 'a'='a'
]

def detect_sql_injection(value: str) -> bool:
    """Returns True if the input matches known SQL injection patterns."""
    if not value:
        return False
    value_upper = value.upper()
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value_upper, re.IGNORECASE):
            return True
    return False

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ------------------------------------------------
# DEMO USER
# ------------------------------------------------

DEMO_USERS = {
    "customer001": {
        "password": "SecurePass123!",
        "name": "Alice Johnson",
        "account_number": "1234-5678",
        "account_type": "Checking",
        "balance": 12450.75
    }
}

# ------------------------------------------------
# REAL TRANSACTIONS
# ------------------------------------------------

REAL_TRANSACTIONS = {
    "customer001": [
        {"date": "2026-02-04", "description": "Salary Deposit",      "amount": 4500,   "type": "Credit", "status": "Completed"},
        {"date": "2026-02-03", "description": "Whole Foods",          "amount": -125.43,"type": "Debit",  "status": "Completed"},
        {"date": "2026-02-02", "description": "Netflix Subscription", "amount": -15.99, "type": "Online", "status": "Completed"}
    ]
}

# ------------------------------------------------
# LOCATION DATA
# India & USA = trusted (grant countries) → penalty 0
# Others get increasing penalties based on threat level
# ------------------------------------------------

COUNTRY_DATA = {
    # ── Trusted (grant countries) ──
    "India":          {"ip": "103.21.58.1",    "flag": "🇮🇳", "region": "South Asia",     "penalty": 0,  "trusted": True},
    "United States":  {"ip": "72.21.215.1",    "flag": "🇺🇸", "region": "North America",  "penalty": 0,  "trusted": True},

    # ── Low risk (+8–12) ──
    "United Kingdom": {"ip": "81.2.69.142",    "flag": "🇬🇧", "region": "Europe",         "penalty": 8,  "trusted": False},
    "Germany":        {"ip": "85.214.132.117", "flag": "🇩🇪", "region": "Europe",         "penalty": 8,  "trusted": False},
    "Canada":         {"ip": "99.234.54.1",    "flag": "🇨🇦", "region": "North America",  "penalty": 8,  "trusted": False},
    "Australia":      {"ip": "203.2.218.1",    "flag": "🇦🇺", "region": "Oceania",        "penalty": 8,  "trusted": False},
    "France":         {"ip": "92.222.14.1",    "flag": "🇫🇷", "region": "Europe",         "penalty": 10, "trusted": False},
    "Japan":          {"ip": "133.242.0.1",    "flag": "🇯🇵", "region": "East Asia",      "penalty": 10, "trusted": False},
    "Singapore":      {"ip": "175.41.128.1",   "flag": "🇸🇬", "region": "South-East Asia","penalty": 10, "trusted": False},
    "UAE":            {"ip": "185.93.1.1",     "flag": "🇦🇪", "region": "Middle East",    "penalty": 12, "trusted": False},

    # ── Medium risk (+15–22) ──
    "Brazil":         {"ip": "186.192.0.1",    "flag": "🇧🇷", "region": "South America",  "penalty": 18, "trusted": False},
    "Mexico":         {"ip": "189.240.0.1",    "flag": "🇲🇽", "region": "North America",  "penalty": 18, "trusted": False},
    "Turkey":         {"ip": "212.252.0.1",    "flag": "🇹🇷", "region": "Europe/Asia",    "penalty": 20, "trusted": False},
    "Indonesia":      {"ip": "114.121.0.1",    "flag": "🇮🇩", "region": "South-East Asia","penalty": 18, "trusted": False},
    "Pakistan":       {"ip": "202.163.0.1",    "flag": "🇵🇰", "region": "South Asia",     "penalty": 22, "trusted": False},
    "Ukraine":        {"ip": "91.232.160.1",   "flag": "🇺🇦", "region": "Eastern Europe", "penalty": 22, "trusted": False},
    "Vietnam":        {"ip": "103.28.248.1",   "flag": "🇻🇳", "region": "South-East Asia","penalty": 20, "trusted": False},

    # ── High risk (+30–60) ──
    "Russia":         {"ip": "95.213.0.1",     "flag": "🇷🇺", "region": "Eastern Europe", "penalty": 35, "trusted": False},
    "China":          {"ip": "111.206.0.1",    "flag": "🇨🇳", "region": "East Asia",      "penalty": 35, "trusted": False},
    "Nigeria":        {"ip": "41.184.0.1",     "flag": "🇳🇬", "region": "West Africa",    "penalty": 40, "trusted": False},
    "Iran":           {"ip": "5.200.0.1",      "flag": "🇮🇷", "region": "Middle East",    "penalty": 45, "trusted": False},
    "North Korea":    {"ip": "175.45.176.1",   "flag": "🇰🇵", "region": "East Asia",      "penalty": 60, "trusted": False},
}

# ------------------------------------------------
# TIME SLOTS
# Business hours = safe, night/odd hours = suspicious
# ------------------------------------------------

TIME_SLOTS = [
    {"label": "09:00 AM – 12:00 PM (Morning Business)",   "hour": 9,  "risk_label": "Normal",      "penalty": 0},
    {"label": "12:00 PM – 03:00 PM (Afternoon Business)", "hour": 12, "risk_label": "Normal",      "penalty": 0},
    {"label": "03:00 PM – 06:00 PM (Late Afternoon)",     "hour": 15, "risk_label": "Normal",      "penalty": 0},
    {"label": "06:00 PM – 09:00 PM (Evening)",            "hour": 18, "risk_label": "Low Risk",    "penalty": 5},
    {"label": "09:00 PM – 12:00 AM (Late Night)",         "hour": 21, "risk_label": "Suspicious",  "penalty": 15},
    {"label": "12:00 AM – 03:00 AM (Midnight)",           "hour": 0,  "risk_label": "High Risk",   "penalty": 25},
    {"label": "03:00 AM – 06:00 AM (Dead of Night)",      "hour": 3,  "risk_label": "High Risk",   "penalty": 30},
    {"label": "06:00 AM – 09:00 AM (Early Morning)",      "hour": 6,  "risk_label": "Low Risk",    "penalty": 5},
]

# ------------------------------------------------
# GLOBAL TRACKERS
# ------------------------------------------------

session_data     = {}
USER_DEVICES     = {}
FAILED_LOGINS    = {}
USER_RISK        = {}
PRE_LOGIN_FAILED = {}

# ------------------------------------------------
# HELPERS
# ------------------------------------------------

def get_device():
    agent = request.headers.get("User-Agent", "")
    return hashlib.md5(agent.encode()).hexdigest()

def get_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0]
    return request.remote_addr

def get_country_info(name):
    return COUNTRY_DATA.get(name, {"ip": "0.0.0.0", "flag": "🌐", "region": "Unknown", "penalty": 30, "trusted": False})

def get_time_penalty(hour):
    """Find the matching time slot for a given hour and return its penalty."""
    matched = TIME_SLOTS[0]
    for slot in TIME_SLOTS:
        if slot["hour"] <= hour:
            matched = slot
    return matched["penalty"], matched["risk_label"]

# ------------------------------------------------
# TRANSACTION GENERATORS
# ------------------------------------------------

def randomized_transactions():
    merchants = ["Amazon", "Uber", "Starbucks", "Walmart", "Netflix"]
    return [{
        "date": datetime.now().strftime("%Y-%m-%d"),
        "description": random.choice(merchants),
        "amount": -random.randint(10, 300),
        "type": "Debit",
        "status": "Completed"
    } for _ in range(5)]

def honeypot_data():
    merchants = ["Amazon", "Target", "Shell", "Uber"]
    tx = [{
        "date": datetime.now().strftime("%Y-%m-%d"),
        "description": random.choice(merchants),
        "amount": -random.randint(5, 120),
        "type": "Debit",
        "status": "Completed"
    } for _ in range(5)]
    return random.randint(200, 400), tx

# ------------------------------------------------
# RISK ENGINE
# ------------------------------------------------

def calculate_risk(previous_risk, activity):
    """
    is_login=True  -> one-time login penalties (location, time, failed logins, new device).
    is_login=False -> ongoing dashboard checks only (device change, IP hop, rapid requests).
    Location and time are NEVER re-added on dashboard loads.
    """
    risk = previous_risk
    is_login = activity.get("is_login", False)

    if is_login:
        # One-time penalties applied only at login
        if activity["new_device"]:
            risk += 6
        fl = activity["failed_logins"]
        if fl > 0:   risk += 3
        if fl > 2:   risk += 5
        if fl > 5:   risk += 10
        if fl > 10:  risk += 15
        if fl > 15:  risk += 25
        # Location — once only
        risk += activity.get("location_penalty", 0)
        # Time — once only
        risk += activity.get("time_penalty", 0)
        # Combined spike: suspicious country + late-night
        if activity.get("location_penalty", 0) > 0 and activity.get("time_penalty", 0) >= 15:
            risk += 10
    else:
        # Dashboard ongoing checks
        if activity["new_device"]:   risk += 6   # device changed mid-session
        if activity["new_location"]: risk += 4   # IP changed mid-session
        # Rapid requests — tiered, triggers at 6+
        rq = activity.get("request_count", 0)
        if rq > 6:   risk += 3
        if rq > 10:  risk += 5
        if rq > 15:  risk += 8
        if rq > 20:  risk += 12
        if rq > 30:  risk += 20

    return min(risk, 100)

# ------------------------------------------------
# SECURITY LOG
# ------------------------------------------------

def security_log(user, risk, activity):
    print("\n🚨========== AI SECURITY MONITOR ==========")
    print(f"USER           : {user}")
    print(f"RISK SCORE     : {risk}")
    print(f"COUNTRY        : {activity.get('country','?')}  TRUSTED: {activity.get('trusted_country',False)}  PENALTY: +{activity.get('location_penalty',0)}")
    print(f"LOGIN HOUR     : {activity.get('login_hour','?')}h  LABEL: {activity.get('time_risk_label','?')}  PENALTY: +{activity.get('time_penalty',0)}")
    status = "✅ SAFE" if risk <= 40 else ("⚠️  SUSPICIOUS" if risk <= 75 else "🚨 HIGH RISK")
    print(f"STATUS         : {status}")
    print("\nFLAGS")
    for k, v in activity.items():
        print(f"  {k}: {v}")
    print("===========================================\n")

# ------------------------------------------------
# ROUTES
# ------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", countries=COUNTRY_DATA, time_slots=TIME_SLOTS)

@app.route('/login', methods=['POST'])
def login():

    customer_id = request.form.get('customer_id', '')
    password = request.form.get('password', '')

    # ── SQL Injection Detection ──────────────────────────
    sql_injection_detected = detect_sql_injection(customer_id) or \
                             detect_sql_injection(password)

    if sql_injection_detected:
        print("\n🚨 SQL INJECTION ATTEMPT DETECTED 🚨")
        print(f"  customer_id field : {customer_id!r}")
        print(f"  password field    : {password!r}")
        print("  HONEYPOT ACTIVATED — feeding attacker fake data\n")

        # Force a fake session so honeypot renders
        session['customer_id'] = 'attacker'
        session['session_id'] = secrets.token_hex(16)
        session['risk_score'] = 75
        session['risk_level'] = 'high'
        session['sql_injection'] = True

        return redirect(url_for('dashboard'))
    # ────────────────────────────────────────────────────

    if customer_id in DEMO_USERS:
        user = DEMO_USERS[customer_id]
        if check_password_hash(user['password_hash'], password):
            session['customer_id'] = customer_id
            session['session_id'] = secrets.token_hex(16)
            features = extract_session_features(customer_id)
            risk_score, risk_level = calculate_risk_score(features)
            session['risk_score'] = risk_score
            session['risk_level'] = risk_level
            return redirect(url_for('dashboard'))

    return render_template('index.html', error="Invalid credentials")

@app.route('/dashboard')
def dashboard():

    if 'customer_id' not in session:
        return redirect(url_for('index'))

    customer_id = session['customer_id']
    risk_level  = session.get('risk_level', 'low')
    risk_score  = session.get('risk_score', 0)

    # SQL injection attackers get honeypot immediately
    if session.get('sql_injection') or risk_level == 'high':
        print("⚠️ HIGH RISK / SQL INJECTION — HONEYPOT ACTIVATED")
        data = get_honeypot_data()
        account_data = data['account']
        transactions = data['transactions']

    else:
        # Normal flow — recalculate risk from behavior
        features = extract_session_features(customer_id)
        risk_score, risk_level = calculate_risk_score(features)
        session['risk_score'] = risk_score
        session['risk_level'] = risk_level

        user = DEMO_USERS[customer_id]
        account_data = {
            'customer_name':    user['name'],
            'account_number':   user['account_number'],
            'account_type':     user['account_type'],
            'balance':          user['balance'],
            'available_balance': user['available_balance']
        }
        transactions = REAL_TRANSACTIONS.get(customer_id, [])

    return render_template(
        'dashboard.html',
        account=account_data,
        transactions=transactions
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    print("\n🔐 SecureBank AI Fraud Detection System Started")
    print("Login: customer001 / SecurePass123!\n")
    print("Risk Rules:")
    print("  India / USA       → Trusted (penalty: 0)")
    print("  UK/Germany/Canada → Low risk (penalty: +8)")
    print("  Russia/Nigeria    → High risk (penalty: +35–60)")
    print("  Business hours    → Safe (penalty: 0)")
    print("  Midnight–3AM      → High risk (penalty: +25–30)")
    print("  Suspicious loc + late night → Extra +10 spike\n")
    app.run(debug=True)
