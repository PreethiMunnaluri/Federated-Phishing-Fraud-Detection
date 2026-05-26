"""
Authentication system for CyberShield AI.
Uses JSON file storage + bcrypt password hashing.
"""

import os
import json
import streamlit as st
import bcrypt
from datetime import datetime

USERS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "users.json")

DEFAULT_ADMIN = {
    "username": "admin",
    "password_hash": "",  # Will be set in initialize_users()
    "email": "admin@cybershield.ai",
    "role": "admin",
    "created_at": "2025-01-01T00:00:00",
}


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def initialize_users():
    """Create users.json with default admin if it doesn't exist."""
    if not os.path.exists(USERS_FILE):
        admin = DEFAULT_ADMIN.copy()
        admin["password_hash"] = hash_password("admin123")
        with open(USERS_FILE, "w") as f:
            json.dump([admin], f, indent=2)
    else:
        # Ensure admin always exists
        users = _load_users_raw()
        if not any(u["username"] == "admin" for u in users):
            admin = DEFAULT_ADMIN.copy()
            admin["password_hash"] = hash_password("admin123")
            users.append(admin)
            _save_users_raw(users)


def _load_users_raw() -> list:
    """Load raw user list from JSON."""
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_users_raw(users: list):
    """Save raw user list to JSON."""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def login(username: str, password: str) -> bool:
    """
    Attempt login. If successful, sets st.session_state['user'].
    Returns True on success.
    """
    initialize_users()
    users = _load_users_raw()
    for user in users:
        if user["username"].lower() == username.lower():
            if verify_password(password, user.get("password_hash", "")):
                st.session_state["user"] = {
                    "username": user["username"],
                    "role": user.get("role", "user"),
                    "email": user.get("email", ""),
                    "logged_in": True,
                    "login_time": datetime.now().isoformat(),
                }
                return True
    return False


def signup(username: str, password: str, email: str, role: str = "user") -> tuple:
    """
    Register a new user.
    Returns (True, 'Success') or (False, 'Error message').
    """
    initialize_users()

    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if "@" not in email or "." not in email:
        return False, "Please enter a valid email address."

    users = _load_users_raw()
    if any(u["username"].lower() == username.lower() for u in users):
        return False, f"Username '{username}' is already taken."
    if any(u.get("email", "").lower() == email.lower() for u in users):
        return False, "An account with this email already exists."

    new_user = {
        "username": username,
        "password_hash": hash_password(password),
        "email": email,
        "role": role,
        "created_at": datetime.now().isoformat(),
    }
    users.append(new_user)
    _save_users_raw(users)
    return True, "Account created successfully! You can now log in."


def logout():
    """Clear session state and log out the user."""
    for key in ["user", "logged_in"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()


def require_login():
    """
    If user is not logged in, show the login/signup form and stop execution.
    Call at the top of protected pages.
    """
    initialize_users()
    if "user" not in st.session_state or not st.session_state.get("user", {}).get("logged_in"):
        _render_login_page()
        st.stop()


def _render_login_page():
    """Render the login/signup page (called internally by require_login)."""
    # This is a minimal fallback; app.py has the full styled version
    st.title("🛡️ CyberShield AI — Please Log In")
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    with tab1:
        with st.form("login_form"):
            uname = st.text_input("Username")
            pwd = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                if login(uname, pwd):
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
    with tab2:
        with st.form("signup_form"):
            new_uname = st.text_input("Username")
            new_email = st.text_input("Email")
            new_pwd = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Create Account")
            if submitted:
                ok, msg = signup(new_uname, new_pwd, new_email)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)


def get_current_user() -> dict:
    """Return the current logged-in user dict, or empty dict if not logged in."""
    return st.session_state.get("user", {})


def is_admin() -> bool:
    """Return True if the current user has the admin role."""
    return get_current_user().get("role") == "admin"


def get_all_users() -> list:
    """Return all users (password hashes excluded)."""
    initialize_users()
    users = _load_users_raw()
    return [{k: v for k, v in u.items() if k != "password_hash"} for u in users]
