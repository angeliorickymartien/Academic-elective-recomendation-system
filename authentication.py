"""
authentication.py - Registration, login, logout, sessions, access control.

Key security ideas used here:
  * Passwords are HASHED (salted scrypt via Werkzeug), never stored as text.
  * Login errors are generic, so attackers can't learn which usernames exist.
  * Failed logins are recorded; repeated failures lock the IP out temporarily.
  * session.clear() before login prevents "session fixation".
  * The session stores ONLY the user id; the role is always re-read from the
    database, so a demoted admin loses access immediately.
"""
import logging
from functools import wraps

from flask import abort, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config
import models
import security

log = logging.getLogger("secureshop.security")

# A fake hash used when the username doesn't exist. We still run the (slow)
# hash check so response time does not reveal whether the user exists.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------------------------------------------------------------
# PASSWORD HASHING
# ---------------------------------------------------------------
def hash_password(password):
    """Salted one-way hash. Hashing the same password twice gives DIFFERENT
    results because a random salt is added each time."""
    return generate_password_hash(password)


def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)


# ---------------------------------------------------------------
# REGISTRATION
# ---------------------------------------------------------------
def register_user(username, email, password, confirm_password, ip):
    """Returns (success, message, user_id)."""
    username = security.clean_text(username, 30).lower()   # lowercase avoids 'Alice' vs 'alice'
    email = security.clean_text(email, 120).lower()
    password = password or ""

    for ok, msg in (security.validate_username(username),
                    security.validate_email(email),
                    security.validate_password(password)):
        if not ok:
            return False, msg, None

    if password != (confirm_password or ""):
        return False, "Passwords do not match.", None

    user_id = models.create_user(username, email, hash_password(password))
    if user_id is None:
        return False, "That username or email is already registered.", None

    models.log_activity(user_id, ip, "REGISTER", f"New account created: {username}")
    log.info("REGISTER user=%r ip=%s", username, ip)
    return True, "Registration successful. Please log in.", user_id


# ---------------------------------------------------------------
# LOGIN / LOGOUT
# ---------------------------------------------------------------
def login_user(username, password, ip, admin_only=False):
    """Returns (success, message). On success the session is created."""
    username = security.clean_text(username, 30).lower()
    password = (password or "")[:128]

    # 1. Lockout: too many recent failures from this IP
    failures = models.count_recent_failed_logins(ip, config.FAILED_LOGIN_WINDOW_MIN)
    if failures >= config.MAX_FAILED_LOGINS:
        log.warning("LOGIN_BLOCKED ip=%s user=%r failures=%d", ip, username, failures)
        models.log_activity(None, ip, "LOGIN_BLOCKED", f"Blocked login attempt for {username}")
        return False, "Too many failed login attempts. Please wait a few minutes and try again."

    # 2. Verify credentials (always run a hash check, even for unknown users)
    user = models.get_user_by_username(username)
    stored_hash = user["password_hash"] if user else _DUMMY_HASH
    password_ok = verify_password(stored_hash, password)
    allowed = (user is not None and password_ok
               and (not admin_only or user["role"] == "admin"))

    # 3. Failure: record it and return a GENERIC message
    if not allowed:
        models.record_login_attempt(username, ip, False)
        models.log_activity(None, ip, "LOGIN_FAILED", f"Failed login for {username}")
        log.warning("LOGIN_FAILED ip=%s user=%r", ip, username)
        return False, "Invalid username or password."

    # 4. Success: start a brand-new session
    session.clear()                      # prevents session fixation
    session["user_id"] = user["id"]
    session.permanent = True             # applies the 30-minute lifetime from config
    models.record_login_attempt(username, ip, True)
    models.log_activity(user["id"], ip, "LOGIN_SUCCESS", f"{username} logged in")
    log.info("LOGIN_SUCCESS ip=%s user=%r", ip, username)
    return True, f"Welcome back, {user['username']}!"


def logout_user(ip):
    user_id = session.get("user_id")
    if user_id is not None:
        models.log_activity(user_id, ip, "LOGOUT", "User logged out")
        log.info("LOGOUT user_id=%s ip=%s", user_id, ip)
    session.clear()


# ---------------------------------------------------------------
# CURRENT USER + TEMPLATE VARIABLES
# ---------------------------------------------------------------
def init_auth(app):
    """Call after init_security(app). Loads the logged-in user for every request."""

    @app.before_request
    def _load_current_user():
        g.user = None
        if request.endpoint == "static":
            return
        user_id = session.get("user_id")
        if user_id is not None:
            g.user = models.get_user_by_id(user_id)
            if g.user is None:           # account was deleted: end the session
                session.clear()

    @app.context_processor
    def _inject_template_variables():
        user = getattr(g, "user", None)
        return {
            "current_user": user,
            "cart_count": models.get_cart_count(user["id"]) if user else 0,
            "currency": config.CURRENCY_SYMBOL,
        }


# ---------------------------------------------------------------
# ACCESS-CONTROL DECORATORS (put them UNDER @app.route)
# ---------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if getattr(g, "user", None) is None:
            flash("Please log in to continue.", "warning")
            next_url = request.path if request.method == "GET" else None
            return redirect(url_for("login", next=next_url))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "user", None)
        ip = security.get_client_ip()

        if user is None or user["role"] != "admin":
            # Record every attempt: the detection engine watches this counter
            attempts = security.admin_attempt_counter.add(ip)
            who = user["username"] if user else "anonymous"
            log.warning("ADMIN_ACCESS_DENIED user=%r ip=%s path=%s attempts=%d",
                        who, ip, request.path, attempts)
            models.log_activity(user["id"] if user else None, ip,
                                "ADMIN_ACCESS_DENIED", request.path)
            if user is None:
                flash("Administrator login required.", "warning")
                return redirect(url_for("admin_login"))
            abort(403)
        return view(*args, **kwargs)
    return wrapped
