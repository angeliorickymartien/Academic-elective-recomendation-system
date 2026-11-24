"""
security.py - Security helpers for SecureShop.

Contains:
  1. Logging setup (app.log, security.log, network.log)
  2. Sliding-window counters (rate limiting + attack detection data)
  3. Input validation functions
  4. CSRF protection
  5. Secure HTTP headers
  6. init_security(app) which wires everything into Flask
"""
import hmac
import logging
import logging.handlers
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from flask import Response, abort, request, session

import config


# ===============================================================
# 1. LOGGING
# ===============================================================
_logging_ready = False


def setup_logging():
    """Create three log files in logs/. Safe to call more than once."""
    global _logging_ready
    if _logging_ready:
        return

    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
    log_files = (
        ("secureshop.app", "app.log"),
        ("secureshop.security", "security.log"),
        ("secureshop.network", "network.log"),
    )
    for logger_name, filename in log_files:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(config.LOG_DIR, filename),
            maxBytes=1_000_000, backupCount=3, encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        if logger_name == "secureshop.security":
            console = logging.StreamHandler()     # also print security events in the terminal
            console.setFormatter(formatter)
            logger.addHandler(console)

    _logging_ready = True


security_log = logging.getLogger("secureshop.security")


# ===============================================================
# 2. SLIDING-WINDOW COUNTERS
# Remember WHEN each event happened per key (usually an IP address),
# and count only events inside the last N seconds.
# ===============================================================
class SlidingWindowCounter:
    def __init__(self, window_seconds):
        self.window = window_seconds
        self._events = defaultdict(deque)
        self._lock = threading.Lock()     # Flask and the monitor use threads

    def _prune(self, events, now):
        cutoff = now - self.window
        while events and events[0] < cutoff:
            events.popleft()

    def add(self, key):
        """Record one event for this key; return how many are in the window."""
        now = time.time()
        with self._lock:
            events = self._events[key]
            self._prune(events, now)
            events.append(now)
            return len(events)

    def count(self, key):
        now = time.time()
        with self._lock:
            events = self._events.get(key)
            if not events:
                return 0
            self._prune(events, now)
            return len(events)

    def snapshot(self):
        """Return {key: count} for every key with events in the window."""
        now = time.time()
        result = {}
        with self._lock:
            for key in list(self._events):
                self._prune(self._events[key], now)
                if self._events[key]:
                    result[key] = len(self._events[key])
                else:
                    del self._events[key]
        return result


request_counter = SlidingWindowCounter(60)                               # requests per minute
invalid_counter = SlidingWindowCounter(config.INVALID_WINDOW_MIN * 60)   # 400/404/405 responses
admin_attempt_counter = SlidingWindowCounter(300)                        # access attempts on /admin

INVALID_STATUS_CODES = (400, 404, 405, 413)


def get_client_ip():
    """The IP address of the connected client.
    We use remote_addr only. The X-Forwarded-For header can be faked by
    an attacker, so we do not trust it (we have no reverse proxy)."""
    return request.remote_addr or "unknown"


# ===============================================================
# 3. INPUT VALIDATION
# Each validator returns (is_valid, error_message).
# Rule: never trust user input; validate on the SERVER.
# (Browser-side checks are only for convenience.)
# ===============================================================
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value, max_length=200):
    """Trim whitespace, strip control characters, enforce a maximum length."""
    value = (value or "").strip()
    value = CONTROL_CHARS_RE.sub("", value)
    return value[:max_length]


def validate_username(username):
    if not USERNAME_RE.match(username or ""):
        return False, "Username must be 3-30 characters: letters, numbers and underscore only."
    return True, ""


def validate_email(email):
    if len(email or "") > 120 or not EMAIL_RE.match(email or ""):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password):
    password = password or ""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters."
    if len(password) > 128:
        return False, "Password must be at most 128 characters."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain a digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain a special character (e.g. @ # ! $)."
    return True, ""


def validate_full_name(name):
    if not 2 <= len(name or "") <= 60:
        return False, "Name must be 2-60 characters."
    return True, ""


def validate_address(address):
    if not 10 <= len(address or "") <= 200:
        return False, "Address must be 10-200 characters."
    return True, ""


def parse_int(value, min_value=1, max_value=999999):
    """Convert text to an int inside a range. Returns None if invalid."""
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        return None
    if number < min_value or number > max_value:
        return None
    return number


def is_safe_redirect_url(target):
    """Allow redirects only to paths on THIS site. Blocks 'open redirect'
    attacks such as ?next=https://evil.com"""
    if not target or "\\" in target:
        return False
    parsed = urlparse(target)
    return (parsed.scheme == "" and parsed.netloc == ""
            and target.startswith("/") and not target.startswith("//"))


# ===============================================================
# 4. CSRF PROTECTION
# A random token is stored in the user's session and must come back
# with every POST form. A malicious site cannot read or guess it.
# ===============================================================
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf():
    sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf_token", "")
    if not sent or not expected:
        return False
    # compare_digest takes constant time, which prevents timing attacks
    return hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8"))


# ===============================================================
# 5. SECURE HTTP HEADERS
# ===============================================================
HSTS_MAX_AGE = 300   # seconds. Kept SHORT for development: browsers remember HSTS
                     # per hostname (ignoring ports) and would force https on every
                     # localhost project for that long. Use 31536000 in production.

CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",    # NO inline scripts allowed
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "font-src 'self' https://cdn.jsdelivr.net",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
])


def add_security_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = f"max-age={HSTS_MAX_AGE}; includeSubDomains"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Server"] = "SecureShop"      # hide the exact server/version
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"   # don't cache personal pages
    return response


# ===============================================================
# 6. WIRING INTO FLASK
# ===============================================================
def init_security(app):
    setup_logging()

    @app.before_request
    def _security_checks():
        ip = get_client_ip()

        # Rate limiting: too many requests per minute from one IP
        request_count = request_counter.add(ip)
        if request_count > config.MAX_REQUESTS_PER_MINUTE:
            # Log only the FIRST blocked request of a burst, so an attacker
            # cannot flood the log file by flooding the server.
            if request_count == config.MAX_REQUESTS_PER_MINUTE + 1:
                security_log.warning("RATE_LIMIT_EXCEEDED ip=%s path=%s (further blocked requests are not logged)",
                                     ip, request.path)
            return Response("429 Too Many Requests. Please slow down.",
                            status=429, headers={"Retry-After": "60"})

        # CSRF check on every state-changing request
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not validate_csrf():
            security_log.warning("CSRF_VALIDATION_FAILED ip=%s path=%s", ip, request.path)
            abort(400, description="Invalid or missing CSRF token.")

    @app.after_request
    def _after_request(response):
        # Count invalid requests (400/404/405...) per IP for the detection engine
        if response.status_code in INVALID_STATUS_CODES:
            invalid_counter.add(get_client_ip())
        return add_security_headers(response)

    # Makes {{ csrf_token() }} available in every template
    app.jinja_env.globals["csrf_token"] = generate_csrf_token
