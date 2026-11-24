"""
config.py - Central configuration for SecureShop.
Every other module imports its settings from here.
"""
import os
import secrets
from datetime import timedelta

# ---------------------------------------------------------------
# 1. FOLDER AND FILE PATHS
# ---------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
LOG_DIR = os.path.join(BASE_DIR, "logs")
CERT_DIR = os.path.join(BASE_DIR, "certs")

DB_PATH = os.path.join(INSTANCE_DIR, "secureshop.db")
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")

for _folder in (INSTANCE_DIR, LOG_DIR, CERT_DIR):
    os.makedirs(_folder, exist_ok=True)


# ---------------------------------------------------------------
# 2. SECRET KEY (signs session cookies; never hard-coded)
# Order: environment variable -> saved file -> newly generated.
# ---------------------------------------------------------------
def _load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    key_file = os.path.join(INSTANCE_DIR, "secret_key.txt")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return f.read().strip()

    new_key = secrets.token_hex(32)
    with open(key_file, "w") as f:
        f.write(new_key)
    return new_key


# ---------------------------------------------------------------
# 3. FLASK SETTINGS (secure cookies and sessions)
# ---------------------------------------------------------------
class Config:
    SECRET_KEY = _load_secret_key()

    SESSION_COOKIE_NAME = "secureshop_session"
    SESSION_COOKIE_SECURE = True      # cookie is sent ONLY over HTTPS
    SESSION_COOKIE_HTTPONLY = True    # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"   # not sent on cross-site POSTs (CSRF defence)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    MAX_CONTENT_LENGTH = 1 * 1024 * 1024   # reject request bodies bigger than 1 MB


# ---------------------------------------------------------------
# 4. SERVER SETTINGS
# ---------------------------------------------------------------
HOST = "127.0.0.1"    # localhost only: the app is NOT exposed to other machines
PORT = 5000

# ---------------------------------------------------------------
# 5. INTRUSION DETECTION THRESHOLDS
# ---------------------------------------------------------------
MAX_FAILED_LOGINS = 5            # failed logins allowed from one IP ...
FAILED_LOGIN_WINDOW_MIN = 5      # ... within this many minutes
MAX_REQUESTS_PER_MINUTE = 100    # more than this from one IP = flood alert
MAX_INVALID_REQUESTS = 10        # 400/404 responses allowed from one IP ...
INVALID_WINDOW_MIN = 5           # ... within this many minutes
MAX_ADMIN_ACCESS_ATTEMPTS = 3    # non-admin hits on /admin allowed
MAX_CONNECTIONS_ALERT = 100      # alert if active connections exceed this
MAX_CONNECTIONS_PER_IP = 20      # simultaneous ESTABLISHED connections from one IP
MAX_HALF_OPEN_CONNECTIONS = 10   # SYN_RECV connections from one IP (SYN-flood indicator)
ALERT_COOLDOWN_MIN = 5           # don't repeat the same alert for the same IP within this time

# ---------------------------------------------------------------
# 6. NETWORK MONITOR SETTINGS
# ---------------------------------------------------------------
MONITOR_INTERVAL_SEC = 5         # how often the monitor takes a snapshot

# ---------------------------------------------------------------
# 7. APPLICATION SETTINGS
# ---------------------------------------------------------------
MIN_PASSWORD_LENGTH = 8
CURRENCY_SYMBOL = "$"

# Demo admin account created automatically on first run.
# CHANGE THIS PASSWORD before showing the project to anyone.
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_EMAIL = "admin@secureshop.local"
DEFAULT_ADMIN_PASSWORD = "Admin@12345"
