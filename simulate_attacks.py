"""
simulate_attacks.py - SAFE local simulator for testing SecureShop's detection.

Sends a SMALL, FIXED number of fake suspicious requests, ONLY to your own
server on 127.0.0.1. It refuses to target anything else.

Usage (start the server first in another terminal:  python app.py):
    python simulate_attacks.py invalid    # 404 requests
    python simulate_attacks.py admin      # admin page probing
    python simulate_attacks.py brute      # failed logins
    python simulate_attacks.py flood      # request burst (blocks you for ~1 minute)
    python simulate_attacks.py all        # all of the above, in a safe order
    python simulate_attacks.py reset      # clear the failed-login lockout for 127.0.0.1
"""
import http.cookiejar
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

import config
import database

TARGET_HOST = "127.0.0.1"
BASE_URL = f"https://{TARGET_HOST}:{config.PORT}"


def require_local_target():
    """Safety guard: never send anything to a non-local address."""
    if TARGET_HOST not in ("127.0.0.1", "localhost"):
        raise SystemExit("Refused: this simulator may only target the local machine.")


def make_opener():
    """An HTTP client that keeps cookies and accepts our self-signed certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
    )


def fetch(opener, path, data=None):
    """Send one request. Returns (status_code, body_text)."""
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(BASE_URL + path, data=body)
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:       # 4xx / 5xx still give us a status
        return error.code, error.read().decode("utf-8", errors="replace")
    except urllib.error.URLError:
        raise SystemExit(f"Cannot reach {BASE_URL}. Start the server first:  python app.py")


def get_csrf_token(page_html):
    match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page_html)
    return match.group(1) if match else ""


# ---------------------------------------------------------------
# SCENARIOS
# ---------------------------------------------------------------
def simulate_invalid_requests():
    count = config.MAX_INVALID_REQUESTS + 2
    print(f"\n[invalid] Requesting {count} pages that do not exist")
    opener = make_opener()
    statuses = Counter()
    for i in range(count):
        status, _ = fetch(opener, f"/simulated-missing-page-{i}")
        statuses[status] += 1
    print(f"   responses: {dict(statuses)}")
    print("   Expected alert: INVALID_REQUESTS (MEDIUM) within ~5 seconds.")


def simulate_admin_probing():
    count = config.MAX_ADMIN_ACCESS_ATTEMPTS + 1
    print(f"\n[admin] Opening /admin {count} times without logging in")
    opener = make_opener()
    for _ in range(count):
        fetch(opener, "/admin")
    print("   Expected alert: ADMIN_ACCESS_ATTEMPTS (HIGH) within ~5 seconds.")


def simulate_brute_force():
    attempts = config.MAX_FAILED_LOGINS + 1
    print(f"\n[brute] {attempts} login attempts with wrong passwords (fake user)")
    opener = make_opener()
    _, page = fetch(opener, "/login")
    token = get_csrf_token(page)
    for number in range(1, attempts + 1):
        status, body = fetch(opener, "/login", {
            "csrf_token": token, "username": "simulated_user",
            "password": f"Wrong@Pass{number}"})
        if "Too many failed" in body:
            result = "BLOCKED by lockout"
        elif "Invalid username" in body:
            result = "rejected"
        else:
            result = f"HTTP {status}"
        print(f"   attempt {number}: {result}")
        time.sleep(0.2)
    print("   Expected alert: BRUTE_FORCE_LOGIN (HIGH) within ~5 seconds.")
    print("   Your IP is now locked out of LOGIN for 5 minutes. Run 'reset' to clear it.")


def simulate_flood():
    count = config.MAX_REQUESTS_PER_MINUTE + 10
    print(f"\n[flood] Sending {count} quick requests to the home page")
    opener = make_opener()
    statuses = Counter()
    for _ in range(count):
        status, _ = fetch(opener, "/")
        statuses[status] += 1
    print(f"   responses: {dict(statuses)}")
    print("   200 = served, 429 = blocked by the rate limiter.")
    print("   Expected alert: REQUEST_FLOOD (HIGH) within ~5 seconds.")
    print("   Your browser will also get HTTP 429 for about a minute.")


def reset_lockout():
    with database.get_connection() as conn:
        removed = conn.execute("DELETE FROM login_attempts WHERE ip_address = ?",
                               (TARGET_HOST,)).rowcount
    print(f"Removed {removed} failed-login records for {TARGET_HOST}.")
    print("(The in-memory request counters expire by themselves within 1-5 minutes.)")


SCENARIOS = {
    "invalid": simulate_invalid_requests,
    "admin": simulate_admin_probing,
    "brute": simulate_brute_force,
    "flood": simulate_flood,
}

if __name__ == "__main__":
    require_local_target()
    choice = sys.argv[1] if len(sys.argv) > 1 else ""

    if choice == "reset":
        reset_lockout()
    elif choice == "all":
        # The flood goes last because it makes the server answer 429 for a minute
        for name in ("invalid", "admin", "brute", "flood"):
            SCENARIOS[name]()
            time.sleep(1)
        print("\nDone. Open the admin dashboard and watch the alerts appear.")
    elif choice in SCENARIOS:
        SCENARIOS[choice]()
    else:
        print(__doc__)
