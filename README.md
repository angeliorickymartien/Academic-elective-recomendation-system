# SecureShop: Secure E-Commerce Network Using Encryption and Network Monitoring

A Flask e-commerce demo built for a Computer Networks & Internet Protocols project.
It shows how TLS encryption, secure authentication, network monitoring and
intrusion detection work together.

## Features
- HTTPS/TLS (self-signed certificate generated locally)
- Registration/login with salted password hashing, secure sessions, CSRF protection
- Product search, cart, checkout with **simulated** payment (no card data is ever collected)
- Secure HTTP headers (CSP, HSTS, X-Frame-Options ...), input validation, parameterized SQL
- Network monitor (psutil): TCP/UDP connections, states, traffic statistics, logs
- Intrusion detection: brute force, request flood, invalid requests, admin probing,
  SYN-flood indicators, unexpected connections
- Admin dashboard with Chart.js and a TLS handshake inspector

## Setup (Windows PowerShell)
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py               # creates the database and the TLS certificate, then starts HTTPS
```
Linux/macOS: `python3 -m venv venv && source venv/bin/activate`, then the same pip/python commands.

Open https://localhost:5000 and accept the browser warning (self-signed certificate:
Advanced -> Proceed to localhost).

Demo admin: `admin` / `Admin@12345` at /admin/login. **Change this password**
(`DEFAULT_ADMIN_PASSWORD` in config.py, before the first run) before showing the project publicly.

## Testing
```powershell
python check_files.py               # are all templates/static files in the right folders?
python -m pytest                    # automated test suite (uses a temporary database)
python run_all_checks.py            # both of the above, summarised
python simulate_attacks.py all      # (server running) fake attacks on YOUR OWN server only
python simulate_attacks.py reset    # clear the failed-login lockout afterwards
```

## Project structure
```
app.py                  routes, error pages, HTTPS startup
config.py               all settings and detection thresholds
database.py / models.py SQLite schema, seed data, every query (parameterized)
authentication.py       register, login, logout, sessions, access control
security.py             headers, validation, CSRF, rate limiting, logging
network_monitor.py      background connection/traffic monitor, DNS + TLS inspection
intrusion_detection.py  detection rules -> alerts
generate_cert.py        self-signed TLS certificate
simulate_attacks.py     safe local attack simulator
templates/  static/     pages, CSS, JavaScript (Chart.js dashboard)
tests/                  pytest suite
logs/                   app.log, security.log, network.log
```

## Ethics
Monitoring covers only this application's own connections on the local machine.
No packet contents are read, no scanning is performed, and the simulator only
targets 127.0.0.1.
