"""
check_setup.py - Verifies the development environment for SecureShop.
Run with:  python check_setup.py
"""
import os
import sys

print("=== SecureShop Setup Check ===\n")

ok_python = sys.version_info >= (3, 10)
print(f"[{'OK' if ok_python else 'FAIL'}] Python version: {sys.version.split()[0]} (need 3.10+)")

in_venv = sys.prefix != sys.base_prefix
print(f"[{'OK' if in_venv else 'WARN'}] Virtual environment active: {in_venv}")

packages = {
    "flask": "Flask",
    "werkzeug": "Werkzeug",
    "cryptography": "cryptography",
    "psutil": "psutil",
    "pytest": "pytest",
    "sqlite3": "sqlite3 (built into Python)",
}
all_pkgs_ok = True
for module, label in packages.items():
    try:
        __import__(module)
        print(f"[OK] {label} is installed")
    except ImportError:
        all_pkgs_ok = False
        print(f"[FAIL] {label} is MISSING -> run: pip install -r requirements.txt")

folders = ["certs", "instance", "logs", "templates", "static/css", "static/js", "tests", "docs"]
all_dirs_ok = True
for folder in folders:
    exists = os.path.isdir(folder)
    all_dirs_ok = all_dirs_ok and exists
    print(f"[{'OK' if exists else 'FAIL'}] Folder: {folder}/")

print("\n=== RESULT ===")
if ok_python and all_pkgs_ok and all_dirs_ok:
    print("All checks passed.")
else:
    print("Some checks failed. Fix the [FAIL] items above and run again.")
