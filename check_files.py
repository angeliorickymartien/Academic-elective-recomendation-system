"""check_files.py - Lists missing project files and finds misplaced copies."""
import os

expected = [
    "templates/base.html", "templates/_product_card.html", "templates/index.html",
    "templates/register.html", "templates/login.html", "templates/products.html",
    "templates/product_detail.html", "templates/cart.html", "templates/checkout.html",
    "templates/confirmation.html", "templates/admin_login.html",
    "templates/admin_dashboard.html", "templates/error.html",
    "static/css/style.css", "static/js/main.js", "static/js/dashboard.js",
]

missing = []
for path in expected:
    if os.path.isfile(path):
        print(f"[OK]      {path}")
    else:
        print(f"[MISSING] {path}")
        missing.append(path)

if missing:
    print("\nLooking for misplaced copies (ignoring venv)...")
    for folder, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in ("venv", "__pycache__", ".git")]
        for name in files:
            for path in missing:
                wanted = os.path.basename(path)
                if name == wanted or name.startswith(wanted + "."):
                    print(f"  Found '{name}' in: {folder}")
else:
    print("\nAll files are in place.")
