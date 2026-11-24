"""
app.py - SecureShop main application.
Run with:   python app.py      then open   https://localhost:5000
"""
import logging
import os
import secrets

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, url_for
from markupsafe import Markup
from werkzeug.serving import WSGIRequestHandler

import authentication
import config
import database
import generate_cert
import intrusion_detection
import models
import network_lab
import network_monitor
import security

# ---------------------------------------------------------------
# APP SETUP (order matters: database -> security -> authentication)
# ---------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(config.Config)

database.init_db()
security.init_security(app)
authentication.init_auth(app)

app_log = logging.getLogger("secureshop.app")


def csrf_field():
    """HTML for the hidden CSRF input. Use {{ csrf_field() }} inside every POST form.
    Markup % escapes the token, so the output is safe."""
    return Markup('<input type="hidden" name="csrf_token" value="%s">') % security.generate_csrf_token()


app.jinja_env.globals["csrf_field"] = csrf_field


def safe_next(default):
    """Return the 'next' form value only if it points inside our own site."""
    target = request.form.get("next", "")
    return target if security.is_safe_redirect_url(target) else default


@app.before_request
def _track_request_start():
    import time
    g.request_start_time = time.perf_counter()


@app.after_request
def _track_packet(response):
    import time
    if not request.path.startswith("/static"):
        elapsed_ms = (time.perf_counter() - getattr(g, "request_start_time", time.perf_counter())) * 1000
        length = response.content_length or len(response.get_data())
        network_lab.record_packet(
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            client_ip=security.get_client_ip(),
            content_length=length,
            elapsed_ms=elapsed_ms,
        )
    return response


# ===============================================================
# PUBLIC PAGES
# ===============================================================
@app.route("/")
def index():
    featured = models.get_all_products()[:4]
    return render_template("index.html", featured=featured,
                           categories=models.get_categories())


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))

    if request.method == "POST":
        ok, message, _ = authentication.register_user(
            request.form.get("username"), request.form.get("email"),
            request.form.get("password"), request.form.get("confirm_password"),
            security.get_client_ip(),
        )
        if ok:
            flash(message, "success")
            return redirect(url_for("login"))
        flash(message, "danger")
    return render_template("register.html", form=request.form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))

    next_url = request.values.get("next", "")
    if not security.is_safe_redirect_url(next_url):
        next_url = ""

    if request.method == "POST":
        ok, message = authentication.login_user(
            request.form.get("username"), request.form.get("password"),
            security.get_client_ip(),
        )
        if ok:
            flash(message, "success")
            return redirect(next_url or url_for("index"))
        flash(message, "danger")
    return render_template("login.html", next_url=next_url, form=request.form)


@app.route("/logout", methods=["POST"])      # POST + CSRF token prevents "logout CSRF"
def logout():
    authentication.logout_user(security.get_client_ip())
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ===============================================================
# PRODUCTS
# ===============================================================
@app.route("/products")
def products():
    search = security.clean_text(request.args.get("q"), 50)
    category = security.clean_text(request.args.get("category"), 30)
    items = models.get_all_products(search=search or None, category=category or None)
    return render_template("products.html", products=items, search=search,
                           category=category, categories=models.get_categories())


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    product = models.get_product(product_id)
    if product is None:
        abort(404)
    return render_template("product_detail.html", product=product,
                           max_qty=min(product["stock"], 10))


# ===============================================================
# SHOPPING CART (login required; every change is a POST with CSRF token)
# ===============================================================
@app.route("/cart")
@authentication.login_required
def cart():
    items = models.get_cart(g.user["id"])
    total = round(sum(item["subtotal"] for item in items), 2)
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add", methods=["POST"])
@authentication.login_required
def cart_add():
    product_id = security.parse_int(request.form.get("product_id"))
    quantity = security.parse_int(request.form.get("quantity", 1), 1, 10)
    if product_id is None or quantity is None:
        abort(400)

    if models.add_to_cart(g.user["id"], product_id, quantity):
        models.log_activity(g.user["id"], security.get_client_ip(),
                            "CART_ADD", f"product {product_id} x{quantity}")
        flash("Added to your cart.", "success")
    else:
        flash("Sorry, that product is unavailable.", "warning")
    return redirect(safe_next(url_for("products")))


@app.route("/cart/update", methods=["POST"])
@authentication.login_required
def cart_update():
    product_id = security.parse_int(request.form.get("product_id"))
    quantity = security.parse_int(request.form.get("quantity"), 0, 99)
    if product_id is None or quantity is None:
        abort(400)
    models.update_cart_quantity(g.user["id"], product_id, quantity)
    flash("Cart updated.", "info")
    return redirect(url_for("cart"))


@app.route("/cart/remove", methods=["POST"])
@authentication.login_required
def cart_remove():
    product_id = security.parse_int(request.form.get("product_id"))
    if product_id is None:
        abort(400)
    models.remove_from_cart(g.user["id"], product_id)
    flash("Item removed from your cart.", "info")
    return redirect(url_for("cart"))


# ===============================================================
# CHECKOUT (simulated payment: NO card details are ever collected)
# ===============================================================
PAYMENT_METHODS = ("Simulated Card", "Simulated Net Banking", "Simulated Wallet")


def simulate_payment(amount, outcome):
    """Pretend payment gateway. The user picks the outcome so both the
    success and failure paths can be demonstrated and tested.
    Returns (approved, payment_reference)."""
    if outcome != "approve" or amount <= 0:
        return False, None
    return True, "SIM-" + secrets.token_hex(6).upper()


@app.route("/checkout", methods=["GET", "POST"])
@authentication.login_required
def checkout():
    user_id = g.user["id"]
    items = models.get_cart(user_id)
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("cart"))
    total = round(sum(item["subtotal"] for item in items), 2)

    def show_form():
        return render_template("checkout.html", items=items, total=total,
                               form=request.form, methods=PAYMENT_METHODS)

    if request.method == "POST":
        name = security.clean_text(request.form.get("shipping_name"), 60)
        address = security.clean_text(request.form.get("shipping_address"), 200)
        method = request.form.get("payment_method", "")
        outcome = request.form.get("payment_result", "approve")

        for ok, message in (security.validate_full_name(name),
                            security.validate_address(address)):
            if not ok:
                flash(message, "danger")
                return show_form()
        if method not in PAYMENT_METHODS:
            flash("Please choose a payment method.", "danger")
            return show_form()

        approved, payment_ref = simulate_payment(total, outcome)
        if not approved:
            models.log_activity(user_id, security.get_client_ip(), "PAYMENT_DECLINED",
                                f"Simulated payment declined ({method})")
            flash("Payment declined (simulation). No order was created.", "danger")
            return show_form()

        try:
            order_id = models.create_order_from_cart(user_id, name, address, payment_ref)
        except ValueError as error:
            flash(str(error), "danger")
            return redirect(url_for("cart"))

        models.log_activity(user_id, security.get_client_ip(), "ORDER_PLACED",
                            f"Order #{order_id}, total {total}")
        app_log.info("ORDER_PLACED order=%s user_id=%s total=%s", order_id, user_id, total)
        return redirect(url_for("confirmation", order_id=order_id))

    return show_form()


@app.route("/order/<int:order_id>")
@authentication.login_required
def confirmation(order_id):
    order = models.get_order(order_id, g.user["id"])    # ownership check (stops IDOR)
    if order is None:
        abort(404)                                      # same answer whether it exists or not
    return render_template("confirmation.html", order=order,
                           items=models.get_order_items(order_id))


# ===============================================================
# ADMIN
# ===============================================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if g.user and g.user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        ok, message = authentication.login_user(
            request.form.get("username"), request.form.get("password"),
            security.get_client_ip(), admin_only=True,
        )
        if ok:
            flash("Administrator login successful.", "success")
            return redirect(url_for("admin_dashboard"))
        flash(message, "danger")
    return render_template("admin_login.html", form=request.form)


@app.route("/admin")
@authentication.admin_required
def admin_dashboard():
    # The page itself is a shell; dashboard.js loads the numbers from the API below.
    return render_template("admin_dashboard.html",
                           refresh_seconds=config.MONITOR_INTERVAL_SEC)


def build_overview():
    """Everything the dashboard needs, gathered into one dictionary."""
    snapshot = network_monitor.get_latest_snapshot()
    connections = snapshot["connections"]

    active = sum(1 for c in connections if c["status"] in intrusion_detection.ACTIVE_STATES)
    request_rates = sorted(security.request_counter.snapshot().items(),
                           key=lambda item: item[1], reverse=True)[:5]

    return {
        "generated_at": snapshot["timestamp"],
        "currency": config.CURRENCY_SYMBOL,
        "monitor_running": network_monitor.monitor_is_running(),
        "stats": {
            "users": models.count_users(),
            "products": models.count_products(),
            "orders": models.count_orders(),
            "revenue": models.get_total_revenue(),
            "failed_logins": models.count_failed_logins_total(),
            "alerts": models.count_alerts(),
            "active_connections": active,
        },
        "network": {
            "summary": snapshot["summary"],
            "connections": connections[:30],
            "traffic": models.get_traffic_history(60),
            "events": models.get_recent_network_events(15),
            "request_rates": [{"ip": ip, "count": count} for ip, count in request_rates],
        },
        "security": {
            "alerts": models.get_recent_alerts(15),
            "severity_counts": models.get_alert_counts_by_severity(),
            "login_activity": models.get_login_activity(12),
        },
        "activity": models.get_recent_activity(15),
    }


@app.route("/admin/api/overview")
@authentication.admin_required
def admin_api_overview():
    return jsonify(build_overview())


@app.route("/admin/api/tls")
@authentication.admin_required
def admin_api_tls():
    """Performs a real TLS handshake with our own server and reports the result."""
    return jsonify({"tls": network_monitor.inspect_tls(),
                    "host": network_monitor.local_network_info()})


# ===============================================================
# CNIP PROTOCOL & NETWORK LAB (Computer Networks & Internet Protocols)
# ===============================================================
@app.route("/network-lab")
def network_lab_view():
    return render_template(
        "network_lab.html",
        topology=network_lab.get_topology(),
        nmap_data=network_lab.get_nmap_scan_analysis(),
        wireshark=network_lab.get_wireshark_guide(),
        refresh_seconds=config.MONITOR_INTERVAL_SEC,
    )


@app.route("/api/network-lab/telemetry")
def api_network_lab_telemetry():
    return jsonify({
        "topology": network_lab.get_topology(),
        "packets": network_lab.get_packet_stream(),
        "snapshot": network_monitor.get_latest_snapshot(),
    })


@app.route("/api/network-lab/simulate", methods=["POST"])
def api_network_lab_simulate():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "transaction")
    result = network_lab.execute_demo_scenario(scenario)
    return jsonify(result)


# ===============================================================
# ERROR PAGES (friendly messages, never technical details)
# ===============================================================
ERROR_PAGES = {
    400: ("Bad Request", "The request could not be processed. If you submitted a form, "
                         "please go back, refresh the page and try again."),
    403: ("Access Denied", "You do not have permission to view this page."),
    404: ("Page Not Found", "The page you are looking for does not exist."),
    405: ("Method Not Allowed", "That action is not allowed on this page."),
    413: ("Request Too Large", "The data you sent was too large."),
    500: ("Server Error", "Something went wrong on our side. Please try again later."),
}


def _make_error_handler(code, title, message):
    def handler(error):
        if code == 500:
            app_log.exception("Unhandled server error")
        return render_template("error.html", code=code, title=title, message=message), code
    return handler


for _code, (_title, _message) in ERROR_PAGES.items():
    app.register_error_handler(_code, _make_error_handler(_code, _title, _message))


# ===============================================================
# START THE SERVER OVER HTTPS
# ===============================================================
class QuietRequestHandler(WSGIRequestHandler):
    """Stops the development server from announcing 'Werkzeug/x.y Python/x.y'."""

    def version_string(self):
        return "SecureShop"


def run():
    if not (os.path.exists(config.CERT_FILE) and os.path.exists(config.KEY_FILE)):
        generate_cert.generate_certificate()

    print("\n" + "=" * 60)
    print(f"  SecureShop is running:  https://localhost:{config.PORT}")
    print("  Your browser will warn about the self-signed certificate.")
    print("  Click Advanced -> Proceed to localhost (this is expected).")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    network_monitor.start_monitor()   # background thread: connections, traffic, detection
    # debug=False on purpose: Flask's debug mode exposes an interactive
    # console that would let an attacker run code on your computer.
    app.run(host=config.HOST, port=config.PORT,
            ssl_context=(config.CERT_FILE, config.KEY_FILE),
            debug=False, use_reloader=False, threaded=True,
            request_handler=QuietRequestHandler)


if __name__ == "__main__":
    run()
