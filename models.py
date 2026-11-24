"""
models.py - All database operations for SecureShop.

SECURITY NOTE: every query uses '?' placeholders (parameterized queries).
User input is NEVER pasted into the SQL text, which prevents SQL injection.
"""
import sqlite3

from database import get_connection


def _to_dict(row):
    return dict(row) if row is not None else None


def _to_dicts(rows):
    return [dict(r) for r in rows]


# ===============================================================
# USERS
# ===============================================================
def create_user(username, email, password_hash):
    """Insert a new user. Returns the new user id, or None if the
    username or email already exists."""
    try:
        with get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(username):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return _to_dict(row)


def get_user_by_email(email):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        return _to_dict(row)


def get_user_by_id(user_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return _to_dict(row)


def count_users():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# ===============================================================
# PRODUCTS
# ===============================================================
def get_all_products(search=None, category=None):
    """List products, optionally filtered by a search word and/or category.
    The SQL text only ever contains fixed fragments; values go in params."""
    sql = "SELECT * FROM products WHERE 1=1"
    params = []
    if search:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    if category:
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY name"

    with get_connection() as conn:
        return _to_dicts(conn.execute(sql, params).fetchall())


def get_product(product_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        return _to_dict(row)


def get_categories():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT DISTINCT category FROM products ORDER BY category"
        ).fetchall()
        return [r["category"] for r in rows]


def count_products():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]


# ===============================================================
# SHOPPING CART
# ===============================================================
def add_to_cart(user_id, product_id, quantity=1):
    """Add a product to the cart (or increase its quantity).
    The quantity is capped at the available stock.
    Returns True on success, False if the product doesn't exist."""
    with get_connection() as conn:
        product = conn.execute(
            "SELECT stock FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        if product is None or product["stock"] <= 0:
            return False

        existing = conn.execute(
            "SELECT quantity FROM cart_items WHERE user_id = ? AND product_id = ?",
            (user_id, product_id),
        ).fetchone()
        current = existing["quantity"] if existing else 0
        new_qty = min(current + quantity, product["stock"])

        if existing:
            conn.execute(
                "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
                (new_qty, user_id, product_id),
            )
        else:
            conn.execute(
                "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                (user_id, product_id, new_qty),
            )
        return True


def get_cart(user_id):
    """Return the user's cart items with product details and subtotals."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT c.product_id, c.quantity,
                      p.name, p.price, p.emoji, p.stock
               FROM cart_items c
               JOIN products p ON p.id = c.product_id
               WHERE c.user_id = ?
               ORDER BY p.name""",
            (user_id,),
        ).fetchall()
    items = _to_dicts(rows)
    for item in items:
        item["subtotal"] = round(item["price"] * item["quantity"], 2)
    return items


def get_cart_total(user_id):
    return round(sum(item["subtotal"] for item in get_cart(user_id)), 2)


def get_cart_count(user_id):
    """Total number of units in the cart (shown as a badge in the navbar)."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(quantity), 0) FROM cart_items WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        return row[0]


def update_cart_quantity(user_id, product_id, quantity):
    """Set an exact quantity. Zero or less removes the item.
    Quantity is capped at the available stock."""
    if quantity <= 0:
        remove_from_cart(user_id, product_id)
        return
    with get_connection() as conn:
        product = conn.execute(
            "SELECT stock FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        if product is None:
            return
        quantity = min(quantity, product["stock"])
        conn.execute(
            "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
            (quantity, user_id, product_id),
        )


def remove_from_cart(user_id, product_id):
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
            (user_id, product_id),
        )


def clear_cart(user_id):
    with get_connection() as conn:
        conn.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))


# ===============================================================
# ORDERS
# ===============================================================
def create_order_from_cart(user_id, shipping_name, shipping_address, payment_ref):
    """Turn the user's cart into an order in ONE database transaction:
    either everything succeeds, or nothing is saved.
    Prices come from the DATABASE, never from the browser, so a user
    cannot change a price by editing the page.
    Returns the new order id. Raises ValueError for cart/stock problems."""
    with get_connection() as conn:
        items = conn.execute(
            """SELECT c.product_id, c.quantity, p.name, p.price, p.stock
               FROM cart_items c
               JOIN products p ON p.id = c.product_id
               WHERE c.user_id = ?""",
            (user_id,),
        ).fetchall()

        if not items:
            raise ValueError("Your cart is empty.")

        total = 0.0
        for item in items:
            if item["quantity"] > item["stock"]:
                raise ValueError(f"Not enough stock for {item['name']}.")
            total += item["price"] * item["quantity"]
        total = round(total, 2)

        cur = conn.execute(
            """INSERT INTO orders (user_id, total, status, payment_ref,
                                   shipping_name, shipping_address)
               VALUES (?, ?, 'PAID', ?, ?, ?)""",
            (user_id, total, payment_ref, shipping_name, shipping_address),
        )
        order_id = cur.lastrowid

        for item in items:
            conn.execute(
                """INSERT INTO order_items (order_id, product_id, product_name,
                                            unit_price, quantity)
                   VALUES (?, ?, ?, ?, ?)""",
                (order_id, item["product_id"], item["name"],
                 item["price"], item["quantity"]),
            )
            # Reduce stock; the "AND stock >= ?" guard stops overselling
            result = conn.execute(
                "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?",
                (item["quantity"], item["product_id"], item["quantity"]),
            )
            if result.rowcount == 0:
                raise ValueError(f"Not enough stock for {item['name']}.")

        conn.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
        return order_id


def get_order(order_id, user_id):
    """Fetch an order ONLY if it belongs to this user. Checking ownership
    stops one user from viewing another user's order by changing the ID
    in the URL (an 'IDOR' vulnerability)."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM orders WHERE id = ? AND user_id = ?",
            (order_id, user_id),
        ).fetchone()
        return _to_dict(row)


def get_order_items(order_id):
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM order_items WHERE order_id = ?", (order_id,)
        ).fetchall())


def get_user_orders(user_id):
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (user_id,)
        ).fetchall())


def count_orders():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]


# ===============================================================
# LOGIN ATTEMPTS, ACTIVITY LOGS AND SECURITY ALERTS
# ===============================================================
def record_login_attempt(username, ip_address, success):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, ip_address, 1 if success else 0),
        )


def count_recent_failed_logins(ip_address, minutes):
    """Failed logins from one IP in the last N minutes (brute-force check)."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT COUNT(*) FROM login_attempts
               WHERE ip_address = ? AND success = 0
                 AND timestamp >= datetime('now', ?)""",
            (ip_address, f"-{int(minutes)} minutes"),
        ).fetchone()
        return row[0]


def count_failed_logins_total():
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE success = 0"
        ).fetchone()[0]


def get_recent_login_attempts(limit=20):
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM login_attempts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())


def log_activity(user_id, ip_address, action, details=""):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO activity_logs (user_id, ip_address, action, details) "
            "VALUES (?, ?, ?, ?)",
            (user_id, ip_address, action, details),
        )


def get_recent_activity(limit=20):
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())


def create_alert(alert_type, severity, ip_address, description):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO security_alerts (alert_type, severity, ip_address, description) "
            "VALUES (?, ?, ?, ?)",
            (alert_type, severity, ip_address, description),
        )


def has_recent_alert(alert_type, ip_address, minutes):
    """True if the same alert type was already raised for this IP recently.
    Prevents the dashboard from filling up with duplicate alerts."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT COUNT(*) FROM security_alerts
               WHERE alert_type = ? AND ip_address = ?
                 AND timestamp >= datetime('now', ?)""",
            (alert_type, ip_address, f"-{int(minutes)} minutes"),
        ).fetchone()
        return row[0] > 0


def get_recent_alerts(limit=20):
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())


def count_alerts():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]


# ===============================================================
# NETWORK MONITORING (used by network_monitor.py and the dashboard)
# ===============================================================
def save_network_events(events):
    """Store newly seen connections (a list of dicts)."""
    if not events:
        return
    rows = [(e["protocol"], e["local_addr"], e["remote_addr"],
             e["status"], e["direction"]) for e in events]
    with get_connection() as conn:
        conn.executemany(
            "INSERT INTO network_events (protocol, local_addr, remote_addr, status, direction) "
            "VALUES (?, ?, ?, ?, ?)", rows)


def save_traffic_stats(bytes_sent, bytes_recv, packets_sent, packets_recv,
                       tcp_count, udp_count):
    """One row per monitor cycle. Byte/packet values are the amount transferred
    DURING that cycle (system-wide network adapter counters)."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO traffic_stats (bytes_sent, bytes_recv, packets_sent, "
            "packets_recv, tcp_count, udp_count) VALUES (?, ?, ?, ?, ?, ?)",
            (bytes_sent, bytes_recv, packets_sent, packets_recv, tcp_count, udp_count))


def get_recent_network_events(limit=30):
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM network_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())


def get_traffic_history(limit=60):
    """Latest N traffic rows, returned oldest-first (ready for a chart)."""
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            "SELECT * FROM (SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?) "
            "ORDER BY id ASC", (limit,)
        ).fetchall())


def prune_network_data(keep_events=500, keep_stats=720):
    """Keep the monitoring tables from growing forever."""
    with get_connection() as conn:
        conn.execute("DELETE FROM network_events WHERE id NOT IN "
                     "(SELECT id FROM network_events ORDER BY id DESC LIMIT ?)", (keep_events,))
        conn.execute("DELETE FROM traffic_stats WHERE id NOT IN "
                     "(SELECT id FROM traffic_stats ORDER BY id DESC LIMIT ?)", (keep_stats,))


def get_ips_with_failed_logins(minutes, threshold):
    """IPs with at least `threshold` failed logins in the last N minutes."""
    with get_connection() as conn:
        return _to_dicts(conn.execute(
            """SELECT ip_address, COUNT(*) AS attempts FROM login_attempts
               WHERE success = 0 AND timestamp >= datetime('now', ?)
               GROUP BY ip_address HAVING COUNT(*) >= ?""",
            (f"-{int(minutes)} minutes", threshold)).fetchall())


# ===============================================================
# DASHBOARD QUERIES
# ===============================================================
def get_total_revenue():
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(total), 0) FROM orders WHERE status = 'PAID'"
        ).fetchone()
        return round(row[0], 2)


def get_alert_counts_by_severity():
    """Always returns all four severities, even when the count is zero."""
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    with get_connection() as conn:
        for row in conn.execute(
                "SELECT severity, COUNT(*) AS n FROM security_alerts GROUP BY severity"):
            counts[row["severity"]] = row["n"]
    return counts


def get_login_activity(hours=12):
    """Successful and failed logins per hour for the last N hours."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour,
                      SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success,
                      SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed
               FROM login_attempts
               WHERE timestamp >= datetime('now', ?)
               GROUP BY hour ORDER BY hour""",
            (f"-{int(hours)} hours",)).fetchall()
        return _to_dicts(rows)
