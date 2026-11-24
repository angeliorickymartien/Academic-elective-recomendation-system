"""
database.py - SQLite connection helper, schema creation and seed data.
Run directly to create the database:   python database.py
"""
import sqlite3
from contextlib import contextmanager

from werkzeug.security import generate_password_hash

import config


def get_db():
    """Open a new connection to the SQLite database file."""
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")   # SQLite ignores foreign keys unless enabled
    return conn


@contextmanager
def get_connection():
    """Commit on success, roll back on error, always close.
    Each call opens its own connection, so it is safe from several threads."""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Timestamps use SQLite datetime('now'), which stores UTC time.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL,
    price       REAL    NOT NULL CHECK (price >= 0),
    category    TEXT    NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    emoji       TEXT    NOT NULL DEFAULT '📦'
);

CREATE TABLE IF NOT EXISTS cart_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity   INTEGER NOT NULL CHECK (quantity > 0),
    UNIQUE (user_id, product_id),
    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS orders (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL,
    total            REAL    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'PAID',
    payment_ref      TEXT    NOT NULL,
    shipping_name    TEXT    NOT NULL,
    shipping_address TEXT    NOT NULL,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS order_items (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id     INTEGER NOT NULL,
    product_id   INTEGER NOT NULL,
    product_name TEXT    NOT NULL,
    unit_price   REAL    NOT NULL,
    quantity     INTEGER NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT,
    ip_address TEXT NOT NULL,
    success    INTEGER NOT NULL,               -- 1 = success, 0 = failed
    timestamp  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    ip_address  TEXT,
    description TEXT NOT NULL,
    timestamp   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    ip_address TEXT,
    action     TEXT NOT NULL,
    details    TEXT,
    timestamp  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS network_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
    protocol    TEXT NOT NULL,                 -- TCP / UDP
    local_addr  TEXT NOT NULL,
    remote_addr TEXT,
    status      TEXT,                          -- ESTABLISHED, LISTEN, TIME_WAIT ...
    direction   TEXT                           -- INBOUND / OUTBOUND / LISTENING
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL DEFAULT (datetime('now')),
    bytes_sent   INTEGER,
    bytes_recv   INTEGER,
    packets_sent INTEGER,
    packets_recv INTEGER,
    tcp_count    INTEGER,
    udp_count    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_login_ip_time ON login_attempts (ip_address, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_time   ON security_alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_time  ON traffic_stats (timestamp);
"""

# (name, description, price, category, stock, emoji)
SEED_PRODUCTS = [
    ("Wireless Bluetooth Headphones", "Over-ear headphones with noise isolation and 30-hour battery life.", 59.99, "Electronics", 25, "🎧"),
    ("Smart Fitness Watch", "Tracks steps, heart rate and sleep. Water resistant, 7-day battery.", 89.99, "Electronics", 15, "⌚"),
    ("Portable Power Bank 20000mAh", "Dual USB output power bank with fast charging support.", 24.99, "Electronics", 40, "🔋"),
    ("Mechanical Keyboard", "Backlit mechanical keyboard with tactile blue switches.", 74.50, "Computers", 20, "⌨️"),
    ("Wireless Mouse", "Ergonomic 2.4 GHz wireless mouse with adjustable DPI.", 19.99, "Computers", 50, "🖱️"),
    ("USB-C Hub 7-in-1", "HDMI, USB 3.0, SD card reader and power delivery in one hub.", 34.99, "Computers", 30, "🔌"),
    ("Laptop Backpack", "Water-resistant backpack with padded laptop compartment.", 39.99, "Accessories", 35, "🎒"),
    ("Stainless Steel Water Bottle", "Insulated 750 ml bottle keeps drinks cold for 24 hours.", 14.99, "Home", 60, "🍶"),
    ("LED Desk Lamp", "Adjustable desk lamp with three brightness levels and USB port.", 22.50, "Home", 28, "💡"),
    ("Running Shoes", "Lightweight breathable running shoes with cushioned sole.", 64.99, "Fashion", 18, "👟"),
    ("Cotton T-Shirt", "Soft 100% cotton round-neck t-shirt.", 12.99, "Fashion", 80, "👕"),
    ("Wi-Fi 6 Router", "Dual-band Wi-Fi 6 router with WPA3 security support.", 49.99, "Networking", 22, "📶"),
    ("Ethernet Cable Cat6 (5m)", "Shielded Cat6 cable for fast, reliable wired connections.", 6.99, "Networking", 100, "🌐"),
]


def init_db():
    """Create tables (if missing) and insert seed data (if empty)."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)

        count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if count == 0:
            conn.executemany(
                "INSERT INTO products (name, description, price, category, stock, emoji) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                SEED_PRODUCTS,
            )

        # Default admin: store a salted HASH, never the password itself.
        admin = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
        if admin is None:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (
                    config.DEFAULT_ADMIN_USERNAME,
                    config.DEFAULT_ADMIN_EMAIL,
                    generate_password_hash(config.DEFAULT_ADMIN_PASSWORD),
                ),
            )


if __name__ == "__main__":
    init_db()
    print(f"Database ready at: {config.DB_PATH}")
