import sqlite3
import os
import threading

DB_PATH = os.path.join(os.path.dirname(__file__), "subscriptions.db")
_lock = threading.Lock()

def init_db():
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id TEXT PRIMARY KEY,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                status TEXT,
                current_period_end INTEGER,
                subscription_status TEXT DEFAULT 'inactive'
            )
        """)
        conn.commit()
        conn.close()

def save_subscription(user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                stripe_customer_id=excluded.stripe_customer_id,
                stripe_subscription_id=excluded.stripe_subscription_id,
                status=excluded.status,
                current_period_end=excluded.current_period_end
        """, (user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end))
        conn.commit()
        conn.close()

def get_subscription(user_id):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end, subscription_status FROM subscriptions WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "user_id": row[0],
                "stripe_customer_id": row[1],
                "stripe_subscription_id": row[2],
                "status": row[3],
                "current_period_end": row[4],
                "subscription_status": row[5] if row[5] else "inactive"
            }
        return None

def has_active_subscription(user_id):
    sub = get_subscription(user_id)
    if not sub:
        return False
    status = sub["status"] or sub["subscription_status"]
    return status == "active"

def delete_subscription(user_id):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM subscriptions WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()

def update_subscription_status(user_id, status):
    user = get_subscription(user_id)
    if user:
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                UPDATE subscriptions SET subscription_status = ?, status = ?
                WHERE user_id = ?
            """, (status, status, user_id))
            conn.commit()
            conn.close()
    else:
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO subscriptions (user_id, subscription_status, status)
                VALUES (?, ?, ?)
            """, (user_id, status, status))
            conn.commit()
            conn.close()

def create_or_update_user(user_id, stripe_customer_id=None):
    user = get_subscription(user_id)
    if user:
        if stripe_customer_id and stripe_customer_id != user.get('stripe_customer_id'):
            with _lock:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("""
                    UPDATE subscriptions SET stripe_customer_id = ? WHERE user_id = ?
                """, (stripe_customer_id, user_id))
                conn.commit()
                conn.close()
    else:
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO subscriptions (user_id, stripe_customer_id, subscription_status, status)
                VALUES (?, ?, 'inactive', 'inactive')
            """, (user_id, stripe_customer_id))
            conn.commit()
            conn.close()

init_db()
