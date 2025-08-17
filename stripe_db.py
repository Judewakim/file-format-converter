import psycopg as psycopg2  # type: ignore
import os
import threading
from urllib.parse import urlparse

DATABASE_URL = os.getenv("DATABASE_URL")
_lock = threading.Lock()

def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    try:
        with _lock:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS subscriptions (
                    user_id TEXT PRIMARY KEY,
                    stripe_customer_id TEXT,
                    stripe_subscription_id TEXT,
                    status TEXT,
                    current_period_end BIGINT,
                    subscription_status TEXT DEFAULT 'inactive'
                )
            """)
            conn.commit()
            conn.close()
            print("Database initialized successfully")
    except Exception as e:
        print(f"Database connection failed: {e}")
        print("App will run without database functionality")

def save_subscription(user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end):
    try:
        with _lock:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
                INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT(user_id) DO UPDATE SET
                    stripe_customer_id=EXCLUDED.stripe_customer_id,
                    stripe_subscription_id=EXCLUDED.stripe_subscription_id,
                    status=EXCLUDED.status,
                    current_period_end=EXCLUDED.current_period_end
            """, (user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end))
            conn.commit()
            conn.close()
    except Exception:
        pass

def get_subscription(user_id):
    try:
        with _lock:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT user_id, stripe_customer_id, stripe_subscription_id, status, current_period_end, subscription_status FROM subscriptions WHERE user_id = %s", (user_id,))
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
    except Exception:
        return None

def has_active_subscription(user_id):
    try:
        sub = get_subscription(user_id)
        if not sub:
            return False
        status = sub["status"] or sub["subscription_status"]
        return status == "active"
    except Exception:
        return False

def delete_subscription(user_id):
    with _lock:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM subscriptions WHERE user_id = %s", (user_id,))
        conn.commit()
        conn.close()

def update_subscription_status(user_id, status):
    try:
        user = get_subscription(user_id)
        if user:
            with _lock:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("""
                    UPDATE subscriptions SET subscription_status = %s, status = %s
                    WHERE user_id = %s
                """, (status, status, user_id))
                conn.commit()
                conn.close()
        else:
            with _lock:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("""
                    INSERT INTO subscriptions (user_id, subscription_status, status)
                    VALUES (%s, %s, %s)
                """, (user_id, status, status))
                conn.commit()
                conn.close()
    except Exception:
        pass

def create_or_update_user(user_id, stripe_customer_id=None):
    try:
        user = get_subscription(user_id)
        if user:
            if stripe_customer_id and stripe_customer_id != user.get('stripe_customer_id'):
                with _lock:
                    conn = get_db_connection()
                    c = conn.cursor()
                    c.execute("""
                        UPDATE subscriptions SET stripe_customer_id = %s WHERE user_id = %s
                    """, (stripe_customer_id, user_id))
                    conn.commit()
                    conn.close()
        else:
            with _lock:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("""
                    INSERT INTO subscriptions (user_id, stripe_customer_id, subscription_status, status)
                    VALUES (%s, %s, 'inactive', 'inactive')
                """, (user_id, stripe_customer_id))
                conn.commit()
                conn.close()
    except Exception:
        pass

# Database will be initialized on first use
