# === database/db.py ===
import psycopg2
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "dbname": "network_vigilance",
    "user": "postgres",
    "password": "1234",  # Replace with your actual password
    "host": "localhost",
    "port": "5432"
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def log_prediction_session(timestamp, total_flows, malicious_flows):
    conn = get_db_connection()
    cur = conn.cursor()

    # Get the most recent prediction log
    cur.execute("""
        SELECT timestamp, total_flows, malicious_flows
        FROM prediction_logs
        ORDER BY timestamp DESC
        LIMIT 1;
    """)
    last_log = cur.fetchone()

    # Check for redundancy (optional: add a time gap condition)
    if last_log:
        last_total, last_malicious = last_log[1], last_log[2]
        if last_total == total_flows and last_malicious == malicious_flows:
            print("[SKIP] Duplicate prediction result — not logging again.")
            cur.close()
            conn.close()
            return

    # Log new prediction session
    cur.execute("""
        INSERT INTO prediction_logs (timestamp, total_flows, malicious_flows)
        VALUES (%s, %s, %s);
    """, (timestamp, total_flows, malicious_flows))

    conn.commit()
    cur.close()
    conn.close()


def log_malicious_flow(src_ip, timestamp, predicted_by, model_score, was_blocked, session_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO malicious_flows (src_ip, timestamp, predicted_by, model_score, was_blocked, session_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (src_ip, session_id) DO NOTHING;
        """, (src_ip, timestamp, predicted_by, model_score, was_blocked, session_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Could not log malicious flow for IP {src_ip}: {e}")

def log_blocked_ip(src_ip):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO blocked_ips (src_ip)
        VALUES (%s);
    """, (src_ip,))
    conn.commit()
    cur.close()
    conn.close()

def get_all_blocked_ips():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, src_ip, timestamp FROM blocked_ips ORDER BY timestamp DESC;")
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

def unblock_ip_by_id(ip_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM blocked_ips WHERE id = %s;", (ip_id,))
    conn.commit()
    cur.close()
    conn.close()

def get_all_prediction_logs():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, timestamp, total_flows, malicious_flows FROM prediction_logs ORDER BY timestamp DESC;")
    logs = cur.fetchall()
    cur.close()
    conn.close()
    return logs

def get_all_malicious_flows():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT id, src_ip, timestamp, predicted_by, model_score, was_blocked, session_id
        FROM malicious_flows
        ORDER BY timestamp DESC;
    """)
    flows = cur.fetchall()
    cur.close()
    conn.close()
    return flows


def delete_prediction_log_by_id(log_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM prediction_logs WHERE id = %s;", (log_id,))
    conn.commit()
    cur.close()
    conn.close()

def get_flows_by_session_id(session_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT id, src_ip, timestamp, predicted_by, model_score, was_blocked, session_id
        FROM malicious_flows
        WHERE session_id = %s
        ORDER BY timestamp DESC;
    """, (session_id,))
    flows = cur.fetchall()
    cur.close()
    conn.close()
    return flows


