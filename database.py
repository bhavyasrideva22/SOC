"""
database.py - SQLite database management for SOC monitoring system
Handles incident storage, user authentication, and login auditing
"""

import sqlite3
import os
from datetime import datetime, timedelta

# Database file path
DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'incidents.db')


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attacker_ip TEXT,
            attack_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            alert_severity TEXT NOT NULL,
            details TEXT,
            raw_log TEXT
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_attacker_ip ON incidents(attacker_ip)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_attack_type ON incidents(attack_type)
    ''')

    init_auth_tables(cursor)
    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully.")


def init_auth_tables(cursor=None):
    """Create users and login audit tables."""
    own_conn = cursor is None
    if own_conn:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            last_login TEXT,
            created_at TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            success INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_login_username ON login_events(username)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_login_success ON login_events(success)
    ''')

    if own_conn:
        conn.commit()
        conn.close()


def seed_default_users(default_users, hash_fn):
    """
    Insert demo users if they do not exist.
    Passwords are hashed before storage (never plain text).
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()

    for entry in default_users:
        cursor.execute('SELECT id FROM users WHERE username = ?', (entry['username'],))
        if cursor.fetchone():
            continue
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', (
            entry['username'],
            hash_fn(entry['password']),
            entry.get('role', 'analyst'),
            now,
        ))
        print(f"[DB] Created user: {entry['username']} ({entry.get('role', 'analyst')})")

    conn.commit()
    conn.close()


def get_user_by_username(username):
    """Fetch user row by username."""
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_last_login(user_id):
    """Record successful login timestamp for a user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users SET last_login = ? WHERE id = ?
    ''', (datetime.utcnow().isoformat(), user_id))
    conn.commit()
    conn.close()


def record_login_event(username, ip_address, success, details=''):
    """Store login attempt (success or failure) for monitoring."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_events (username, ip_address, success, timestamp, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        username,
        ip_address,
        1 if success else 0,
        datetime.utcnow().isoformat(),
        details,
    ))
    conn.commit()
    conn.close()


def count_recent_failed_logins(username=None, ip_address=None, window_seconds=300):
    """Count failed logins in the recent window (brute-force detection)."""
    since = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    clauses = ['success = 0', 'timestamp >= ?']
    params = [since]

    if username:
        clauses.append('username = ?')
        params.append(username)
    if ip_address:
        clauses.append('ip_address = ?')
        params.append(ip_address)

    query = f"SELECT COUNT(*) FROM login_events WHERE {' AND '.join(clauses)}"
    cursor.execute(query, params)
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_recent_login_events(limit=20):
    """Return recent login audit entries."""
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM login_events ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_incident(timestamp, attacker_ip, attack_type, risk_score, alert_severity, details, raw_log=""):
    """Insert a new security incident into the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO incidents (timestamp, attacker_ip, attack_type, risk_score, alert_severity, details, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, attacker_ip, attack_type, risk_score, alert_severity, details, raw_log))
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()
    return incident_id


def get_all_incidents(limit=100):
    """Retrieve all incidents ordered by most recent first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM incidents ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_suspicious_ips():
    """Get list of suspicious IPs with their incident counts and max risk score."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            attacker_ip,
            COUNT(*) as incident_count,
            MAX(risk_score) as max_risk,
            MAX(alert_severity) as highest_severity,
            MAX(timestamp) as last_seen
        FROM incidents
        WHERE attacker_ip IS NOT NULL AND attacker_ip != ''
        GROUP BY attacker_ip
        ORDER BY incident_count DESC
        LIMIT 20
    ''')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_attack_counts():
    """Get count of each attack type for visualization."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT attack_type, COUNT(*) as count
        FROM incidents
        GROUP BY attack_type
        ORDER BY count DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_severity_counts():
    """Get count of each severity level."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT alert_severity, COUNT(*) as count
        FROM incidents
        GROUP BY alert_severity
    ''')
    rows = cursor.fetchall()
    conn.close()
    return {row['alert_severity']: row['count'] for row in rows}


def get_recent_incidents(hours=24):
    """Get incidents from the last N hours."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM incidents
        WHERE timestamp >= datetime('now', ?)
        ORDER BY id DESC
    ''', (f'-{hours} hours',))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_total_count():
    """Get total number of incidents."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM incidents')
    count = cursor.fetchone()[0]
    conn.close()
    return count


def clear_all_incidents():
    """Clear all incidents (for testing/reset purposes)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM incidents')
    conn.commit()
    conn.close()
