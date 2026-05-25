"""
database.py - SQLite database management for SOC monitoring system
Handles incident storage, retrieval, and management
"""

import sqlite3
import os
from datetime import datetime

# Database file path
DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'incidents.db')


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

    # Index for faster IP lookups
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_attacker_ip ON incidents(attacker_ip)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_attack_type ON incidents(attack_type)
    ''')

    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully.")


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
