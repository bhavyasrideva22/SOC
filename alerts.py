"""
alerts.py - SOC alert generation system
Formats and outputs security alerts in SOC-style format
"""

from datetime import datetime
from risk_engine import get_risk_score, get_threat_level, get_alert_severity, score_summary

# Alert message templates per attack type
ALERT_TEMPLATES = {
    'failed_login': {
        'title': 'Suspicious Login Detected',
        'description': 'A failed authentication attempt has been recorded.',
    },
    'brute_force': {
        'title': 'Brute-Force Attack Detected',
        'description': 'Multiple failed logins from a single source indicate a brute-force attack.',
    },
    'port_scan': {
        'title': 'Port Scanning Activity Detected',
        'description': 'Systematic port probing detected — possible reconnaissance activity.',
    },
    'malware': {
        'title': 'Malware Signature Detected',
        'description': 'A known malware signature has been identified in log data.',
    },
    'unauthorized_access': {
        'title': 'Unauthorized Access Attempt',
        'description': 'An attempt to access restricted resources without authorization.',
    },
    'unknown': {
        'title': 'Unknown Threat Detected',
        'description': 'An unclassified suspicious event was recorded.',
    },
}

# Severity icons for CLI output
SEVERITY_ICONS = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
}


def generate_alert(attack_type: str, attacker_ip: str = '', details: str = '') -> dict:
    """
    Generate a structured SOC alert dict for a given attack type.
    Returns a full alert object ready for storage or display.
    """
    score = get_risk_score(attack_type)
    summary = score_summary(score)
    template = ALERT_TEMPLATES.get(attack_type, ALERT_TEMPLATES['unknown'])
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    alert = {
        'timestamp': timestamp,
        'attack_type': attack_type,
        'attacker_ip': attacker_ip or 'Unknown',
        'risk_score': score,
        'threat_level': summary['threat_level'],
        'alert_severity': summary['severity'],
        'title': template['title'],
        'description': template['description'],
        'details': details or template['description'],
        'color': summary['color'],
    }

    return alert


def format_alert_text(alert: dict) -> str:
    """Format alert as a human-readable SOC-style string for CLI/logs."""
    icon = SEVERITY_ICONS.get(alert['alert_severity'], '⚪')
    sep = '=' * 55
    return (
        f"\n{sep}\n"
        f"{icon} [{alert['alert_severity']} ALERT] {alert['title']}\n"
        f"  Time      : {alert['timestamp']}\n"
        f"  IP        : {alert['attacker_ip']}\n"
        f"  Type      : {alert['attack_type'].replace('_', ' ').title()}\n"
        f"  Risk Score: {alert['risk_score']}\n"
        f"  Threat    : {alert['threat_level']}\n"
        f"  Details   : {alert['details']}\n"
        f"{sep}\n"
    )


def print_alert(alert: dict):
    """Print a formatted alert to the console."""
    try:
        print(format_alert_text(alert))
    except UnicodeEncodeError:
        print(format_alert_text(alert).encode('ascii', errors='replace').decode('ascii'))


def get_alert_badge_class(severity: str) -> str:
    """Return Bootstrap badge class for a given severity (for HTML templates)."""
    classes = {
        'CRITICAL': 'danger',
        'HIGH':     'warning',
        'MEDIUM':   'info',
        'LOW':      'success',
    }
    return classes.get(severity, 'secondary')
