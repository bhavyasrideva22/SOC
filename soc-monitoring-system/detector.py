"""
detector.py - Threat detection engine
Parses log lines and identifies suspicious security events
"""

import re
from collections import defaultdict
from datetime import datetime

# Regex patterns for log analysis
PATTERNS = {
    'failed_login': re.compile(
        r'failed\s+login\s+from\s+([\d\.]+)', re.IGNORECASE
    ),
    'port_scan': re.compile(
        r'port\s+scan\s+detected\s+from\s+([\d\.]+)', re.IGNORECASE
    ),
    'malware': re.compile(
        r'malware\s+signature\s+detected', re.IGNORECASE
    ),
    'unauthorized_access': re.compile(
        r'unauthorized\s+access\s+attempt\s+from\s+([\d\.]+)', re.IGNORECASE
    ),
}

# Brute force detection: threshold for failed logins from same IP
BRUTE_FORCE_THRESHOLD = 3

# Track failed login counts per IP (in-memory, per session)
_failed_login_tracker = defaultdict(int)
_brute_force_flagged = set()  # IPs already flagged for brute force


def reset_tracker():
    """Reset in-memory login tracker (call on startup or test reset)."""
    global _failed_login_tracker, _brute_force_flagged
    _failed_login_tracker = defaultdict(int)
    _brute_force_flagged = set()


def extract_ip(log_line: str, pattern_key: str) -> str:
    """Extract IP address from a log line using the given pattern key."""
    match = PATTERNS[pattern_key].search(log_line)
    if match:
        try:
            return match.group(1)
        except IndexError:
            return ''
    return ''


def detect_threats(log_line: str) -> list:
    """
    Analyze a single log line and return a list of detected threat dicts.
    Each threat dict contains: attack_type, attacker_ip, details, risk_score_key
    """
    threats = []
    log_line = log_line.strip()

    if not log_line:
        return threats

    # --- Failed Login Detection ---
    if PATTERNS['failed_login'].search(log_line):
        ip = extract_ip(log_line, 'failed_login')
        _failed_login_tracker[ip] += 1
        threats.append({
            'attack_type': 'failed_login',
            'attacker_ip': ip,
            'details': f'Failed login attempt detected from {ip}',
            'raw_log': log_line,
        })

        # Check for brute force escalation
        if (
            _failed_login_tracker[ip] >= BRUTE_FORCE_THRESHOLD
            and ip not in _brute_force_flagged
        ):
            _brute_force_flagged.add(ip)
            threats.append({
                'attack_type': 'brute_force',
                'attacker_ip': ip,
                'details': (
                    f'HIGH ALERT: Possible Brute Force Attack from {ip} '
                    f'({_failed_login_tracker[ip]} failed attempts)'
                ),
                'raw_log': log_line,
            })

    # --- Port Scan Detection ---
    elif PATTERNS['port_scan'].search(log_line):
        ip = extract_ip(log_line, 'port_scan')
        threats.append({
            'attack_type': 'port_scan',
            'attacker_ip': ip,
            'details': f'Port scanning activity detected from {ip}',
            'raw_log': log_line,
        })

    # --- Malware Detection ---
    elif PATTERNS['malware'].search(log_line):
        threats.append({
            'attack_type': 'malware',
            'attacker_ip': '',
            'details': f'Malware signature detected in log: {log_line}',
            'raw_log': log_line,
        })

    # --- Unauthorized Access Detection ---
    elif PATTERNS['unauthorized_access'].search(log_line):
        ip = extract_ip(log_line, 'unauthorized_access')
        threats.append({
            'attack_type': 'unauthorized_access',
            'attacker_ip': ip,
            'details': f'Unauthorized access attempt from {ip}',
            'raw_log': log_line,
        })

    return threats


def get_failed_login_count(ip: str) -> int:
    """Return current failed login count for an IP."""
    return _failed_login_tracker.get(ip, 0)


def is_brute_force_flagged(ip: str) -> bool:
    """Check if IP has been flagged for brute force."""
    return ip in _brute_force_flagged
