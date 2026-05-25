"""
risk_engine.py - Risk scoring and threat level calculation
Assigns numerical risk scores and threat levels to detected incidents
"""

# Risk score weights for each attack type
RISK_SCORES = {
    'failed_login':       10,
    'brute_force':        40,
    'port_scan':          30,
    'malware':            50,
    'unauthorized_access': 35,
    'unknown':            5,
}

# Threat level thresholds
THREAT_LEVELS = [
    (61, 'HIGH'),
    (31, 'MEDIUM'),
    (0,  'LOW'),
]

# Alert severity mapping
ALERT_SEVERITY = {
    'HIGH':   'CRITICAL',
    'MEDIUM': 'HIGH',
    'LOW':    'LOW',
}


def get_risk_score(attack_type: str) -> int:
    """Return the base risk score for a given attack type."""
    return RISK_SCORES.get(attack_type, RISK_SCORES['unknown'])


def get_threat_level(score: int) -> str:
    """Determine threat level based on cumulative risk score."""
    for threshold, level in THREAT_LEVELS:
        if score >= threshold:
            return level
    return 'LOW'


def get_alert_severity(threat_level: str) -> str:
    """Map threat level to SOC alert severity label."""
    return ALERT_SEVERITY.get(threat_level, 'LOW')


def calculate_ip_risk(incidents: list) -> int:
    """Calculate cumulative risk score for a set of incidents from one IP."""
    total = sum(incident.get('risk_score', 0) for incident in incidents)
    return min(total, 100)  # cap at 100


def get_severity_color(severity: str) -> str:
    """Return a color hex code for a given severity level (for UI/charts)."""
    colors = {
        'CRITICAL': '#ff2d55',
        'HIGH':     '#ff9500',
        'MEDIUM':   '#ffcc00',
        'LOW':      '#34c759',
    }
    return colors.get(severity, '#8e8e93')


def score_summary(score: int) -> dict:
    """Return a full risk summary dict for a given score."""
    threat_level = get_threat_level(score)
    severity = get_alert_severity(threat_level)
    return {
        'score': score,
        'threat_level': threat_level,
        'severity': severity,
        'color': get_severity_color(severity),
    }
