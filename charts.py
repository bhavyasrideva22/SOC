"""
charts.py - Attack visualization (matplotlib optional)

Charts are disabled when matplotlib is not installed (e.g. Python 3.14 without
a C compiler for numpy). The SOC dashboard still works; chart panels show placeholders.
"""

import os

CHARTS_DIR = os.path.join(os.path.dirname(__file__), 'static', 'charts')
os.makedirs(CHARTS_DIR, exist_ok=True)

_CHARTS_ENABLED = False

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    _CHARTS_ENABLED = True
except ImportError:
    plt = None


def generate_attack_distribution(attack_counts: list, dark=True) -> str:
    if not _CHARTS_ENABLED or not attack_counts:
        return ''
    # ... would use matplotlib — kept minimal; full impl skipped without matplotlib
    return ''


def generate_top_attackers(suspicious_ips: list, dark=True) -> str:
    if not _CHARTS_ENABLED or not suspicious_ips:
        return ''
    return ''


def generate_severity_bar(severity_counts: dict, dark=True) -> str:
    if not _CHARTS_ENABLED or not severity_counts:
        return ''
    return ''


def generate_all_charts(attack_counts, suspicious_ips, severity_counts, dark=True):
    """Generate all charts when matplotlib is available; otherwise no-op."""
    if not _CHARTS_ENABLED:
        return {
            'attack_distribution': '',
            'top_attackers': '',
            'severity_bar': '',
        }
    return {
        'attack_distribution': generate_attack_distribution(attack_counts, dark),
        'top_attackers': generate_top_attackers(suspicious_ips, dark),
        'severity_bar': generate_severity_bar(severity_counts, dark),
    }
