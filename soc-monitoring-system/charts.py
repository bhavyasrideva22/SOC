"""
charts.py - Attack visualization using Matplotlib
Generates security charts for the SOC dashboard
"""

import os
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server use
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime

CHARTS_DIR = os.path.join(os.path.dirname(__file__), 'static', 'charts')
os.makedirs(CHARTS_DIR, exist_ok=True)

# Color palette for charts
COLORS = {
    'brute_force':        '#ff2d55',
    'malware':            '#ff3b30',
    'unauthorized_access':'#ff9500',
    'port_scan':          '#ffcc00',
    'failed_login':       '#34c759',
    'unknown':            '#636366',
}

DARK_BG   = '#0d1117'
LIGHT_BG  = '#ffffff'
GRID_DARK = '#21262d'
TEXT_DARK = '#e6edf3'
TEXT_LIGHT= '#1a1a2e'


def _apply_style(ax, fig, dark=True):
    bg   = DARK_BG  if dark else LIGHT_BG
    text = TEXT_DARK if dark else TEXT_LIGHT
    grid = GRID_DARK if dark else '#e0e0e0'
    fig.patch.set_facecolor(bg)
    ax.set_facecolor(bg)
    ax.tick_params(colors=text, labelsize=9)
    ax.xaxis.label.set_color(text)
    ax.yaxis.label.set_color(text)
    ax.title.set_color(text)
    for spine in ax.spines.values():
        spine.set_edgecolor(grid)
    ax.yaxis.grid(True, color=grid, linestyle='--', linewidth=0.5, alpha=0.7)
    ax.set_axisbelow(True)


def generate_attack_distribution(attack_counts: list, dark=True) -> str:
    """
    Generate a donut chart showing distribution of attack types.
    Returns the filepath of the saved chart.
    """
    if not attack_counts:
        return ''

    labels = [r['attack_type'].replace('_', ' ').title() for r in attack_counts]
    values = [r['count'] for r in attack_counts]
    colors = [COLORS.get(r['attack_type'], '#636366') for r in attack_counts]

    bg = DARK_BG if dark else LIGHT_BG
    text = TEXT_DARK if dark else TEXT_LIGHT

    fig, ax = plt.subplots(figsize=(5.5, 4), dpi=100)
    fig.patch.set_facecolor(bg)
    ax.set_facecolor(bg)

    wedges, texts, autotexts = ax.pie(
        values,
        labels=None,
        colors=colors,
        autopct='%1.0f%%',
        pctdistance=0.78,
        startangle=140,
        wedgeprops=dict(width=0.55, edgecolor=bg, linewidth=2),
    )
    for at in autotexts:
        at.set_color(text)
        at.set_fontsize(8)

    ax.legend(
        wedges, labels,
        loc='lower center',
        bbox_to_anchor=(0.5, -0.12),
        ncol=2,
        fontsize=7.5,
        frameon=False,
        labelcolor=text,
    )
    ax.set_title('Attack Distribution', color=text, fontsize=11, pad=10, fontweight='bold')

    path = os.path.join(CHARTS_DIR, 'attack_distribution.png')
    plt.tight_layout()
    plt.savefig(path, dpi=100, bbox_inches='tight', facecolor=bg)
    plt.close()
    return path


def generate_top_attackers(suspicious_ips: list, dark=True) -> str:
    """
    Generate a horizontal bar chart of top attacking IPs.
    Returns the filepath of the saved chart.
    """
    if not suspicious_ips:
        return ''

    top = suspicious_ips[:8]
    ips = [r['attacker_ip'] for r in top]
    counts = [r['incident_count'] for r in top]
    bar_colors = ['#ff2d55' if c >= 5 else '#ff9500' if c >= 3 else '#ffcc00' for c in counts]

    bg = DARK_BG if dark else LIGHT_BG
    text = TEXT_DARK if dark else TEXT_LIGHT

    fig, ax = plt.subplots(figsize=(5.5, max(3, len(ips) * 0.55)), dpi=100)
    _apply_style(ax, fig, dark)

    bars = ax.barh(ips, counts, color=bar_colors, height=0.6, edgecolor='none')
    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
            str(count), va='center', ha='left', color=text, fontsize=9
        )
    ax.set_xlabel('Incident Count', color=text, fontsize=9)
    ax.set_title('Top Attacking IPs', color=text, fontsize=11, pad=10, fontweight='bold')
    ax.tick_params(axis='y', labelsize=8)
    ax.invert_yaxis()

    path = os.path.join(CHARTS_DIR, 'top_attackers.png')
    plt.tight_layout()
    plt.savefig(path, dpi=100, bbox_inches='tight', facecolor=bg)
    plt.close()
    return path


def generate_severity_bar(severity_counts: dict, dark=True) -> str:
    """
    Generate a bar chart of alerts by severity level.
    Returns the filepath of the saved chart.
    """
    severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    sev_colors = {'LOW': '#34c759', 'MEDIUM': '#ffcc00', 'HIGH': '#ff9500', 'CRITICAL': '#ff2d55'}

    labels = [s for s in severity_order if s in severity_counts]
    values = [severity_counts[s] for s in labels]
    colors = [sev_colors[s] for s in labels]

    if not labels:
        return ''

    bg = DARK_BG if dark else LIGHT_BG
    text = TEXT_DARK if dark else TEXT_LIGHT

    fig, ax = plt.subplots(figsize=(5, 3.5), dpi=100)
    _apply_style(ax, fig, dark)

    bars = ax.bar(labels, values, color=colors, width=0.5, edgecolor='none', zorder=3)
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
            str(val), ha='center', va='bottom', color=text, fontsize=10, fontweight='bold'
        )
    ax.set_ylabel('Alert Count', color=text, fontsize=9)
    ax.set_title('Alerts by Severity', color=text, fontsize=11, pad=10, fontweight='bold')

    path = os.path.join(CHARTS_DIR, 'severity_bar.png')
    plt.tight_layout()
    plt.savefig(path, dpi=100, bbox_inches='tight', facecolor=bg)
    plt.close()
    return path


def generate_all_charts(attack_counts, suspicious_ips, severity_counts, dark=True):
    """Generate all charts and return their paths."""
    return {
        'attack_distribution': generate_attack_distribution(attack_counts, dark),
        'top_attackers': generate_top_attackers(suspicious_ips, dark),
        'severity_bar': generate_severity_bar(severity_counts, dark),
    }
