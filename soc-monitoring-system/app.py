"""
app.py - Flask SOC Dashboard Backend
"""

import os
import time
from flask import Flask, render_template, jsonify, request

import database
import monitor
import charts
from alerts import get_alert_badge_class

app = Flask(__name__)

@app.context_processor
def inject_now():
    return {'now': int(time.time())}

_started = False

@app.before_request
def startup():
    global _started
    if not _started:
        _started = True
        database.init_db()
        try:
            monitor.start_monitoring()
        except Exception as e:
            print(f"[APP] Monitor start failed: {e}")


@app.route('/')
def index():
    incidents    = database.get_all_incidents(limit=50)
    susp_ips     = database.get_suspicious_ips()
    attack_cnts  = database.get_attack_counts()
    severity_map = database.get_severity_counts()
    total        = database.get_total_count()

    charts.generate_all_charts(attack_cnts, susp_ips, severity_map)

    critical = severity_map.get('CRITICAL', 0)
    high     = severity_map.get('HIGH', 0)
    medium   = severity_map.get('MEDIUM', 0)
    low      = severity_map.get('LOW', 0)

    return render_template(
        'index.html',
        incidents=incidents,
        suspicious_ips=susp_ips,
        attack_counts=attack_cnts,
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        get_badge=get_alert_badge_class,
    )


@app.route('/api/incidents')
def api_incidents():
    limit = request.args.get('limit', 20, type=int)
    return jsonify(database.get_all_incidents(limit=limit))


@app.route('/api/stats')
def api_stats():
    severity_map = database.get_severity_counts()
    attack_cnts  = database.get_attack_counts()
    susp_ips     = database.get_suspicious_ips()
    total        = database.get_total_count()
    return jsonify({
        'total':        total,
        'critical':     severity_map.get('CRITICAL', 0),
        'high':         severity_map.get('HIGH', 0),
        'medium':       severity_map.get('MEDIUM', 0),
        'low':          severity_map.get('LOW', 0),
        'attack_types': attack_cnts,
        'top_ips':      susp_ips[:5],
    })


@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    data = request.get_json(silent=True) or {}
    log_line = data.get('log', '').strip()
    if not log_line:
        return jsonify({'error': 'No log line provided'}), 400
    monitor.append_log(log_line)
    time.sleep(0.2)
    from detector import detect_threats
    from alerts import generate_alert
    threats = detect_threats(log_line)
    for threat in threats:
        alert = generate_alert(
            attack_type=threat['attack_type'],
            attacker_ip=threat.get('attacker_ip', ''),
            details=threat.get('details', ''),
        )
        database.insert_incident(
            timestamp=alert['timestamp'],
            attacker_ip=alert['attacker_ip'],
            attack_type=alert['attack_type'],
            risk_score=alert['risk_score'],
            alert_severity=alert['alert_severity'],
            details=alert['details'],
            raw_log=log_line,
        )
    return jsonify({'ok': True, 'threats_detected': len(threats)})


@app.route('/api/reset', methods=['POST'])
def api_reset():
    database.clear_all_incidents()
    monitor.process_existing_logs()
    return jsonify({'ok': True})


@app.route('/api/charts/refresh', methods=['POST'])
def refresh_charts():
    attack_cnts  = database.get_attack_counts()
    susp_ips     = database.get_suspicious_ips()
    severity_map = database.get_severity_counts()
    charts.generate_all_charts(attack_cnts, susp_ips, severity_map)
    return jsonify({'ok': True})


if __name__ == '__main__':
    database.init_db()
    monitor.start_monitoring()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
