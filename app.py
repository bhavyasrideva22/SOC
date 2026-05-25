"""
app.py - Flask SOC Dashboard Backend with secure authentication
"""

import os
import time
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session

import database
import monitor
import charts
import auth
from alerts import get_alert_badge_class

app = Flask(__name__)
auth.init_auth(app)


@app.context_processor
def inject_now():
    return {'now': int(time.time())}


@app.context_processor
def inject_user():
    return {'current_user': auth.get_current_user()}


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


@app.route('/health')
def health():
    """Render health check — must return 200 (not a redirect)."""
    return jsonify({'status': 'ok'}), 200


@app.before_request
def enforce_session_timeout():
    """Logout users after inactivity period."""
    if request.endpoint in ('login', 'static', 'health', None):
        return
    if auth.SESSION_USERNAME_KEY in session and not auth.is_session_valid():
        auth.logout_user()
        flash('Session expired due to inactivity. Please log in again.', 'warning')
        return redirect(url_for('login'))


@app.route('/')
def home():
    """Entry point: send users to dashboard or login."""
    if auth.is_session_valid():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Display login page and validate credentials."""
    if auth.is_session_valid():
        return redirect(url_for('dashboard'))

    username = ''
    success_message = request.args.get('logged_out')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user, error = auth.authenticate(username, password)
        if user:
            auth.login_user(user)
            auth.record_successful_login(user)
            flash(f'Login successful. Welcome {user["username"].title()}.', 'success')
            return redirect(url_for('dashboard'))

        auth.record_failed_login(username)
        flash('Invalid username or password', 'error')
        return render_template(
            'login.html',
            username=username,
            success_message=success_message,
        )

    return render_template('login.html', username=username, success_message=success_message)


@app.route('/logout')
def logout():
    """Clear session and return to login."""
    auth.logout_user()
    return redirect(url_for('login', logged_out='You have been logged out successfully.'))


@app.route('/dashboard')
@auth.login_required
def dashboard():
    """Protected SOC dashboard — requires authentication."""
    incidents = database.get_all_incidents(limit=50)
    susp_ips = database.get_suspicious_ips()
    attack_cnts = database.get_attack_counts()
    severity_map = database.get_severity_counts()
    total = database.get_total_count()

    charts.generate_all_charts(attack_cnts, susp_ips, severity_map)

    critical = severity_map.get('CRITICAL', 0)
    high = severity_map.get('HIGH', 0)
    medium = severity_map.get('MEDIUM', 0)
    low = severity_map.get('LOW', 0)

    user = auth.get_current_user()
    is_admin = user and user['role'] == 'admin'

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
        is_admin=is_admin,
        current_user=user,
    )


@app.route('/api/incidents')
@auth.login_required
def api_incidents():
    limit = request.args.get('limit', 20, type=int)
    return jsonify(database.get_all_incidents(limit=limit))


@app.route('/api/stats')
@auth.login_required
def api_stats():
    severity_map = database.get_severity_counts()
    attack_cnts = database.get_attack_counts()
    susp_ips = database.get_suspicious_ips()
    total = database.get_total_count()
    return jsonify({
        'total': total,
        'critical': severity_map.get('CRITICAL', 0),
        'high': severity_map.get('HIGH', 0),
        'medium': severity_map.get('MEDIUM', 0),
        'low': severity_map.get('LOW', 0),
        'attack_types': attack_cnts,
        'top_ips': susp_ips[:5],
    })


@app.route('/api/simulate', methods=['POST'])
@auth.login_required
@auth.roles_required('admin')
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
@auth.login_required
@auth.admin_required
def api_reset():
    database.clear_all_incidents()
    monitor.process_existing_logs()
    return jsonify({'ok': True})


@app.route('/api/charts/refresh', methods=['POST'])
@auth.login_required
def refresh_charts():
    attack_cnts = database.get_attack_counts()
    susp_ips = database.get_suspicious_ips()
    severity_map = database.get_severity_counts()
    charts.generate_all_charts(attack_cnts, susp_ips, severity_map)
    return jsonify({'ok': True})


@app.route('/api/auth/login-events')
@auth.login_required
@auth.admin_required
def api_login_events():
    """Admin-only: recent authentication audit log."""
    return jsonify(database.get_recent_login_events(limit=50))


if __name__ == '__main__':
    database.init_db()
    monitor.start_monitoring()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    app.run(debug=debug, host='0.0.0.0', port=port, use_reloader=False)
