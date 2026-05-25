"""
auth.py - Flask authentication for SOC analysts and administrators.

Features:
- Session-based login with werkzeug password hashing
- Role-based access (admin / analyst)
- Inactivity timeout and logout
- Failed-login tracking and brute-force alerts
"""

import os
import time
from functools import wraps

from flask import (
    session,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash

import database

# Session configuration
SESSION_TIMEOUT_SECONDS = 30 * 60  # 30 minutes inactivity
SESSION_USER_KEY = 'user_id'
SESSION_USERNAME_KEY = 'username'
SESSION_ROLE_KEY = 'role'
SESSION_LAST_ACTIVITY_KEY = 'last_activity'

# Brute-force detection for login attempts
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 5 * 60  # 5 minutes

# Default demo credentials (passwords stored hashed in SQLite only)
DEFAULT_USERS = [
    {'username': 'admin', 'password': 'admin123', 'role': 'admin'},
    {'username': 'analyst', 'password': 'analyst123', 'role': 'analyst'},
]


def init_auth(app):
    """Register auth hooks and seed default users."""
    app.secret_key = os.environ.get(
        'FLASK_SECRET_KEY',
        'soc-monitor-change-this-in-production-2024',
    )
    app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_TIMEOUT_SECONDS
    database.init_auth_tables()
    database.seed_default_users(DEFAULT_USERS, hash_password)


def hash_password(plain_password):
    """Hash a password with werkzeug (never store plain text)."""
    return generate_password_hash(plain_password)


def verify_password(stored_hash, plain_password):
    """Verify plain password against stored hash."""
    return check_password_hash(stored_hash, plain_password)


def _touch_session():
    """Update last activity timestamp for inactivity logout."""
    session[SESSION_LAST_ACTIVITY_KEY] = time.time()
    session.modified = True


def is_session_valid():
    """Return True if user is logged in and session has not expired."""
    if SESSION_USERNAME_KEY not in session:
        return False
    last = session.get(SESSION_LAST_ACTIVITY_KEY)
    if last is None:
        return False
    if time.time() - last > SESSION_TIMEOUT_SECONDS:
        return False
    return True


def login_user(user):
    """Create authenticated session after successful login."""
    session.permanent = True
    session[SESSION_USER_KEY] = user['id']
    session[SESSION_USERNAME_KEY] = user['username']
    session[SESSION_ROLE_KEY] = user['role']
    _touch_session()


def logout_user():
    """Clear all session data."""
    session.clear()


def get_current_user():
    """Return current session user dict or None."""
    if not is_session_valid():
        return None
    return {
        'id': session.get(SESSION_USER_KEY),
        'username': session.get(SESSION_USERNAME_KEY),
        'role': session.get(SESSION_ROLE_KEY),
    }


def get_client_ip():
    """Best-effort client IP for login audit logs."""
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()


def authenticate(username, password):
    """
    Validate credentials against SQLite.
    Returns (user_dict, error_message).
    """
    username = (username or '').strip()
    password = password or ''

    if not username or not password:
        return None, 'Invalid username or password'

    user = database.get_user_by_username(username)
    if not user or not verify_password(user['password_hash'], password):
        return None, 'Invalid username or password'

    return user, None


def record_failed_login(username, ip_address=None):
    """Log failed attempt and check for brute-force patterns."""
    ip = ip_address or get_client_ip()
    database.record_login_event(
        username=username or 'unknown',
        ip_address=ip,
        success=False,
        details='Authentication failure',
    )
    print(f"[AUTH] Failed login for '{username}' from {ip}")

    failed_count = database.count_recent_failed_logins(
        username=username,
        ip_address=ip,
        window_seconds=BRUTE_FORCE_WINDOW_SECONDS,
    )
    if failed_count >= BRUTE_FORCE_THRESHOLD:
        _raise_brute_force_alert(username, ip, failed_count)


def record_successful_login(user):
    """Log successful authentication."""
    ip = get_client_ip()
    database.record_login_event(
        username=user['username'],
        ip_address=ip,
        success=True,
        details='Login successful',
    )
    database.update_last_login(user['id'])
    print(f"[AUTH] Login successful: {user['username']} ({user['role']}) from {ip}")


def _raise_brute_force_alert(username, ip_address, attempt_count):
    """Generate SOC alert when multiple failed logins are detected."""
    details = (
        f'Brute-force login attempt detected: {attempt_count} failed logins '
        f'for user "{username}" from {ip_address} within '
        f'{BRUTE_FORCE_WINDOW_SECONDS // 60} minutes'
    )
    print(f"[AUTH ALERT] {details}")
    database.record_login_event(
        username=username or 'unknown',
        ip_address=ip_address,
        success=False,
        details=details,
    )
    try:
        from datetime import datetime
        from alerts import generate_alert
        alert = generate_alert(
            attack_type='brute_force',
            attacker_ip=ip_address if ip_address != 'unknown' else '',
            details=details,
        )
        database.insert_incident(
            timestamp=alert['timestamp'],
            attacker_ip=alert['attacker_ip'],
            attack_type=alert['attack_type'],
            risk_score=alert['risk_score'],
            alert_severity=alert['alert_severity'],
            details=alert['details'],
            raw_log=f'AUTH: {details}',
        )
    except Exception as e:
        print(f"[AUTH] Could not create brute-force incident: {e}")


def login_required(f):
    """Decorator: require authenticated session; redirect to login for HTML."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_session_valid():
            logout_user()
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'redirect': url_for('login')}), 401
            return redirect(url_for('login'))
        _touch_session()
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Decorator: require admin role."""

    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        if user['role'] != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required for this action.', 'warning')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated


def roles_required(*roles):
    """Decorator factory: restrict route to given roles."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            if user['role'] not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Forbidden'}), 403
                flash('You do not have permission to access this resource.', 'warning')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)

        return decorated

    return decorator
