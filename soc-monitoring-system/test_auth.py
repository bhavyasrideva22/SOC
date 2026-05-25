"""
test_auth.py - Authentication system test examples

Run from project directory:
    python test_auth.py

Requires Flask test client (included with Flask).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import database
import auth
from app import app


def run_tests():
    """Execute sample login workflow tests."""
    database.init_db()
    auth.init_auth(app)

    client = app.test_client()
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  PASS: {name}")
            passed += 1
        else:
            print(f"  FAIL: {name}")
            failed += 1

    print("\n=== SOC Authentication Tests ===\n")

    # 1. Unauthenticated dashboard redirect
    r = client.get('/dashboard', follow_redirects=False)
    check('Unauthenticated /dashboard redirects to login', r.status_code == 302 and '/login' in r.location)

    # 2. Login page loads
    r = client.get('/login')
    check('Login page returns 200', r.status_code == 200)
    check('Login page contains username field', b'username' in r.data)

    # 3. Invalid credentials
    r = client.post('/login', data={'username': 'admin', 'password': 'wrong'}, follow_redirects=True)
    check('Invalid login shows error', b'Invalid username or password' in r.data)

    # 4. Valid admin login
    r = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    check('Valid admin login succeeds', r.status_code == 200)
    check('Welcome message after login', b'Welcome' in r.data or b'welcome' in r.data.lower())

    # 5. Dashboard accessible when logged in
    r = client.get('/dashboard')
    check('Authenticated dashboard returns 200', r.status_code == 200)

    # 6. API protected
    client.get('/logout')
    r = client.get('/api/stats')
    check('API returns 401 when logged out', r.status_code == 401)

    # 7. Analyst login
    r = client.post('/login', data={'username': 'analyst', 'password': 'analyst123'}, follow_redirects=True)
    check('Analyst login succeeds', r.status_code == 200)

    # 8. Analyst cannot simulate (admin-only API)
    r = client.post('/api/simulate', json={'log': 'test'}, content_type='application/json')
    check('Analyst blocked from simulate API', r.status_code == 403)

    # 9. Logout
    r = client.get('/logout', follow_redirects=True)
    check('Logout redirects to login', '/login' in (r.request.path or '') or b'logged out' in r.data.lower())

    # 10. Password hashing in database
    user = database.get_user_by_username('admin')
    check('Admin user exists in DB', user is not None)
    check('Password stored as hash (not plain)', user and user['password_hash'] != 'admin123')
    check('Hash verifies with werkzeug', user and auth.verify_password(user['password_hash'], 'admin123'))

    print(f"\n=== Results: {passed} passed, {failed} failed ===\n")
    return failed == 0


if __name__ == '__main__':
    ok = run_tests()
    sys.exit(0 if ok else 1)
