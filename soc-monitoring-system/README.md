# 🛡️ SOC Log Monitoring & Threat Detection System

A Python-based mini **SIEM (Security Information and Event Management)** system for real-time log analysis, threat detection, incident tracking, and SOC dashboard visualization.

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🔍 Real-Time Monitoring | Watchdog-based log file watching |
| 🧠 Threat Detection | Detects brute force, port scans, malware, unauthorized access |
| 📊 Risk Scoring | Numeric scores + LOW / MEDIUM / HIGH levels |
| 🚨 Alert System | SOC-style alerts with severity classification |
| 🗄️ SQLite Storage | Persistent incident database |
| 🌐 Flask Dashboard | Live web SOC dashboard with auto-refresh |
| 📈 Charts | Matplotlib attack distribution, severity, top IPs |
| 🌙 Light/Dark Mode | Toggle between dark and light dashboard themes |
| 💉 Log Simulator | Inject events directly from the dashboard |
| 🔐 Secure Login | Flask sessions, hashed passwords, role-based access |
| 👤 RBAC | Admin (full access) vs Analyst (monitoring only) |
| 🚨 Auth Monitoring | Failed login tracking and brute-force alerts |

---

## 🔐 Authentication

| Role | Username | Password | Access |
|------|----------|----------|--------|
| Admin | `admin` | `admin123` | Full dashboard + log simulator |
| Analyst | `analyst` | `analyst123` | Monitoring view only |

**Login workflow:** Open app → `/login` → enter credentials → session created → `/dashboard`

- Passwords hashed with `werkzeug.security` (never stored in plain text)
- Sessions expire after **30 minutes** of inactivity
- **5+ failed logins** in 5 minutes triggers a brute-force SOC alert
- Use `/logout` or the dashboard **Logout** button to end a session

```bash
# Run authentication tests
python test_auth.py
```

---

## 📁 Project Structure

```
soc-monitoring-system/
├── app.py              # Flask backend, login & protected routes
├── auth.py             # Session auth, RBAC, brute-force detection
├── monitor.py          # Watchdog log monitoring engine
├── detector.py         # Threat detection engine
├── database.py         # SQLite incidents + users + login audit
├── alerts.py           # Alert generation system
├── risk_engine.py      # Risk scoring & threat levels
├── charts.py           # Matplotlib chart generation
├── test_auth.py        # Authentication test suite
├── requirements.txt
├── runtime.txt
├── logs/
│   └── sample.log      # Sample log file (monitored)
├── database/
│   └── incidents.db    # SQLite database (auto-created)
├── templates/
│   ├── login.html      # Bootstrap login page
│   └── index.html      # SOC Dashboard HTML
├── static/
│   ├── style.css       # Dashboard + login styles
│   └── charts/         # Generated chart images
└── reports/            # (optional) exported reports
```

---

## ⚙️ Installation

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py
```

Open your browser at: **http://localhost:5000** — you will be redirected to the login page.

---

## 🌐 Deployment

### Render / Railway

**Start command:**
```
gunicorn app:app
```

**Environment:** Python 3.11.9 (see `runtime.txt`)

---

## 📋 Attack Detection

| Attack Type | Trigger Pattern | Risk Score |
|---|---|---|
| Failed Login | `Failed login from <IP>` | +10 |
| Brute Force | 3+ failed logins from same IP | +40 |
| Port Scan | `Port scan detected from <IP>` | +30 |
| Malware | `Malware signature detected` | +50 |
| Unauthorized Access | `Unauthorized access attempt from <IP>` | +35 |

**Threat Levels:**
- 🟢 0–30 = **LOW**
- 🟡 31–60 = **MEDIUM**
- 🔴 61+ = **HIGH** → **CRITICAL**

---

## 💡 Usage

### Add log lines to `logs/sample.log` and they'll be detected automatically.

Or use the **Simulate** panel on the dashboard to inject events live.

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Main SOC dashboard |
| `/api/incidents` | GET | All incidents (JSON) |
| `/api/stats` | GET | Summary statistics |
| `/api/simulate` | POST | Inject a log line |
| `/api/reset` | POST | Clear all incidents |
| `/api/charts/refresh` | POST | Regenerate charts |

---

## 🧪 Testing

```bash
# Inject sample events via curl
curl -X POST http://localhost:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"log": "Failed login from 10.0.0.1"}'
```

---

## 📝 Resume Description

> Built a Python-based SOC monitoring and threat detection system capable of real-time log analysis, suspicious activity detection (brute force, port scans, malware), alert generation, incident tracking, risk scoring, and SIEM-style SOC dashboard visualization with light/dark mode support.

---

## 🤝 License

MIT License — free to use and modify.
