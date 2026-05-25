"""
monitor.py - Real-time log monitoring engine using Watchdog
Watches log files for changes and triggers threat detection pipeline
"""

import os
import time
import threading
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import detector
import database
import alerts
from risk_engine import get_risk_score

# Path to the log file being monitored
LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'sample.log')

# Global flag to control monitoring loop
_monitoring = False
_observer = None
_monitor_thread = None

# Track file position to read only new lines
_file_positions = {}


def _process_log_line(line: str):
    """Run a single log line through detection and storage pipeline."""
    line = line.strip()
    if not line:
        return

    threats = detector.detect_threats(line)
    for threat in threats:
        alert = alerts.generate_alert(
            attack_type=threat['attack_type'],
            attacker_ip=threat.get('attacker_ip', ''),
            details=threat.get('details', ''),
        )
        alerts.print_alert(alert)

        # Store in database
        database.insert_incident(
            timestamp=alert['timestamp'],
            attacker_ip=alert['attacker_ip'],
            attack_type=alert['attack_type'],
            risk_score=alert['risk_score'],
            alert_severity=alert['alert_severity'],
            details=alert['details'],
            raw_log=line,
        )


def _read_new_lines(filepath: str):
    """Read only the new lines added to a file since last read."""
    last_pos = _file_positions.get(filepath, 0)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            _file_positions[filepath] = f.tell()
        for line in new_lines:
            _process_log_line(line)
    except FileNotFoundError:
        print(f"[MONITOR] Log file not found: {filepath}")
    except Exception as e:
        print(f"[MONITOR] Error reading log file: {e}")


class LogFileHandler(FileSystemEventHandler):
    """Watchdog handler that reacts to log file modifications."""

    def __init__(self, filepath):
        self.filepath = os.path.abspath(filepath)

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.filepath:
            _read_new_lines(self.filepath)


def process_existing_logs():
    """Process all existing log lines on startup."""
    print(f"[MONITOR] Processing existing logs from {LOG_FILE} ...")
    detector.reset_tracker()
    _file_positions[LOG_FILE] = 0
    _read_new_lines(LOG_FILE)
    print(f"[MONITOR] Finished processing existing logs.")


def start_monitoring():
    """Start watchdog observer to monitor log file in background."""
    global _monitoring, _observer, _monitor_thread

    if _monitoring:
        print("[MONITOR] Already running.")
        return

    database.init_db()
    process_existing_logs()

    log_dir = os.path.dirname(os.path.abspath(LOG_FILE))
    handler = LogFileHandler(LOG_FILE)

    _observer = Observer()
    _observer.schedule(handler, path=log_dir, recursive=False)
    _observer.start()
    _monitoring = True
    print(f"[MONITOR] Watching {LOG_FILE} for changes...")


def stop_monitoring():
    """Stop watchdog observer."""
    global _monitoring, _observer
    if _observer:
        _observer.stop()
        _observer.join()
        _monitoring = False
        print("[MONITOR] Monitoring stopped.")


def is_monitoring() -> bool:
    return _monitoring


def append_log(line: str):
    """Append a line to the monitored log file (for testing/simulation)."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(line.strip() + '\n')
