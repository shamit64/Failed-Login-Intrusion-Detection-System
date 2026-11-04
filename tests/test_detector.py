"""Unit tests for failed_login_ids.py  -  run with:  python3 -m unittest discover tests"""
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from failed_login_ids import Detector, Event, parse_line  # noqa: E402

T0 = datetime(2026, 11, 1, 10, 0, 0)


def fail(sec, ip="1.2.3.4", user="root"):
    return Event(T0 + timedelta(seconds=sec), ip, user, False, 0)


def ok(sec, ip="1.2.3.4", user="root"):
    return Event(T0 + timedelta(seconds=sec), ip, user, True, 0)


def run(det, events):
    alerts = []
    for e in events:
        alerts += det.process(e)
    return [a.kind for a in alerts]


class TestParsing(unittest.TestCase):
    def test_ssh_failed_password(self):
        e = parse_line("Nov  1 10:05:00 srv sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2", 1, 2026)
        self.assertEqual((e.ip, e.user, e.success), ("203.0.113.45", "root", False))
        self.assertEqual(e.timestamp, datetime(2026, 11, 1, 10, 5, 0))

    def test_invalid_user(self):
        e = parse_line("Nov  1 10:05:00 srv sshd[1]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2", 1, 2026)
        self.assertEqual((e.ip, e.user), ("10.0.0.1", "admin"))

    def test_accepted_login(self):
        e = parse_line("Nov  1 10:05:00 srv sshd[1]: Accepted password for bob from 10.0.0.8 port 22 ssh2", 1, 2026)
        self.assertTrue(e.success)

    def test_iso_timestamp_app_log(self):
        e = parse_line("2026-11-01T10:05:00 app: LOGIN FAILED user=alice ip=192.0.2.5", 1, 2026)
        self.assertEqual((e.ip, e.user, e.success), ("192.0.2.5", "alice", False))

    def test_leap_day(self):
        e = parse_line("Feb 29 10:00:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2", 1, 2028)
        self.assertEqual(e.timestamp.day, 29)

    def test_unrelated_line_ignored(self):
        self.assertIsNone(parse_line("Nov  1 10:40:00 srv CRON[1]: session opened for user root", 1, 2026))


class TestDetection(unittest.TestCase):
    def test_brute_force_triggers_at_threshold(self):
        kinds = run(Detector(threshold=5, window=60), [fail(i * 5) for i in range(5)])
        self.assertIn("BRUTE_FORCE", kinds)

    def test_below_threshold_no_alert(self):
        self.assertEqual(run(Detector(threshold=5, window=60), [fail(i * 5) for i in range(4)]), [])

    def test_slow_failures_outside_window_ignored(self):
        # 5 failures, 2 minutes apart: never 5 inside one 60s window
        self.assertEqual(run(Detector(threshold=5, window=60), [fail(i * 120) for i in range(5)]), [])

    def test_success_after_brute_force_is_critical(self):
        kinds = run(Detector(), [fail(i) for i in range(5)] + [ok(10)])
        self.assertIn("SUCCESS_AFTER_BRUTE_FORCE", kinds)

    def test_password_spray(self):
        events = [fail(i, user=u) for i, u in enumerate(["admin", "test", "oracle", "ubuntu"])]
        self.assertIn("PASSWORD_SPRAY", run(Detector(threshold=10), events))

    def test_targeted_account(self):
        events = [fail(i, ip=f"10.0.0.{i}", user="carol") for i in range(4)]
        self.assertIn("TARGETED_ACCOUNT", run(Detector(), events))

    def test_whitelist(self):
        self.assertEqual(run(Detector(whitelist=["1.2.3.4"]), [fail(i) for i in range(10)]), [])

    def test_alert_not_repeated(self):
        kinds = run(Detector(threshold=5), [fail(i) for i in range(20)])
        self.assertEqual(kinds.count("BRUTE_FORCE"), 1)


class TestCommandLine(unittest.TestCase):
    def test_sample_log_end_to_end(self):
        log = os.path.join(ROOT, "sample_logs", "sample_auth.log")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "failed_login_ids.py"), log, "--year", "2026"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)  # alerts found
        self.assertIn("SUCCESS_AFTER_BRUTE_FORCE: 203.0.113.45", r.stdout)
        self.assertIn("Alerts raised:     5", r.stdout)


if __name__ == "__main__":
    unittest.main()
