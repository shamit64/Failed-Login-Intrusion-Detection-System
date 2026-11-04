#!/usr/bin/env python3
"""
failed_login_ids.py - A simple intrusion detection script.

Scans an authentication log (e.g. /var/log/auth.log, /var/log/secure) for
failed login attempts and raises an alert when a single source IP (or a
single username) fails too many times within a sliding time window.

Detects:
  * Brute force      - one IP with many failures in a short window
  * Password spraying - one IP failing against many different usernames
  * Targeted account - one username failing from many IPs
  * Success after failures - a successful login from an IP that was
                             flagged for brute force (possible compromise)

Usage:
  python3 failed_login_ids.py /var/log/auth.log
  python3 failed_login_ids.py auth.log --threshold 5 --window 60
  python3 failed_login_ids.py auth.log --json > alerts.json
  python3 failed_login_ids.py auth.log --follow          # live monitoring
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

# --------------------------------------------------------------------------- #
# Log patterns
# --------------------------------------------------------------------------- #

# Syslog timestamp, e.g. "Nov  1 10:15:32"
SYSLOG_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
# ISO-8601 timestamp, e.g. "2026-11-01T10:15:32" or "2026-11-01 10:15:32"
ISO_TS = r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)"

FAILURE_PATTERNS = [
    # sshd: Failed password for root from 1.2.3.4 port 22 ssh2
    # sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from " + IP),
    # sshd: Invalid user admin from 1.2.3.4 port 22
    re.compile(r"Invalid user (?P<user>\S+) from " + IP),
    # PAM: authentication failure; ... rhost=1.2.3.4  user=root
    re.compile(r"authentication failure;.*rhost=" + IP + r"(?:\s+user=(?P<user>\S+))?"),
    # Generic app logs: "LOGIN FAILED user=bob ip=1.2.3.4"
    re.compile(r"(?i)login failed.*?user[=:]\s*(?P<user>\S+).*?ip[=:]\s*" + IP),
]

SUCCESS_PATTERNS = [
    # sshd: Accepted password for root from 1.2.3.4 port 22 ssh2
    re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from " + IP),
    re.compile(r"(?i)login success.*?user[=:]\s*(?P<user>\S+).*?ip[=:]\s*" + IP),
]

TS_PATTERNS = [
    (re.compile("^" + ISO_TS), ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")),
    (re.compile("^" + SYSLOG_TS), ("%b %d %H:%M:%S",)),
]


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class Event:
    timestamp: datetime
    ip: str
    user: str
    success: bool
    line_no: int


@dataclass
class Alert:
    kind: str
    severity: str
    subject: str           # the IP or username the alert is about
    first_seen: str
    last_seen: str
    count: int
    details: dict = field(default_factory=dict)

    def __str__(self):
        extra = ", ".join(f"{k}={v}" for k, v in self.details.items())
        return (f"[{self.severity}] {self.kind}: {self.subject} - {self.count} events "
                f"between {self.first_seen} and {self.last_seen}"
                + (f" ({extra})" if extra else ""))


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def parse_timestamp(line, year):
    """Return a datetime from the start of the line, or None."""
    for regex, fmts in TS_PATTERNS:
        m = regex.match(line)
        if not m:
            continue
        raw = re.sub(r"\s+", " ", m.group("ts"))
        for fmt in fmts:
            try:
                # Syslog lines have no year - prepend the given/current year.
                if "%Y" not in fmt:
                    return datetime.strptime(f"{year} {raw}", "%Y " + fmt)
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


def parse_line(line, line_no, year):
    """Turn one log line into an Event, or None if it isn't a login event."""
    for patterns, success in ((FAILURE_PATTERNS, False), (SUCCESS_PATTERNS, True)):
        for regex in patterns:
            m = regex.search(line)
            if m:
                ts = parse_timestamp(line, year)
                if ts is None:
                    return None
                user = m.groupdict().get("user") or "<unknown>"
                return Event(ts, m.group("ip"), user, success, line_no)
    return None


# --------------------------------------------------------------------------- #
# Detection engine
# --------------------------------------------------------------------------- #

class Detector:
    def __init__(self, threshold=5, window=60, spray_users=4, target_ips=4,
                 whitelist=None):
        self.threshold = threshold
        self.window = timedelta(seconds=window)
        self.spray_users = spray_users
        self.target_ips = target_ips
        self.whitelist = set(whitelist or [])

        self.ip_failures = defaultdict(deque)     # ip   -> deque[Event]
        self.user_failures = defaultdict(deque)   # user -> deque[Event]
        self.flagged_ips = set()                  # IPs already alerted on
        self.alerted = set()                      # (kind, subject) de-dupe
        self.total_failures = 0
        self.total_success = 0
        self.fail_by_ip = defaultdict(int)

    @staticmethod
    def _fmt(dt):
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _prune(self, dq, now):
        while dq and now - dq[0].timestamp > self.window:
            dq.popleft()

    def _emit(self, kind, severity, subject, events, **details):
        key = (kind, subject)
        if key in self.alerted:
            return None
        self.alerted.add(key)
        return Alert(kind, severity, subject,
                     self._fmt(events[0].timestamp), self._fmt(events[-1].timestamp),
                     len(events), details)

    def process(self, ev):
        """Feed one event, return a list of new alerts (possibly empty)."""
        if ev.ip in self.whitelist:
            return []

        alerts = []

        if ev.success:
            self.total_success += 1
            if ev.ip in self.flagged_ips:
                a = self._emit("SUCCESS_AFTER_BRUTE_FORCE", "CRITICAL", ev.ip, [ev],
                               user=ev.user, line=ev.line_no)
                if a:
                    alerts.append(a)
            return alerts

        self.total_failures += 1
        self.fail_by_ip[ev.ip] += 1

        # --- per-IP sliding window -------------------------------------- #
        ip_q = self.ip_failures[ev.ip]
        ip_q.append(ev)
        self._prune(ip_q, ev.timestamp)

        if len(ip_q) >= self.threshold:
            self.flagged_ips.add(ev.ip)
            users = sorted({e.user for e in ip_q})
            a = self._emit("BRUTE_FORCE", "HIGH", ev.ip, list(ip_q),
                           window_s=int(self.window.total_seconds()),
                           users=",".join(users[:5]) + ("..." if len(users) > 5 else ""))
            if a:
                alerts.append(a)

        distinct_users = {e.user for e in ip_q}
        if len(distinct_users) >= self.spray_users:
            a = self._emit("PASSWORD_SPRAY", "HIGH", ev.ip, list(ip_q),
                           distinct_users=len(distinct_users))
            if a:
                alerts.append(a)

        # --- per-user sliding window (distributed attack) ---------------- #
        u_q = self.user_failures[ev.user]
        u_q.append(ev)
        self._prune(u_q, ev.timestamp)

        distinct_ips = {e.ip for e in u_q}
        if len(distinct_ips) >= self.target_ips:
            a = self._emit("TARGETED_ACCOUNT", "MEDIUM", ev.user, list(u_q),
                           distinct_ips=len(distinct_ips))
            if a:
                alerts.append(a)

        return alerts


# --------------------------------------------------------------------------- #
# I/O
# --------------------------------------------------------------------------- #

def read_lines(path, follow):
    """Yield lines from a file; with follow=True keep tailing it like `tail -f`."""
    with open(path, "r", errors="replace") as fh:
        while True:
            line = fh.readline()
            if line:
                yield line
            elif follow:
                time.sleep(0.5)
            else:
                return


def main():
    ap = argparse.ArgumentParser(description="Detect repeated failed logins in a log file.")
    ap.add_argument("logfile", help="path to the log file (e.g. /var/log/auth.log)")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="failures from one IP within the window to trigger an alert (default 5)")
    ap.add_argument("-w", "--window", type=int, default=60,
                    help="sliding window size in seconds (default 60)")
    ap.add_argument("--spray-users", type=int, default=4,
                    help="distinct usernames from one IP to flag password spraying (default 4)")
    ap.add_argument("--target-ips", type=int, default=4,
                    help="distinct IPs failing on one user to flag a targeted account (default 4)")
    ap.add_argument("--whitelist", nargs="*", default=[],
                    help="IPs to ignore (e.g. your monitoring host)")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year to assume for syslog timestamps (default: current year)")
    ap.add_argument("--json", action="store_true", help="output alerts as JSON")
    ap.add_argument("-f", "--follow", action="store_true",
                    help="keep watching the file for new lines (like tail -f)")
    args = ap.parse_args()

    det = Detector(args.threshold, args.window, args.spray_users,
                   args.target_ips, args.whitelist)
    all_alerts = []

    try:
        for n, line in enumerate(read_lines(args.logfile, args.follow), 1):
            ev = parse_line(line, n, args.year)
            if not ev:
                continue
            for alert in det.process(ev):
                all_alerts.append(alert)
                if not args.json:
                    print(alert, flush=True)
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.logfile}")
    except PermissionError:
        sys.exit(f"error: permission denied: {args.logfile} (try sudo)")
    except KeyboardInterrupt:
        pass

    if args.json:
        print(json.dumps([asdict(a) for a in all_alerts], indent=2))
        return 1 if all_alerts else 0

    # Summary
    print("\n=== Summary ===")
    print(f"Failed logins:     {det.total_failures}")
    print(f"Successful logins: {det.total_success}")
    print(f"Alerts raised:     {len(all_alerts)}")
    if det.fail_by_ip:
        print("Top offending IPs:")
        top = sorted(det.fail_by_ip.items(), key=lambda kv: kv[1], reverse=True)[:5]
        for ip, cnt in top:
            mark = "  <-- flagged" if ip in det.flagged_ips else ""
            print(f"  {ip:<18} {cnt:>5} failures{mark}")

    # Non-zero exit code when alerts exist, handy for cron/CI.
    return 1 if all_alerts else 0


if __name__ == "__main__":
    sys.exit(main())
