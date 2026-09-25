#!/usr/bin/env python3
"""
Unit tests for log_analyser.py — stdlib unittest only, no third-party deps.

Run with:
    python3 -m unittest discover -s tests -v

or directly:
    python3 tests/test_log_analyser.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import log_analyser as la  # noqa: E402


class TestTimestampParsing(unittest.TestCase):
    def test_iso8601_format(self):
        line = "2026-09-15T18:45:10.022036+08:00 host sshd[1]: Accepted password for x from 1.2.3.4 port 1 ssh2"
        ts = la.parse_syslog_ts(line)
        self.assertIsNotNone(ts)
        self.assertEqual((ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second),
                          (2026, 9, 15, 18, 45, 10))

    def test_classic_bsd_format(self):
        line = "Sep 15 10:00:01 host sshd[1]: Failed password for invalid user x from 1.2.3.4 port 1 ssh2"
        ts = la.parse_syslog_ts(line, year=2026)
        self.assertIsNotNone(ts)
        self.assertEqual((ts.month, ts.day, ts.hour, ts.minute, ts.second),
                          (9, 15, 10, 0, 1))

    def test_no_timestamp_returns_none(self):
        self.assertIsNone(la.parse_syslog_ts("no timestamp on this line"))


class TestAuthLogParsing(unittest.TestCase):
    def setUp(self):
        self.fixture = os.path.join(os.path.dirname(__file__), "sample_auth.log")

    def test_parses_expected_event_count(self):
        events = la.parse_auth_log(self.fixture)
        self.assertEqual(len(events), 11)

    def test_failed_login_captured(self):
        events = la.parse_auth_log(self.fixture)
        failed = [e for e in events if e["type"] == "failed_login"]
        self.assertTrue(any(e["ip"] == "203.0.113.5" for e in failed))

    def test_accepted_login_captured(self):
        events = la.parse_auth_log(self.fixture)
        accepted = [e for e in events if e["type"] == "accepted_login"]
        self.assertTrue(any(e["user"] == "er723" for e in accepted))

    def test_sudo_captured(self):
        events = la.parse_auth_log(self.fixture)
        sudo = [e for e in events if e["type"] == "sudo"]
        self.assertGreaterEqual(len(sudo), 1)

    def test_missing_file_returns_empty_list(self):
        events = la.parse_auth_log("/nonexistent/path/auth.log")
        self.assertEqual(events, [])


class TestOssecParsing(unittest.TestCase):
    def setUp(self):
        self.fixture = os.path.join(os.path.dirname(__file__), "sample_ossec_alerts.json")

    def test_parses_expected_alert_count(self):
        events = la.parse_ossec_alerts(self.fixture)
        self.assertEqual(len(events), 3)

    def test_high_level_alert_present(self):
        events = la.parse_ossec_alerts(self.fixture)
        self.assertTrue(any(e["level"] >= 12 for e in events))


class TestCorrelation(unittest.TestCase):
    def test_brute_force_flagged_above_threshold(self):
        events = la.parse_auth_log(os.path.join(os.path.dirname(__file__), "sample_auth.log"))
        flags = la.correlate(events)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["ip"], "203.0.113.5")
        self.assertGreaterEqual(flags[0]["count"], la.BRUTE_FORCE_THRESHOLD)

    def test_no_flags_below_threshold(self):
        events = [
            {"type": "failed_login", "ip": "9.9.9.9", "user": "a", "ts": None},
            {"type": "failed_login", "ip": "9.9.9.9", "user": "b", "ts": None},
        ]
        flags = la.correlate(events)
        self.assertEqual(flags, [])

    def test_compromise_escalation(self):
        events = la.parse_auth_log(os.path.join(os.path.dirname(__file__), "sample_auth.log"))
        flags = la.correlate(events)
        brute_ips = {f["ip"] for f in flags}
        hits = la.check_successful_after_bruteforce(events, brute_ips)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "203.0.113.5")


if __name__ == "__main__":
    unittest.main()
