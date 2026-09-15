#!/usr/bin/env python3
"""
SOC Log Analyser (Tier 1) — free, lightweight, dependency-free (stdlib only).

Ingests:
  - Linux auth logs (/var/log/auth.log or /var/log/secure) — SSH brute force,
    invalid users, successful logins, sudo usage.
  - OSSEC alerts (alerts.json, one JSON object per line — OSSEC's jsonout_output).

Correlates events by source IP and flags brute-force / anomalous activity.
Outputs a color-coded terminal triage summary and an optional CSV export.

Usage:
  python3 log_analyser.py --auth /var/log/auth.log --ossec /var/ossec/logs/alerts/alerts.json
  python3 log_analyser.py --auth /var/log/auth.log --watch
  python3 log_analyser.py --auth /var/log/auth.log --csv report.csv

No third-party dependencies. No network access required. Designed to run on
low-RAM VMs (tested target: 8GB VirtualBox Kali).
"""

import argparse
import csv
import json
import re
import sys
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# ---------- Terminal colors (no deps) ----------
class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    BLD = "\033[1m"
    END = "\033[0m"

def sev_color(level):
    if level >= 12:
        return C.RED
    if level >= 7:
        return C.YEL
    return C.GRN

# ---------- Auth log parsing ----------
FAILED_PW_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)"
)
SYSLOG_TS_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
ISO_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

def parse_syslog_ts(line, year=None):
    m = ISO_TS_RE.match(line)
    if m:
        try:
            return datetime.strptime(m.group("ts"), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    year = year or datetime.now().year
    try:
        return datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def parse_auth_log(path):
    """Yields normalized event dicts from an auth.log/secure file."""
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                ts = parse_syslog_ts(line)
                m = FAILED_PW_RE.search(line)
                if m:
                    events.append({"ts": ts, "type": "failed_login",
                                    "user": m.group("user"), "ip": m.group("ip"),
                                    "raw": line.strip()})
                    continue
                m = INVALID_USER_RE.search(line)
                if m:
                    events.append({"ts": ts, "type": "invalid_user",
                                    "user": m.group("user"), "ip": m.group("ip"),
                                    "raw": line.strip()})
                    continue
                m = ACCEPTED_RE.search(line)
                if m:
                    events.append({"ts": ts, "type": "accepted_login",
                                    "user": m.group("user"), "ip": m.group("ip"),
                                    "raw": line.strip()})
                    continue
                m = SUDO_RE.search(line)
                if m:
                    events.append({"ts": ts, "type": "sudo",
                                    "user": m.group("user"), "ip": None,
                                    "cmd": m.group("cmd"), "raw": line.strip()})
                    continue
    except FileNotFoundError:
        print(f"{C.YEL}[!] auth log not found: {path}{C.END}", file=sys.stderr)
    return events

# ---------- OSSEC alert parsing ----------
def parse_ossec_alerts(path):
    """OSSEC jsonout_output alerts.json — one JSON object per line."""
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rule = obj.get("rule", {})
                events.append({
                    "type": "ossec_alert",
                    "level": rule.get("level", 0),
                    "description": rule.get("description", ""),
                    "ip": obj.get("srcip"),
                    "full_log": obj.get("full_log", "")[:200],
                })
    except FileNotFoundError:
        print(f"{C.YEL}[!] OSSEC alerts file not found: {path}{C.END}", file=sys.stderr)
    return events

# ---------- Correlation / triage logic ----------
BRUTE_FORCE_THRESHOLD = 5     # failed logins
BRUTE_FORCE_WINDOW_MIN = 10   # within N minutes

def correlate(auth_events):
    """Group failed logins by source IP and flag brute-force patterns."""
    by_ip = defaultdict(list)
    for e in auth_events:
        if e["type"] in ("failed_login", "invalid_user") and e["ip"]:
            by_ip[e["ip"]].append(e)

    flags = []
    for ip, evs in by_ip.items():
        evs_sorted = [e for e in evs if e["ts"]]
        evs_sorted.sort(key=lambda x: x["ts"])
        if len(evs) >= BRUTE_FORCE_THRESHOLD:
            # check if threshold met within the time window at any point
            window = timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
            triggered = False
            for i in range(len(evs_sorted)):
                if not evs_sorted[i]["ts"]:
                    continue
                count = 1
                for j in range(i + 1, len(evs_sorted)):
                    if evs_sorted[j]["ts"] and evs_sorted[j]["ts"] - evs_sorted[i]["ts"] <= window:
                        count += 1
                if count >= BRUTE_FORCE_THRESHOLD:
                    triggered = True
                    break
            if triggered or not evs_sorted:  # no timestamps parsed -> flag on raw count
                flags.append({
                    "ip": ip, "count": len(evs),
                    "users": sorted(set(e["user"] for e in evs)),
                    "severity": "HIGH" if len(evs) >= 15 else "MEDIUM",
                })
    return flags

def check_successful_after_bruteforce(auth_events, brute_ips):
    """Flag any accepted login from an IP that also triggered brute-force alerts."""
    hits = []
    for e in auth_events:
        if e["type"] == "accepted_login" and e["ip"] in brute_ips:
            hits.append(e)
    return hits

# ---------- Reporting ----------
def print_report(auth_events, ossec_events, brute_flags, compromised_hits):
    print(f"\n{C.BLD}{C.CYN}==== SOC Tier 1 Log Analyser — Triage Summary ===={C.END}")
    print(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")

    print(f"{C.BLD}Auth events parsed:{C.END} {len(auth_events)}")
    print(f"{C.BLD}OSSEC alerts parsed:{C.END} {len(ossec_events)}\n")

    if brute_flags:
        print(f"{C.RED}{C.BLD}[!] Possible brute-force activity ({len(brute_flags)} source IP(s)):{C.END}")
        for f in sorted(brute_flags, key=lambda x: -x["count"]):
            col = C.RED if f["severity"] == "HIGH" else C.YEL
            print(f"  {col}{f['severity']:<6}{C.END} {f['ip']:<16} "
                  f"{f['count']} failed attempts, users tried: {', '.join(f['users'][:5])}")
    else:
        print(f"{C.GRN}[+] No brute-force patterns detected in auth log.{C.END}")

    if compromised_hits:
        print(f"\n{C.RED}{C.BLD}[!!] CRITICAL — successful login from a brute-forcing IP:{C.END}")
        for h in compromised_hits:
            print(f"  {C.RED}{h['ip']} -> user '{h['user']}' — POSSIBLE COMPROMISE{C.END}")
            print(f"      {h['raw']}")

    sudo_events = [e for e in auth_events if e["type"] == "sudo"]
    if sudo_events:
        print(f"\n{C.BLD}Sudo command usage ({len(sudo_events)} events):{C.END}")
        top_users = Counter(e["user"] for e in sudo_events).most_common(5)
        for user, cnt in top_users:
            print(f"  {user}: {cnt} commands")

    if ossec_events:
        levels = Counter(e["level"] for e in ossec_events)
        print(f"\n{C.BLD}OSSEC alerts by level:{C.END}")
        for lvl in sorted(levels, reverse=True):
            col = sev_color(lvl)
            print(f"  {col}Level {lvl:>2}{C.END}: {levels[lvl]} alert(s)")
        high = [e for e in ossec_events if e["level"] >= 12]
        if high:
            print(f"\n{C.RED}{C.BLD}[!] High-severity OSSEC alerts (level >= 12):{C.END}")
            for e in high[:10]:
                print(f"  L{e['level']} {e['description']} (src: {e.get('ip')})")

    print(f"\n{C.BLD}{C.CYN}==== End of summary ===={C.END}\n")

def write_csv(path, auth_events, ossec_events, brute_flags):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "type", "severity", "ip", "user_or_desc", "detail"])
        for fl in brute_flags:
            w.writerow(["auth", "brute_force", fl["severity"], fl["ip"],
                        ",".join(fl["users"]), f"{fl['count']} failed attempts"])
        for e in auth_events:
            if e["type"] in ("accepted_login", "sudo"):
                w.writerow(["auth", e["type"], "-", e.get("ip", ""), e.get("user", ""),
                            e.get("cmd", e.get("raw", ""))[:150]])
        for e in ossec_events:
            w.writerow(["ossec", "alert", e["level"], e.get("ip", ""),
                        e["description"], e.get("full_log", "")])
    print(f"{C.GRN}[+] CSV report written to {path}{C.END}")

# ---------- Main ----------
def run_once(args):
    auth_events = parse_auth_log(args.auth) if args.auth else []
    ossec_events = parse_ossec_alerts(args.ossec) if args.ossec else []
    brute_flags = correlate(auth_events)
    brute_ips = {f["ip"] for f in brute_flags}
    compromised_hits = check_successful_after_bruteforce(auth_events, brute_ips)
    print_report(auth_events, ossec_events, brute_flags, compromised_hits)
    if args.csv:
        write_csv(args.csv, auth_events, ossec_events, brute_flags)

def main():
    p = argparse.ArgumentParser(description="Free, lightweight Tier 1 SOC log analyser.")
    p.add_argument("--auth", help="Path to auth.log / secure log file")
    p.add_argument("--ossec", help="Path to OSSEC alerts.json (jsonout_output)")
    p.add_argument("--csv", help="Write a CSV report to this path")
    p.add_argument("--watch", action="store_true",
                    help="Re-run every --interval seconds (Ctrl+C to stop)")
    p.add_argument("--interval", type=int, default=60,
                    help="Seconds between runs in --watch mode (default 60)")
    args = p.parse_args()

    if not args.auth and not args.ossec:
        p.error("Provide at least one of --auth or --ossec")

    if args.watch:
        try:
            while True:
                run_once(args)
                print(f"{C.CYN}(watching — next check in {args.interval}s, Ctrl+C to stop){C.END}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        run_once(args)

if __name__ == "__main__":
    main()
