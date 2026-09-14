# SOC Log Analyser (Tier 1) — Free & Lightweight

A single Python file, **zero third-party dependencies**, no database, no
ELK/Splunk. Built to run comfortably on an 8GB RAM Kali VM alongside OSSEC.

## Repo layout

```
log_analyser.py          the tool (stdlib-only)
tests/sample_auth.log         fixture for offline testing
tests/sample_ossec_alerts.json  fixture for offline testing
tests/TEST_LOG.md             running log of live test results
docs/LIVE_TESTING.md          step-by-step live test procedure
docs/ESCALATION.md            Tier 1 -> Tier 2 escalation process
docs/incidents/                per-incident notes (created as needed)
reports/                       generated CSV output (gitignored)
CHANGELOG.md
LICENSE (MIT)
```

See [`docs/LIVE_TESTING.md`](docs/LIVE_TESTING.md) before running against
a real target, and [`docs/ESCALATION.md`](docs/ESCALATION.md) for what to
do with each severity of flag it produces.

## What it does

- Parses **auth.log / secure** for:
  - Failed password attempts / invalid users
  - Accepted (successful) logins
  - `sudo` command usage
- Parses **OSSEC `alerts.json`** (enable `jsonout_output` in `ossec.conf`)
- **Correlates by source IP**: 5+ failed logins within 10 minutes = flagged
  brute-force. If that same IP later gets a successful login, it's escalated
  to CRITICAL (possible compromise).
- Prints a color-coded terminal triage summary, and can export CSV for
  further review or ticketing.

## Requirements

Python 3.6+ (already on Kali). That's it — no `pip install` needed.

## One-shot usage

```bash
python3 log_analyser.py --auth /var/log/auth.log --ossec /var/ossec/logs/alerts/alerts.json
```

CSV export:
```bash
python3 log_analyser.py --auth /var/log/auth.log --csv report.csv
```

Auth log only (no OSSEC yet):
```bash
python3 log_analyser.py --auth /var/log/auth.log
```

## Automated / continuous mode

Built-in polling loop (no cron needed, good for a lab demo):
```bash
python3 log_analyser.py --auth /var/log/auth.log --ossec /var/ossec/logs/alerts/alerts.json --watch --interval 60
```

For real "set and forget" automation, use cron instead (lighter than a
long-running Python loop):
```bash
crontab -e
# run every 10 minutes, append CSV report
*/10 * * * * /usr/bin/python3 /path/to/log_analyser.py --auth /var/log/auth.log --ossec /var/ossec/logs/alerts/alerts.json --csv /path/to/reports/report_$(date +\%s).csv >> /path/to/reports/analyser.log 2>&1
```

## Enabling OSSEC JSON alerts (if not already on)

In `/var/ossec/etc/ossec.conf`, inside `<global>`:
```xml
<jsonout_output>yes</jsonout_output>
```
Then restart OSSEC: `sudo /var/ossec/bin/ossec-control restart`
Alerts will appear at `/var/ossec/logs/alerts/alerts.json`.

## Tuning

Edit these two constants near the top of `log_analyser.py`:
```python
BRUTE_FORCE_THRESHOLD = 5     # failed logins to trigger a flag
BRUTE_FORCE_WINDOW_MIN = 10   # time window in minutes
```

## Why this design (Tier 1 relevance)

This mirrors the actual first-pass triage a Tier 1 analyst does before
escalating to Tier 2: identify noisy/repeated auth failures, check whether
an attacker IP ever succeeded (compromise indicator), and cross-reference
against HIDS alerts for anything already scored by OSSEC's rule engine.
It intentionally does NOT try to be a SIEM — no storage, no dashboards,
no agents — just fast, free, disposable triage output.

## Extending it later

- Add web server log parsing (nginx/apache) the same way — one regex block
  + one entry in `run_once()`.
- Swap the CSV writer for a call into your `recon-detector` pipeline if you
  want a single unified alert feed.
- If you outgrow this, the natural free next step is Wazuh (OSSEC's
  actively maintained fork) with its built-in dashboard — still free, just
  heavier than this script.
