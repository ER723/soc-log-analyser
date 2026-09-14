# Live Test Process

This document is the repeatable procedure for validating that the log
analyser actually detects real attack activity on the lab VM, not just the
static sample files in `tests/`.

## Scope

Tier 1 validation covers two detection paths:
1. Auth log brute-force detection (SSH)
2. OSSEC alert ingestion (HIDS-side correlation)

## Pre-test checklist

- [ ] Kali VM (`ER723-lab`) is up, SSH service (`sshd`) is running
- [ ] OSSEC is running: `sudo /var/ossec/bin/ossec-control status`
- [ ] `jsonout_output` is enabled in `ossec.conf` and `alerts.json` is being
      written to (`tail -f /var/ossec/logs/alerts/alerts.json`)
- [ ] `log_analyser.py` runs clean against the sample fixtures first:
      ```bash
      python3 log_analyser.py --auth tests/sample_auth.log --ossec tests/sample_ossec_alerts.json
      ```
      Expect: 1 MEDIUM brute-force flag on 203.0.113.5, 1 CRITICAL
      compromise flag, 1 level-13 OSSEC alert.

## Test 1 — Simulated SSH brute force

Run from a **second VM or the host machine** (not the target itself) so the
traffic is realistic:

```bash
# on the attacking machine — requires hydra (free, in Kali by default)
hydra -l testuser -P /usr/share/wordlists/rockyou.txt -t 4 ssh://<target-ip> -f
```

Or, for a quick lightweight version without a wordlist tool, loop plain SSH
attempts:
```bash
for i in {1..8}; do ssh baduser@<target-ip> -o BatchMode=no -o ConnectTimeout=3; done
```

On the target VM, after the attempts:
```bash
python3 log_analyser.py --auth /var/log/auth.log
```

**Expected result:** the attacking IP is flagged MEDIUM or HIGH depending on
attempt count. If you then log in successfully (e.g. `ssh er723@target-ip`)
from the *same attacking machine*, re-run the analyser — expect the
CRITICAL "possible compromise" escalation.

## Test 2 — OSSEC correlation

Trigger a rule OSSEC already watches for, e.g. add a user:
```bash
sudo useradd testuser99 && sudo userdel testuser99
```
Then:
```bash
python3 log_analyser.py --ossec /var/ossec/logs/alerts/alerts.json
```
**Expected result:** a level ≥ 10 "new user" style alert appears in the
"High-severity OSSEC alerts" section.

## Test 3 — Combined run + CSV export

```bash
python3 log_analyser.py --auth /var/log/auth.log \
  --ossec /var/ossec/logs/alerts/alerts.json \
  --csv reports/live_test_$(date +%Y%m%d_%H%M).csv
```
Confirm the CSV opens and contains rows for every flag shown in the
terminal summary.

## Pass/fail criteria

| Check | Pass condition |
|---|---|
| Sample fixture run | Matches expected output above, exit code 0 |
| Brute-force test | Attacking IP flagged within 1 run of the threshold being crossed |
| Compromise escalation | CRITICAL line appears after successful login from a flagged IP |
| OSSEC correlation | Injected alert shows up in the OSSEC summary section |
| CSV export | File created, row count matches terminal flag count |

## Logging test runs

Record each live test in `tests/TEST_LOG.md` (date, tester, what was run,
pass/fail, notes) so there's a history to reference during escalation
review or when tuning `BRUTE_FORCE_THRESHOLD`.
