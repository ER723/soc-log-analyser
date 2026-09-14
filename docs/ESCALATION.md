# Escalation Process (Tier 1 → Tier 2)

This defines what a Tier 1 analyst does with each output the log analyser
produces. It's written for a solo/lab context but follows standard SOC
escalation shape (triage → validate → contain/escalate → document).

## Severity mapping

| Analyser output | Meaning | Tier 1 action |
|---|---|---|
| `MEDIUM` brute-force flag | 5–14 failed logins from one IP within 10 min | Monitor. Note IP. No immediate escalation unless repeated across runs. |
| `HIGH` brute-force flag | 15+ failed logins from one IP within 10 min | Escalate to Tier 2 within the shift. Block IP at firewall/hosts.deny as an interim step if policy allows. |
| `CRITICAL` — successful login after brute-force | An IP that was brute-forcing also achieved a successful login | **Immediate escalation.** Treat as suspected compromise. |
| OSSEC level 7–11 | Notable but not urgent (policy violations, minor anomalies) | Log and review at end of shift. |
| OSSEC level ≥ 12 | High severity (new user, integrity change, etc.) | Escalate same as HIGH/CRITICAL above. |

## Step-by-step process

### 1. Detect
Run the analyser (scheduled via cron or `--watch`). A flag appears in the
terminal summary and/or CSV.

### 2. Validate (Tier 1)
Before escalating, rule out false positives:
- Is the source IP a known/whitelisted admin IP (e.g. your own jump box)?
- Does the failure pattern match a misconfigured service instead of an
  attacker (e.g. a script with a stale password)?
- Cross-check the same IP/timeframe against OSSEC alerts for corroboration.

Document the validation check in `tests/TEST_LOG.md` or an incident note —
even "checked, appears to be false positive: <reason>" is a valid record.

### 3. Contain (only for HIGH/CRITICAL, if you have authority to act)
- Block the IP: `sudo iptables -A INPUT -s <ip> -j DROP` (or hosts.deny)
- If CRITICAL (possible compromise): also consider disabling the affected
  account and rotating its password.
- Preserve evidence first — copy the relevant log lines and the CSV export
  to an incident folder before making changes.

### 4. Escalate
For anything HIGH, CRITICAL, or OSSEC ≥ 12, write a short escalation note
with:
- Timestamp of detection
- Source IP, affected account(s)
- Analyser output (attach the CSV row or terminal excerpt)
- Validation steps already taken
- Containment actions already taken (if any)
- Recommended next step for Tier 2 (e.g. "confirm whether account
  `er723` was actually used maliciously post-login")

In a real SOC this note goes into the ticketing system (e.g. TheHive,
Jira). For this lab, use `docs/incidents/` (create a dated `.md` file per
incident) so there's a paper trail in the repo.

### 5. Close or hand off
- If Tier 1 determined it's a false positive: document and close.
- If escalated: link the incident file in the hand-off note and keep it
  open until Tier 2 confirms disposition.

## Tuning feedback loop

If real testing produces too many MEDIUM false positives (e.g. your own
flaky SSH client), adjust `BRUTE_FORCE_THRESHOLD` /
`BRUTE_FORCE_WINDOW_MIN` in `log_analyser.py` and note the change + reason
in `CHANGELOG.md`.
