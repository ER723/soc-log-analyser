
# Live Test Log

Record of every live test run against `log_analyser.py`. Append new
entries at the bottom.

| Date | Tester | Test performed | Result | Notes |
|---|---|---|---|---|
| 2026-09-15 | er723 | SSH brute force (7x failed login) from 10.0.2.15 via loop | PASS | MEDIUM flag + CRITICAL escalation both fired correctly |
| 2026-09-15 | er723 | Combined live test: SSH brute force + /etc/passwd integrity change via useradd, full auth.log + alerts.json run | PASS | 57 auth events, 31 OSSEC alerts parsed; brute-force MEDIUM + CRITICAL escalation confirmed; syscheck real-time detection confirmed (took ~4min post-restart to flush); added er723 to ossec group for passwordless alert reading |
