---
name: Bug report
about: Something isn't detecting/parsing correctly
title: "[BUG] "
labels: bug
---

**Describe the bug**
A clear description of what's wrong (e.g. an event that should have been
flagged but wasn't, or a false positive).

**Log sample**
Paste a minimal, *sanitized* snippet of the auth.log or OSSEC alert line
that triggers the issue (redact real IPs/hostnames if needed).

**Expected behavior**
What you expected the analyser to report.

**Actual behavior**
What it actually reported (paste terminal output or CSV row).

**Environment**
- OS/distro: (e.g. Kali 2026.x)
- Python version: `python3 --version`
- Log source: auth.log / OSSEC alerts.json / both

**Additional context**
Anything else relevant (log format quirks, custom OSSEC rules, etc.)
