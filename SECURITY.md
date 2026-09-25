# Security Policy

## Supported versions

This is a single-branch lab/portfolio project — only `main` is supported.
There are no maintained release branches.

## Reporting a vulnerability

If you find a security issue in this tool (e.g. a regex that could be
tricked into missing an attack, a path that mishandles untrusted log
input, or anything in the CI/CD configuration itself), please report it
privately rather than opening a public issue:

- Preferred: use GitHub's [private vulnerability reporting](https://github.com/ER723/soc-log-analyser/security/advisories/new)
  for this repo (Security tab → "Report a vulnerability").
- Alternative: open a regular issue with minimal detail and a note asking
  for a private channel, and we'll follow up.

Please include:
- A description of the issue and its potential impact
- Steps to reproduce (a minimal log sample is ideal)
- Any suggested fix, if you have one

## Scope

This tool is a **local, offline log parser** — it doesn't accept network
input, doesn't run as a service, and doesn't execute anything from the
logs it reads. The most relevant risk classes are:
- A malformed or adversarial log line causing a crash (denial of service
  against the analyst running it) rather than remote code execution
- Incorrect detection logic causing a real attack to be missed
  (false negative) or overwhelming false positives (alert fatigue)

Supply-chain concerns in the CI/CD pipeline itself (GitHub Actions) are
also in scope — see `.github/workflows/` for the pinned-action setup.

## Response

This is a solo-maintained lab project, so response times aren't
guaranteed on an SLA — but reports will be acknowledged and addressed as
promptly as possible.
