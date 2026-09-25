# Changelog

## [Unreleased]
- Added real unit test suite (`tests/test_log_analyser.py`, stdlib
  `unittest`) covering timestamp parsing, auth log parsing, OSSEC parsing,
  and brute-force/compromise correlation.
- Added GitHub Actions CI (`.github/workflows/ci.yml`) running tests + lint
  on every push across Python 3.10–3.12.
- Added `ruff.toml` lint config; codebase passes clean.
- Added `pyproject.toml` (zero runtime dependencies, declared explicitly)
  and `uv.lock` for a reproducible dev environment.
- Added `CONTRIBUTING.md`, issue templates, and a PR template.
- Added a sample output screenshot and documentation index to the README.
- Patched ISO8601 timestamp parsing (modern rsyslog default) alongside the
  original classic BSD syslog format.

## Initial release
- auth.log + OSSEC alerts.json parsing, brute-force correlation, CSV
  export, watch mode.
