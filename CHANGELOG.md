# Changelog

## [Unreleased]
- CI now runs the suite via `pytest` with coverage reporting
  (`--cov=log_analyser --cov-report=term-missing --cov-report=xml`) and
  adds a `mypy` type-checking step, both installed with `uv sync --locked`
  against `uv.lock` for hash-verified, reproducible dev dependencies.
- Expanded `CONTRIBUTING.md` with fuller setup, style, and test/PR guidance,
  and added `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1).
- Added `authors` and `[project.urls]` (Homepage, Repository, Issues) to
  `pyproject.toml`.
- Added the RepoGrade badge to the README.
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
