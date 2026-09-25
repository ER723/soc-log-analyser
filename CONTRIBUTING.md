# Contributing

Thanks for considering a contribution to this project. It's intentionally
small and dependency-free — please keep that spirit in any changes.

## Setup

No installation required to run the tool itself (stdlib only):

```bash
git clone https://github.com/ER723/soc-log-analyser.git
cd soc-log-analyser
python3 log_analyser.py --auth tests/sample_auth.log --ossec tests/sample_ossec_alerts.json
```

For development (linting), install the optional dev dependency:

```bash
pip install -e ".[dev]"
```

## Code style

- Stdlib only for the tool itself — no runtime dependencies. If you think a
  dependency is justified, open an issue first to discuss it.
- Formatted/linted with [ruff](https://docs.astral.sh/ruff/); config is in
  `ruff.toml`. Run before committing:
  ```bash
  ruff check .
  ruff check . --fix   # auto-fix what's fixable
  ```
- Keep functions small and testable — see `log_analyser.py`'s existing
  parse/correlate/report separation as the pattern to follow.

## Tests

Tests are stdlib `unittest`, no test framework dependency:

```bash
python3 -m unittest discover -s tests -v
```

Please add or update a test in `tests/test_log_analyser.py` for any
behavior change, especially new regex patterns or correlation logic —
these are easy to silently break.

If your change affects real-world detection behavior, consider also
running the live test procedure in
[`docs/LIVE_TESTING.md`](docs/LIVE_TESTING.md) and noting the result in
`tests/TEST_LOG.md`.

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Make your change with tests.
3. Confirm `python3 -m unittest discover -s tests` and `ruff check .` both
   pass locally (CI will also check this).
4. Open a PR describing what changed and why. Reference any related issue.
5. Keep PRs focused — one logical change per PR is easier to review than a
   bundle of unrelated fixes.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/` — they prompt for
the info that's usually needed to reproduce or evaluate a request.
