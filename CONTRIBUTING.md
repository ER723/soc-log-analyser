# Contributing

Thanks for considering a contribution to this project. It's intentionally
small and dependency-free — please keep that spirit in any changes. The
goal is a tool a Tier 1 SOC analyst can drop onto any box with Python 3.10+
and run immediately, with zero setup friction and zero supply-chain risk
from the tool itself.

## Setup

No installation is required to run the tool itself (stdlib only):

```bash
git clone https://github.com/ER723/soc-log-analyser.git
cd soc-log-analyser
python3 log_analyser.py --auth tests/sample_auth.log --ossec tests/sample_ossec_alerts.json
```

For development (linting, type checking, running the test suite with
coverage), install the project in editable mode with the `dev` extra. This
repo uses [`uv`](https://docs.astral.sh/uv/) to install everything —
including transitive dependencies — pinned to exact, hash-verified
versions from `uv.lock`, so your local environment matches CI exactly:

```bash
pip install uv
uv sync --extra dev --locked
```

That creates a `.venv/` with `ruff`, `pytest`, `pytest-cov`, and `mypy`
installed. Prefix any dev command with `uv run` (e.g. `uv run pytest`) so
it runs inside that environment, or activate `.venv` yourself.

## Code style

- Stdlib only for the tool itself — no runtime dependencies. If you think a
  dependency is justified, open an issue first to discuss it; the bar is
  high, since dependency-free is a core design goal, not an accident.
- Formatted/linted with [ruff](https://docs.astral.sh/ruff/); config is in
  `ruff.toml`. Run before committing:
  ```bash
  uv run ruff check .
  uv run ruff check . --fix   # auto-fix what's fixable
  ```
- Type-annotate new or changed functions where practical, and keep
  `mypy` clean:
  ```bash
  uv run mypy log_analyser.py
  ```
- Keep functions small and testable — see `log_analyser.py`'s existing
  parse/correlate/report separation as the pattern to follow. A change that
  mixes parsing, correlation, and printing in one function is harder to
  test and harder to review.

## Tests

The suite is written against stdlib `unittest` (so it needs no framework
to run at all — `python3 -m unittest discover -s tests -v` always works,
even with nothing installed), but CI runs it through `pytest`, which is
fully compatible with `unittest`-style tests and also gives us coverage
reporting:

```bash
uv run pytest tests/ --cov=log_analyser --cov-report=term-missing -v
```

Please add or update a test in `tests/test_log_analyser.py` for any
behavior change, especially new regex patterns or correlation logic —
these are easy to silently break, and a passing test is the only way a
reviewer can trust a parsing change didn't regress an existing log format.

Example of the existing test style, for reference:

```python
class TestCorrelation(unittest.TestCase):
    def test_brute_force_flagged_above_threshold(self):
        events = [make_failed_login("10.0.0.5") for _ in range(6)]
        flags = correlate(events)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["ip"], "10.0.0.5")
```

If your change affects real-world detection behavior, consider also
running the live test procedure in
[`docs/LIVE_TESTING.md`](docs/LIVE_TESTING.md) and noting the result in
`tests/TEST_LOG.md`.

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Make your change with tests.
3. Confirm `uv run pytest tests/ -v`, `uv run mypy log_analyser.py`, and
   `uv run ruff check .` all pass locally — CI runs the exact same three
   checks across Python 3.10, 3.11, and 3.12, so catching problems locally
   first saves a round trip.
4. If you touched dependencies in `pyproject.toml`'s `dev` extra, run
   `uv lock` and commit the updated `uv.lock` so CI's hash-verified install
   stays in sync.
5. Open a PR describing what changed and why. Reference any related issue.
6. Keep PRs focused — one logical change per PR is easier to review than a
   bundle of unrelated fixes. Large refactors are welcome, but flag them in
   an issue first so we can agree on direction before you invest the time.

Reviews aim to check three things: does it work (tests pass and the change
is exercised by one), does it stay dependency-free, and does it keep the
tool simple enough that a Tier 1 analyst can read the source in one sitting.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/` — they prompt for
the info that's usually needed to reproduce or evaluate a request, such as
the log format involved, the Python version, and the exact command run.

## Code of conduct

Participation in this project is expected to stay respectful and
constructive; see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for the full
expectations.
