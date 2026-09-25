"""
Fuzz target for log_analyser's line-parsing logic (regexes + timestamp
parsing). These run against attacker-controlled input by design (log
lines from a potentially-compromised host), so they're the actual attack
surface worth fuzzing — malformed or adversarial lines should never crash
the analyser or hang it (catastrophic regex backtracking).

Run locally (outside ClusterFuzzLite) with:
    pip install atheris
    python3 fuzz/fuzz_parse_auth_line.py

Runs automatically in CI via ClusterFuzzLite on every PR (short run) and
on a daily schedule (longer batch run) — see .github/workflows/cflite_*.yml.
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

with atheris.instrument_imports():
    import log_analyser as la


def TestOneInput(data):
    try:
        line = data.decode("utf-8", errors="ignore")
    except Exception:
        return

    # Exercise every regex and the timestamp parser directly against
    # arbitrary bytes. None of these should ever raise or hang.
    la.FAILED_PW_RE.search(line)
    la.INVALID_USER_RE.search(line)
    la.ACCEPTED_RE.search(line)
    la.SUDO_RE.search(line)
    la.parse_syslog_ts(line)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
