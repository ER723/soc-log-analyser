"""
Fuzz target for OSSEC alert JSON parsing — alerts.json is written by OSSEC
but a compromised host or a malformed rule config could still produce
adversarial JSON. parse_ossec_alerts must never crash on garbage input;
malformed lines should just be skipped (see the JSONDecodeError handling
in log_analyser.py).

Run locally with:
    pip install atheris
    python3 fuzz/fuzz_parse_ossec_alerts.py
"""

import os
import sys
import tempfile

import atheris

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

with atheris.instrument_imports():
    import log_analyser as la


def TestOneInput(data):
    try:
        content = data.decode("utf-8", errors="ignore")
    except Exception:
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        la.parse_ossec_alerts(path)
    finally:
        os.unlink(path)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
