#!/bin/bash -eu
# Builds both fuzz targets for ClusterFuzzLite. Runs inside the
# oss-fuzz-base/base-builder-python container (see .clusterfuzzlite/Dockerfile).
#
# --paths tells PyInstaller's static import analysis where to find
# log_analyser.py: PyInstaller only auto-adds the fuzz script's OWN
# directory (fuzz/) to its analysis path, not the repo root, so without
# this the frozen binary is missing the log_analyser module entirely
# (fails at runtime with ModuleNotFoundError even though `python3
# fuzz/fuzz_x.py` works fine locally, since that relies on this file's
# own sys.path.insert() — which PyInstaller's static analysis never sees).

compile_python_fuzzer fuzz/fuzz_parse_auth_line.py --paths="$SRC/soc-log-analyser"
compile_python_fuzzer fuzz/fuzz_parse_ossec_alerts.py --paths="$SRC/soc-log-analyser"

