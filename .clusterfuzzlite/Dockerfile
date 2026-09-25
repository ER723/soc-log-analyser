# ClusterFuzzLite build container for this project's Python fuzz targets.
# See: https://google.github.io/clusterfuzzlite/build-integration/python/
#
# Pinned to the exact digest resolved during our own verified build (see
# CI logs) rather than a floating :latest tag, for Pinned-Dependencies.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:aac6099136dd15a1f35400dac58cef67fa02fcd4138c68c254976fc2229c3950

# Container ships Python 3.11 — atheris 3.1.0+ only publishes 3.12+ wheels,
# so this is pinned to the last version with a cp311 wheel, hash-verified.
COPY requirements-fuzz.txt /tmp/requirements-fuzz.txt
RUN pip3 install --require-hashes -r /tmp/requirements-fuzz.txt

COPY . $SRC/soc-log-analyser
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/soc-log-analyser
