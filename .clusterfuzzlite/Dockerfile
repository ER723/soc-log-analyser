# ClusterFuzzLite build container for this project's Python fuzz targets.
# See: https://google.github.io/clusterfuzzlite/build-integration/python/
FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install atheris

COPY . $SRC/soc-log-analyser
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/soc-log-analyser
