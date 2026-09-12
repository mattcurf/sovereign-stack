ARG BASE_IMAGE=sovereign-stack/base-container:local
FROM ${BASE_IMAGE} AS dependencies
USER 0:0
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip=25.1.1+dfsg-1
COPY requirements.lock /requirements.lock
RUN python3 -m pip install --require-hashes --only-binary=:all: --no-compile \
        --no-cache-dir --target=/opt/python -r /requirements.lock \
    && mkdir -p /evidence \
    && cp /requirements.lock /evidence/ \
    && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > /evidence/build-packages.tsv \
    && cp -a /usr/share/doc /evidence/build-doc

FROM ${BASE_IMAGE}
USER 0:0
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3=3.13.5-1 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
COPY --from=dependencies /opt/python/ /opt/python/
COPY --from=dependencies /evidence/ /usr/share/sovereign-stack/python/
COPY app.py /app/app.py
ENV PYTHONPATH=/opt/python PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
EXPOSE 8080
CMD ["/usr/bin/python3", "/app/app.py"]
