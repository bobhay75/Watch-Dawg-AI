FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    SENTINEL_CONFIG_ROOT=/app/sentinel/examples \
    SENTINEL_STATE_ROOT=/state

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g libzstd1 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libzstd1)" ge '1.5.7+dfsg-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 sentinel \
    && install -d -m 0700 -o sentinel -g sentinel /state

COPY sentinel/requirements.txt /tmp/sentinel-requirements.txt

RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    --require-hashes --requirement /tmp/sentinel-requirements.txt \
    && rm /tmp/sentinel-requirements.txt \
    && python -m pip uninstall --yes pip

COPY --chown=sentinel:sentinel sentinel /app/sentinel

USER sentinel

EXPOSE 8080

CMD ["python", "-m", "sentinel.api"]
