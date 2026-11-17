FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    SENTINEL_CONFIG_ROOT=/app/sentinel/examples \
    SENTINEL_STATE_ROOT=/state

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall --yes pip

RUN useradd --create-home --uid 10001 sentinel \
    && mkdir /state \
    && chown sentinel:sentinel /state

COPY --chown=sentinel:sentinel sentinel /app/sentinel

USER sentinel

EXPOSE 8080

CMD ["python", "-m", "sentinel.api"]
