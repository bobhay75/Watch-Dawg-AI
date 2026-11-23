# syntax=docker/dockerfile:1
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# Narrow signed-distribution update for the scanner-reported zlib advisory.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt /app/requirements.txt
# Optional build-only CA bundle supports inspected networks without a TLS bypass.
RUN --mount=type=secret,id=package_ca \
    if [ -s /run/secrets/package_ca ]; then \
      PIP_CERT=/run/secrets/package_ca python -m pip install --no-cache-dir --require-hashes -r requirements.txt; \
    else \
      python -m pip install --no-cache-dir --require-hashes -r requirements.txt; \
    fi
RUN python -m pip uninstall --yes pip
COPY --chown=10001:10001 backend/server.py backend/providers.py backend/security.py backend/audit.py /app/backend/
RUN mkdir -p /var/lib/watchdawg/audit && chown 10001:10001 /var/lib/watchdawg/audit && chmod 0700 /var/lib/watchdawg/audit
USER 10001:10001
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8001", "--no-server-header", "--no-proxy-headers", "--no-access-log", "--limit-concurrency", "64", "--timeout-keep-alive", "5"]
