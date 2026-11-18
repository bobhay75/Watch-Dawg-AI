# syntax=docker/dockerfile:1
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
# Narrow signed-distribution update for the scanner-reported zlib advisory.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Optional build-only trust bundle; never disable package TLS verification.
RUN --mount=type=secret,id=package_ca \
    if [ -s /run/secrets/package_ca ]; then \
      PIP_CERT=/run/secrets/package_ca python -m pip install --no-cache-dir -r requirements.txt; \
    else \
      python -m pip install --no-cache-dir -r requirements.txt; \
    fi
RUN python -m pip uninstall --yes pip

RUN adduser --disabled-password --gecos "" key9 && chown -R key9:key9 /app
COPY --chown=key9:key9 main.py /app/main.py
COPY --chown=key9:key9 agents /app/agents
COPY --chown=key9:key9 key9_core /app/key9_core

USER key9
EXPOSE 8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
