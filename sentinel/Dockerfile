FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    SENTINEL_CONFIG_ROOT=/app/sentinel/examples \
    SENTINEL_STATE_ROOT=/state

WORKDIR /app

RUN useradd --create-home --uid 10001 sentinel \
    && install -d -m 0700 -o sentinel -g sentinel /state

COPY sentinel/requirements.txt /tmp/sentinel-requirements.txt

RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    --requirement /tmp/sentinel-requirements.txt \
    && rm /tmp/sentinel-requirements.txt

COPY --chown=sentinel:sentinel sentinel /app/sentinel

USER sentinel

EXPOSE 8080

CMD ["python", "-m", "sentinel.api"]
