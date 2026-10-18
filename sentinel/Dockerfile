FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    SENTINEL_CONFIG_ROOT=/app/sentinel/examples \
    SENTINEL_STATE_ROOT=/state

WORKDIR /app

RUN useradd --create-home --uid 10001 sentinel \
    && mkdir /state \
    && chown sentinel:sentinel /state

COPY sentinel/requirements.txt /tmp/sentinel-requirements.txt
RUN pip install --no-cache-dir -r /tmp/sentinel-requirements.txt

COPY --chown=sentinel:sentinel sentinel /app/sentinel

USER sentinel

EXPOSE 8080

CMD ["python", "-m", "sentinel.api"]
