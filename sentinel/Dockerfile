FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    SENTINEL_CONFIG_ROOT=/app/sentinel/examples \
    SENTINEL_STATE_ROOT=/state

WORKDIR /app

RUN useradd --create-home --uid 10001 sentinel \
    && mkdir /state \
    && chown sentinel:sentinel /state

COPY --chown=sentinel:sentinel sentinel /app/sentinel

USER sentinel

EXPOSE 8080

CMD ["python", "-m", "sentinel.api"]
