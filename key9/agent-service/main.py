"""Cloud Run entry point for the ADK API server."""

from __future__ import annotations

import os

from fastapi import FastAPI
from google.adk.cli.fast_api import get_fast_api_app


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENTS_DIR = os.path.join(BASE_DIR, "agents")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "KEY9_ALLOWED_ORIGINS",
        "https://watch-dawg-key9.thebobsomest1.chatgpt.site,http://localhost:3000",
    ).split(",")
    if origin.strip()
]

app: FastAPI = get_fast_api_app(
    agents_dir=AGENTS_DIR,
    session_service_uri=os.getenv("KEY9_SESSION_URI", "memory://"),
    allow_origins=ALLOWED_ORIGINS,
    web=False,
)


@app.get("/healthz", tags=["operations"])
async def healthcheck() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "watch-dawg-key9-agent",
        "model": os.getenv("KEY9_MODEL", "gemini-3.5-flash"),
        "secret_values_visible_to_model": 0,
        "sandbox": os.getenv("KEY9_SANDBOX", "true").lower() == "true",
    }


@app.get("/v1/security-posture", tags=["operations"])
async def security_posture() -> dict[str, object]:
    return {
        "fail_closed": True,
        "model_secret_access": False,
        "target_allowlist": True,
        "scope_allowlist": True,
        "short_lived_leases": True,
        "owner_approval_for_writes": True,
        "redacted_audit": True,
    }
