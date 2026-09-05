"""Cloud Run entry point for the ADK API server."""

from __future__ import annotations

import os
import secrets

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from google.adk.cli.fast_api import get_fast_api_app
from pydantic import BaseModel, Field

from key9_core.config import sandbox_enabled, session_service_uri
from key9_core.workflow import approve_accounting_export


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
BRIDGE_TOKEN = os.getenv("KEY9_BRIDGE_TOKEN", "").strip()
# Cloud Run reserves some paths ending in "z", including common /healthz routes.
PUBLIC_PATHS = frozenset({"/v1/health", "/v1/security-posture"})

app: FastAPI = get_fast_api_app(
    agents_dir=AGENTS_DIR,
    session_service_uri=session_service_uri(),
    allow_origins=ALLOWED_ORIGINS,
    web=False,
)


class ExportApprovalRequest(BaseModel):
    job_id: str = Field(default="WD-1042", max_length=64)
    human_approved: bool


@app.middleware("http")
async def require_private_bridge(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    if not BRIDGE_TOKEN:
        return JSONResponse(
            {"detail": "bridge_token_not_configured"},
            status_code=503,
        )
    provided = request.headers.get("x-key9-bridge-token", "")
    if not provided or not secrets.compare_digest(provided, BRIDGE_TOKEN):
        return JSONResponse({"detail": "bridge_unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/v1/health", tags=["operations"])
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
        "atomic_lease_consumption": True,
        "invocation_target_binding": True,
        "public_demo_can_relay_owner_approval": False,
        "authenticated_owner_approval": "required_not_implemented",
        "redaction_boundary": "recursive_known-value-and-pattern",
        "audit_receipts": "dynamic_sandbox_evidence",
        "model_can_self_approve": False,
        "persistent_sessions_required_outside_sandbox": True,
    }


@app.post("/v1/approve-export", tags=["actions"])
async def approve_export(
    approval: ExportApprovalRequest,
    x_key9_human_approval: str = Header(default=""),
) -> dict[str, object]:
    if not sandbox_enabled():
        raise HTTPException(
            status_code=503,
            detail="production_owner_authentication_required",
        )
    if not approval.human_approved or x_key9_human_approval != "confirmed":
        raise HTTPException(status_code=400, detail="human_approval_required")
    return approve_accounting_export(approval.job_id)
