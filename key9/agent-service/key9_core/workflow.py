"""Seeded Watch-Dawg connector tools for the contest proof-of-action flow.

The connector boundary is deterministic so judges can reproduce the same
closeout. Replacing these functions with production HTTP calls does not change
the agent or policy interface.
"""

from __future__ import annotations

from decimal import Decimal
import os
from collections.abc import Callable
from typing import Any

from .broker import (
    CredentialBroker,
    GoogleSecretManagerProvider,
    SandboxSecretProvider,
)


DEMO_JOB = {
    "job_id": "WD-1042",
    "name": "Johnson remodel",
    "labor_entries": 18,
    "labor_total": "6840.00",
    "material_total": "3271.66",
    "photos": 27,
    "open_requests": 0,
}

DEMO_RECEIPTS = [
    {"vendor": "Ozark Building Supply", "amount": "1264.18", "matched": True},
    {"vendor": "Branson West Hardware", "amount": "842.61", "matched": True},
    {"vendor": "Table Rock Lumber", "amount": "1078.45", "matched": True},
]


def _build_broker() -> CredentialBroker:
    sandbox = os.getenv("KEY9_SANDBOX", "true").lower() == "true"
    provider = SandboxSecretProvider() if sandbox else GoogleSecretManagerProvider()
    return CredentialBroker(provider)


_BROKER = _build_broker()


def _brokered_action(
    *,
    alias: str,
    target: str,
    scopes: list[str],
    owner_approved: bool,
    action: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Authorize and execute one action without returning credential material."""
    decision, lease_id = _BROKER.authorize(
        alias=alias,
        target=target,
        scopes=scopes,
        owner_approved=owner_approved,
    )
    if not decision.allowed or lease_id is None:
        return {
            "status": "approval_required" if decision.requires_approval else "blocked",
            "reason": decision.reason,
            "credential_alias": alias,
            "external_write_performed": False,
            "secret_values_visible_to_model": 0,
        }

    try:
        result = _BROKER.invoke(lease_id, lambda _credential: action())
    except Exception:  # The connector boundary fails closed and emits no provider detail.
        return {
            "status": "blocked",
            "reason": "credential_connector_unavailable",
            "credential_alias": alias,
            "external_write_performed": False,
            "secret_values_visible_to_model": 0,
        }

    return {
        **result,
        "credential_alias": alias,
        "lease_state": "revoked_after_use",
        "secret_values_visible_to_model": 0,
    }


def plan_secure_closeout(goal: str, job_id: str = "WD-1042") -> dict[str, Any]:
    """Create a bounded action plan from a closeout goal without requesting secrets."""
    if job_id != DEMO_JOB["job_id"]:
        return {"status": "blocked", "reason": "sandbox_job_not_found", "job_id": job_id}
    return {
        "status": "planned",
        "goal": goal[:500],
        "job_id": job_id,
        "actions": [
            "read_watchdawg_job",
            "collect_job_receipts",
            "reconcile_job",
            "prepare_accounting_export",
        ],
        "approval_required_for": ["prepare_accounting_export"],
        "secret_values_visible_to_model": 0,
    }


def read_watchdawg_job(job_id: str = "WD-1042") -> dict[str, Any]:
    """Read a Watch-Dawg sandbox job through an alias-backed connector."""
    if job_id != DEMO_JOB["job_id"]:
        return {"status": "blocked", "reason": "sandbox_job_not_found", "job_id": job_id}
    return _brokered_action(
        alias="watchdawg.production",
        target="https://api.watch-dawg.ai",
        scopes=["jobs:read"],
        owner_approved=False,
        action=lambda: {"status": "success", **DEMO_JOB},
    )


def collect_job_receipts(job_id: str = "WD-1042") -> dict[str, Any]:
    """Collect seeded receipt metadata; receipt-folder credentials stay at the broker."""
    if job_id != DEMO_JOB["job_id"]:
        return {"status": "blocked", "reason": "sandbox_job_not_found", "job_id": job_id}
    return _brokered_action(
        alias="drive.receipts",
        target="https://www.googleapis.com",
        scopes=["receipts:read"],
        owner_approved=False,
        action=lambda: {
            "status": "success",
            "job_id": job_id,
            "receipts": DEMO_RECEIPTS,
            "count": len(DEMO_RECEIPTS),
        },
    )


def reconcile_job(job_id: str = "WD-1042") -> dict[str, Any]:
    """Reconcile labor/material evidence and surface, rather than hide, disagreement."""
    if job_id != DEMO_JOB["job_id"]:
        return {"status": "blocked", "reason": "sandbox_job_not_found", "job_id": job_id}

    receipt_total = sum(Decimal(item["amount"]) for item in DEMO_RECEIPTS)
    ledger_total = Decimal(DEMO_JOB["material_total"])
    mismatch = ledger_total - receipt_total
    return {
        "status": "review_required" if mismatch else "balanced",
        "job_id": job_id,
        "receipt_total": f"{receipt_total:.2f}",
        "material_ledger_total": f"{ledger_total:.2f}",
        "mismatch": f"{mismatch:.2f}",
        "finding": "One material charge lacks matching receipt evidence." if mismatch else None,
        "autonomous_financial_verdict": False,
    }


def prepare_accounting_export(
    job_id: str = "WD-1042",
    owner_approved: bool = False,
) -> dict[str, Any]:
    """Prepare a reversible export draft; hold external writes for owner approval."""
    if job_id != DEMO_JOB["job_id"]:
        return {"status": "blocked", "reason": "sandbox_job_not_found", "job_id": job_id}
    return _brokered_action(
        alias="accounting.export",
        target="https://sandbox-accounting.watch-dawg.ai",
        scopes=["exports:create"],
        owner_approved=owner_approved,
        action=lambda: {
            "status": "success",
            "job_id": job_id,
            "artifact": "Johnson-remodel-closeout.csv",
            "rows": 21,
            "external_write_performed": True,
        },
    )
