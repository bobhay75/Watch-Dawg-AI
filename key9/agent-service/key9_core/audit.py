"""Redacted, evidence-bound audit receipts for KEY-9 sandbox actions."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any

from .policy import normalize_target_host
from .redaction import redact_payload


AUDIT_SCHEMA = "key9.audit.v1"
ACS_ALIGNMENT = "preview-shaped-not-conformance-tested"


def create_audit_receipt(
    *,
    alias: str,
    target: str,
    scopes: list[str],
    status: str,
    phase: str,
    sandbox: bool,
    external_write_performed: bool | None,
    result: Any,
) -> dict[str, Any]:
    """Create a unique receipt whose digest covers the redacted result."""
    if phase not in {"authorization", "connector"}:
        raise ValueError("unsupported_audit_phase")
    safe_result = redact_payload(result)
    canonical_result = json.dumps(
        safe_result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    if phase == "authorization":
        claim = "policy_blocked_or_held"
    elif external_write_performed is None:
        claim = "connector_effect_unknown"
    elif sandbox:
        claim = "sandbox_fixture_only"
    elif external_write_performed:
        claim = "connector_reported_external_effect"
    else:
        claim = "connector_reported_no_external_effect"

    return {
        "schema": AUDIT_SCHEMA,
        "event_id": f"k9e_{uuid.uuid4().hex}",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "event_type": (
            "authorization_decision"
            if phase == "authorization"
            else "credential_connector_action"
        ),
        "actor": "key9.policy_engine" if phase == "authorization" else "key9.connector",
        "credential_alias": alias,
        "target_host": normalize_target_host(target),
        "scopes": sorted({scope.strip().lower() for scope in scopes}),
        "status": status,
        "sandbox": sandbox,
        "external_write_performed": external_write_performed,
        "evidence_claim": claim,
        "result_sha256": hashlib.sha256(canonical_result.encode("utf-8")).hexdigest(),
        "acs_alignment": ACS_ALIGNMENT,
    }
