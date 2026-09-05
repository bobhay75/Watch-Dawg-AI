"""Fail-closed deployment configuration checks."""

from __future__ import annotations

from collections.abc import Mapping
import os


def sandbox_enabled(environ: Mapping[str, str] | None = None) -> bool:
    values = os.environ if environ is None else environ
    return values.get("KEY9_SANDBOX", "true").strip().lower() == "true"


def session_service_uri(environ: Mapping[str, str] | None = None) -> str:
    """Reject process-local sessions whenever production mode is selected."""
    values = os.environ if environ is None else environ
    uri = values.get("KEY9_SESSION_URI", "memory://").strip() or "memory://"
    scheme = uri.partition(":")[0].lower()
    process_local = scheme in {"memory", "sqlite", "sqlite+aiosqlite"} or uri == ":memory:"
    if not sandbox_enabled(values) and process_local:
        raise RuntimeError("persistent_session_required_outside_sandbox")
    return uri
