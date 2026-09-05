"""Credential broker: retrieve late, inject once, redact, and discard."""

from __future__ import annotations

from collections.abc import Callable
import json
import os
from typing import Any, Protocol

from .policy import LeaseStore, PolicyDecision, PolicyEngine, normalize_target_host
from .redaction import redact_payload


class SecretProvider(Protocol):
    def access(self, alias: str) -> str: ...


class GoogleSecretManagerProvider:
    """Maps fixed aliases to Secret Manager resources outside model control."""

    def __init__(self, alias_map: dict[str, str] | None = None) -> None:
        configured = alias_map or json.loads(os.getenv("KEY9_SECRET_MAP_JSON", "{}"))
        self._alias_map = dict(configured)

    def access(self, alias: str) -> str:
        resource = self._alias_map.get(alias)
        if not resource:
            raise PermissionError("secret_alias_unconfigured")

        from google.cloud import secretmanager  # Imported only inside Cloud Run.

        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(request={"name": resource})
        return response.payload.data.decode("utf-8")


class SandboxSecretProvider:
    """Non-sensitive provider for tests and the public contest demonstration."""

    def __init__(self) -> None:
        self._values = {
            "watchdawg.production": "sandbox-watchdawg-token",
            "drive.receipts": "sandbox-drive-token",
            "accounting.export": "sandbox-accounting-token",
        }

    def access(self, alias: str) -> str:
        try:
            return self._values[alias]
        except KeyError as exc:
            raise PermissionError("secret_alias_unconfigured") from exc


class CredentialBroker:
    def __init__(
        self,
        provider: SecretProvider,
        policy: PolicyEngine | None = None,
        leases: LeaseStore | None = None,
    ) -> None:
        self._provider = provider
        self._policy = policy or PolicyEngine()
        self._leases = leases or LeaseStore()

    def authorize(
        self,
        *,
        alias: str,
        target: str,
        scopes: list[str],
        owner_approved: bool = False,
        ttl_seconds: int = 60,
    ) -> tuple[PolicyDecision, str | None]:
        decision = self._policy.evaluate(
            alias=alias,
            target=target,
            scopes=scopes,
            requested_ttl_seconds=ttl_seconds,
            owner_approved=owner_approved,
        )
        if not decision.allowed:
            return decision, None
        lease = self._leases.issue(
            alias=alias,
            target=target,
            scopes=scopes,
            decision=decision,
            owner_approved=owner_approved,
        )
        return decision, lease.lease_id

    def invoke(
        self,
        lease_id: str,
        *,
        target: str,
        executor: Callable[[str], Any],
    ) -> Any:
        # Consume authority before target checking, provider access, or connector
        # execution. Every invocation attempt is therefore single-use, including
        # failures and concurrent replays.
        lease = self._leases.consume(lease_id)
        if normalize_target_host(target) != lease.target_host:
            raise PermissionError("lease_target_mismatch")

        secret_value = ""
        try:
            secret_value = self._provider.access(lease.alias)
            result = executor(secret_value)
            return redact_payload(result, (secret_value,))
        finally:
            secret_value = ""  # Drop the last application-level reference.
