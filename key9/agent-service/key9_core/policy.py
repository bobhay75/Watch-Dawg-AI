"""Fail-closed authorization for credential-backed agent actions.

The model supplies a secret *alias*, target, and requested scopes. It never
supplies a secret resource name and never receives secret material.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import time
from typing import Iterable, Mapping
from urllib.parse import urlparse


FORBIDDEN_SCOPES = frozenset(
    {
        "secret:read",
        "secret:reveal",
        "credential:export",
        "password:show",
        "token:raw",
    }
)


@dataclass(frozen=True)
class PolicyRule:
    alias: str
    target_host: str
    allowed_scopes: frozenset[str]
    write_scopes: frozenset[str] = frozenset()
    max_ttl_seconds: int = 60


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    ttl_seconds: int = 0


@dataclass(frozen=True)
class CredentialLease:
    lease_id: str
    alias: str
    target_host: str
    scopes: frozenset[str]
    expires_at: float
    approved: bool

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


DEFAULT_POLICY: Mapping[str, PolicyRule] = {
    "watchdawg.production": PolicyRule(
        alias="watchdawg.production",
        target_host="api.watch-dawg.ai",
        allowed_scopes=frozenset({"jobs:read", "audit:write"}),
        write_scopes=frozenset({"audit:write"}),
        max_ttl_seconds=60,
    ),
    "drive.receipts": PolicyRule(
        alias="drive.receipts",
        target_host="www.googleapis.com",
        allowed_scopes=frozenset({"receipts:read"}),
        max_ttl_seconds=300,
    ),
    "accounting.export": PolicyRule(
        alias="accounting.export",
        target_host="sandbox-accounting.watch-dawg.ai",
        allowed_scopes=frozenset({"exports:create"}),
        write_scopes=frozenset({"exports:create"}),
        max_ttl_seconds=30,
    ),
}


def _normalize_host(target: str) -> str:
    value = target.strip().lower()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme != "https" or not parsed.hostname:
        return ""
    try:
        return parsed.hostname.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError:
        return ""


class PolicyEngine:
    """Evaluates aliases against an immutable allowlist."""

    def __init__(self, rules: Mapping[str, PolicyRule] | None = None) -> None:
        self._rules = dict(rules or DEFAULT_POLICY)

    def evaluate(
        self,
        *,
        alias: str,
        target: str,
        scopes: Iterable[str],
        requested_ttl_seconds: int = 60,
        owner_approved: bool = False,
    ) -> PolicyDecision:
        rule = self._rules.get(alias)
        if rule is None:
            return PolicyDecision(False, "unknown_secret_alias")

        target_host = _normalize_host(target)
        if not target_host or target_host != rule.target_host:
            return PolicyDecision(False, "target_not_allowlisted")

        requested_scopes = frozenset(scope.strip().lower() for scope in scopes)
        if not requested_scopes:
            return PolicyDecision(False, "scope_required")
        if requested_scopes & FORBIDDEN_SCOPES:
            return PolicyDecision(False, "secret_disclosure_forbidden")
        if not requested_scopes.issubset(rule.allowed_scopes):
            return PolicyDecision(False, "scope_not_allowlisted")

        requires_approval = bool(requested_scopes & rule.write_scopes)
        if requires_approval and not owner_approved:
            return PolicyDecision(False, "owner_approval_required", True)

        ttl = max(1, min(int(requested_ttl_seconds), rule.max_ttl_seconds))
        return PolicyDecision(True, "allowed", requires_approval, ttl)


@dataclass
class LeaseStore:
    """Process-local lease registry. Production persistence can use Firestore."""

    _leases: dict[str, CredentialLease] = field(default_factory=dict)

    def issue(
        self,
        *,
        alias: str,
        target: str,
        scopes: Iterable[str],
        decision: PolicyDecision,
        owner_approved: bool,
    ) -> CredentialLease:
        if not decision.allowed:
            raise PermissionError(decision.reason)

        lease = CredentialLease(
            lease_id=f"k9l_{secrets.token_urlsafe(18)}",
            alias=alias,
            target_host=_normalize_host(target),
            scopes=frozenset(scopes),
            expires_at=time.time() + decision.ttl_seconds,
            approved=owner_approved,
        )
        self._leases[lease.lease_id] = lease
        return lease

    def validate(self, lease_id: str) -> CredentialLease:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise PermissionError("lease_not_found")
        if lease.expired:
            self._leases.pop(lease_id, None)
            raise PermissionError("lease_expired")
        return lease

    def revoke(self, lease_id: str) -> bool:
        return self._leases.pop(lease_id, None) is not None

    def revoke_all(self) -> int:
        count = len(self._leases)
        self._leases.clear()
        return count
