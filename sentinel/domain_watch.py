from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Protocol


class DomainInspector(Protocol):
    def inspect(self, hostname: str, port: int, timeout_seconds: float) -> dict[str, Any]: ...


Resolver = Callable[[str, int], Iterable[str]]
Connector = Callable[[str, int, float], Any]


def _default_resolver(hostname: str, port: int) -> Iterable[str]:
    return {
        item[4][0]
        for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    }


def _public_addresses(addresses: Iterable[str]) -> list[str]:
    validated: set[str] = set()
    for raw_address in addresses:
        try:
            address = ipaddress.ip_address(str(raw_address))
        except ValueError as exc:
            raise ValueError("hostname resolved to an invalid address") from exc
        if not address.is_global or address.is_multicast:
            raise ValueError("domain target resolved to a non-public address")
        validated.add(str(address))
    addresses = sorted(validated)
    if not addresses:
        raise ValueError("hostname did not resolve")
    return addresses


def _default_connector(address: str, port: int, timeout_seconds: float) -> Any:
    return socket.create_connection((address, port), timeout=timeout_seconds)


class SocketDomainInspector:
    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.resolver = resolver or _default_resolver
        self.connector = connector or _default_connector
        self.tls_context = tls_context or ssl.create_default_context()

    def inspect(self, hostname: str, port: int, timeout_seconds: float) -> dict[str, Any]:
        addresses = _public_addresses(self.resolver(hostname, port))
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        certificate: dict[str, Any] | None = None
        cipher: Any = None
        protocol: str | None = None
        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TLS inspection deadline exceeded")
            try:
                with self.connector(address, port, remaining) as raw:
                    with self.tls_context.wrap_socket(raw, server_hostname=hostname) as secured:
                        certificate = secured.getpeercert()
                        cipher = secured.cipher()
                        protocol = secured.version()
                break
            except (ConnectionError, OSError, TimeoutError) as exc:
                last_error = exc
        if certificate is None:
            if last_error is not None:
                raise last_error
            raise ConnectionError("no validated address could be contacted")
        expires_raw = certificate.get("notAfter")
        if not expires_raw:
            raise ValueError("TLS certificate does not expose an expiry")
        expires_at = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(expires_raw), timezone.utc
        )
        days_remaining = (expires_at - datetime.now(timezone.utc)).total_seconds() / 86400
        return {
            "addresses": addresses,
            "tls_version": protocol,
            "cipher": cipher[0] if cipher else None,
            "certificate_subject": dict(item[0] for item in certificate.get("subject", ())),
            "certificate_issuer": dict(item[0] for item in certificate.get("issuer", ())),
            "certificate_expires_at": expires_at.isoformat(),
            "certificate_days_remaining": round(days_remaining, 2),
        }


class DnsTlsWatchPack:
    kind = "dns_tls"
    allowed_authorization_modes = {"public", "owner", "contract"}

    def __init__(self, inspector: DomainInspector | None = None):
        self.inspector = inspector or SocketDomainInspector()

    def observe(self, target: dict[str, Any]):
        from .core import Observation

        hostname = str(target.get("hostname", "")).strip().lower().rstrip(".")
        if not hostname or "/" in hostname or "@" in hostname:
            raise ValueError("dns_tls target requires a plain hostname")
        port = int(target.get("port", 443))
        if port < 1 or port > 65535:
            raise ValueError("port must be between 1 and 65535")
        timeout_seconds = min(max(float(target.get("timeout_seconds", 8)), 1), 20)
        facts = self.inspector.inspect(hostname, port, timeout_seconds)
        facts["hostname"] = hostname
        facts["port"] = port
        facts["address_set_sha256"] = hashlib.sha256(
            "\0".join(facts.get("addresses", [])).encode("utf-8")
        ).hexdigest()
        return Observation(
            target_id=str(target["id"]),
            kind=self.kind,
            ok=True,
            facts=facts,
            evidence=[f"{hostname}:{port}"],
        )

    def evaluate(self, target, current, previous):
        from .core import Finding

        checks = target.get("checks", {})
        facts = current.facts
        findings = []
        warning_days = float(checks.get("tls_expiry_warning_days", 30))
        critical_days = float(checks.get("tls_expiry_critical_days", 7))
        days = float(facts["certificate_days_remaining"])
        if days <= critical_days:
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="TLS_CERTIFICATE_EXPIRY_CRITICAL",
                    severity="critical",
                    title="TLS certificate is near expiry",
                    detail=f"The certificate has {days:.1f} days remaining.",
                    evidence={
                        "hostname": facts["hostname"],
                        "expires_at": facts["certificate_expires_at"],
                        "days_remaining": days,
                        "critical_days": critical_days,
                    },
                )
            )
        elif days <= warning_days:
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="TLS_CERTIFICATE_EXPIRY_WARNING",
                    severity="high",
                    title="TLS certificate entered the warning window",
                    detail=f"The certificate has {days:.1f} days remaining.",
                    evidence={
                        "hostname": facts["hostname"],
                        "expires_at": facts["certificate_expires_at"],
                        "days_remaining": days,
                        "warning_days": warning_days,
                    },
                )
            )

        required_version = checks.get("minimum_tls_version")
        if required_version and _tls_rank(facts.get("tls_version")) < _tls_rank(required_version):
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="TLS_VERSION_BELOW_MINIMUM",
                    severity="high",
                    title="TLS version is below the configured minimum",
                    detail=f"Observed {facts.get('tls_version')}; expected {required_version} or newer.",
                    evidence={
                        "observed": facts.get("tls_version"),
                        "minimum": required_version,
                    },
                )
            )

        if (
            previous
            and previous.ok
            and previous.facts.get("address_set_sha256")
            != facts.get("address_set_sha256")
        ):
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="DNS_ADDRESS_SET_CHANGED",
                    severity="info",
                    title="Public DNS address set changed",
                    detail="The resolved address set changed since the prior observation.",
                    evidence={
                        "before": previous.facts.get("addresses", []),
                        "after": facts.get("addresses", []),
                    },
                    stateful=False,
                )
            )
        return findings


def _tls_rank(value: Any) -> int:
    return {
        "TLSv1": 10,
        "TLSv1.1": 11,
        "TLSv1.2": 12,
        "TLSv1.3": 13,
    }.get(str(value), 0)
