from __future__ import annotations

import ipaddress
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .core import Finding, Observation


MAX_PORTS = 16
KNOWN_SERVICES = {
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    27017: "mongodb",
}
Resolver = Callable[[str], set[str]]
Connector = Callable[[str, int, float], bool]


def _default_resolver(hostname: str) -> set[str]:
    return {item[4][0] for item in socket.getaddrinfo(hostname, None)}


def _default_connector(address: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except (ConnectionError, OSError, TimeoutError):
        return False


def _authorized_ports(target: dict[str, Any]) -> tuple[str, list[int]]:
    hostname = str(target.get("hostname", "")).strip().rstrip(".").lower()
    if not hostname or "://" in hostname or "/" in hostname:
        raise ValueError("service target requires one plain hostname")

    raw_ports = target.get("ports")
    if not isinstance(raw_ports, list) or not raw_ports:
        raise ValueError("service target requires an explicit ports list")
    if len(raw_ports) > MAX_PORTS:
        raise ValueError(f"service target may check at most {MAX_PORTS} explicit ports")
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in raw_ports):
        raise ValueError("service ports must be integers between 1 and 65535")
    ports = sorted(set(raw_ports))
    if len(ports) != len(raw_ports):
        raise ValueError("service ports must not contain duplicates")

    authorization = target.get("authorization")
    if not isinstance(authorization, dict):
        raise ValueError("service target requires a documented authorization record")
    if not str(authorization.get("id", "")).strip():
        raise ValueError("service authorization requires a record id")
    approved_methods = authorization.get("approved_methods", [])
    if not isinstance(approved_methods, list) or "tcp-connect" not in approved_methods:
        raise ValueError("service authorization must approve tcp-connect")
    scope = authorization.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("service authorization requires an exact scope")
    if str(scope.get("hostname", "")).strip().rstrip(".").lower() != hostname:
        raise ValueError("service authorization hostname does not match the target")
    if scope.get("ports") != raw_ports:
        raise ValueError("service authorization ports must exactly match the target")

    expires_at = authorization.get("expires_at")
    if not isinstance(expires_at, str):
        raise ValueError("service authorization requires an expiration time")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("service authorization expiration must be ISO-8601") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("service authorization is expired or lacks a timezone")
    return hostname, ports


class ServiceExposureWatchPack:
    """Checks explicitly approved TCP ports without banners or exploitation."""

    kind = "service_exposure"
    allowed_authorization_modes = {"owner", "contract"}

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
    ) -> None:
        self.resolver = resolver or _default_resolver
        self.connector = connector or _default_connector

    def observe(self, target: dict[str, Any]) -> Observation:
        hostname, ports = _authorized_ports(target)
        raw_addresses = self.resolver(hostname)
        parsed_addresses = []
        for raw_address in raw_addresses:
            try:
                address = ipaddress.ip_address(str(raw_address))
            except ValueError as exc:
                raise ValueError("service hostname resolved to an invalid address") from exc
            if not address.is_global or address.is_multicast:
                raise ValueError("service discovery is limited to public addresses")
            parsed_addresses.append(str(address))
        addresses = sorted(set(parsed_addresses))
        if not addresses:
            raise ValueError("service hostname did not resolve")
        timeout = min(max(float(target.get("timeout_seconds", 2)), 0.2), 5.0)
        port_status = {}
        for port in ports:
            deadline = time.monotonic() + timeout
            is_open = False
            for address in addresses:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if self.connector(address, port, remaining):
                    is_open = True
                    break
            port_status[str(port)] = {
                "open": is_open,
                "service_hint": KNOWN_SERVICES.get(port, "unknown"),
            }
        return Observation(
            target_id=str(target["id"]),
            kind=self.kind,
            ok=True,
            facts={
                "hostname": hostname,
                "resolved_addresses": addresses,
                "ports": port_status,
                "method": "tcp-connect-only",
                "banner_collection": False,
                "exploitation": False,
            },
            evidence=[f"tcp://{hostname}:{port}" for port in ports],
        )

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]:
        expected_raw = target.get("checks", {}).get("expected_open_ports", [])
        if not isinstance(expected_raw, list) or any(
            isinstance(port, bool) or not isinstance(port, int)
            for port in expected_raw
        ):
            raise ValueError("expected_open_ports must be a list of integers")
        checked = {int(port) for port in current.facts["ports"]}
        expected = set(expected_raw)
        if not expected.issubset(checked):
            raise ValueError("expected_open_ports must be included in the authorized ports")
        observed = {
            int(port)
            for port, status in current.facts["ports"].items()
            if status["open"]
        }
        findings: list[Finding] = []
        for port in sorted(observed - expected):
            findings.append(Finding(
                target_id=current.target_id,
                code=f"UNEXPECTED_OPEN_PORT_{port}",
                severity="high",
                title="Unexpected network service is reachable",
                detail=f"TCP port {port} accepted a connection but is not in the approved service baseline.",
                evidence={"port": port, "service_hint": KNOWN_SERVICES.get(port, "unknown")},
            ))
        for port in sorted(expected - observed):
            findings.append(Finding(
                target_id=current.target_id,
                code=f"EXPECTED_SERVICE_UNREACHABLE_{port}",
                severity="medium",
                title="Expected network service is unreachable",
                detail=f"TCP port {port} did not accept a connection but is in the approved service baseline.",
                evidence={"port": port, "service_hint": KNOWN_SERVICES.get(port, "unknown")},
            ))
        return findings
