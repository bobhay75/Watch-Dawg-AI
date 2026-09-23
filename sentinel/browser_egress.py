from __future__ import annotations

import ipaddress
import select
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Final, Iterable
from urllib.parse import urlsplit, urlunsplit


EGRESS_POLICY_SCHEMA: Final[str] = "watch-dawg-browser-egress-policy/v1"
MAX_HEADER_BYTES: Final[int] = 65_536
MAX_REQUEST_LINE_BYTES: Final[int] = 8_192
MAX_RECORDED_ATTEMPTS: Final[int] = 200
CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0
TUNNEL_IDLE_TIMEOUT_SECONDS: Final[float] = 30.0
PASSIVE_HTTP_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})
DEFAULT_WEB_PORTS: Final[frozenset[int]] = frozenset({80, 443})


class BrowserEgressError(RuntimeError):
    """Raised when browser traffic cannot satisfy the public-egress policy."""


@dataclass(frozen=True)
class ResolvedEndpoint:
    family: int
    socktype: int
    proto: int
    sockaddr: tuple[Any, ...]
    address: str


def public_address_policy(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True only for globally routable addresses."""
    return bool(address.is_global)


def resolve_public_endpoints(
    host: str,
    port: int,
    *,
    resolver: Callable[..., Iterable[tuple[Any, ...]]] = socket.getaddrinfo,
    address_policy: Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool] = public_address_policy,
) -> list[ResolvedEndpoint]:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise BrowserEgressError("egress hostname is missing or too long")
    if any(character.isspace() or ord(character) < 32 for character in host):
        raise BrowserEgressError("egress hostname contains invalid characters")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise BrowserEgressError("egress port is outside the valid TCP range")

    try:
        answers = list(resolver(host, port, type=socket.SOCK_STREAM))
    except OSError as exc:
        raise BrowserEgressError("egress hostname resolution failed") from exc
    if not answers:
        raise BrowserEgressError("egress hostname returned no TCP endpoints")

    endpoints: list[ResolvedEndpoint] = []
    seen: set[tuple[int, str, int]] = set()
    disallowed: list[str] = []
    for answer in answers:
        if len(answer) < 5:
            raise BrowserEgressError("egress resolver returned a malformed endpoint")
        family, socktype, proto, _canonname, sockaddr = answer[:5]
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype != socket.SOCK_STREAM:
            continue
        try:
            parsed = ipaddress.ip_address(str(sockaddr[0]))
        except (IndexError, TypeError, ValueError) as exc:
            raise BrowserEgressError("egress resolver returned an invalid IP address") from exc
        if not address_policy(parsed):
            disallowed.append(parsed.compressed)
            continue
        key = (family, parsed.compressed, int(sockaddr[1]))
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(
            ResolvedEndpoint(
                family=family,
                socktype=socket.SOCK_STREAM,
                proto=int(proto),
                sockaddr=tuple(sockaddr),
                address=parsed.compressed,
            )
        )

    # Reject the whole hostname if DNS returns any non-public answer. Picking a
    # public member from a mixed set would leave an SSRF ambiguity.
    if disallowed:
        raise BrowserEgressError("egress hostname resolved to at least one non-public address")
    if not endpoints:
        raise BrowserEgressError("egress hostname produced no allowed public TCP endpoints")
    return endpoints


def _authority(host: str, port: int, scheme: str) -> str:
    rendered = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = 443 if scheme == "https" else 80
    return rendered if port == default else f"{rendered}:{port}"


def _parse_connect_target(value: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(f"//{value}")
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError as exc:
        raise BrowserEgressError("CONNECT target is malformed") from exc
    if not host or parsed.username or parsed.password or parsed.path not in {"", "/"}:
        raise BrowserEgressError("CONNECT target must be a hostname and port")
    return host, port


def _read_headers(stream: Any) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    total = 0
    while True:
        raw = stream.readline(MAX_REQUEST_LINE_BYTES + 1)
        total += len(raw)
        if len(raw) > MAX_REQUEST_LINE_BYTES or total > MAX_HEADER_BYTES:
            raise BrowserEgressError("proxy request headers exceed the configured limit")
        if raw in {b"\r\n", b"\n", b""}:
            break
        try:
            line = raw.decode("iso-8859-1").rstrip("\r\n")
            name, separator, value = line.partition(":")
        except UnicodeError as exc:
            raise BrowserEgressError("proxy request header could not be decoded") from exc
        if not separator or not name.strip():
            raise BrowserEgressError("proxy request contains a malformed header")
        headers.append((name.strip(), value.strip()))
    return headers


def _connect_resolved(endpoint: ResolvedEndpoint, timeout: float) -> socket.socket:
    sock = socket.socket(endpoint.family, endpoint.socktype, endpoint.proto)
    sock.settimeout(timeout)
    try:
        sock.connect(endpoint.sockaddr)
    except Exception:
        sock.close()
        raise
    return sock


def _connect_first(endpoints: list[ResolvedEndpoint], timeout: float) -> tuple[socket.socket, ResolvedEndpoint]:
    last_error: OSError | None = None
    for endpoint in endpoints:
        try:
            return _connect_resolved(endpoint, timeout), endpoint
        except OSError as exc:
            last_error = exc
    raise BrowserEgressError("could not connect to any validated public endpoint") from last_error


def _relay_bidirectional(client: socket.socket, upstream: socket.socket, idle_timeout: float) -> None:
    client.setblocking(False)
    upstream.setblocking(False)
    peers = {client: upstream, upstream: client}
    last_activity = time.monotonic()
    while peers:
        remaining = max(0.0, idle_timeout - (time.monotonic() - last_activity))
        if remaining <= 0:
            return
        readable, _, exceptional = select.select(list(peers), [], list(peers), min(1.0, remaining))
        if exceptional:
            return
        if not readable:
            continue
        for source in readable:
            destination = peers[source]
            try:
                chunk = source.recv(65_536)
            except (BlockingIOError, ConnectionResetError, OSError):
                return
            if not chunk:
                return
            try:
                destination.sendall(chunk)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            last_activity = time.monotonic()


class _ThreadingProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyHandler(socketserver.StreamRequestHandler):
    server: Any

    def _send_error(self, status: int, message: str) -> None:
        body = f"Watch-Dawg browser egress denied: {message}\n".encode("utf-8")
        response = (
            f"HTTP/1.1 {status} Denied\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        try:
            self.request.sendall(response)
        except OSError:
            pass

    def handle(self) -> None:
        try:
            raw_line = self.rfile.readline(MAX_REQUEST_LINE_BYTES + 1)
            if not raw_line or len(raw_line) > MAX_REQUEST_LINE_BYTES:
                raise BrowserEgressError("proxy request line is missing or too long")
            try:
                line = raw_line.decode("ascii").rstrip("\r\n")
                method, target, version = line.split(" ", 2)
            except (UnicodeError, ValueError) as exc:
                raise BrowserEgressError("proxy request line is malformed") from exc
            method = method.upper()
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                raise BrowserEgressError("proxy accepts only HTTP/1.x")
            headers = _read_headers(self.rfile)
            if method == "CONNECT":
                self._handle_connect(target)
            elif method in PASSIVE_HTTP_METHODS:
                self._handle_http(method, target, headers)
            else:
                self.server.record_attempt(
                    method=method,
                    host="<unknown>",
                    port=0,
                    allowed=False,
                    reason="non_passive_method",
                )
                raise BrowserEgressError("proxy permits only passive HTTP methods")
        except BrowserEgressError as exc:
            self._send_error(403, str(exc))
        except OSError:
            self._send_error(502, "public upstream connection failed")

    def _resolve(self, host: str, port: int, method: str) -> tuple[socket.socket, ResolvedEndpoint]:
        if port not in self.server.allowed_ports:
            reason = "egress port is outside the browser web-port allowlist"
            self.server.record_attempt(
                method=method,
                host=host,
                port=port,
                allowed=False,
                reason=reason,
            )
            raise BrowserEgressError(reason)
        try:
            endpoints = resolve_public_endpoints(
                host,
                port,
                resolver=self.server.resolver,
                address_policy=self.server.address_policy,
            )
            upstream, endpoint = _connect_first(endpoints, self.server.connect_timeout)
        except BrowserEgressError as exc:
            self.server.record_attempt(
                method=method,
                host=host,
                port=port,
                allowed=False,
                reason=str(exc),
            )
            raise
        self.server.record_attempt(
            method=method,
            host=host,
            port=port,
            allowed=True,
            reason="validated_public_endpoint",
            address=endpoint.address,
        )
        return upstream, endpoint

    def _handle_connect(self, target: str) -> None:
        host, port = _parse_connect_target(target)
        upstream, _endpoint = self._resolve(host, port, "CONNECT")
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n")
            _relay_bidirectional(self.request, upstream, self.server.tunnel_idle_timeout)
        finally:
            upstream.close()

    def _handle_http(self, method: str, target: str, headers: list[tuple[str, str]]) -> None:
        try:
            parsed = urlsplit(target)
            if parsed.scheme.lower() != "http" or not parsed.hostname:
                raise BrowserEgressError("plain proxy requests must use an absolute http:// URL")
            if parsed.username or parsed.password:
                raise BrowserEgressError("proxy URLs may not contain embedded credentials")
            host = parsed.hostname
            port = parsed.port or 80
        except ValueError as exc:
            raise BrowserEgressError("plain proxy request URL is malformed") from exc

        header_map = {name.lower(): value for name, value in headers}
        if header_map.get("transfer-encoding"):
            raise BrowserEgressError("request bodies are not allowed through the passive egress proxy")
        try:
            content_length = int(header_map.get("content-length", "0") or "0")
        except ValueError as exc:
            raise BrowserEgressError("request Content-Length is invalid") from exc
        if content_length != 0:
            raise BrowserEgressError("request bodies are not allowed through the passive egress proxy")

        upstream, _endpoint = self._resolve(host, port, method)
        try:
            path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            outbound = [f"{method} {path} HTTP/1.1\r\n"]
            skipped = {"connection", "proxy-connection", "keep-alive", "host", "transfer-encoding"}
            for name, value in headers:
                if name.lower() in skipped:
                    continue
                outbound.append(f"{name}: {value}\r\n")
            outbound.append(f"Host: {_authority(host, port, 'http')}\r\n")
            outbound.append("Connection: close\r\n\r\n")
            upstream.sendall("".join(outbound).encode("iso-8859-1"))
            while True:
                chunk = upstream.recv(65_536)
                if not chunk:
                    break
                self.request.sendall(chunk)
        finally:
            upstream.close()


class BrowserEgressProxy:
    """Loopback-only proxy that resolves once and connects to validated IPs."""

    def __init__(
        self,
        *,
        resolver: Callable[..., Iterable[tuple[Any, ...]]] = socket.getaddrinfo,
        address_policy: Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool] = public_address_policy,
        allowed_ports: Iterable[int] = DEFAULT_WEB_PORTS,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        tunnel_idle_timeout: float = TUNNEL_IDLE_TIMEOUT_SECONDS,
    ) -> None:
        normalized_ports = frozenset(int(port) for port in allowed_ports)
        if not normalized_ports or len(normalized_ports) > 8 or any(port < 1 or port > 65535 for port in normalized_ports):
            raise BrowserEgressError("browser egress port allowlist is invalid")
        self._resolver = resolver
        self._address_policy = address_policy
        self._public_only_policy = address_policy is public_address_policy
        self._allowed_ports = normalized_ports
        self._connect_timeout = min(max(float(connect_timeout), 1.0), 30.0)
        self._tunnel_idle_timeout = min(max(float(tunnel_idle_timeout), 5.0), 120.0)
        self._server: _ThreadingProxyServer | None = None
        self._thread: threading.Thread | None = None
        self._attempts: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def __enter__(self) -> "BrowserEgressProxy":
        if self._server is not None:
            raise BrowserEgressError("browser egress proxy is already running")
        server = _ThreadingProxyServer(("127.0.0.1", 0), _ProxyHandler)
        server.resolver = self._resolver
        server.address_policy = self._address_policy
        server.allowed_ports = self._allowed_ports
        server.connect_timeout = self._connect_timeout
        server.tunnel_idle_timeout = self._tunnel_idle_timeout
        server.record_attempt = self._record_attempt
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            name="watch-dawg-browser-egress",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @property
    def server_url(self) -> str:
        if self._server is None:
            raise BrowserEgressError("browser egress proxy is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def attempts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._attempts]

    def _record_attempt(
        self,
        *,
        method: str,
        host: str,
        port: int,
        allowed: bool,
        reason: str,
        address: str | None = None,
    ) -> None:
        with self._lock:
            if len(self._attempts) >= MAX_RECORDED_ATTEMPTS:
                return
            item: dict[str, Any] = {
                "method": method,
                "host": host[:253],
                "port": port,
                "allowed": allowed,
                "reason": reason[:300],
            }
            if address:
                item["address"] = address
            self._attempts.append(item)

    def summary(self) -> dict[str, Any]:
        attempts = self.attempts
        return {
            "schema": EGRESS_POLICY_SCHEMA,
            "mode": "resolve_once_loopback_proxy",
            "attempts_recorded": len(attempts),
            "allowed_attempts": sum(bool(item.get("allowed")) for item in attempts),
            "blocked_attempts": sum(not bool(item.get("allowed")) for item in attempts),
            "attempt_limit": MAX_RECORDED_ATTEMPTS,
            "policy": {
                "public_addresses_only": self._public_only_policy,
                "mixed_public_private_dns_answers": "deny",
                "connect_to_validated_ip": True,
                "allowed_tcp_ports": sorted(self._allowed_ports),
                "passive_plain_http_methods": sorted(PASSIVE_HTTP_METHODS),
                "loopback_listener_only": True,
            },
        }

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2.0)
