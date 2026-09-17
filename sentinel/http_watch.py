from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import time
from html.parser import HTMLParser
from typing import Any, Callable, Iterable, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from .core import Finding, Observation, stable_hash


MAX_BODY_BYTES = 2_000_000
MAX_REDIRECTS = 5
INVALID_URL_EVIDENCE = "<invalid-url>"
SAFE_RESPONSE_HEADERS = frozenset({
    "cache-control",
    "content-length",
    "content-security-policy",
    "content-type",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
})
Resolver = Callable[[str, int], Iterable[str]]


class HttpFetcher(Protocol):
    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]: ...


def _safe_response_headers(headers: Any) -> dict[str, str]:
    if not hasattr(headers, "items"):
        return {}
    return {
        str(key).lower(): str(value)[:4096]
        for key, value in headers.items()
        if str(key).lower() in SAFE_RESPONSE_HEADERS
    }


def sanitize_http_url_for_evidence(value: Any, fallback: str = INVALID_URL_EVIDENCE) -> str:
    """Return an HTTP(S) URL without credential-bearing URL components."""
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return fallback
        port = parsed.port
    except (TypeError, ValueError):
        return fallback

    hostname = parsed.hostname
    if ":" in hostname:
        hostname = f"[{hostname}]"
    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))


def _http_url_parts(url: str) -> tuple[Any, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are allowed")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("target URL must contain a hostname and no embedded credentials")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("target URL contains an invalid hostname or port") from exc
    if any(ord(character) < 33 or ord(character) == 127 for character in hostname):
        raise ValueError("target URL contains an invalid hostname")
    return parsed, hostname, port


def _default_resolver(hostname: str, port: int) -> Iterable[str]:
    return {
        item[4][0]
        for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    }


def _validated_public_addresses(addresses: Iterable[str]) -> list[str]:
    validated: set[str] = set()
    for raw_address in addresses:
        try:
            address = ipaddress.ip_address(str(raw_address))
        except ValueError as exc:
            raise ValueError("target hostname resolved to an invalid address") from exc
        if not address.is_global or address.is_multicast:
            raise ValueError("private, loopback, link-local, and reserved targets are blocked")
        validated.add(str(address))
    addresses = sorted(validated)
    if not addresses:
        raise ValueError("target hostname did not resolve")
    return addresses


def validate_public_http_url(url: str) -> None:
    """Validate URL syntax and require every address in one DNS answer to be public."""
    _, hostname, port = _http_url_parts(url)
    _validated_public_addresses(_default_resolver(hostname, port))


def validate_http_url_syntax(url: str) -> None:
    """Validate an HTTP(S) URL without performing a separate DNS lookup."""
    _http_url_parts(url)


def _origin(url: str) -> tuple[str, str, int]:
    parsed, hostname, port = _http_url_parts(url)
    return parsed.scheme.lower(), hostname, port


def _host_header(hostname: str, port: int, scheme: str) -> str:
    displayed_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    return displayed_host if port == default_port else f"{displayed_host}:{port}"


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose socket target is an already-vetted numeric address."""

    def __init__(
        self,
        hostname: str,
        port: int,
        pinned_address: str,
        timeout: float,
    ) -> None:
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    """HTTPS connection pinned to an IP while verifying the authorized hostname."""

    default_port = 443

    def __init__(
        self,
        hostname: str,
        port: int,
        pinned_address: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port, pinned_address, timeout)
        self._context = context

    def connect(self) -> None:
        super().connect()
        assert self.sock is not None
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        except Exception:
            self.sock.close()
            raise


def _read_response_body(
    response: Any,
    connection: http.client.HTTPConnection,
    *,
    deadline: float,
    max_body_bytes: int,
) -> bytes:
    """Read at most max+1 bytes while enforcing one absolute deadline."""
    chunks: list[bytes] = []
    remaining_bytes = max_body_bytes + 1
    reader = getattr(response, "read1", None)
    if reader is None:
        reader = response.read
    while remaining_bytes:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise TimeoutError("HTTP response deadline exceeded")
        connection_socket = getattr(connection, "sock", None)
        if connection_socket is not None:
            connection_socket.settimeout(remaining_seconds)
        chunk = reader(min(65_536, remaining_bytes))
        if not chunk:
            break
        chunks.append(chunk)
        remaining_bytes -= len(chunk)
    return b"".join(chunks)


class SafeHttpFetcher:
    """A bounded HTTP fetcher pinned to one validated DNS answer per request."""

    USER_AGENT = "Watch-Dawg-Sentinel/0.1 (+https://github.com/bobhay75/Watch-Dawg-AI)"

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.resolver = resolver or _default_resolver
        self.tls_context = tls_context or ssl.create_default_context()

    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        started = time.monotonic()
        deadline = started + max(float(timeout_seconds), 0.001)
        current_url = str(url)
        initial_origin = _origin(current_url)

        for redirect_count in range(MAX_REDIRECTS + 1):
            response = self._request_once(
                current_url,
                deadline=deadline,
                max_body_bytes=max_body_bytes,
            )
            location = response.pop("location", None)
            if response["status"] not in {301, 302, 303, 307, 308} or not location:
                response["final_url"] = sanitize_http_url_for_evidence(current_url)
                response["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
                return response
            if redirect_count == MAX_REDIRECTS:
                raise ValueError(f"redirect limit of {MAX_REDIRECTS} exceeded")

            redirected_url = urljoin(current_url, location)
            redirected_origin = _origin(redirected_url)
            if redirected_origin != initial_origin:
                raise ValueError("cross-origin redirects are blocked")
            current_url = redirected_url

        raise AssertionError("redirect loop should have returned or raised")

    def _request_once(
        self,
        url: str,
        *,
        deadline: float,
        max_body_bytes: int,
    ) -> dict[str, Any]:
        parsed, hostname, port = _http_url_parts(url)
        addresses = _validated_public_addresses(self.resolver(hostname, port))
        request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = {
            "Host": _host_header(hostname, port, parsed.scheme.lower()),
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.5",
            "Connection": "close",
        }
        last_error: Exception | None = None

        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP request deadline exceeded")
            if parsed.scheme.lower() == "https":
                connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
                    hostname,
                    port,
                    address,
                    remaining,
                    self.tls_context,
                )
            else:
                connection = _PinnedHTTPConnection(hostname, port, address, remaining)
            try:
                connection.request("GET", request_target, headers=headers)
                response = connection.getresponse()
                body = _read_response_body(
                    response,
                    connection,
                    deadline=deadline,
                    max_body_bytes=max_body_bytes,
                )
                truncated = len(body) > max_body_bytes
                body = body[:max_body_bytes]
                response_headers = _safe_response_headers(response.headers)
                charset = response.headers.get_content_charset() or "utf-8"
                return {
                    "status": int(response.status),
                    "headers": response_headers,
                    "body": body.decode(charset, errors="replace"),
                    "body_bytes": len(body),
                    "truncated": truncated,
                    "location": response.headers.get("Location"),
                }
            except (ConnectionError, http.client.HTTPException, OSError, TimeoutError) as exc:
                last_error = exc
            finally:
                connection.close()

        if last_error is not None:
            raise last_error
        raise ConnectionError("no validated address could be contacted")


class _HtmlFactsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.in_json_ld = False
        self.title_parts: list[str] = []
        self.script_parts: list[str] = []
        self.json_ld_scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "script" and attributes.get("type", "").lower() == "application/ld+json":
            self.in_json_ld = True
            self.script_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        if tag.lower() == "script" and self.in_json_ld:
            self.json_ld_scripts.append("".join(self.script_parts))
            self.in_json_ld = False
            self.script_parts = []

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_json_ld:
            self.script_parts.append(data)


def _json_ld_offer_prices(scripts: list[str]) -> list[Any]:
    prices: list[Any] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("@type") == "Offer" and "price" in value:
                prices.append(value["price"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for script in scripts:
        try:
            walk(json.loads(script))
        except (TypeError, ValueError):
            continue
    return prices


def _is_zero_price(value: Any) -> bool:
    try:
        return float(value) == 0
    except (TypeError, ValueError):
        return False


class HttpWatchPack:
    kind = "http"
    allowed_authorization_modes = {"public", "owner", "contract"}

    def __init__(self, fetcher: HttpFetcher | None = None):
        self.fetcher = fetcher or SafeHttpFetcher()

    def observe(self, target: dict[str, Any]) -> Observation:
        target_id = str(target["id"])
        url = str(target["url"])
        safe_url = sanitize_http_url_for_evidence(url)
        timeout = min(max(float(target.get("timeout_seconds", 10)), 1), 30)
        max_bytes = min(max(int(target.get("max_body_bytes", 500_000)), 1_000), MAX_BODY_BYTES)
        try:
            response = self.fetcher.fetch(url, timeout, max_bytes)
            body = str(response.pop("body"))
            response["final_url"] = sanitize_http_url_for_evidence(
                response.get("final_url", url),
                fallback=safe_url,
            )
            parser = _HtmlFactsParser()
            parser.feed(body)
            headers = _safe_response_headers(response.get("headers", {}))
            facts = {
                **response,
                "headers": headers,
                "title": " ".join("".join(parser.title_parts).split()),
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "json_ld_offer_prices": _json_ld_offer_prices(parser.json_ld_scripts),
                "required_text": {
                    marker: marker.casefold() in body.casefold()
                    for marker in target.get("checks", {}).get("contains", [])
                },
                "forbidden_text": {
                    marker: marker.casefold() in body.casefold()
                    for marker in target.get("checks", {}).get("not_contains", [])
                },
            }
            return Observation(
                target_id=target_id,
                kind=self.kind,
                ok=True,
                facts=facts,
                evidence=[facts["final_url"]],
            )
        except Exception as exc:
            return Observation(
                target_id=target_id,
                kind=self.kind,
                ok=False,
                facts={"error_type": type(exc).__name__, "error": str(exc)[:300], "url": safe_url},
                evidence=[safe_url],
            )

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        checks = target.get("checks", {})
        if not current.ok:
            return [
                Finding(
                    target_id=current.target_id,
                    code="HTTP_OBSERVATION_FAILED",
                    severity="high",
                    title="Website observation failed",
                    detail="Sentinel could not establish the target's current public state.",
                    evidence=current.facts,
                )
            ]

        status = int(current.facts["status"])
        allowed_statuses = checks.get("allowed_statuses")
        status_allowed = status in allowed_statuses if allowed_statuses else 200 <= status < 400
        if not status_allowed:
            findings.append(self._finding(current, "HTTP_STATUS_UNEXPECTED", "high", "Unexpected HTTP status", f"The target returned HTTP {status}.", {"status": status}))

        max_latency = checks.get("max_latency_ms")
        if max_latency is not None and float(current.facts["latency_ms"]) > float(max_latency):
            findings.append(self._finding(current, "HTTP_LATENCY_HIGH", "medium", "Response time crossed the limit", f"Observed latency was {current.facts['latency_ms']} ms; the configured limit is {max_latency} ms.", {"latency_ms": current.facts["latency_ms"], "limit_ms": max_latency}))

        for marker, present in current.facts.get("required_text", {}).items():
            if not present:
                code = f"REQUIRED_TEXT_MISSING_{stable_hash(marker)[:10]}"
                findings.append(self._finding(current, code, "medium", "Required page content disappeared", f"The configured text marker was not found: {marker}", {"marker": marker}))

        for marker, present in current.facts.get("forbidden_text", {}).items():
            if present:
                code = f"FORBIDDEN_TEXT_PRESENT_{stable_hash(marker)[:10]}"
                findings.append(self._finding(current, code, "medium", "Known-bad page content is present", f"The configured unwanted text marker was found: {marker}", {"marker": marker}))

        headers = current.facts.get("headers", {})
        for header in checks.get("required_headers", []):
            normalized = str(header).lower()
            if normalized not in headers:
                findings.append(self._finding(current, f"HEADER_MISSING_{stable_hash(normalized)[:10]}", "low", "Configured response header is missing", f"The {normalized} response header was not present. This is a configuration signal, not proof of compromise.", {"header": normalized}))

        if checks.get("jsonld_offer_price_nonzero"):
            prices = current.facts.get("json_ld_offer_prices", [])
            if not prices:
                findings.append(self._finding(current, "JSONLD_OFFER_PRICE_MISSING", "medium", "Structured ticket price is missing", "No JSON-LD Offer price was found on the event page.", {}))
            elif any(_is_zero_price(price) for price in prices):
                findings.append(self._finding(current, "JSONLD_OFFER_PRICE_ZERO", "medium", "Structured ticket price is zero", "The visible event can have a paid price while search-engine Event data reports an Offer price of zero.", {"prices": prices}))

        if previous and previous.ok:
            old_status = previous.facts.get("status")
            if old_status != status:
                findings.append(self._finding(current, "HTTP_STATUS_CHANGED", "medium", "HTTP status changed", f"Status changed from {old_status} to {status}.", {"before": old_status, "after": status}, stateful=False))
            if checks.get("track_content") and previous.facts.get("body_sha256") != current.facts.get("body_sha256"):
                findings.append(self._finding(current, "PAGE_CONTENT_CHANGED", "info", "Page content changed", "The bounded page-body fingerprint changed since the prior observation.", {"before": previous.facts.get("body_sha256"), "after": current.facts.get("body_sha256")}, stateful=False))
            if previous.facts.get("final_url") != current.facts.get("final_url"):
                findings.append(self._finding(current, "FINAL_URL_CHANGED", "medium", "Final landing URL changed", "The target now resolves to a different final URL.", {"before": previous.facts.get("final_url"), "after": current.facts.get("final_url")}, stateful=False))
        return findings

    @staticmethod
    def _finding(current: Observation, code: str, severity: str, title: str, detail: str, evidence: dict[str, Any], stateful: bool = True) -> Finding:
        return Finding(
            target_id=current.target_id,
            code=code,
            severity=severity,
            title=title,
            detail=detail,
            truth="VERIFIED",
            evidence={**evidence, "source": current.evidence[0] if current.evidence else None},
            stateful=stateful,
        )
