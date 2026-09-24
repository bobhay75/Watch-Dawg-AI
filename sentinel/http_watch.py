from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .core import Finding, Observation, stable_hash, utc_now_iso
from .evidence_store import ContentAddressedEvidenceStore


MAX_BODY_BYTES = 2_000_000
INVALID_URL_EVIDENCE = "<invalid-url>"


class HttpFetcher(Protocol):
    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]: ...


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


def validate_public_http_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are allowed")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("target URL must contain a hostname and no embedded credentials")
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    }
    if not addresses:
        raise ValueError("target hostname did not resolve")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("private, loopback, link-local, and reserved targets are blocked")


class _SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        validate_public_http_url(urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SafeHttpFetcher:
    """A bounded, public-network-only HTTP fetcher. It never crawls."""

    USER_AGENT = "Watch-Dawg-Sentinel/0.1 (+https://github.com/bobhay75/Watch-Dawg-AI)"

    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        validate_public_http_url(url)
        request = Request(
            url,
            headers={"User-Agent": self.USER_AGENT, "Accept": "text/html,application/json;q=0.9,*/*;q=0.5"},
        )
        opener = build_opener(_SafeRedirectHandler())
        started = time.monotonic()
        try:
            response = opener.open(request, timeout=timeout_seconds)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(max_body_bytes + 1)
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            truncated = len(body) > max_body_bytes
            body = body[:max_body_bytes]
            headers = {key.lower(): value for key, value in response.headers.items()}
            charset = response.headers.get_content_charset() or "utf-8"
            text = body.decode(charset, errors="replace")
            return {
                "status": int(response.status),
                "final_url": response.geturl(),
                "latency_ms": elapsed_ms,
                "headers": headers,
                "body": text,
                "body_raw": body,
                "body_bytes": len(body),
                "truncated": truncated,
            }


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

    def __init__(
        self,
        fetcher: HttpFetcher | None = None,
        evidence_store: ContentAddressedEvidenceStore | None = None,
    ):
        self.fetcher = fetcher or SafeHttpFetcher()
        self.evidence_store = evidence_store

    def observe(self, target: dict[str, Any]) -> Observation:
        target_id = str(target["id"])
        url = str(target["url"])
        safe_url = sanitize_http_url_for_evidence(url)
        timeout = min(max(float(target.get("timeout_seconds", 10)), 1), 30)
        max_bytes = min(max(int(target.get("max_body_bytes", 500_000)), 1_000), MAX_BODY_BYTES)
        observed_at = utc_now_iso()
        try:
            if target.get("require_content_addressed_evidence") and self.evidence_store is None:
                raise ValueError("content-addressed evidence store is required for this target")
            response = self.fetcher.fetch(url, timeout, max_bytes)
            body = str(response.pop("body"))
            raw_body = response.pop("body_raw", None)
            if not isinstance(raw_body, bytes):
                raw_body = body.encode("utf-8")
            response["final_url"] = sanitize_http_url_for_evidence(
                response.get("final_url", url),
                fallback=safe_url,
            )
            parser = _HtmlFactsParser()
            parser.feed(body)
            headers = dict(response.get("headers", {}))
            coverage = {
                "scope": "single_url",
                "requested_url": safe_url,
                "final_url": response["final_url"],
                "authenticated": False,
                "javascript_rendering": False,
                "subresources_collected": False,
                "body_truncated": bool(response.get("truncated", False)),
                "max_body_bytes": max_bytes,
            }
            facts = {
                **response,
                "headers": headers,
                "title": " ".join("".join(parser.title_parts).split()),
                "body_sha256": hashlib.sha256(raw_body).hexdigest(),
                "json_ld_offer_prices": _json_ld_offer_prices(parser.json_ld_scripts),
                "required_text": {
                    marker: marker.casefold() in body.casefold()
                    for marker in target.get("checks", {}).get("contains", [])
                },
                "forbidden_text": {
                    marker: marker.casefold() in body.casefold()
                    for marker in target.get("checks", {}).get("not_contains", [])
                },
                "coverage": coverage,
            }
            evidence = [facts["final_url"]]
            if self.evidence_store is not None:
                body_artifact = self.evidence_store.put_bytes(
                    raw_body,
                    media_type=str(headers.get("content-type", "application/octet-stream")),
                    source=facts["final_url"],
                    observed_at=observed_at,
                    artifact_type="http-response-body",
                )
                capture_manifest = {
                    "schema": "watch-dawg-http-capture/v1",
                    "target_id": target_id,
                    "observed_at": observed_at,
                    "requested_url": safe_url,
                    "final_url": facts["final_url"],
                    "status": facts["status"],
                    "latency_ms": facts["latency_ms"],
                    "headers": headers,
                    "body": body_artifact,
                    "coverage": coverage,
                }
                capture_artifact = self.evidence_store.put_json(
                    capture_manifest,
                    source=facts["final_url"],
                    observed_at=observed_at,
                    artifact_type="http-capture-manifest",
                )
                package_manifest = {
                    "schema": "watch-dawg-evidence-package/v1",
                    "target_id": target_id,
                    "observed_at": observed_at,
                    "capture_ref": capture_artifact["ref"],
                    "artifact_refs": [body_artifact["ref"], capture_artifact["ref"]],
                    "coverage": coverage,
                }
                package_artifact = self.evidence_store.put_json(
                    package_manifest,
                    source=facts["final_url"],
                    observed_at=observed_at,
                    artifact_type="evidence-package-manifest",
                )
                facts["evidence_package"] = {
                    "schema": "watch-dawg-evidence-package/v1",
                    "package_ref": package_artifact["ref"],
                    "capture_ref": capture_artifact["ref"],
                    "artifacts": [body_artifact, capture_artifact, package_artifact],
                }
                evidence.extend(
                    [package_artifact["ref"], capture_artifact["ref"], body_artifact["ref"]]
                )
            return Observation(
                target_id=target_id,
                kind=self.kind,
                ok=True,
                facts=facts,
                observed_at=observed_at,
                evidence=evidence,
            )
        except Exception as exc:
            return Observation(
                target_id=target_id,
                kind=self.kind,
                ok=False,
                facts={"error_type": type(exc).__name__, "error": str(exc)[:300], "url": safe_url},
                observed_at=observed_at,
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
