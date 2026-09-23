from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable, Final
from urllib.parse import urlsplit, urlunsplit

from .browser_egress import BrowserEgressProxy, EGRESS_POLICY_SCHEMA
from .core import utc_now_iso
from .evidence_store import ContentAddressedEvidenceStore
from .evidence_verify import PackageVerificationError, read_verified_artifact, read_verified_json
from .http_watch import sanitize_http_url_for_evidence, validate_public_http_url


BROWSER_CAPTURE_SCHEMA: Final[str] = "watch-dawg-browser-capture/v1"
BROWSER_PACKAGE_SCHEMA: Final[str] = "watch-dawg-browser-evidence-package/v1"
BROWSER_VERIFICATION_SCHEMA: Final[str] = "watch-dawg-browser-evidence-verification/v1"
DEFAULT_VIEWPORT: Final[dict[str, int]] = {"width": 1440, "height": 900}
MAX_DOM_BYTES: Final[int] = 2_000_000
MAX_CONSOLE_EVENTS: Final[int] = 200
MAX_NETWORK_EVENTS: Final[int] = 500
MAX_REQUESTS: Final[int] = 250
MAX_MESSAGE_CHARS: Final[int] = 2_000
ALLOWED_PASSIVE_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})
LOCAL_SCHEMES: Final[frozenset[str]] = frozenset({"about", "blob", "data"})


class BrowserCaptureError(RuntimeError):
    """Raised when bounded passive browser capture cannot be completed safely."""


def _bounded_text(value: Any, limit: int = MAX_MESSAGE_CHARS) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _safe_url(value: Any) -> str:
    return sanitize_http_url_for_evidence(value)


def _safe_websocket_url(value: Any) -> str:
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme.lower() not in {"ws", "wss"} or not parsed.hostname:
            return "<websocket>"
        hostname = parsed.hostname
        if ":" in hostname:
            hostname = f"[{hostname}]"
        port = parsed.port
        default = 443 if parsed.scheme.lower() == "wss" else 80
        netloc = hostname if port in {None, default} else f"{hostname}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))
    except (TypeError, ValueError):
        return "<websocket>"


def _validate_browser_request(
    url: str,
    method: str,
    *,
    url_validator: Callable[[str], None] = validate_public_http_url,
) -> tuple[bool, str | None]:
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return False, "invalid_url"
    if scheme in LOCAL_SCHEMES:
        return True, None
    if scheme not in {"http", "https"}:
        return False, "unsupported_scheme"
    if method.upper() not in ALLOWED_PASSIVE_METHODS:
        return False, "non_passive_method"
    try:
        url_validator(url)
    except (OSError, ValueError):
        return False, "non_public_network_target"
    return True, None


def _canonical_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def capture_browser_evidence(
    *,
    evidence_root: str | Path,
    url: str,
    target_id: str,
    timeout_ms: int = 15_000,
    settle_ms: int = 750,
    viewport: dict[str, int] | None = None,
    max_requests: int = MAX_REQUESTS,
    max_network_events: int = MAX_NETWORK_EVENTS,
    max_console_events: int = MAX_CONSOLE_EVENTS,
    url_validator: Callable[[str], None] = validate_public_http_url,
    _egress_proxy_factory: Callable[[], BrowserEgressProxy] | None = None,
) -> dict[str, Any]:
    """Capture bounded public/passive browser evidence with no page interaction.

    Browser traffic is forced through a loopback egress proxy that resolves a
    hostname once, rejects mixed/non-public answer sets, and connects directly
    to the validated IP. The Playwright route remains a second policy layer.
    WebSockets are closed locally without connecting to the server. Non-passive
    HTTP methods are aborted. The capture performs no clicks, form submissions,
    credential injection, downloads, or remediation.

    ``_egress_proxy_factory`` exists only so the real-Chromium test can route to
    its loopback fixture. The CLI/API do not expose an egress-policy override.
    """
    if not isinstance(target_id, str) or not target_id.strip() or len(target_id) > 200:
        raise BrowserCaptureError("target_id must be non-empty text no longer than 200 characters")
    target_id = target_id.strip()
    timeout_ms = min(max(int(timeout_ms), 1_000), 30_000)
    settle_ms = min(max(int(settle_ms), 0), 2_000)
    max_requests = min(max(int(max_requests), 1), MAX_REQUESTS)
    max_network_events = min(max(int(max_network_events), 1), MAX_NETWORK_EVENTS)
    max_console_events = min(max(int(max_console_events), 1), MAX_CONSOLE_EVENTS)
    viewport = dict(viewport or DEFAULT_VIEWPORT)
    width = min(max(int(viewport.get("width", 1440)), 320), 1920)
    height = min(max(int(viewport.get("height", 900)), 240), 1080)
    viewport = {"width": width, "height": height}

    try:
        url_validator(url)
    except (OSError, ValueError) as exc:
        raise BrowserCaptureError(f"browser target is not an allowed public URL: {exc}") from exc

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BrowserCaptureError(
            "browser capture requires the pinned Playwright dependency from sentinel/browser/requirements.txt"
        ) from exc

    observed_at = utc_now_iso()
    network_events: list[dict[str, Any]] = []
    console_events: list[dict[str, Any]] = []
    blocked_requests: list[dict[str, Any]] = []
    request_count = 0
    request_budget_exceeded = False

    def append_network(event: dict[str, Any]) -> None:
        if len(network_events) < max_network_events:
            network_events.append(event)

    def append_console(event: dict[str, Any]) -> None:
        if len(console_events) < max_console_events:
            console_events.append(event)

    def append_blocked(event: dict[str, Any]) -> None:
        if len(blocked_requests) < 100:
            blocked_requests.append(event)

    proxy_factory = _egress_proxy_factory or BrowserEgressProxy
    try:
        with proxy_factory() as egress_proxy:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    proxy={"server": egress_proxy.server_url},
                    args=[
                        "--proxy-bypass-list=<-loopback>",
                        "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    ],
                )
                context = browser.new_context(
                    viewport=viewport,
                    accept_downloads=False,
                    service_workers="block",
                    java_script_enabled=True,
                    ignore_https_errors=False,
                )

                def block_websocket(websocket_route: Any) -> None:
                    append_blocked(
                        {
                            "url": _safe_websocket_url(websocket_route.url),
                            "method": "WEBSOCKET",
                            "resource_type": "websocket",
                            "reason": "websocket_blocked_for_passive_capture",
                        }
                    )
                    websocket_route.close(code=1008, reason="Watch-Dawg passive capture")

                context.route_web_socket("**/*", block_websocket)
                page = context.new_page()
                page.set_default_timeout(timeout_ms)
                page.set_default_navigation_timeout(timeout_ms)

                def handle_route(route: Any, request: Any) -> None:
                    nonlocal request_count, request_budget_exceeded
                    request_count += 1
                    safe = _safe_url(request.url)
                    if request_count > max_requests:
                        request_budget_exceeded = True
                        append_blocked(
                            {
                                "url": safe,
                                "method": request.method,
                                "resource_type": request.resource_type,
                                "reason": "request_budget_exceeded",
                            }
                        )
                        route.abort("blockedbyclient")
                        return
                    allowed, reason = _validate_browser_request(
                        request.url,
                        request.method,
                        url_validator=url_validator,
                    )
                    if not allowed:
                        append_blocked(
                            {
                                "url": safe,
                                "method": request.method,
                                "resource_type": request.resource_type,
                                "reason": reason,
                            }
                        )
                        route.abort("blockedbyclient")
                        return
                    route.continue_()

                page.route("**/*", handle_route)

                def on_console(message: Any) -> None:
                    append_console(
                        {
                            "type": _bounded_text(message.type, 80),
                            "text": _bounded_text(message.text),
                        }
                    )

                def on_page_error(error: Any) -> None:
                    append_console(
                        {
                            "type": "pageerror",
                            "text": _bounded_text(error),
                        }
                    )

                def on_response(response: Any) -> None:
                    request = response.request
                    try:
                        headers = response.headers
                    except PlaywrightError:
                        headers = {}
                    append_network(
                        {
                            "event": "response",
                            "url": _safe_url(response.url),
                            "method": request.method,
                            "resource_type": request.resource_type,
                            "status": response.status,
                            "content_type": _bounded_text(headers.get("content-type", ""), 300),
                        }
                    )

                def on_request_failed(request: Any) -> None:
                    append_network(
                        {
                            "event": "request_failed",
                            "url": _safe_url(request.url),
                            "method": request.method,
                            "resource_type": request.resource_type,
                            "failure": _bounded_text(request.failure or "unknown", 300),
                        }
                    )

                page.on("console", on_console)
                page.on("pageerror", on_page_error)
                page.on("response", on_response)
                page.on("requestfailed", on_request_failed)

                started = time.monotonic()
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except PlaywrightTimeoutError as exc:
                    raise BrowserCaptureError("browser navigation timed out before DOMContentLoaded") from exc
                if response is None:
                    raise BrowserCaptureError("browser navigation produced no main-document response")
                if settle_ms:
                    page.wait_for_timeout(settle_ms)
                elapsed_ms = round((time.monotonic() - started) * 1000, 1)

                final_url = _safe_url(page.url)
                dom_text = page.content()
                dom_bytes = dom_text.encode("utf-8")
                if len(dom_bytes) > MAX_DOM_BYTES:
                    raise BrowserCaptureError(
                        f"rendered DOM exceeds the {MAX_DOM_BYTES}-byte evidence limit"
                    )
                screenshot = page.screenshot(full_page=False, type="png")
                title = _bounded_text(page.title(), 1_000)
                main_status = response.status
                context.close()
                browser.close()
            egress_summary = egress_proxy.summary()
            egress_attempts = egress_proxy.attempts
    except BrowserCaptureError:
        raise
    except PlaywrightError as exc:
        raise BrowserCaptureError(f"browser capture failed: {_bounded_text(exc)}") from exc

    store = ContentAddressedEvidenceStore(evidence_root)
    dom_artifact = store.put_bytes(
        dom_bytes,
        media_type="text/html; charset=utf-8",
        source=final_url,
        observed_at=observed_at,
        artifact_type="rendered-dom",
    )
    screenshot_artifact = store.put_bytes(
        screenshot,
        media_type="image/png",
        source=final_url,
        observed_at=observed_at,
        artifact_type="viewport-screenshot",
    )
    console_payload = {
        "schema": "watch-dawg-browser-console/v1",
        "events": console_events,
        "events_recorded": len(console_events),
        "event_limit": max_console_events,
    }
    console_artifact = store.put_bytes(
        _canonical_json_bytes(console_payload),
        media_type="application/json",
        source=final_url,
        observed_at=observed_at,
        artifact_type="browser-console-events",
    )
    egress_payload = {
        "schema": EGRESS_POLICY_SCHEMA,
        "summary": egress_summary,
        "attempts": egress_attempts,
    }
    egress_artifact = store.put_bytes(
        _canonical_json_bytes(egress_payload),
        media_type="application/json",
        source=final_url,
        observed_at=observed_at,
        artifact_type="browser-egress-policy-events",
    )
    network_payload = {
        "schema": "watch-dawg-browser-network/v1",
        "events": network_events,
        "events_recorded": len(network_events),
        "event_limit": max_network_events,
        "requests_seen": request_count,
        "request_limit": max_requests,
        "request_budget_exceeded": request_budget_exceeded,
        "blocked_requests": blocked_requests,
        "egress_policy_ref": egress_artifact["ref"],
    }
    network_artifact = store.put_bytes(
        _canonical_json_bytes(network_payload),
        media_type="application/json",
        source=final_url,
        observed_at=observed_at,
        artifact_type="browser-network-events",
    )

    coverage = {
        "scope": "single_url_browser",
        "requested_url": _safe_url(url),
        "final_url": final_url,
        "authenticated": False,
        "javascript_rendering": True,
        "service_workers": "blocked",
        "websockets": "blocked_without_upstream_connection",
        "passive_methods_only": sorted(ALLOWED_PASSIVE_METHODS),
        "browser_egress": {
            "schema": EGRESS_POLICY_SCHEMA,
            "mode": egress_summary["mode"],
            "public_addresses_only": True,
            "mixed_public_private_dns_answers": "deny",
            "connect_to_validated_ip": True,
            "proxy_bypass_loopback_disabled": True,
            "quic_disabled": True,
            "non_proxied_webrtc_udp_policy": "disabled",
        },
        "viewport": viewport,
        "full_page_screenshot": False,
        "request_limit": max_requests,
        "requests_seen": request_count,
        "request_budget_exceeded": request_budget_exceeded,
        "blocked_request_count": len(blocked_requests),
        "network_event_limit": max_network_events,
        "console_event_limit": max_console_events,
        "dom_byte_limit": MAX_DOM_BYTES,
    }
    capture_manifest = {
        "schema": BROWSER_CAPTURE_SCHEMA,
        "target_id": target_id,
        "observed_at": observed_at,
        "requested_url": _safe_url(url),
        "final_url": final_url,
        "main_status": main_status,
        "navigation_elapsed_ms": elapsed_ms,
        "title": title,
        "coverage": coverage,
        "artifacts": {
            "rendered_dom": dom_artifact,
            "screenshot": screenshot_artifact,
            "console": console_artifact,
            "network": network_artifact,
            "egress": egress_artifact,
        },
    }
    capture_artifact = store.put_json(
        capture_manifest,
        source=final_url,
        observed_at=observed_at,
        artifact_type="browser-capture-manifest",
    )
    artifact_refs = [
        dom_artifact["ref"],
        screenshot_artifact["ref"],
        console_artifact["ref"],
        network_artifact["ref"],
        egress_artifact["ref"],
        capture_artifact["ref"],
    ]
    package_manifest = {
        "schema": BROWSER_PACKAGE_SCHEMA,
        "target_id": target_id,
        "observed_at": observed_at,
        "capture_ref": capture_artifact["ref"],
        "artifact_refs": artifact_refs,
        "coverage": coverage,
    }
    package_artifact = store.put_json(
        package_manifest,
        source=final_url,
        observed_at=observed_at,
        artifact_type="browser-evidence-package-manifest",
    )
    return {
        "schema": BROWSER_PACKAGE_SCHEMA,
        "status": "CAPTURED",
        "package_ref": package_artifact["ref"],
        "capture_ref": capture_artifact["ref"],
        "artifact_refs": artifact_refs,
        "coverage": coverage,
    }


def verify_browser_package(evidence_root: str | Path, package_ref: str) -> dict[str, Any]:
    root = Path(evidence_root)
    try:
        package = read_verified_json(root, package_ref)
    except PackageVerificationError as exc:
        raise BrowserCaptureError(f"browser package failed hash verification: {exc}") from exc
    if package.get("schema") != BROWSER_PACKAGE_SCHEMA:
        raise BrowserCaptureError("unsupported browser evidence package schema")
    capture_ref = package.get("capture_ref")
    if not isinstance(capture_ref, str):
        raise BrowserCaptureError("browser package capture_ref is missing")
    try:
        capture = read_verified_json(root, capture_ref)
    except PackageVerificationError as exc:
        raise BrowserCaptureError(f"browser capture manifest failed verification: {exc}") from exc
    if capture.get("schema") != BROWSER_CAPTURE_SCHEMA:
        raise BrowserCaptureError("unsupported browser capture schema")
    if capture.get("target_id") != package.get("target_id"):
        raise BrowserCaptureError("browser package and capture target_id do not match")
    if capture.get("observed_at") != package.get("observed_at"):
        raise BrowserCaptureError("browser package and capture observed_at do not match")
    if capture.get("coverage") != package.get("coverage"):
        raise BrowserCaptureError("browser package and capture coverage do not match")

    artifacts = capture.get("artifacts")
    expected_artifacts = {"rendered_dom", "screenshot", "console", "network", "egress"}
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        raise BrowserCaptureError("browser capture artifact map is incomplete")
    required_refs = {capture_ref}
    verified_refs = [package_ref]
    for name, metadata in artifacts.items():
        if not isinstance(metadata, dict) or not isinstance(metadata.get("ref"), str):
            raise BrowserCaptureError(f"browser {name} artifact metadata is invalid")
        reference = metadata["ref"]
        required_refs.add(reference)
        try:
            payload = read_verified_artifact(root, reference)
        except PackageVerificationError as exc:
            raise BrowserCaptureError(f"browser {name} artifact failed verification: {exc}") from exc
        if metadata.get("size_bytes") != len(payload):
            raise BrowserCaptureError(f"browser {name} size metadata does not match stored bytes")
        if reference not in verified_refs:
            verified_refs.append(reference)

    artifact_refs = package.get("artifact_refs")
    if not isinstance(artifact_refs, list) or any(not isinstance(item, str) for item in artifact_refs):
        raise BrowserCaptureError("browser package artifact_refs must be a list of references")
    if not required_refs.issubset(set(artifact_refs)):
        raise BrowserCaptureError("browser package artifact_refs omit required artifacts")
    if capture_ref not in verified_refs:
        verified_refs.append(capture_ref)
    return {
        "schema": BROWSER_VERIFICATION_SCHEMA,
        "status": "VERIFIED_BROWSER_EVIDENCE",
        "package_ref": package_ref,
        "capture_ref": capture_ref,
        "target_id": package.get("target_id"),
        "observed_at": package.get("observed_at"),
        "final_url": capture.get("final_url"),
        "main_status": capture.get("main_status"),
        "verified_refs": verified_refs,
        "coverage": package.get("coverage"),
        "limitations": [
            "Browser evidence establishes integrity of captured artifacts, not the truth of a business claim.",
            "HTTP(S) browser traffic is forced through a loopback proxy that resolves once, rejects mixed/non-public DNS answers, and connects to the validated IP.",
            "The Playwright route layer independently blocks non-public HTTP(S) targets and non-passive HTTP methods; WebSockets are closed without an upstream connection.",
            "The screenshot is viewport-bounded and the rendered DOM, console, network events, egress decisions, and request count are capped.",
            "Network metadata does not preserve response bodies for subresources.",
            "This process-level proxy is a browser egress choke point, not a host firewall or privileged network namespace.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture or verify bounded Watch-Dawg browser evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture")
    capture.add_argument("--evidence-root", required=True, type=Path)
    capture.add_argument("--url", required=True)
    capture.add_argument("--target-id", required=True)
    capture.add_argument("--timeout-ms", type=int, default=15_000)
    capture.add_argument("--settle-ms", type=int, default=750)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence-root", required=True, type=Path)
    verify.add_argument("--package-ref", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "capture":
            result = capture_browser_evidence(
                evidence_root=args.evidence_root,
                url=args.url,
                target_id=args.target_id,
                timeout_ms=args.timeout_ms,
                settle_ms=args.settle_ms,
            )
        else:
            result = verify_browser_package(args.evidence_root, args.package_ref)
    except (BrowserCaptureError, OSError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
