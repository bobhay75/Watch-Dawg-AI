from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from sentinel.axe_adapter import verify_axe_analysis
from sentinel.browser_capture import (
    BROWSER_PACKAGE_SCHEMA,
    BrowserCaptureError,
    _validate_browser_request,
    capture_browser_evidence,
    verify_browser_package,
)
from sentinel.browser_egress import (
    BrowserEgressError,
    BrowserEgressProxy,
    resolve_public_endpoints,
)
from sentinel.evidence_verify import read_verified_artifact, read_verified_json
from sentinel.proofpass_receipt import (
    BROWSER_SUBJECT_TYPE,
    generate_keypair,
    issue_receipt,
    load_private_key,
    load_public_key,
    verify_receipt,
)


class BrowserRequestPolicyTests(unittest.TestCase):
    def test_blocks_non_passive_methods(self) -> None:
        allowed, reason = _validate_browser_request(
            "https://example.com/api",
            "POST",
            url_validator=lambda value: None,
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "non_passive_method")

    def test_blocks_non_public_network_targets(self) -> None:
        allowed, reason = _validate_browser_request("http://127.0.0.1/private", "GET")
        self.assertFalse(allowed)
        self.assertEqual(reason, "non_public_network_target")

    def test_allows_local_non_network_schemes(self) -> None:
        for url in ("about:blank", "data:text/plain,ok", "blob:https://example.com/id"):
            allowed, reason = _validate_browser_request(url, "GET")
            self.assertTrue(allowed)
            self.assertIsNone(reason)

    def test_resolve_once_policy_rejects_mixed_public_and_private_dns_answers(self) -> None:
        def resolver(host: str, port: int, *, type: int) -> list[tuple[object, ...]]:
            self.assertEqual(host, "mixed.example")
            self.assertEqual(port, 443)
            self.assertEqual(type, socket.SOCK_STREAM)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
            ]

        with self.assertRaisesRegex(BrowserEgressError, "non-public address"):
            resolve_public_endpoints("mixed.example", 443, resolver=resolver)

    def test_loopback_proxy_denies_direct_connect_to_private_address(self) -> None:
        with BrowserEgressProxy() as proxy:
            parsed = urlsplit(proxy.server_url)
            self.assertIsNotNone(parsed.hostname)
            self.assertIsNotNone(parsed.port)
            with socket.create_connection((str(parsed.hostname), int(parsed.port)), timeout=2) as client:
                client.sendall(
                    b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:443\r\n"
                    b"Connection: close\r\n\r\n"
                )
                response = client.recv(4096)
            self.assertIn(b"403 Denied", response)
            self.assertTrue(proxy.attempts)
            self.assertFalse(proxy.attempts[0]["allowed"])

    def test_proxy_rejects_non_web_port_before_resolution(self) -> None:
        resolver_called = False

        def resolver(host: str, port: int, *, type: int) -> list[tuple[object, ...]]:
            nonlocal resolver_called
            resolver_called = True
            return []

        with BrowserEgressProxy(resolver=resolver) as proxy:
            parsed = urlsplit(proxy.server_url)
            with socket.create_connection((str(parsed.hostname), int(parsed.port)), timeout=2) as client:
                client.sendall(
                    b"CONNECT example.com:22 HTTP/1.1\r\n"
                    b"Host: example.com:22\r\n"
                    b"Connection: close\r\n\r\n"
                )
                response = client.recv(4096)
        self.assertIn(b"403 Denied", response)
        self.assertFalse(resolver_called)


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            body = b"""<!doctype html>
<html lang=\"en\"><head><title>Browser Evidence Fixture</title></head>
<body>
<script src=\"/script.js\"></script>
<p id=\"ready\">ready</p>
<img src=\"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==\">
</body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/script.js":
            body = b'console.log("watch-dawg-browser-fixture");'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


@unittest.skipUnless(
    os.environ.get("WATCH_DAWG_BROWSER_TESTS") == "1",
    "browser integration tests require pinned Playwright + Chromium",
)
class BrowserCaptureIntegrationTests(unittest.TestCase):
    def _start_server(self) -> tuple[ThreadingHTTPServer, threading.Thread]:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _capture(
        self,
        root: Path,
        server: ThreadingHTTPServer,
        *,
        with_axe: bool = False,
    ) -> dict[str, object]:
        url = f"http://127.0.0.1:{server.server_port}/"

        def local_fixture_proxy() -> BrowserEgressProxy:
            return BrowserEgressProxy(
                address_policy=lambda address: True,
                allowed_ports={server.server_port},
            )

        axe_script: str | None = None
        if with_axe:
            axe_script = os.environ.get("WATCH_DAWG_AXE_SCRIPT")
            self.assertTrue(axe_script, "WATCH_DAWG_AXE_SCRIPT must point to pinned axe.min.js")

        return capture_browser_evidence(
            evidence_root=root,
            url=url,
            target_id="browser-fixture",
            settle_ms=200,
            url_validator=lambda value: None,
            axe_script_path=axe_script,
            _egress_proxy_factory=local_fixture_proxy,
        )

    def test_real_chromium_capture_is_content_addressed_and_verifiable(self) -> None:
        server, thread = self._start_server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                result = self._capture(root, server, with_axe=True)
                self.assertEqual(result["schema"], BROWSER_PACKAGE_SCHEMA)
                self.assertEqual(result["status"], "CAPTURED")
                self.assertFalse(result["coverage"]["authenticated"])
                self.assertTrue(result["coverage"]["javascript_rendering"])
                self.assertEqual(result["coverage"]["passive_methods_only"], ["GET", "HEAD"])
                self.assertEqual(
                    result["coverage"]["browser_egress"]["mode"],
                    "resolve_once_loopback_proxy",
                )
                self.assertEqual(result["coverage"]["websockets"], "blocked_without_upstream_connection")

                verified = verify_browser_package(root, str(result["package_ref"]))
                self.assertEqual(verified["status"], "VERIFIED_BROWSER_EVIDENCE")
                self.assertEqual(verified["package_ref"], result["package_ref"])

                capture = read_verified_json(root, str(result["capture_ref"]))
                self.assertEqual(capture["title"], "Browser Evidence Fixture")
                artifacts = capture["artifacts"]

                screenshot = read_verified_artifact(root, artifacts["screenshot"]["ref"])
                self.assertTrue(screenshot.startswith(b"\x89PNG\r\n\x1a\n"))

                dom = read_verified_artifact(root, artifacts["rendered_dom"]["ref"])
                self.assertIn(b"Browser Evidence Fixture", dom)
                self.assertIn(b'id="ready"', dom)

                console = json.loads(
                    read_verified_artifact(root, artifacts["console"]["ref"]).decode("utf-8")
                )
                self.assertTrue(
                    any("watch-dawg-browser-fixture" in event.get("text", "") for event in console["events"])
                )

                network = json.loads(
                    read_verified_artifact(root, artifacts["network"]["ref"]).decode("utf-8")
                )
                self.assertGreaterEqual(network["requests_seen"], 2)
                self.assertFalse(network["request_budget_exceeded"])
                self.assertEqual(network["egress_policy_ref"], artifacts["egress"]["ref"])
                self.assertTrue(
                    any(event.get("status") == 200 for event in network["events"] if event.get("event") == "response")
                )

                egress = json.loads(
                    read_verified_artifact(root, artifacts["egress"]["ref"]).decode("utf-8")
                )
                self.assertEqual(egress["summary"]["mode"], "resolve_once_loopback_proxy")
                self.assertGreaterEqual(egress["summary"]["allowed_attempts"], 1)
                self.assertEqual(egress["summary"]["policy"]["allowed_tcp_ports"], [server.server_port])
                self.assertFalse(egress["summary"]["policy"]["public_addresses_only"])
                self.assertTrue(any(item.get("allowed") for item in egress["attempts"]))

                axe_summary = result["derived_analyses"]["axe"]
                self.assertEqual(axe_summary["engine_version"], "4.13.0")
                self.assertGreaterEqual(axe_summary["counts"]["violation_rules"], 1)
                axe_verification = verify_axe_analysis(root, str(axe_summary["analysis_ref"]))
                self.assertEqual(axe_verification["status"], "VERIFIED_AXE_ANALYSIS")
                self.assertEqual(
                    axe_verification["browser_evidence_status"],
                    "VERIFIED_BROWSER_EVIDENCE",
                )
                axe_analysis = read_verified_json(root, str(axe_summary["analysis_ref"]))
                violation_ids = {item["id"] for item in axe_analysis["violations"]}
                self.assertIn("image-alt", violation_ids)
                self.assertEqual(
                    axe_analysis["options"]["additional_network_requests_expected"],
                    0,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_browser_package_receipt_verifies_with_independent_public_key(self) -> None:
        server, thread = self._start_server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "evidence"
                result = self._capture(root, server)
                private_path = base / "issuer-private.pem"
                public_path = base / "issuer-public.pem"
                generate_keypair(private_path, public_path)

                receipt = issue_receipt(
                    evidence_root=root,
                    package_ref=str(result["package_ref"]),
                    private_key=load_private_key(private_path),
                    issuer_id="watch-dawg-browser-test",
                    issued_at="2026-09-23T05:30:00+00:00",
                )
                self.assertEqual(receipt["subject"]["type"], BROWSER_SUBJECT_TYPE)
                self.assertEqual(receipt["evidence"]["status"], "VERIFIED_BROWSER_EVIDENCE")

                verification = verify_receipt(
                    evidence_root=root,
                    receipt=receipt,
                    public_key=load_public_key(public_path),
                )
                self.assertEqual(verification["status"], "VERIFIED_RECEIPT")
                self.assertEqual(verification["subject_type"], BROWSER_SUBJECT_TYPE)
                self.assertEqual(verification["evidence_integrity"], "VERIFIED_BROWSER_EVIDENCE")
                self.assertEqual(verification["package_ref"], result["package_ref"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_browser_package_tamper_fails_verification(self) -> None:
        server, thread = self._start_server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                result = self._capture(root, server)
                digest = str(result["package_ref"]).removeprefix("sha256:")
                package_path = root / "sha256" / digest[:2] / digest
                package_path.write_bytes(b"tampered")
                with self.assertRaisesRegex(BrowserCaptureError, "failed hash verification"):
                    verify_browser_package(root, str(result["package_ref"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
