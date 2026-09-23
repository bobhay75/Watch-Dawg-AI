from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sentinel.browser_capture import (
    BROWSER_PACKAGE_SCHEMA,
    BrowserCaptureError,
    _validate_browser_request,
    capture_browser_evidence,
    verify_browser_package,
)
from sentinel.evidence_verify import read_verified_artifact, read_verified_json


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


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            body = b"""<!doctype html>
<html><head><title>Browser Evidence Fixture</title></head>
<body>
<script src=\"/script.js\"></script>
<p id=\"ready\">ready</p>
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
    def test_real_chromium_capture_is_content_addressed_and_verifiable(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                url = f"http://127.0.0.1:{server.server_port}/"
                result = capture_browser_evidence(
                    evidence_root=root,
                    url=url,
                    target_id="browser-fixture",
                    settle_ms=200,
                    url_validator=lambda value: None,
                )
                self.assertEqual(result["schema"], BROWSER_PACKAGE_SCHEMA)
                self.assertEqual(result["status"], "CAPTURED")
                self.assertFalse(result["coverage"]["authenticated"])
                self.assertTrue(result["coverage"]["javascript_rendering"])
                self.assertTrue(result["coverage"]["passive_methods_only"])

                verified = verify_browser_package(root, result["package_ref"])
                self.assertEqual(verified["status"], "VERIFIED_BROWSER_EVIDENCE")
                self.assertEqual(verified["package_ref"], result["package_ref"])

                capture = read_verified_json(root, result["capture_ref"])
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
                self.assertTrue(
                    any(event.get("status") == 200 for event in network["events"] if event.get("event") == "response")
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_browser_package_tamper_fails_verification(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                url = f"http://127.0.0.1:{server.server_port}/"
                result = capture_browser_evidence(
                    evidence_root=root,
                    url=url,
                    target_id="browser-fixture",
                    settle_ms=100,
                    url_validator=lambda value: None,
                )
                digest = result["package_ref"].removeprefix("sha256:")
                package_path = root / "sha256" / digest[:2] / digest
                package_path.write_bytes(b"tampered")
                with self.assertRaisesRegex(BrowserCaptureError, "failed hash verification"):
                    verify_browser_package(root, result["package_ref"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
