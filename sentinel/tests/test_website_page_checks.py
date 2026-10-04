from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from sentinel.evidence_store import ContentAddressedEvidenceStore
from sentinel.http_watch import HttpWatchPack
from sentinel.website_page_checks import PageAnalysisError, analyze_package, store_analysis


class FakeHttpFetcher:
    def __init__(self, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        self.body = body.encode("utf-8")
        self.content_type = content_type

    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        return {
            "status": 200,
            "final_url": url,
            "latency_ms": 10.0,
            "headers": {"content-type": self.content_type},
            "body": self.body.decode("utf-8"),
            "body_raw": self.body,
            "body_bytes": len(self.body),
            "truncated": False,
        }


def capture(root: Path, body: str, content_type: str = "text/html; charset=utf-8") -> tuple[ContentAddressedEvidenceStore, str]:
    store = ContentAddressedEvidenceStore(root / "evidence")
    observation = HttpWatchPack(
        FakeHttpFetcher(body, content_type),
        evidence_store=store,
    ).observe({
        "id": "site",
        "url": "https://example.com/",
        "require_content_addressed_evidence": True,
    })
    if not observation.ok:
        raise AssertionError(observation.facts)
    return store, observation.facts["evidence_package"]["package_ref"]


class WebsitePageChecksTests(unittest.TestCase):
    def test_detects_mixed_content_and_insecure_password_forms_without_network_calls(self) -> None:
        html = """
        <html><head><title>Example</title>
          <script src="http://cdn.example.net/app.js"></script>
        </head><body>
          <img src="http://cdn.example.net/photo.jpg">
          <form method="get" action="http://example.com/login">
            <input type="password" name="password">
          </form>
          <form method="post" action="https://payments.example.net/checkout">
            <input type="text" name="order">
          </form>
        </body></html>
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = capture(root, html)
            result = analyze_package(store.root, package_ref)
            codes = {item["code"] for item in result["findings"]}
            self.assertIn("MIXED_CONTENT_ACTIVE", codes)
            self.assertIn("MIXED_CONTENT_PASSIVE", codes)
            self.assertIn("FORM_INSECURE_TRANSPORT", codes)
            self.assertIn("PASSWORD_FORM_USES_GET", codes)
            self.assertIn("FORM_CROSS_ORIGIN_ACTION", codes)
            self.assertEqual(result["status"], "DETERMINISTIC_ANALYSIS")
            self.assertEqual(result["coverage"]["network_requests_added_by_analysis"], 0)
            self.assertEqual(result["package_ref"], package_ref)

    def test_clean_https_markup_does_not_invent_security_findings(self) -> None:
        html = """
        <html><head><title>Clean</title>
          <script src="/app.js"></script>
        </head><body>
          <img src="/photo.jpg">
          <form method="post" action="/contact">
            <input type="text" name="message">
          </form>
        </body></html>
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = capture(root, html)
            result = analyze_package(store.root, package_ref)
            codes = {item["code"] for item in result["findings"]}
            self.assertNotIn("MIXED_CONTENT_ACTIVE", codes)
            self.assertNotIn("MIXED_CONTENT_PASSIVE", codes)
            self.assertNotIn("FORM_INSECURE_TRANSPORT", codes)
            self.assertNotIn("PASSWORD_FORM_USES_GET", codes)
            self.assertNotIn("FORM_CROSS_ORIGIN_ACTION", codes)
            self.assertNotIn("PAGE_TITLE_MISSING", codes)

    def test_analysis_output_is_content_addressable_and_repeatable(self) -> None:
        html = "<html><head><title>Stable</title></head><body><img src='/a.png'></body></html>"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = capture(root, html)
            first = store_analysis(store.root, analyze_package(store.root, package_ref))
            second = store_analysis(store.root, analyze_package(store.root, package_ref))
            self.assertEqual(first["analysis_ref"], second["analysis_ref"])
            self.assertTrue(store.verify(first["analysis_ref"]))

    def test_non_html_capture_is_rejected_instead_of_guessed_at(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = capture(
                root,
                '{"status":"ok"}',
                content_type="application/json",
            )
            with self.assertRaisesRegex(PageAnalysisError, "require an HTML capture"):
                analyze_package(store.root, package_ref)

    def test_missing_title_is_reported_as_low_severity_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = capture(root, "<html><body>Hello</body></html>")
            result = analyze_package(store.root, package_ref)
            finding = next(item for item in result["findings"] if item["code"] == "PAGE_TITLE_MISSING")
            self.assertEqual(finding["severity"], "low")
            self.assertEqual(finding["truth"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
