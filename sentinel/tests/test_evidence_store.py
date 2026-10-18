from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from typing import Any

from sentinel.core import SentinelEngine, StateStore
from sentinel.evidence_store import ContentAddressedEvidenceStore, EvidenceIntegrityError
from sentinel.http_watch import HttpWatchPack


class FakeHttpFetcher:
    def __init__(self, body: bytes = b"<html><title>Example</title><body>ok</body></html>"):
        self.body = body
        self.calls = 0

    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        self.calls += 1
        return {
            "status": 200,
            "final_url": url,
            "latency_ms": 12.5,
            "headers": {
                "content-type": "text/html; charset=utf-8",
                "strict-transport-security": "max-age=31536000",
            },
            "body": self.body.decode("utf-8"),
            "body_raw": self.body,
            "body_bytes": len(self.body),
            "truncated": False,
        }


class ContentAddressedEvidenceStoreTests(unittest.TestCase):
    def test_round_trip_is_content_addressed_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedEvidenceStore(directory)
            artifact = store.put_bytes(
                b"evidence",
                media_type="text/plain",
                source="https://example.com/",
                observed_at="2026-09-22T00:00:00+00:00",
                artifact_type="fixture",
            )
            expected = hashlib.sha256(b"evidence").hexdigest()
            self.assertEqual(artifact["ref"], f"sha256:{expected}")
            self.assertTrue(store.verify(artifact["ref"]))
            self.assertEqual(store.read_bytes(artifact["ref"]), b"evidence")

            duplicate = store.put_bytes(
                b"evidence",
                media_type="text/plain",
                source="https://example.com/",
                observed_at="2026-09-22T00:01:00+00:00",
                artifact_type="fixture",
            )
            self.assertEqual(duplicate["ref"], artifact["ref"])

    def test_existing_corrupt_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedEvidenceStore(directory)
            artifact = store.put_bytes(
                b"original",
                media_type="application/octet-stream",
                source="https://example.com/",
                observed_at="2026-09-22T00:00:00+00:00",
                artifact_type="fixture",
            )
            digest = artifact["sha256"]
            path = Path(directory) / "sha256" / digest[:2] / digest
            path.write_bytes(b"tampered")
            self.assertFalse(store.verify(artifact["ref"]))
            with self.assertRaises(EvidenceIntegrityError):
                store.put_bytes(
                    b"original",
                    media_type="application/octet-stream",
                    source="https://example.com/",
                    observed_at="2026-09-22T00:02:00+00:00",
                    artifact_type="fixture",
                )


class HttpEvidencePackageTests(unittest.TestCase):
    def test_http_observation_preserves_body_capture_and_package_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedEvidenceStore(Path(directory) / "evidence")
            fetcher = FakeHttpFetcher()
            pack = HttpWatchPack(fetcher, evidence_store=store)
            observation = pack.observe({
                "id": "site",
                "url": "https://example.com/",
                "require_content_addressed_evidence": True,
            })

            self.assertTrue(observation.ok)
            package = observation.facts["evidence_package"]
            self.assertEqual(package["schema"], "watch-dawg-evidence-package/v1")
            self.assertEqual(len(package["artifacts"]), 3)
            self.assertTrue(store.verify(package["package_ref"]))
            self.assertTrue(store.verify(package["capture_ref"]))
            for artifact in package["artifacts"]:
                self.assertTrue(store.verify(artifact["ref"]))
            self.assertEqual(
                observation.facts["body_sha256"],
                hashlib.sha256(fetcher.body).hexdigest(),
            )
            self.assertEqual(observation.facts["coverage"]["scope"], "single_url")
            self.assertFalse(observation.facts["coverage"]["authenticated"])
            self.assertFalse(observation.facts["coverage"]["javascript_rendering"])

    def test_required_evidence_store_blocks_before_network_collection(self) -> None:
        fetcher = FakeHttpFetcher()
        pack = HttpWatchPack(fetcher)
        target = {
            "id": "site",
            "url": "https://example.com/",
            "require_content_addressed_evidence": True,
        }
        observation = pack.observe(target)
        self.assertFalse(observation.ok)
        self.assertEqual(fetcher.calls, 0)
        findings = pack.evaluate(target, observation, None)
        self.assertEqual(findings[0].code, "HTTP_OBSERVATION_FAILED")
        self.assertIn("content-addressed evidence store", observation.facts["error"])

    def test_engine_surfaces_coverage_and_evidence_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ContentAddressedEvidenceStore(root / "evidence")
            pack = HttpWatchPack(FakeHttpFetcher(), evidence_store=store)
            engine = SentinelEngine(StateStore(root / "state.json"), [pack])
            result = engine.run([{
                "id": "site",
                "kind": "http",
                "url": "https://example.com/",
                "authorization": {"mode": "public"},
                "require_content_addressed_evidence": True,
                "checks": {"required_headers": ["strict-transport-security"]},
            }])
            site = result["results"][0]
            self.assertEqual(site["coverage"]["scope"], "single_url")
            self.assertEqual(site["evidence_package"]["schema"], "watch-dawg-evidence-package/v1")
            self.assertTrue(store.verify(site["evidence_package"]["package_ref"]))
            self.assertEqual(site["finding_counts"]["inference"], 0)
            self.assertEqual(site["finding_counts"]["verified"], 0)
            self.assertEqual(site["verdict"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
