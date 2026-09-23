from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from sentinel.evidence_store import ContentAddressedEvidenceStore
from sentinel.evidence_verify import (
    PackageVerificationError,
    export_verified_package,
    verify_package,
)
from sentinel.http_watch import HttpWatchPack


class FakeHttpFetcher:
    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        body = b"<html><title>Verifier</title><body>proof</body></html>"
        return {
            "status": 200,
            "final_url": url,
            "latency_ms": 9.5,
            "headers": {"content-type": "text/html; charset=utf-8"},
            "body": body.decode("utf-8"),
            "body_raw": body,
            "body_bytes": len(body),
            "truncated": False,
        }


def build_package(root: Path) -> tuple[ContentAddressedEvidenceStore, str]:
    store = ContentAddressedEvidenceStore(root)
    observation = HttpWatchPack(FakeHttpFetcher(), evidence_store=store).observe({
        "id": "site",
        "url": "https://example.com/",
        "require_content_addressed_evidence": True,
    })
    if not observation.ok:
        raise AssertionError(observation.facts)
    return store, observation.facts["evidence_package"]["package_ref"]


class EvidenceVerifierTests(unittest.TestCase):
    def test_verifies_package_without_ai_or_runtime_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            _, package_ref = build_package(root)
            result = verify_package(root, package_ref)
            self.assertEqual(result["status"], "VERIFIED_INTEGRITY")
            self.assertEqual(result["package_ref"], package_ref)
            self.assertEqual(result["target_id"], "site")
            self.assertEqual(len(result["verified_refs"]), 3)
            self.assertFalse(result["coverage"]["javascript_rendering"])

    def test_fails_when_linked_body_is_tampered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            store, package_ref = build_package(root)
            result = verify_package(root, package_ref)
            body_ref = result["body_ref"]
            digest = body_ref.split(":", 1)[1]
            body_path = root / "sha256" / digest[:2] / digest
            body_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(PackageVerificationError, "hash mismatch"):
                verify_package(root, package_ref)

    def test_fails_when_package_omits_required_capture_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            store, package_ref = build_package(root)
            package = json.loads(store.read_bytes(package_ref).decode("utf-8"))
            package["artifact_refs"] = []
            replacement = store.put_json(
                package,
                source="https://example.com/",
                observed_at=package["observed_at"],
                artifact_type="evidence-package-manifest",
            )
            with self.assertRaisesRegex(PackageVerificationError, "omit"):
                verify_package(root, replacement["ref"])

    def test_export_contains_only_verified_core_artifacts_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "evidence"
            _, package_ref = build_package(root)
            destination = base / "export"
            result = export_verified_package(root, package_ref, destination)
            self.assertEqual(result["status"], "VERIFIED_INTEGRITY")
            self.assertEqual(
                sorted(path.name for path in destination.iterdir()),
                sorted([
                    "package.json",
                    "capture.json",
                    "response-body.bin",
                    "verification.json",
                    "README.txt",
                ]),
            )
            verification = json.loads(
                (destination / "verification.json").read_text(encoding="utf-8")
            )
            self.assertEqual(verification["package_ref"], package_ref)

    def test_export_refuses_nonempty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "evidence"
            _, package_ref = build_package(root)
            destination = base / "export"
            destination.mkdir()
            (destination / "existing.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(PackageVerificationError, "absent or empty"):
                export_verified_package(root, package_ref, destination)


if __name__ == "__main__":
    unittest.main()
