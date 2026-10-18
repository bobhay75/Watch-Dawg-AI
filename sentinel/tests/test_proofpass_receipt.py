from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from sentinel.evidence_store import ContentAddressedEvidenceStore
from sentinel.http_watch import HttpWatchPack
from sentinel.proofpass_receipt import (
    ProofPassError,
    generate_keypair,
    issue_receipt,
    load_private_key,
    load_public_key,
    read_receipt,
    verify_receipt,
    write_receipt,
)


class FakeHttpFetcher:
    def __init__(self) -> None:
        self.body = b"<html><head><title>Proof</title></head><body>evidence</body></html>"

    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        return {
            "status": 200,
            "final_url": url,
            "latency_ms": 15.0,
            "headers": {
                "content-type": "text/html; charset=utf-8",
                "strict-transport-security": "max-age=31536000",
            },
            "body": self.body.decode("utf-8"),
            "body_raw": self.body,
            "body_bytes": len(self.body),
            "truncated": False,
        }


def make_package(root: Path) -> tuple[ContentAddressedEvidenceStore, str]:
    store = ContentAddressedEvidenceStore(root / "evidence")
    observation = HttpWatchPack(FakeHttpFetcher(), evidence_store=store).observe({
        "id": "website",
        "url": "https://example.com/",
        "require_content_addressed_evidence": True,
    })
    if not observation.ok:
        raise AssertionError(observation.facts)
    return store, observation.facts["evidence_package"]["package_ref"]


class ProofPassReceiptTests(unittest.TestCase):
    def test_signed_receipt_verifies_against_independently_supplied_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = make_package(root)
            private_path = root / "issuer-private.pem"
            public_path = root / "issuer-public.pem"
            generated = generate_keypair(private_path, public_path)
            self.assertEqual(private_path.stat().st_mode & 0o077, 0)

            receipt = issue_receipt(
                evidence_root=store.root,
                package_ref=package_ref,
                private_key=load_private_key(private_path),
                issuer_id="watch-dawg-test-issuer",
                issued_at="2026-09-23T05:00:00+00:00",
            )
            self.assertEqual(receipt["schema"], "proofpass-receipt/v1")
            self.assertEqual(receipt["attestation"], "EVIDENCE_INTEGRITY")
            self.assertEqual(receipt["issuer"]["key_id"], generated["key_id"])
            self.assertNotIn("truth", receipt)
            self.assertTrue(any("not truth" in item for item in receipt["limitations"]))

            verified = verify_receipt(
                evidence_root=store.root,
                receipt=receipt,
                public_key=load_public_key(public_path),
            )
            self.assertEqual(verified["status"], "VERIFIED_RECEIPT")
            self.assertTrue(verified["signature_valid"])
            self.assertTrue(verified["trusted_public_key_matched"])
            self.assertEqual(verified["evidence_integrity"], "VERIFIED_INTEGRITY")
            self.assertEqual(verified["package_ref"], package_ref)

    def test_tampered_receipt_fails_signature_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = make_package(root)
            private_path = root / "issuer-private.pem"
            public_path = root / "issuer-public.pem"
            generate_keypair(private_path, public_path)
            receipt = issue_receipt(
                evidence_root=store.root,
                package_ref=package_ref,
                private_key=load_private_key(private_path),
                issuer_id="issuer-a",
            )
            receipt["issuer"]["id"] = "issuer-b"
            with self.assertRaisesRegex(ProofPassError, "signature verification failed"):
                verify_receipt(
                    evidence_root=store.root,
                    receipt=receipt,
                    public_key=load_public_key(public_path),
                )

    def test_wrong_trust_key_is_rejected_before_evidence_is_treated_as_attested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = make_package(root)
            private_path = root / "issuer-private.pem"
            public_path = root / "issuer-public.pem"
            other_private = root / "other-private.pem"
            other_public = root / "other-public.pem"
            generate_keypair(private_path, public_path)
            generate_keypair(other_private, other_public)
            receipt = issue_receipt(
                evidence_root=store.root,
                package_ref=package_ref,
                private_key=load_private_key(private_path),
                issuer_id="issuer-a",
            )
            with self.assertRaisesRegex(ProofPassError, "does not match the trusted public key"):
                verify_receipt(
                    evidence_root=store.root,
                    receipt=receipt,
                    public_key=load_public_key(other_public),
                )

    def test_evidence_tamper_after_signing_breaks_receipt_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = make_package(root)
            private_path = root / "issuer-private.pem"
            public_path = root / "issuer-public.pem"
            generate_keypair(private_path, public_path)
            receipt = issue_receipt(
                evidence_root=store.root,
                package_ref=package_ref,
                private_key=load_private_key(private_path),
                issuer_id="issuer-a",
            )

            package_digest = package_ref.removeprefix("sha256:")
            package_path = store.root / "sha256" / package_digest[:2] / package_digest
            package_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(ProofPassError, r"evidence package failed.*verification"):
                verify_receipt(
                    evidence_root=store.root,
                    receipt=receipt,
                    public_key=load_public_key(public_path),
                )

    def test_private_key_file_permissions_fail_closed(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX permission test")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "issuer-private.pem"
            public_path = root / "issuer-public.pem"
            generate_keypair(private_path, public_path)
            private_path.chmod(0o644)
            with self.assertRaisesRegex(ProofPassError, "permissions"):
                load_private_key(private_path)

    def test_receipt_writer_refuses_overwrite_and_reader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, package_ref = make_package(root)
            private_path = root / "issuer-private.pem"
            public_path = root / "issuer-public.pem"
            generate_keypair(private_path, public_path)
            receipt = issue_receipt(
                evidence_root=store.root,
                package_ref=package_ref,
                private_key=load_private_key(private_path),
                issuer_id="issuer-a",
            )
            receipt_path = root / "receipt.json"
            write_receipt(receipt_path, receipt)
            loaded = read_receipt(receipt_path)
            self.assertEqual(loaded["receipt_id"], receipt["receipt_id"])
            with self.assertRaisesRegex(ProofPassError, "refusing to overwrite"):
                write_receipt(receipt_path, receipt)

            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ProofPassError, "strict UTF-8 JSON"):
                read_receipt(duplicate)


if __name__ == "__main__":
    unittest.main()
