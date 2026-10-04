from __future__ import annotations

import base64
import hashlib
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sentinel.api import ApiError, SentinelApiService, build_handler
from sentinel.swarm_ingest import (
    ALGORITHM,
    MAX_SWARM_REQUEST_BYTES,
    SwarmIngestRateLimiter,
    SwarmSnapshotIngestor,
    _history_paths,
    load_swarm_enrollments,
)
from sentinel.swarm_proof import load_proof_hmac_key, verify_proof_hmac
from sentinel.swarm_watch import SwarmDefenseWatchPack


API_TOKEN = "api-token-with-at-least-thirty-two-characters"
DEVICE_TOKEN = "device-token-with-at-least-thirty-two-characters"
DEVICE_ID = "android-5cd252fb0ce8932436faf8cc"
SNAPSHOT_RELATIVE_PATH = f"android/{DEVICE_ID}.json"
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
PROOF_HMAC_KEY = b"p" * 32


class ApiHarness:
    def __init__(self, service: SentinelApiService) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(service))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "ApiHarness":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def post(
        self,
        payload: dict | None = None,
        *,
        token: str = DEVICE_TOKEN,
        raw_body: bytes | None = None,
        device_id_header: str = DEVICE_ID,
    ) -> tuple[int, dict]:
        body = raw_body
        if body is None:
            body = json.dumps(payload).encode("utf-8")
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_port,
            timeout=5,
        )
        connection.request(
            "POST",
            "/v1/swarm/snapshot",
            body=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-WatchDawg-Device-ID": device_id_header,
            },
        )
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    def post_with_duplicate_identity_header(
        self,
        payload: dict,
        *,
        duplicate_header: str,
    ) -> tuple[int, dict]:
        body = json.dumps(payload).encode("utf-8")
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_port,
            timeout=5,
        )
        connection.putrequest("POST", "/v1/swarm/snapshot")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Authorization", f"Bearer {DEVICE_TOKEN}")
        connection.putheader("X-WatchDawg-Device-ID", DEVICE_ID)
        if duplicate_header == "authorization":
            connection.putheader("Authorization", f"Bearer {DEVICE_TOKEN}")
        elif duplicate_header == "device_id":
            connection.putheader("X-WatchDawg-Device-ID", DEVICE_ID)
        else:
            raise ValueError("unsupported duplicate header test")
        connection.endheaders(body)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    def post_with_raw_content_length(
        self,
        raw_length: str,
        body: bytes,
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_port,
            timeout=5,
        )
        connection.putrequest("POST", "/v1/swarm/snapshot")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", raw_length)
        connection.putheader("Authorization", f"Bearer {DEVICE_TOKEN}")
        connection.putheader("X-WatchDawg-Device-ID", DEVICE_ID)
        connection.endheaders(body)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result


class SwarmSnapshotIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.snapshot_root = self.root / "snapshots"
        # Stable test-only key keeps the Android device id/key-id derivation fixed.
        self.private_key = ec.derive_private_key(1, ec.SECP256R1())
        public_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = hashlib.sha256(public_der).hexdigest()
        enrollment_json = json.dumps(
            {
                DEVICE_ID: {
                    "token_sha256": hashlib.sha256(DEVICE_TOKEN.encode()).hexdigest(),
                    "key_id": self.key_id,
                    "public_key_der_base64": base64.b64encode(public_der).decode(),
                    "snapshot_path": SNAPSHOT_RELATIVE_PATH,
                }
            }
        )
        self.enrollments = load_swarm_enrollments(
            enrollment_json,
            self.snapshot_root,
        )
        self.ingestor = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=self.root / "state/replay.sqlite3",
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW,
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        self.service = SentinelApiService(
            token=API_TOKEN,
            profiles={},
            state_root=self.root / "state",
            swarm_ingestor=self.ingestor,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def snapshot(*, sequence: int = 1, collected_at: datetime = NOW) -> dict:
        return {
            "actions_executed": False,
            "collected_at": collected_at.isoformat(),
            "collection": {
                "complete": True,
                "event_limit": 500,
                "events_emitted": 0,
                "package_deltas_truncated": False,
                "permission_deltas_truncated": False,
                "usage_events_truncated": False,
                "usage_history_gap": False,
                "usage_query_available": False,
            },
            "collector": {
                "android_api": 35,
                "app_version": "1.0.0",
                "collection_mode": "non_root_public_api",
                "platform": "android",
                "security_patch": "2026-09-01",
                "signing_key_security": "software",
                "usage_access": "not_granted",
                "usage_query_status": "not_granted",
            },
            "connectivity": {
                "captive_portal": False,
                "content_observed": False,
                "destinations_observed": False,
                "metered": False,
                "scope": "active_transport_only",
                "transports": [],
                "validated": False,
            },
            "device_id": DEVICE_ID,
            "events": [],
            "limitations": [
                "No root, accessibility, VPN, camera, or microphone permission is used.",
                "Android public APIs do not expose other apps' live camera or microphone use to this app.",
                "Sensor-capability events mean a foreground app held a related permission; they do not prove sensor use.",
                "Connectivity evidence reports active transport metadata only, not destinations or content.",
                "Package identifiers are HMAC-pseudonymized on this device before export.",
                "A package signing certificate is mandatory Android packaging metadata and does not establish publisher trust.",
            ],
            "mesh": {
                "enabled": False,
                "peer_count": 0,
                "raw_data_sharing": False,
                "signed_updates_only": True,
            },
            "permission_posture": {
                "baseline_initialized": False,
                "granted_sensitive_permission_counts": {
                    "ACCESS_COARSE_LOCATION": 0,
                    "ACCESS_FINE_LOCATION": 0,
                    "CALL_PHONE": 0,
                    "CAMERA": 0,
                    "POST_NOTIFICATIONS": 0,
                    "READ_CALENDAR": 0,
                    "READ_CONTACTS": 0,
                    "READ_PHONE_STATE": 0,
                    "READ_SMS": 0,
                    "RECEIVE_SMS": 0,
                    "RECORD_AUDIO": 0,
                    "SEND_SMS": 0,
                    "WRITE_CALENDAR": 0,
                    "WRITE_CONTACTS": 0,
                },
                "inventory_scope": "installed_packages_visible_to_security_app",
                "package_identifiers": "device_keyed_hmac_sha256",
                "packages_observed": 0,
            },
            "posture": {
                "disk_encrypted": True,
                "screen_lock": True,
                "security_updates_current": True,
            },
            "posture_evidence": {
                "adb_enabled": "disabled",
                "developer_options": "disabled",
                "disk_encryption_status": "active",
                "secure_boot": {
                    "scope": "verified_boot_state",
                    "source": "android_public_api",
                    "status": "unsupported",
                },
                "security_patch": "2026-09-01",
                "security_patch_age_days": 16,
                "security_patch_policy_max_age_days": 120,
            },
            "schema_version": 1,
            "sensors": {
                "camera": {
                    "scope": "direct_cross_app_access",
                    "source": "android_public_api",
                    "status": "unsupported",
                },
                "identity": {
                    "scope": "device_authentication_events",
                    "source": "android_public_api",
                    "status": "unsupported",
                },
                "microphone": {
                    "scope": "direct_cross_app_access",
                    "source": "android_public_api",
                    "status": "unsupported",
                },
                "network": {
                    "scope": "active_transport_only",
                    "source": "android_connectivity",
                    "status": "observed",
                },
                "process": {
                    "scope": "foreground_transitions",
                    "source": "android_usage_stats",
                    "status": "not_granted",
                },
            },
            "sequence": sequence,
        }

    @staticmethod
    def canonical(value: dict) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def envelope(self, snapshot: dict | None = None) -> tuple[dict, bytes]:
        raw = self.canonical(self.snapshot() if snapshot is None else snapshot)
        signature = self.private_key.sign(raw, ec.ECDSA(hashes.SHA256()))
        return (
            {
                "schema_version": 1,
                "device_id": DEVICE_ID,
                "key_id": self.key_id,
                "algorithm": ALGORITHM,
                "signed_payload": base64.b64encode(raw).decode(),
                "signature": base64.b64encode(signature).decode(),
            },
            raw,
        )

    def test_good_signature_is_saved_exactly_with_server_owned_proof(self) -> None:
        envelope, raw = self.envelope()
        with ApiHarness(self.service) as api:
            status, body = api.post(envelope)

        self.assertEqual(status, 201)
        self.assertTrue(body["accepted"])
        self.assertEqual(body["snapshot_sha256"], hashlib.sha256(raw).hexdigest())
        target = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        self.assertEqual(target.read_bytes(), raw)
        proof = json.loads(
            target.with_name(target.name + ".proof.json").read_text(encoding="utf-8")
        )
        self.assertTrue(proof["signature_verified"])
        self.assertEqual(proof["payload_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(proof["key_id"], self.key_id)
        self.assertTrue(verify_proof_hmac(proof, PROOF_HMAC_KEY))
        history_snapshot, history_proof, history_signature = _history_paths(
            target,
            1,
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(history_snapshot.read_bytes(), raw)
        self.assertEqual(json.loads(history_proof.read_bytes()), proof)
        self.private_key.public_key().verify(
            history_signature.read_bytes(),
            raw,
            ec.ECDSA(hashes.SHA256()),
        )

    def test_tampered_payload_is_rejected_before_storage(self) -> None:
        envelope, _ = self.envelope()
        tampered = self.canonical(self.snapshot(sequence=2))
        envelope["signed_payload"] = base64.b64encode(tampered).decode()
        with ApiHarness(self.service) as api:
            status, body = api.post(envelope)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_signature")
        self.assertFalse((self.snapshot_root / SNAPSHOT_RELATIVE_PATH).exists())

    def test_unknown_and_raw_package_fields_are_rejected_before_storage(self) -> None:
        def add_unknown_top_level(snapshot: dict) -> None:
            snapshot["unknown_field"] = True

        def add_raw_package_name(snapshot: dict) -> None:
            snapshot["events"].append(
                {
                    "baseline": "unexpected",
                    "bytes_out": 0,
                    "destination": "",
                    "evidence_kind": "package_inventory_delta",
                    "observed_at": NOW.isoformat(),
                    "package_has_signing_certificate": True,
                    "process": "pkg-hmac256:" + "a" * 64,
                    "raw_package_name": "com.example.private",
                    "sensitive": False,
                    "type": "package_added",
                }
            )
            snapshot["collection"]["events_emitted"] = 1

        target = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        proof = target.with_name(target.name + ".proof.json")
        replay_state = self.root / "state/replay.sqlite3"
        for name, mutate in (
            ("unknown_top_level", add_unknown_top_level),
            ("raw_package_name", add_raw_package_name),
        ):
            with self.subTest(name=name):
                snapshot = self.snapshot()
                mutate(snapshot)
                envelope, _ = self.envelope(snapshot)
                with ApiHarness(self.service) as api:
                    status, body = api.post(envelope)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_snapshot")
                self.assertNotIn("com.example.private", json.dumps(body))
                self.assertFalse(target.exists())
                self.assertFalse(proof.exists())
                self.assertFalse(replay_state.exists())

    def test_wrong_token_and_unknown_device_are_indistinguishable(self) -> None:
        envelope, _ = self.envelope()
        unknown = dict(envelope)
        unknown["device_id"] = "not-enrolled"
        with ApiHarness(self.service) as api:
            wrong_status, wrong_body = api.post(envelope, token="x" * 40)
            unknown_status, unknown_body = api.post(
                unknown,
                device_id_header="not-enrolled",
            )
        self.assertEqual(wrong_status, 401)
        self.assertEqual(unknown_status, 401)
        self.assertEqual(wrong_body["error"]["code"], "unauthorized_device")
        self.assertEqual(unknown_body["error"]["code"], "unauthorized_device")

    def test_device_bearer_token_uses_bounded_urlsafe_ascii_grammar(self) -> None:
        invalid_tokens = (
            "a" * 31,
            "a" * 257,
            "a" * 31 + ":",
            "a" * 31 + " ",
            "a" * 31 + "é",
        )
        for token in invalid_tokens:
            with self.subTest(token_length=len(token)):
                with self.assertRaises(ApiError) as raised:
                    self.ingestor.preauthenticate(DEVICE_ID, token)
                self.assertEqual(raised.exception.code, "unauthorized_device")

    def test_authentication_happens_before_large_body_is_read(self) -> None:
        with ApiHarness(self.service) as api:
            status, body = api.post(
                raw_body=b"x" * (MAX_SWARM_REQUEST_BYTES + 1),
                token="x" * 40,
            )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized_device")

    def test_device_header_is_required_before_body_processing(self) -> None:
        envelope, _ = self.envelope()
        with ApiHarness(self.service) as api:
            status, body = api.post(envelope, device_id_header="")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized_device")

    def test_duplicate_authentication_headers_fail_before_body_processing(self) -> None:
        envelope, _ = self.envelope()
        for header in ("authorization", "device_id"):
            with self.subTest(header=header):
                with ApiHarness(self.service) as api:
                    status, body = api.post_with_duplicate_identity_header(
                        envelope,
                        duplicate_header=header,
                    )
                self.assertEqual(status, 401)
                self.assertEqual(body["error"]["code"], "unauthorized_device")

    def test_content_length_uses_strict_http_decimal_grammar(self) -> None:
        for raw_length, request_body in (("+2", b"{}"), ("1_0", b"0123456789")):
            with self.subTest(raw_length=raw_length):
                with ApiHarness(self.service) as api:
                    status, body = api.post_with_raw_content_length(
                        raw_length,
                        request_body,
                    )
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_content_length")

    def test_stale_and_future_fifo_backlog_drains_and_preserves_every_batch(self) -> None:
        def snapshot_with_event(
            *, sequence: int, collected_at: datetime, event_type: str, pseudonym: str
        ) -> dict:
            value = self.snapshot(sequence=sequence, collected_at=collected_at)
            value["events"] = [
                {
                    "baseline": "unexpected",
                    "bytes_out": 0,
                    "destination": "",
                    "evidence_kind": "package_inventory_delta",
                    "observed_at": collected_at.isoformat(),
                    "package_has_signing_certificate": True,
                    "process": f"pkg-hmac256:{pseudonym * 64}",
                    "sensitive": False,
                    "type": event_type,
                }
            ]
            value["collection"]["events_emitted"] = 1
            value["permission_posture"]["baseline_initialized"] = True
            return value

        stale = snapshot_with_event(
            sequence=1,
            collected_at=NOW - timedelta(hours=2),
            event_type="package_added",
            pseudonym="a",
        )
        future = snapshot_with_event(
            sequence=2,
            collected_at=NOW + timedelta(hours=2),
            event_type="package_updated",
            pseudonym="b",
        )
        corrected = snapshot_with_event(
            sequence=3,
            collected_at=NOW,
            event_type="package_removed",
            pseudonym="c",
        )
        envelopes_and_raw = [
            self.envelope(stale),
            self.envelope(future),
            self.envelope(corrected),
        ]
        with ApiHarness(self.service) as api:
            responses = [api.post(envelope) for envelope, _ in envelopes_and_raw]

        self.assertEqual([status for status, _ in responses], [201, 201, 201])
        self.assertEqual(
            [body["sequence"] for _, body in responses],
            [1, 2, 3],
        )
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        self.assertEqual(snapshot_path.read_bytes(), envelopes_and_raw[-1][1])
        for sequence, (_, raw) in enumerate(envelopes_and_raw, start=1):
            with self.subTest(sequence=sequence):
                digest = hashlib.sha256(raw).hexdigest()
                archived_snapshot, archived_proof, archived_signature = _history_paths(
                    snapshot_path,
                    sequence,
                    digest,
                )
                self.assertEqual(archived_snapshot.read_bytes(), raw)
                proof = json.loads(archived_proof.read_bytes())
                self.assertEqual(proof["sequence"], sequence)
                self.assertEqual(proof["payload_sha256"], digest)
                self.assertTrue(verify_proof_hmac(proof, PROOF_HMAC_KEY))
                self.private_key.public_key().verify(
                    archived_signature.read_bytes(),
                    raw,
                    ec.ECDSA(hashes.SHA256()),
                )

    def test_exact_accepted_retry_is_idempotent_after_restart_and_staleness(self) -> None:
        envelope, raw = self.envelope()
        with ApiHarness(self.service) as api:
            first_status, first_receipt = api.post(envelope)
        self.assertEqual(first_status, 201)
        self.assertEqual(
            set(first_receipt),
            {"accepted", "device_id", "key_id", "sequence", "snapshot_sha256"},
        )
        self.assertEqual(first_receipt["snapshot_sha256"], hashlib.sha256(raw).hexdigest())

        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        history_paths = _history_paths(
            snapshot_path,
            1,
            hashlib.sha256(raw).hexdigest(),
        )
        snapshot_before = snapshot_path.read_bytes()
        proof_before = proof_path.read_bytes()
        history_before = tuple(path.read_bytes() for path in history_paths)
        resigned_envelope, resigned_raw = self.envelope(self.snapshot())
        self.assertEqual(resigned_raw, raw)
        self.assertNotEqual(resigned_envelope["signature"], envelope["signature"])

        restarted = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=self.root / "state/replay.sqlite3",
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW + timedelta(days=1),
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        restarted_service = SentinelApiService(
            token=API_TOKEN,
            profiles={},
            state_root=self.root / "state",
            swarm_ingestor=restarted,
        )
        with patch.object(
            restarted,
            "_atomic_write",
            side_effect=AssertionError("an exact retry must not rewrite storage"),
        ):
            with ApiHarness(restarted_service) as api:
                retry_status, retry_receipt = api.post(resigned_envelope)

        self.assertEqual(retry_status, 201)
        self.assertEqual(retry_receipt, first_receipt)
        self.assertEqual(snapshot_path.read_bytes(), snapshot_before)
        self.assertEqual(proof_path.read_bytes(), proof_before)
        self.assertEqual(
            tuple(path.read_bytes() for path in history_paths),
            history_before,
        )

        snapshot_path.write_bytes(b"locally-corrupted-snapshot")
        proof_path.write_bytes(b'{}\n')
        repaired_receipt = restarted.ingest(envelope, DEVICE_TOKEN)
        self.assertEqual(repaired_receipt, first_receipt)
        self.assertEqual(snapshot_path.read_bytes(), snapshot_before)
        self.assertEqual(proof_path.read_bytes(), proof_before)
        self.assertEqual(
            tuple(path.read_bytes() for path in history_paths),
            history_before,
        )

    def test_retry_repairs_crash_after_replay_commit_before_snapshot(self) -> None:
        envelope, raw = self.envelope()
        with patch.object(
            self.ingestor,
            "_ensure_immutable_file",
            side_effect=OSError("injected crash before accepted-history publish"),
        ):
            with self.assertRaisesRegex(OSError, "injected crash"):
                self.ingestor.ingest(envelope, DEVICE_TOKEN)

        replay_path = self.root / "state/replay.sqlite3"
        with sqlite3.connect(replay_path) as connection:
            row = connection.execute(
                """
                SELECT sequence, snapshot_sha256, received_at
                FROM swarm_replay_state
                WHERE device_id = ?
                """,
                (DEVICE_ID,),
            ).fetchone()
        self.assertEqual(
            row,
            (1, hashlib.sha256(raw).hexdigest(), NOW.isoformat()),
        )
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        self.assertFalse(snapshot_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertFalse(snapshot_path.with_name(snapshot_path.name + ".history").exists())

        higher_envelope, _ = self.envelope(self.snapshot(sequence=2))
        with self.assertRaises(ApiError) as blocked:
            self.ingestor.ingest(higher_envelope, DEVICE_TOKEN)
        self.assertEqual(blocked.exception.status, 409)
        self.assertEqual(blocked.exception.code, "previous_snapshot_incomplete")

        restarted = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=replay_path,
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW + timedelta(days=1),
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        receipt = restarted.ingest(envelope, DEVICE_TOKEN)
        self.assertEqual(receipt["sequence"], 1)
        self.assertEqual(snapshot_path.read_bytes(), raw)
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["received_at"], NOW.isoformat())
        self.assertTrue(verify_proof_hmac(proof, PROOF_HMAC_KEY))
        for history_path in _history_paths(
            snapshot_path,
            1,
            hashlib.sha256(raw).hexdigest(),
        ):
            self.assertTrue(history_path.is_file())

        higher_receipt = restarted.ingest(higher_envelope, DEVICE_TOKEN)
        self.assertEqual(higher_receipt["sequence"], 2)

    def test_retry_repairs_crash_after_snapshot_before_proof(self) -> None:
        envelope, raw = self.envelope()
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        original_write = self.ingestor._atomic_write

        def fail_proof_write(target: Path, data: bytes) -> None:
            if target == snapshot_path:
                original_write(target, data)
                return
            raise OSError("injected crash before proof publish")

        with patch.object(
            self.ingestor,
            "_atomic_write",
            side_effect=fail_proof_write,
        ):
            with self.assertRaisesRegex(OSError, "injected crash"):
                self.ingestor.ingest(envelope, DEVICE_TOKEN)

        self.assertEqual(snapshot_path.read_bytes(), raw)
        self.assertFalse(proof_path.exists())

        restarted = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=self.root / "state/replay.sqlite3",
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW + timedelta(days=1),
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        with patch.object(
            restarted,
            "_atomic_write",
            wraps=restarted._atomic_write,
        ) as repaired_write:
            receipt = restarted.ingest(envelope, DEVICE_TOKEN)
        self.assertEqual(receipt["sequence"], 1)
        repaired_write.assert_called_once()
        self.assertEqual(repaired_write.call_args.args[0], proof_path)
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["received_at"], NOW.isoformat())
        self.assertTrue(verify_proof_hmac(proof, PROOF_HMAC_KEY))

    def test_retry_completes_partial_immutable_history_before_advancing(self) -> None:
        envelope, raw = self.envelope()
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        history_snapshot, history_proof, history_signature = _history_paths(
            snapshot_path,
            1,
            hashlib.sha256(raw).hexdigest(),
        )
        with patch.object(
            self.ingestor,
            "_ensure_archived_signature",
            side_effect=OSError("injected crash before archived signature"),
        ):
            with self.assertRaisesRegex(OSError, "injected crash"):
                self.ingestor.ingest(envelope, DEVICE_TOKEN)

        self.assertEqual(history_snapshot.read_bytes(), raw)
        self.assertFalse(history_signature.exists())
        self.assertFalse(history_proof.exists())
        self.assertFalse(snapshot_path.exists())

        higher_envelope, _ = self.envelope(self.snapshot(sequence=2))
        with self.assertRaises(ApiError) as blocked:
            self.ingestor.ingest(higher_envelope, DEVICE_TOKEN)
        self.assertEqual(blocked.exception.code, "previous_snapshot_incomplete")

        self.assertEqual(self.ingestor.ingest(envelope, DEVICE_TOKEN)["sequence"], 1)
        self.assertTrue(history_signature.is_file())
        self.assertTrue(history_proof.is_file())
        self.private_key.public_key().verify(
            history_signature.read_bytes(),
            raw,
            ec.ECDSA(hashes.SHA256()),
        )
        self.assertEqual(self.ingestor.ingest(higher_envelope, DEVICE_TOKEN)["sequence"], 2)

    def test_old_replay_database_schema_is_migrated_before_repair(self) -> None:
        envelope, raw = self.envelope()
        replay_path = self.root / "state/replay.sqlite3"
        replay_path.parent.mkdir(parents=True)
        with sqlite3.connect(replay_path) as connection:
            connection.execute(
                """
                CREATE TABLE swarm_replay_state (
                    device_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    collected_at TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO swarm_replay_state (
                    device_id, sequence, collected_at, snapshot_sha256
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    DEVICE_ID,
                    1,
                    NOW.isoformat(),
                    hashlib.sha256(raw).hexdigest(),
                ),
            )

        migrated = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=replay_path,
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW + timedelta(days=1),
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        receipt = migrated.ingest(envelope, DEVICE_TOKEN)
        self.assertEqual(receipt["sequence"], 1)
        with sqlite3.connect(replay_path) as connection:
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(swarm_replay_state)"
                )
            }
            received_at = connection.execute(
                """
                SELECT received_at FROM swarm_replay_state WHERE device_id = ?
                """,
                (DEVICE_ID,),
            ).fetchone()[0]
        self.assertIn("received_at", columns)
        self.assertEqual(received_at, NOW.isoformat())

    def test_per_device_lock_prevents_concurrent_sequence_regression(self) -> None:
        envelope_one, _ = self.envelope(self.snapshot(sequence=1))
        envelope_two, raw_two = self.envelope(self.snapshot(sequence=2))
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        first_snapshot_started = threading.Event()
        release_first_snapshot = threading.Event()
        second_request_started = threading.Event()
        original_write = self.ingestor._atomic_write

        def controlled_write(target: Path, data: bytes) -> None:
            if target == snapshot_path and b'"sequence":1' in data:
                first_snapshot_started.set()
                if not release_first_snapshot.wait(timeout=5):
                    raise TimeoutError("test did not release first snapshot write")
            original_write(target, data)

        def ingest_second() -> dict:
            second_request_started.set()
            return self.ingestor.ingest(envelope_two, DEVICE_TOKEN)

        with patch.object(
            self.ingestor,
            "_atomic_write",
            side_effect=controlled_write,
        ), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.ingestor.ingest, envelope_one, DEVICE_TOKEN)
            self.assertTrue(first_snapshot_started.wait(timeout=5))
            second = pool.submit(ingest_second)
            self.assertTrue(second_request_started.wait(timeout=5))
            self.assertFalse(second.done())
            release_first_snapshot.set()
            self.assertEqual(first.result(timeout=5)["sequence"], 1)
            self.assertEqual(second.result(timeout=5)["sequence"], 2)

        self.assertEqual(snapshot_path.read_bytes(), raw_two)
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["sequence"], 2)
        self.assertTrue(verify_proof_hmac(proof, PROOF_HMAC_KEY))

    def test_history_entry_cap_fails_closed_but_exact_retry_and_retention_work(
        self,
    ) -> None:
        capped = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=self.root / "state/capped-replay.sqlite3",
            proof_hmac_key=PROOF_HMAC_KEY,
            history_max_entries_per_device=2,
            clock=lambda: NOW,
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        first_envelope, first_raw = self.envelope(self.snapshot(sequence=1))
        second_envelope, _ = self.envelope(self.snapshot(sequence=2))
        third_envelope, _ = self.envelope(self.snapshot(sequence=3))

        self.assertEqual(capped.ingest(first_envelope, DEVICE_TOKEN)["sequence"], 1)
        second_receipt = capped.ingest(second_envelope, DEVICE_TOKEN)
        self.assertEqual(second_receipt["sequence"], 2)
        self.assertEqual(capped.ingest(second_envelope, DEVICE_TOKEN), second_receipt)

        with self.assertRaises(ApiError) as full:
            capped.ingest(third_envelope, DEVICE_TOKEN)
        self.assertEqual(full.exception.status, 507)
        self.assertEqual(full.exception.code, "history_capacity_exceeded")

        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        for path in _history_paths(
            snapshot_path,
            1,
            hashlib.sha256(first_raw).hexdigest(),
        ):
            path.unlink()

        self.assertEqual(capped.ingest(third_envelope, DEVICE_TOKEN)["sequence"], 3)

    def test_higher_sequence_repairs_mutable_latest_from_immutable_history(
        self,
    ) -> None:
        first_envelope, first_raw = self.envelope(self.snapshot(sequence=1))
        second_envelope, second_raw = self.envelope(self.snapshot(sequence=2))
        self.assertEqual(self.ingestor.ingest(first_envelope, DEVICE_TOKEN)["sequence"], 1)

        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        snapshot_path.write_bytes(b"corrupted mutable latest")
        proof_path.unlink()

        self.assertEqual(self.ingestor.ingest(second_envelope, DEVICE_TOKEN)["sequence"], 2)
        self.assertEqual(snapshot_path.read_bytes(), second_raw)
        for sequence, raw in ((1, first_raw), (2, second_raw)):
            with self.subTest(sequence=sequence):
                for history_path in _history_paths(
                    snapshot_path,
                    sequence,
                    hashlib.sha256(raw).hexdigest(),
                ):
                    self.assertTrue(history_path.is_file())

    def test_history_cap_configuration_is_bounded(self) -> None:
        for invalid in (False, 0, 100_001):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "history_max_entries"):
                    SwarmSnapshotIngestor(
                        enrollments=self.enrollments,
                        replay_state_path=self.root / f"state/invalid-{invalid}.sqlite3",
                        proof_hmac_key=PROOF_HMAC_KEY,
                        history_max_entries_per_device=invalid,
                    )

    def test_new_storage_directories_are_parent_fsynced_before_success(self) -> None:
        envelope, _ = self.envelope()
        original_fsync = SwarmSnapshotIngestor._fsync_directory
        with patch.object(
            SwarmSnapshotIngestor,
            "_fsync_directory",
            side_effect=original_fsync,
        ) as fsync_directory:
            receipt = self.ingestor.ingest(envelope, DEVICE_TOKEN)
        self.assertEqual(receipt["sequence"], 1)
        fsynced = {call.args[0] for call in fsync_directory.call_args_list}
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        history_root = snapshot_path.with_name(snapshot_path.name + ".history")
        self.assertIn(self.root / "state", fsynced)
        self.assertIn(snapshot_path.parent, fsynced)
        self.assertIn(history_root, fsynced)
        self.assertIn(history_root.parent, fsynced)

    def test_older_or_same_sequence_with_different_payload_is_rejected(self) -> None:
        accepted_envelope, _ = self.envelope(self.snapshot(sequence=2))
        mutated = self.snapshot(sequence=2)
        mutated["posture"]["screen_lock"] = False
        conflicting_envelope, _ = self.envelope(mutated)
        older_envelope, _ = self.envelope(self.snapshot(sequence=1))

        with ApiHarness(self.service) as api:
            accepted_status, _ = api.post(accepted_envelope)

        restarted = SwarmSnapshotIngestor(
            enrollments=self.enrollments,
            replay_state_path=self.root / "state/replay.sqlite3",
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW + timedelta(days=1),
            rate_limiter=SwarmIngestRateLimiter(device_cooldown_seconds=0),
        )
        restarted_service = SentinelApiService(
            token=API_TOKEN,
            profiles={},
            state_root=self.root / "state",
            swarm_ingestor=restarted,
        )
        with ApiHarness(restarted_service) as api:
            conflicting_status, conflicting_body = api.post(conflicting_envelope)
            older_status, older_body = api.post(older_envelope)

        self.assertEqual(accepted_status, 201)
        self.assertEqual(conflicting_status, 409)
        self.assertEqual(conflicting_body["error"]["code"], "replayed_snapshot")
        self.assertEqual(older_status, 409)
        self.assertEqual(older_body["error"]["code"], "replayed_snapshot")

    def test_outer_envelope_duplicate_key_is_rejected(self) -> None:
        envelope, _ = self.envelope()
        raw = json.dumps(envelope).encode("utf-8")
        raw = raw[:-1] + f',"device_id":"{DEVICE_ID}"}}'.encode()
        with ApiHarness(self.service) as api:
            status, body = api.post(raw_body=raw)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_json")

    def test_request_limit_is_enforced_before_ingestion(self) -> None:
        with ApiHarness(self.service) as api:
            status, body = api.post(raw_body=b"x" * (MAX_SWARM_REQUEST_BYTES + 1))
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "request_too_large")

    def test_enrollment_snapshot_path_cannot_escape_server_root(self) -> None:
        public_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        escaped = json.dumps(
            {
                DEVICE_ID: {
                    "token_sha256": hashlib.sha256(DEVICE_TOKEN.encode()).hexdigest(),
                    "key_id": self.key_id,
                    "public_key_der_base64": base64.b64encode(public_der).decode(),
                    "snapshot_path": "../outside.json",
                }
            }
        )
        with self.assertRaisesRegex(ValueError, "escapes"):
            load_swarm_enrollments(escaped, self.snapshot_root)

    def test_enrollments_reject_shared_credentials_and_path_intersections(self) -> None:
        first_public_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        second_private_key = ec.generate_private_key(ec.SECP256R1())
        second_public_der = second_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        first_id = f"android-{hashlib.sha256(first_public_der).hexdigest()[:24]}"
        second_id = f"android-{hashlib.sha256(second_public_der).hexdigest()[:24]}"
        first = {
            "token_sha256": hashlib.sha256(b"first-token").hexdigest(),
            "key_id": hashlib.sha256(first_public_der).hexdigest(),
            "public_key_der_base64": base64.b64encode(first_public_der).decode(),
            "snapshot_path": "android/first.json",
        }
        second = {
            "token_sha256": hashlib.sha256(b"second-token").hexdigest(),
            "key_id": hashlib.sha256(second_public_der).hexdigest(),
            "public_key_der_base64": base64.b64encode(second_public_der).decode(),
            "snapshot_path": "android/second.json",
        }
        cases = [
            ("duplicate_path", {**second, "snapshot_path": first["snapshot_path"]}, "intersects"),
            (
                "proof_path_collision",
                {**second, "snapshot_path": "android/first.json.proof.json"},
                "intersects",
            ),
            (
                "nested_path",
                {**second, "snapshot_path": "android/first.json/child.json"},
                "intersects",
            ),
            (
                "history_path_collision",
                {**second, "snapshot_path": "android/first.json.history/child.json"},
                "intersects",
            ),
            (
                "device_key_mismatch",
                {
                    **second,
                    "key_id": first["key_id"],
                    "public_key_der_base64": first["public_key_der_base64"],
                },
                "device id does not match its key id",
            ),
            (
                "duplicate_token",
                {**second, "token_sha256": first["token_sha256"]},
                "reuses token_sha256",
            ),
        ]
        for name, second_entry, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, message):
                    load_swarm_enrollments(
                        json.dumps({first_id: first, second_id: second_entry}),
                        self.snapshot_root,
                    )

    def test_replay_database_cannot_intersect_snapshot_or_proof_paths(self) -> None:
        snapshot_path = self.enrollments[DEVICE_ID].snapshot_path
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        history_path = snapshot_path.with_name(snapshot_path.name + ".history")
        for name, replay_path in (
            ("snapshot", snapshot_path),
            ("proof", proof_path),
            ("history", history_path),
            ("snapshot_parent", snapshot_path.parent),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "must not intersect"):
                    SwarmSnapshotIngestor(
                        enrollments=self.enrollments,
                        replay_state_path=replay_path,
                        proof_hmac_key=PROOF_HMAC_KEY,
                    )

    def test_watch_pack_can_require_verified_ingest_and_trusted_key(self) -> None:
        envelope, _ = self.envelope()
        self.ingestor.ingest(envelope, DEVICE_TOKEN)
        target = {
            "id": "owned-phone-shadow",
            "kind": "swarm_device",
            "enabled": True,
            "mode": "shadow",
            "device_id": DEVICE_ID,
            "snapshot_path": SNAPSHOT_RELATIVE_PATH,
            "require_verified_ingest": True,
            "trusted_key_ids": [self.key_id],
            "authorization": {
                "id": "AUTH-TEST",
                "approved_methods": ["read-device-snapshot"],
                "scope": {
                    "device_id": DEVICE_ID,
                    "snapshot_path": SNAPSHOT_RELATIVE_PATH,
                },
                "expires_at": "2030-01-01T00:00:00Z",
            },
        }
        observation = SwarmDefenseWatchPack(
            self.snapshot_root,
            proof_hmac_key=PROOF_HMAC_KEY,
            clock=lambda: NOW,
        ).observe(target)
        self.assertTrue(observation.facts["provenance"]["signature_verified"])
        self.assertEqual(observation.facts["provenance"]["key_id"], self.key_id)

        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        snapshot_path.write_bytes(snapshot_path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "verified ingestion provenance"):
            SwarmDefenseWatchPack(
                self.snapshot_root,
                proof_hmac_key=PROOF_HMAC_KEY,
                clock=lambda: NOW,
            ).observe(target)

    def test_forged_or_tampered_proof_sidecar_fails_closed(self) -> None:
        envelope, _ = self.envelope()
        self.ingestor.ingest(envelope, DEVICE_TOKEN)
        snapshot_path = self.snapshot_root / SNAPSHOT_RELATIVE_PATH
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        proof["received_at"] = (NOW - timedelta(days=1)).isoformat()
        proof_path.write_text(json.dumps(proof), encoding="utf-8")
        target = {
            "id": "owned-phone-shadow",
            "enabled": True,
            "mode": "shadow",
            "device_id": DEVICE_ID,
            "snapshot_path": SNAPSHOT_RELATIVE_PATH,
            "require_verified_ingestion": True,
            "trusted_key_ids": [self.key_id],
            "authorization": {
                "id": "AUTH-TEST",
                "approved_methods": ["read-device-snapshot"],
                "scope": {
                    "device_id": DEVICE_ID,
                    "snapshot_path": SNAPSHOT_RELATIVE_PATH,
                },
                "expires_at": "2030-01-01T00:00:00Z",
            },
        }
        with self.assertRaisesRegex(ValueError, "verified ingestion provenance"):
            SwarmDefenseWatchPack(
                self.snapshot_root,
                proof_hmac_key=PROOF_HMAC_KEY,
                clock=lambda: NOW,
            ).observe(target)

    def test_proof_hmac_environment_key_requires_exactly_32_bytes(self) -> None:
        valid = base64.b64encode(PROOF_HMAC_KEY).decode()
        self.assertEqual(
            load_proof_hmac_key(valid, required=True),
            PROOF_HMAC_KEY,
        )
        with self.assertRaisesRegex(ValueError, "required"):
            load_proof_hmac_key(None, required=True)
        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            load_proof_hmac_key(
                base64.b64encode(b"short").decode(),
                required=True,
            )
        with self.assertRaisesRegex(ValueError, "valid base64"):
            load_proof_hmac_key("%%%", required=True)


if __name__ == "__main__":
    unittest.main()
