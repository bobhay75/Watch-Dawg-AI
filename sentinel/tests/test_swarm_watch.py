from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sentinel.core import SentinelEngine, StateStore
from sentinel.swarm_proof import proof_hmac_sha256
from sentinel.swarm_watch import SwarmDefenseWatchPack
from sentinel.tests.android_snapshot_fixture import (
    ANDROID_DEVICE_ID,
    PACKAGE_A,
    PACKAGE_B,
    capability_event,
    make_android_snapshot,
    package_event,
    permission_event,
    synchronize_collection,
)

KEY_ID = "a" * 64
PROOF_HMAC_KEY = b"w" * 32
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


class SwarmDefenseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.snapshot = {"device_id": "owned-phone", "sensors": {key: True for key in ("camera", "microphone", "identity", "process", "network")}, "posture": {key: True for key in ("disk_encrypted", "secure_boot", "screen_lock", "security_updates_current")}, "mesh": {"enabled": True, "peer_count": 2, "signed_updates_only": True, "raw_data_sharing": False}, "events": []}
        self.target = {"id": "phone-shadow", "kind": "swarm_device", "enabled": True, "mode": "shadow", "device_id": "owned-phone", "snapshot_path": "phone.json", "authorization": {"mode": "owner", "id": "AUTH-1", "approved_methods": ["read-device-snapshot"], "scope": {"device_id": "owned-phone", "snapshot_path": "phone.json"}, "expires_at": "2099-01-01T00:00:00Z"}}

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write(self) -> Path:
        path = self.root / "phone.json"
        path.write_text(json.dumps(self.snapshot), encoding="utf-8")
        return path

    def use_object_sensors(self) -> None:
        self.snapshot = make_android_snapshot(collected_at=NOW)
        self.target["device_id"] = ANDROID_DEVICE_ID
        self.target["authorization"]["scope"]["device_id"] = ANDROID_DEVICE_ID

    def require_verified_ingestion(self) -> None:
        self.target["require_verified_ingestion"] = True
        self.target["trusted_key_ids"] = [KEY_ID]

    def write_proof(self, *, received_at: datetime = NOW) -> Path:
        if "collection" in self.snapshot:
            synchronize_collection(self.snapshot)
        path = self.write()
        proof = {
            "algorithm": "SHA256withECDSA",
            "device_id": self.snapshot["device_id"],
            "key_id": KEY_ID,
            "payload_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "received_at": received_at.isoformat(),
            "schema_version": 1,
            "sequence": self.snapshot["sequence"],
            "signature_verified": True,
        }
        proof["proof_hmac_sha256"] = proof_hmac_sha256(
            proof,
            PROOF_HMAC_KEY,
        )
        path.with_name(path.name + ".proof.json").write_text(
            json.dumps(proof),
            encoding="utf-8",
        )
        return path

    def pack(
        self,
        *,
        clock: datetime = NOW,
        proof_hmac_key: bytes | None = PROOF_HMAC_KEY,
    ) -> SwarmDefenseWatchPack:
        return SwarmDefenseWatchPack(
            self.root,
            proof_hmac_key=proof_hmac_key,
            clock=lambda: clock,
        )

    def test_legacy_safe_snapshot_is_advisory_with_provenance_warning(self) -> None:
        self.write()
        pack = self.pack()
        observation = pack.observe(self.target)
        self.assertFalse(observation.facts["actions_executed"])
        self.assertEqual(observation.facts["sensor_schema"], "legacy_boolean")
        self.assertEqual(
            observation.facts["sensor_coverage"]["camera"]["status"],
            "legacy_reported",
        )
        findings = pack.evaluate(self.target, observation, None)
        self.assertEqual(
            [finding.code for finding in findings],
            ["SWARM_SENSOR_PROVENANCE_UNVERIFIED"],
        )
        self.assertEqual(findings[0].truth, "VERIFIED")
        self.assertEqual(findings[0].evidence_grade, "D")
        self.assertFalse(findings[0].evidence["actions_executed"])

    def test_camera_microphone_identity_and_egress_anomalies_are_advisory(self) -> None:
        self.snapshot["events"] = [{"type": "camera_access", "process": "unknown.exe", "process_signed": False, "baseline": "unexpected"}, {"type": "microphone_access", "process": "meeting.exe", "process_signed": True, "baseline": "unexpected"}, {"type": "identity_event", "process": "login", "process_signed": True, "baseline": "unexpected"}, {"type": "network_egress", "destination": "sensitive.example", "sensitive": True, "baseline": "unexpected", "bytes_out": 5000}]
        self.write()
        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        anomalies = [
            finding
            for finding in findings
            if finding.code != "SWARM_SENSOR_PROVENANCE_UNVERIFIED"
        ]
        self.assertEqual(len(anomalies), 4)
        self.assertTrue(all(finding.evidence["actions_executed"] is False for finding in findings))
        self.assertTrue(all(finding.truth == "INFERENCE" for finding in anomalies))
        self.assertTrue(all(finding.evidence_grade == "D" for finding in anomalies))
        self.assertTrue(all(finding.confidence == 35 for finding in anomalies))
        output = str(observation.to_dict()) + str([finding.to_dict() for finding in findings])
        self.assertNotIn("sensitive.example", output)
        self.assertNotIn("unknown.exe", output)
        self.assertNotIn("meeting.exe", output)
        self.assertNotIn("login", output)
        self.assertTrue(
            all(
                event["process"].startswith("legacy-sha256:")
                for event in observation.facts["events"]
            )
        )
        self.assertIn("destination_sha256", output)

    def test_object_sensors_require_explicit_verified_ingestion(self) -> None:
        self.use_object_sensors()
        self.write()
        pack = self.pack()
        with self.assertRaisesRegex(
            ValueError,
            "require_verified_ingestion: true",
        ):
            pack.observe(self.target)

        self.require_verified_ingestion()
        with self.assertRaisesRegex(ValueError, "verified ingestion provenance"):
            pack.observe(self.target)

        self.write_proof()
        observation = pack.observe(self.target)
        self.assertTrue(observation.facts["provenance"]["signature_verified"])
        self.assertEqual(observation.facts["sensor_schema"], "object_v2")

    def test_verified_object_sensors_preserve_scope_and_limitations(self) -> None:
        self.use_object_sensors()
        self.require_verified_ingestion()
        self.write_proof()
        pack = self.pack()
        observation = pack.observe(self.target)

        process = observation.facts["sensor_coverage"]["process"]
        self.assertEqual(process["status"], "observed")
        self.assertEqual(process["source"], "android_usage_stats")
        self.assertEqual(process["scope"], "foreground_transitions")
        self.assertEqual(process["provenance"], "verified_ingestion")
        findings = pack.evaluate(self.target, observation, None)
        limitation = [
            finding
            for finding in findings
            if finding.code.startswith("SWARM_SENSOR_PLATFORM_LIMITATION_")
        ]
        self.assertEqual(len(limitation), 3)
        self.assertEqual(
            {finding.evidence["sensor"] for finding in limitation},
            {"camera", "identity", "microphone"},
        )
        self.assertTrue(all(finding.severity == "info" for finding in limitation))
        self.assertTrue(all(finding.truth == "VERIFIED" for finding in limitation))
        self.assertTrue(all(finding.evidence_grade == "B" for finding in limitation))
        self.assertNotIn(
            "SWARM_SENSOR_PROVENANCE_UNVERIFIED",
            {finding.code for finding in findings},
        )
        self.assertTrue(observation.facts["telemetry"]["fresh"])

    def test_verified_proof_requires_server_hmac_key(self) -> None:
        self.use_object_sensors()
        self.require_verified_ingestion()
        self.write_proof()
        with self.assertRaisesRegex(ValueError, "proof HMAC key"):
            self.pack(proof_hmac_key=None).observe(self.target)

    def test_forged_sidecar_signature_verified_flag_is_rejected(self) -> None:
        self.use_object_sensors()
        self.require_verified_ingestion()
        path = self.write()
        forged = {
            "algorithm": "SHA256withECDSA",
            "device_id": self.snapshot["device_id"],
            "key_id": KEY_ID,
            "payload_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "proof_hmac_sha256": "0" * 64,
            "received_at": NOW.isoformat(),
            "schema_version": 1,
            "sequence": self.snapshot["sequence"],
            "signature_verified": True,
        }
        path.with_name(path.name + ".proof.json").write_text(
            json.dumps(forged),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "verified ingestion provenance"):
            self.pack().observe(self.target)

    def test_snapshot_and_proof_are_retried_until_one_generation_matches(self) -> None:
        snapshot_path = self.root / "phone.json"
        with patch.object(
            SwarmDefenseWatchPack,
            "_read_bounded_file",
            side_effect=[b"old", b"new", b"new", b"new"],
        ), patch.object(
            SwarmDefenseWatchPack,
            "_read_optional_bounded_file",
            side_effect=[b"old-proof", b"new-proof", b"new-proof", b"new-proof"],
        ):
            snapshot, proof = self.pack()._read_coherent_snapshot(snapshot_path)
        self.assertEqual(snapshot, b"new")
        self.assertEqual(proof, b"new-proof")

    def test_stable_mismatched_generation_retries_until_hmac_proof_matches(self) -> None:
        snapshot_path = self.root / "phone.json"
        snapshot = b'{"generation":"new"}'

        def proof_for(payload: bytes, sequence: int) -> bytes:
            proof = {
                "algorithm": "SHA256withECDSA",
                "device_id": "owned-phone",
                "key_id": KEY_ID,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "received_at": NOW.isoformat(),
                "schema_version": 1,
                "sequence": sequence,
                "signature_verified": True,
            }
            proof["proof_hmac_sha256"] = proof_hmac_sha256(
                proof,
                PROOF_HMAC_KEY,
            )
            return json.dumps(proof).encode("utf-8")

        old_proof = proof_for(b'{"generation":"old"}', 6)
        new_proof = proof_for(snapshot, 7)
        with patch.object(
            SwarmDefenseWatchPack,
            "_read_bounded_file",
            side_effect=[snapshot, snapshot, snapshot, snapshot],
        ), patch.object(
            SwarmDefenseWatchPack,
            "_read_optional_bounded_file",
            side_effect=[old_proof, old_proof, new_proof, new_proof],
        ):
            actual_snapshot, actual_proof = self.pack()._read_coherent_snapshot(
                snapshot_path,
                require_matching_proof=True,
            )
        self.assertEqual(actual_snapshot, snapshot)
        self.assertEqual(actual_proof, new_proof)

    def test_stale_verified_telemetry_suppresses_dynamic_conclusions(self) -> None:
        self.use_object_sensors()
        self.snapshot["posture"]["screen_lock"] = False
        self.snapshot["events"] = [capability_event()]
        self.require_verified_ingestion()
        self.write_proof()
        pack = self.pack(clock=NOW + timedelta(hours=2))
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        stale = next(
            finding
            for finding in findings
            if finding.code == "SWARM_TELEMETRY_STALE"
        )
        self.assertEqual(stale.severity, "high")
        self.assertEqual(stale.truth, "VERIFIED")
        self.assertEqual(stale.evidence_grade, "A")
        codes = {finding.code for finding in findings}
        self.assertFalse(
            any(code.startswith("SWARM_DEVICE_POSTURE_WEAK_") for code in codes)
        )
        self.assertFalse(any("_CAPABLE_FOREGROUND_" in code for code in codes))
        self.assertTrue(stale.evidence["dynamic_conclusions_suppressed"])

    def test_stale_telemetry_does_not_resolve_last_known_active_risk(self) -> None:
        self.use_object_sensors()
        self.snapshot["posture"]["screen_lock"] = False
        self.require_verified_ingestion()
        self.write_proof()
        state_store = StateStore(self.root / "state.json")
        first = SentinelEngine(state_store, [self.pack()]).run([self.target])
        first_codes = {
            item["code"] for item in first["results"][0]["current_findings"]
        }
        self.assertIn("SWARM_DEVICE_POSTURE_WEAK_SCREEN_LOCK", first_codes)

        self.snapshot["posture"]["screen_lock"] = True
        self.write_proof()
        second = SentinelEngine(
            state_store,
            [self.pack(clock=NOW + timedelta(hours=2))],
        ).run([self.target])
        second_codes = {
            item["code"] for item in second["results"][0]["current_findings"]
        }
        self.assertIn("SWARM_TELEMETRY_STALE", second_codes)
        self.assertIn("SWARM_DEVICE_POSTURE_WEAK_SCREEN_LOCK", second_codes)
        self.assertEqual(second["resolved_count"], 0)

    def test_missing_or_future_verified_timestamps_are_not_fresh(self) -> None:
        for condition in ("missing_collection", "future_receipt"):
            with self.subTest(condition=condition):
                self.snapshot = {
                    "device_id": "owned-phone",
                    "sensors": {},
                    "posture": {
                        key: True
                        for key in (
                            "disk_encrypted",
                            "secure_boot",
                            "screen_lock",
                            "security_updates_current",
                        )
                    },
                    "mesh": {
                        "enabled": False,
                        "peer_count": 0,
                        "signed_updates_only": True,
                        "raw_data_sharing": False,
                    },
                    "events": [],
                }
                self.use_object_sensors()
                if condition == "missing_collection":
                    self.snapshot.pop("collected_at")
                    received_at = NOW
                else:
                    received_at = NOW + timedelta(minutes=5)
                self.require_verified_ingestion()
                self.write_proof(received_at=received_at)
                pack = self.pack()
                observation = pack.observe(self.target)
                findings = pack.evaluate(self.target, observation, None)
                stale = next(
                    finding
                    for finding in findings
                    if finding.code == "SWARM_TELEMETRY_STALE"
                )
                self.assertEqual(stale.evidence_grade, "A")

    def test_max_snapshot_age_is_bounded(self) -> None:
        self.use_object_sensors()
        self.require_verified_ingestion()
        self.write_proof()
        for invalid in (59, 86_401, True, "3600"):
            with self.subTest(invalid=invalid):
                self.target["max_snapshot_age_seconds"] = invalid
                with self.assertRaisesRegex(ValueError, "max_snapshot_age_seconds"):
                    self.pack().observe(self.target)

    def test_scope_is_compared_exactly_and_never_promoted(self) -> None:
        self.use_object_sensors()
        self.require_verified_ingestion()
        self.target["required_sensor_scopes"] = {
            "network": "routed_ip_flows_uid",
        }
        self.write_proof()
        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        limited = next(
            finding
            for finding in findings
            if finding.code == "SWARM_SENSOR_SCOPE_LIMITED_NETWORK"
        )
        self.assertEqual(
            {
                "reported_scope": limited.evidence["reported_scope"],
                "required_scope": limited.evidence["required_scope"],
            },
            {
                "reported_scope": "active_transport_only",
                "required_scope": "routed_ip_flows_uid",
            },
        )

    def test_new_sensor_gap_alerts_while_existing_gap_remains(self) -> None:
        self.use_object_sensors()
        self.snapshot["collector"]["usage_access"] = "not_granted"
        self.snapshot["collector"]["usage_query_status"] = "not_granted"
        self.snapshot["sensors"]["process"]["status"] = "not_granted"
        self.snapshot["collection"]["usage_query_available"] = False
        self.require_verified_ingestion()
        self.write_proof()
        state_store = StateStore(self.root / "state.json")
        engine = SentinelEngine(state_store, [self.pack()])

        first = engine.run([self.target])
        first_codes = {
            item["code"] for item in first["results"][0]["new_alerts"]
        }
        self.assertIn("SWARM_SENSOR_COVERAGE_INCOMPLETE_PROCESS", first_codes)

        self.snapshot["sequence"] += 1
        self.snapshot["connectivity"] = {
            "content_observed": False,
            "destinations_observed": False,
            "error": "permission_unavailable",
            "scope": "active_transport_only",
            "transports": [],
        }
        self.snapshot["sensors"]["network"]["status"] = "error"
        self.write_proof()
        second = engine.run([self.target])
        second_codes = {
            item["code"] for item in second["results"][0]["new_alerts"]
        }
        self.assertIn("SWARM_SENSOR_COVERAGE_INCOMPLETE_NETWORK", second_codes)
        self.assertNotIn("SWARM_SENSOR_COVERAGE_INCOMPLETE_PROCESS", second_codes)

    def test_newly_required_platform_limited_sensor_alerts(self) -> None:
        self.use_object_sensors()
        self.require_verified_ingestion()
        self.write_proof()
        state_store = StateStore(self.root / "state.json")
        engine = SentinelEngine(state_store, [self.pack()])

        first = engine.run([self.target])
        first_codes = {
            item["code"] for item in first["results"][0]["new_alerts"]
        }
        self.assertIn(
            "SWARM_SENSOR_PLATFORM_LIMITATION_CAMERA_OPTIONAL",
            first_codes,
        )

        self.target["required_sensor_scopes"] = {
            "camera": "direct_cross_app_access"
        }
        second = engine.run([self.target])
        second_codes = {
            item["code"] for item in second["results"][0]["new_alerts"]
        }
        self.assertIn(
            "SWARM_SENSOR_PLATFORM_LIMITATION_CAMERA_REQUIRED",
            second_codes,
        )

    def test_invalid_object_sensor_claim_fails_closed(self) -> None:
        self.use_object_sensors()
        self.snapshot["sensors"]["network"] = {
            "status": "observed",
            "source": "android_connectivity",
            "scope": "routed_ip_flows_uid",
        }
        self.require_verified_ingestion()
        self.write_proof()
        with self.assertRaisesRegex(ValueError, "Android sensor schema"):
            self.pack().observe(self.target)

    def test_signed_android_rejects_legacy_event_types(self) -> None:
        self.use_object_sensors()
        self.snapshot["events"] = [
            {
                "type": "identity_event",
                "process": "login",
                "process_signed": True,
                "baseline": "unexpected",
            }
        ]
        self.require_verified_ingestion()
        self.write_proof()
        with self.assertRaisesRegex(ValueError, "Android event") as raised:
            self.pack().observe(self.target)
        self.assertNotIn("login", str(raised.exception))

    def test_android_capability_correlations_survive_as_inferences(self) -> None:
        self.use_object_sensors()
        self.snapshot["events"] = [
            capability_event(process=PACKAGE_A),
            capability_event(
                "microphone_capable_foreground",
                process=PACKAGE_B,
                certificate_present=False,
                baseline="known",
                observed_at="2026-09-17T12:01:00Z",
            ),
        ]
        self.require_verified_ingestion()
        self.write_proof()
        pack = self.pack()
        observation = pack.observe(self.target)
        self.assertEqual(
            observation.facts["events"][0]["evidence_kind"],
            "capability_inference",
        )
        self.assertEqual(
            observation.facts["events"][0]["observed_at"],
            "2026-09-17T12:00:00Z",
        )
        findings = pack.evaluate(self.target, observation, None)
        capability = [
            finding
            for finding in findings
            if "_CAPABLE_FOREGROUND_" in finding.code
        ]
        self.assertEqual(len(capability), 2)
        self.assertEqual(
            {finding.severity for finding in capability},
            {"low", "medium"},
        )
        # Certificate presence is Android packaging metadata, not publisher
        # trust, so a false value does not elevate a known-baseline event.
        known = next(item for item in capability if item.severity == "low")
        self.assertIs(
            known.evidence["package_has_signing_certificate"],
            False,
        )
        self.assertTrue(all(finding.truth == "INFERENCE" for finding in capability))
        self.assertTrue(all(finding.evidence_grade == "B" for finding in capability))
        self.assertTrue(
            all("does not show" in finding.detail for finding in capability)
        )
        self.assertTrue(
            all(finding.evidence["actions_executed"] is False for finding in capability)
        )

    def test_package_and_permission_deltas_are_evaluated_without_raw_names(self) -> None:
        self.use_object_sensors()
        self.snapshot["events"] = [
            package_event(process=PACKAGE_A),
            permission_event(process=PACKAGE_B),
        ]
        self.require_verified_ingestion()
        self.write_proof()
        pack = self.pack()
        observation = pack.observe(self.target)
        sanitized_permission = observation.facts["events"][1]
        self.assertEqual(sanitized_permission["permission"], "CAMERA")
        self.assertIs(sanitized_permission["granted"], True)
        findings = pack.evaluate(self.target, observation, None)
        package = next(
            finding
            for finding in findings
            if finding.code.startswith("SWARM_PACKAGE_ADDED_")
        )
        permission = next(
            finding
            for finding in findings
            if finding.code.startswith("SWARM_PERMISSION_CHANGE_")
        )
        self.assertEqual(package.severity, "low")
        self.assertEqual(package.truth, "VERIFIED")
        self.assertEqual(package.evidence_grade, "B")
        self.assertEqual(permission.severity, "medium")
        self.assertEqual(permission.truth, "VERIFIED")
        self.assertEqual(permission.evidence["permission"], "CAMERA")
        self.assertNotIn("package.name", str([item.to_dict() for item in findings]))
        self.assertTrue(
            all(
                finding.evidence["actions_executed"] is False
                for finding in (package, permission)
            )
        )

    def test_same_signed_android_event_batch_alerts_only_once(self) -> None:
        self.use_object_sensors()
        self.snapshot["events"] = [
            package_event(process=PACKAGE_A),
            permission_event(process=PACKAGE_B),
        ]
        self.require_verified_ingestion()
        self.write_proof()
        state_store = StateStore(self.root / "state.json")
        engine = SentinelEngine(state_store, [self.pack()])

        first = engine.run([self.target])
        first_event_codes = {
            item["code"]
            for item in first["results"][0]["new_alerts"]
            if item["code"].startswith(("SWARM_PACKAGE_", "SWARM_PERMISSION_"))
        }
        self.assertEqual(len(first_event_codes), 2)

        second = engine.run([self.target])
        second_event_codes = {
            item["code"]
            for item in second["results"][0]["new_alerts"]
            if item["code"].startswith(("SWARM_PACKAGE_", "SWARM_PERMISSION_"))
        }
        self.assertEqual(second_event_codes, set())
        self.assertEqual(second["resolved_count"], 0)

        # A new signed sequence is a new event batch, even if the collector
        # conservatively repeats a delta after a checkpoint uncertainty.
        self.snapshot["sequence"] += 1
        self.write_proof()
        third = engine.run([self.target])
        third_event_codes = {
            item["code"]
            for item in third["results"][0]["new_alerts"]
            if item["code"].startswith(("SWARM_PACKAGE_", "SWARM_PERMISSION_"))
        }
        self.assertEqual(len(third_event_codes), 2)
        self.assertTrue(third_event_codes.isdisjoint(first_event_codes))
        self.assertEqual(third["resolved_count"], 0)

    def test_each_newly_failed_posture_control_alerts_independently(self) -> None:
        self.use_object_sensors()
        self.snapshot["posture"]["screen_lock"] = False
        self.require_verified_ingestion()
        self.write_proof()
        state_store = StateStore(self.root / "state.json")
        engine = SentinelEngine(state_store, [self.pack()])

        first = engine.run([self.target])
        first_codes = {
            item["code"] for item in first["results"][0]["new_alerts"]
        }
        self.assertIn("SWARM_DEVICE_POSTURE_WEAK_SCREEN_LOCK", first_codes)
        first_screen_lock = next(
            item
            for item in first["results"][0]["new_alerts"]
            if item["code"] == "SWARM_DEVICE_POSTURE_WEAK_SCREEN_LOCK"
        )
        self.assertEqual(first_screen_lock["truth"], "VERIFIED")
        self.assertEqual(first_screen_lock["evidence_grade"], "B")

        self.snapshot["sequence"] += 1
        self.snapshot["posture"]["disk_encrypted"] = False
        self.snapshot["posture_evidence"]["disk_encryption_status"] = "inactive"
        self.write_proof()
        second = engine.run([self.target])
        second_codes = {
            item["code"] for item in second["results"][0]["new_alerts"]
        }
        self.assertIn("SWARM_DEVICE_POSTURE_WEAK_DISK_ENCRYPTED", second_codes)
        self.assertNotIn("SWARM_DEVICE_POSTURE_WEAK_SCREEN_LOCK", second_codes)
        self.assertEqual(second["resolved_count"], 0)

    def test_signed_android_security_telemetry_is_evaluated_conservatively(self) -> None:
        self.use_object_sensors()
        self.snapshot["collector"]["signing_key_security"] = "software"
        self.snapshot["posture_evidence"]["adb_enabled"] = "enabled"
        self.snapshot["posture_evidence"]["developer_options"] = "enabled"
        self.snapshot["connectivity"]["validated"] = False
        self.snapshot["connectivity"]["captive_portal"] = True
        permission_posture = self.snapshot["permission_posture"]
        permission_posture["packages_observed"] = 10
        permission_posture["granted_sensitive_permission_counts"]["CAMERA"] = 3
        permission_posture["granted_sensitive_permission_counts"][
            "RECORD_AUDIO"
        ] = 2
        self.require_verified_ingestion()
        self.write_proof()

        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        by_code = {finding.code: finding for finding in findings}

        expected_severities = {
            "SWARM_SIGNING_KEY_SOFTWARE_BACKED": "medium",
            "SWARM_ADB_ENABLED": "medium",
            "SWARM_DEVELOPER_OPTIONS_ENABLED": "low",
            "SWARM_NETWORK_CAPTIVE_PORTAL": "medium",
            "SWARM_SENSITIVE_PERMISSION_FOOTPRINT": "info",
        }
        for code, severity in expected_severities.items():
            with self.subTest(code=code):
                self.assertIn(code, by_code)
                self.assertEqual(by_code[code].severity, severity)
                self.assertEqual(by_code[code].truth, "VERIFIED")
                self.assertEqual(by_code[code].evidence_grade, "B")
                self.assertIn("actions_executed", by_code[code].evidence)
                self.assertFalse(by_code[code].evidence["actions_executed"])
        self.assertNotIn("SWARM_NETWORK_UNVALIDATED", by_code)
        permission_evidence = by_code[
            "SWARM_SENSITIVE_PERMISSION_FOOTPRINT"
        ].evidence
        self.assertEqual(
            permission_evidence["nonzero_granted_permission_counts"],
            {"CAMERA": 3, "RECORD_AUDIO": 2},
        )
        self.assertNotIn("process", str(permission_evidence))
        self.assertIn(
            "not evidence that the key is compromised",
            by_code["SWARM_SIGNING_KEY_SOFTWARE_BACKED"].detail,
        )
        self.assertIn(
            "does not prove use, abuse, or compromise",
            by_code["SWARM_SENSITIVE_PERMISSION_FOOTPRINT"].detail,
        )

    def test_unknown_key_and_unvalidated_network_are_low_noise_findings(self) -> None:
        self.use_object_sensors()
        self.snapshot["collector"]["signing_key_security"] = "unknown"
        self.snapshot["connectivity"]["validated"] = False
        self.require_verified_ingestion()
        self.write_proof()

        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        by_code = {finding.code: finding for finding in findings}

        self.assertEqual(
            by_code["SWARM_SIGNING_KEY_SECURITY_UNKNOWN"].severity,
            "info",
        )
        self.assertEqual(by_code["SWARM_NETWORK_UNVALIDATED"].severity, "low")
        self.assertNotIn("SWARM_NETWORK_CAPTIVE_PORTAL", by_code)
        self.assertNotIn("SWARM_SENSITIVE_PERMISSION_FOOTPRINT", by_code)
        self.assertEqual(
            observation.facts["android_security"]["connectivity"]["transports"],
            ["wifi"],
        )

    def test_unknown_android_posture_is_visibility_not_failed_control(self) -> None:
        self.use_object_sensors()
        self.snapshot["posture"]["disk_encrypted"] = False
        self.snapshot["posture"]["security_updates_current"] = False
        evidence = self.snapshot["posture_evidence"]
        evidence["disk_encryption_status"] = "unsupported_or_unavailable"
        evidence["security_patch"] = "unknown"
        evidence["security_patch_age_days"] = -1
        evidence["adb_enabled"] = "unavailable"
        evidence["developer_options"] = "unavailable"
        self.snapshot["collector"]["security_patch"] = "unknown"
        self.require_verified_ingestion()
        self.write_proof()

        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        codes = {finding.code for finding in findings}
        self.assertFalse(
            any(code.startswith("SWARM_DEVICE_POSTURE_WEAK_") for code in codes)
        )
        limitations = [
            finding
            for finding in findings
            if finding.code.startswith("SWARM_POSTURE_VISIBILITY_LIMITED_")
        ]
        self.assertEqual(
            {finding.evidence["control"] for finding in limitations},
            {
                "adb_enabled",
                "developer_options",
                "disk_encrypted",
                "secure_boot",
                "security_updates_current",
            },
        )
        self.assertTrue(
            all(
                "not treated as a failed control" in finding.detail
                for finding in limitations
            )
        )
        self.assertEqual(
            {
                finding.evidence["control"]: finding.severity
                for finding in limitations
            },
            {
                "adb_enabled": "info",
                "developer_options": "info",
                "disk_encrypted": "medium",
                "secure_boot": "info",
                "security_updates_current": "medium",
            },
        )

    def test_incomplete_collection_is_explicit_not_false_absence(self) -> None:
        self.use_object_sensors()
        self.snapshot["collector"]["usage_query_status"] = "error"
        self.snapshot["sensors"]["process"]["status"] = "error"
        self.snapshot["collection"]["usage_query_available"] = False
        self.require_verified_ingestion()
        self.write_proof()

        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        incomplete = next(
            finding
            for finding in findings
            if finding.code == "SWARM_COLLECTION_USAGE_QUERY_UNAVAILABLE"
        )
        self.assertEqual(incomplete.severity, "medium")
        self.assertIn("not evidence of absence", incomplete.detail)

    def test_usage_history_gap_is_explicit_partial_coverage(self) -> None:
        self.use_object_sensors()
        self.snapshot["collection"]["usage_history_gap"] = True
        self.snapshot["collector"]["usage_query_status"] = "partial"
        self.snapshot["sensors"]["process"]["status"] = "partial"
        self.require_verified_ingestion()
        self.write_proof()

        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        by_code = {finding.code: finding for finding in findings}
        gap = by_code["SWARM_COLLECTION_USAGE_HISTORY_GAP"]
        self.assertFalse(gap.stateful)
        self.assertEqual(gap.severity, "medium")
        self.assertEqual(gap.truth, "VERIFIED")
        self.assertEqual(gap.evidence_grade, "B")
        self.assertEqual(gap.evidence["collection_gap"], "usage_history_gap")
        self.assertIn("not evidence of absence", gap.detail)
        self.assertIn("SWARM_SENSOR_COVERAGE_INCOMPLETE_PROCESS", by_code)

        state_store = StateStore(self.root / "state.json")
        engine = SentinelEngine(state_store, [pack])
        first = engine.run([self.target])
        first_codes = {
            item["code"] for item in first["results"][0]["new_alerts"]
        }
        self.assertIn("SWARM_COLLECTION_USAGE_HISTORY_GAP", first_codes)

        repeated = engine.run([self.target])
        repeated_codes = {
            item["code"] for item in repeated["results"][0]["new_alerts"]
        }
        self.assertNotIn("SWARM_COLLECTION_USAGE_HISTORY_GAP", repeated_codes)

        self.snapshot["sequence"] += 1
        self.snapshot["collection"]["usage_history_gap"] = False
        self.snapshot["collector"]["usage_query_status"] = "observed"
        self.snapshot["sensors"]["process"]["status"] = "observed"
        self.write_proof()
        recovered = engine.run([self.target])
        resolved_codes = {
            item["code"] for item in recovered["results"][0]["resolved"]
        }
        self.assertNotIn("SWARM_COLLECTION_USAGE_HISTORY_GAP", resolved_codes)

    def test_requires_exact_owner_scope_and_explicit_shadow_mode(self) -> None:
        self.write()
        pack = self.pack()
        self.target["authorization"]["approved_methods"] = "read-device-snapshot"
        with self.assertRaisesRegex(ValueError, "approve read-device-snapshot"):
            pack.observe(self.target)
        self.target["authorization"]["approved_methods"] = [
            "read-device-snapshot"
        ]
        self.target["authorization"]["scope"]["device_id"] = "different-device"
        with self.assertRaisesRegex(ValueError, "device must exactly match"):
            pack.observe(self.target)
        self.target["authorization"]["scope"]["device_id"] = "owned-phone"
        self.target["mode"] = "enforce"
        with self.assertRaisesRegex(ValueError, "shadow or advisory"):
            pack.observe(self.target)

    def test_mesh_trust_failures_have_independent_alerts(self) -> None:
        self.snapshot["mesh"]["signed_updates_only"] = False
        self.snapshot["mesh"]["raw_data_sharing"] = True
        self.write()
        pack = self.pack()
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        codes = {finding.code for finding in findings}
        self.assertIn("SWARM_MESH_UNSIGNED_UPDATES_ALLOWED", codes)
        self.assertIn("SWARM_MESH_RAW_DATA_SHARING_ENABLED", codes)
        mesh_findings = [
            finding
            for finding in findings
            if finding.code.startswith("SWARM_MESH_")
        ]
        self.assertTrue(all(item.truth == "INFERENCE" for item in mesh_findings))
        self.assertTrue(all(item.confidence == 35 for item in mesh_findings))
        self.assertTrue(all(item.evidence_grade == "D" for item in mesh_findings))
