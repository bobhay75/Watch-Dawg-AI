from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel.api import ApiError
from sentinel.swarm_ingest import parse_canonical_snapshot
from sentinel.swarm_schema import (
    MAX_EVENT_COUNT,
    validate_verified_android_snapshot,
)
from sentinel.tests.android_snapshot_fixture import (
    PACKAGE_A,
    capability_event,
    make_android_snapshot,
    permission_event,
    synchronize_collection,
)


NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


class AndroidSnapshotSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = make_android_snapshot(collected_at=NOW)

    def validate(self) -> None:
        synchronize_collection(self.snapshot)
        validate_verified_android_snapshot(self.snapshot)

    def test_complete_fixture_is_valid(self) -> None:
        self.validate()

    def test_python_parser_matches_shared_java_golden_vector(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "android-sensor/app/src/test/resources/canonical-v1-golden.json"
        )
        raw = path.read_text(encoding="utf-8").strip().encode("utf-8")
        parsed = parse_canonical_snapshot(raw)
        self.assertEqual(parsed["collector"]["android_api"], 36)
        self.assertEqual(parsed["unicode"], "é")

    def test_python_canonical_parser_rejects_floats_recursively(self) -> None:
        with self.assertRaises(ApiError) as raised:
            parse_canonical_snapshot(b'{"nested":{"value":1.0}}')
        self.assertEqual(raised.exception.code, "invalid_signed_payload")

    def test_raw_or_malformed_package_identity_is_rejected_without_echo(self) -> None:
        for process in (
            "com.example.secretbank",
            "pkg-hmac256:" + "A" * 64,
            "pkg-hmac256:" + "1" * 63,
            "pkg-hmac256:" + "1" * 65,
        ):
            with self.subTest(process=process):
                self.snapshot = make_android_snapshot(collected_at=NOW)
                self.snapshot["events"] = [capability_event(process=process)]
                synchronize_collection(self.snapshot)
                with self.assertRaises(ValueError) as raised:
                    validate_verified_android_snapshot(self.snapshot)
                self.assertNotIn(process, str(raised.exception))

    def test_unknown_top_level_or_nested_fields_are_rejected_without_echo(self) -> None:
        secret = "com.example.raw.package"
        variants = []
        top_level = copy.deepcopy(self.snapshot)
        top_level["raw_package"] = secret
        variants.append(top_level)
        nested = copy.deepcopy(self.snapshot)
        nested["collector"]["debug_package"] = secret
        variants.append(nested)
        for candidate in variants:
            with self.subTest(keys=sorted(candidate)):
                with self.assertRaises(ValueError) as raised:
                    validate_verified_android_snapshot(candidate)
                self.assertNotIn(secret, str(raised.exception))

    def test_event_and_permission_allowlists_are_exact(self) -> None:
        for event in (
            {**capability_event(), "type": "identity_event"},
            permission_event(permission="android.permission.CAMERA"),
            permission_event(permission="INTERNET"),
        ):
            with self.subTest(event_type=event["type"]):
                self.snapshot = make_android_snapshot(collected_at=NOW)
                self.snapshot["events"] = [event]
                synchronize_collection(self.snapshot)
                with self.assertRaisesRegex(ValueError, "Android event"):
                    validate_verified_android_snapshot(self.snapshot)

    def test_event_bool_integer_and_timestamp_types_are_strict(self) -> None:
        mutations = {
            "certificate_string": ("package_has_signing_certificate", "false"),
            "bytes_bool": ("bytes_out", False),
            "bytes_string": ("bytes_out", "0"),
            "naive_timestamp": ("observed_at", "2026-09-17T12:00:00"),
            "numeric_timestamp": ("observed_at", 1_789_646_400),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                self.snapshot = make_android_snapshot(collected_at=NOW)
                event = capability_event()
                event[field] = value
                self.snapshot["events"] = [event]
                synchronize_collection(self.snapshot)
                with self.assertRaisesRegex(ValueError, "Android event"):
                    validate_verified_android_snapshot(self.snapshot)

    def test_event_timestamp_is_bound_to_collection_window(self) -> None:
        for name, observed_at, accepted in (
            ("old_boundary", NOW - timedelta(hours=24), True),
            ("future_boundary", NOW + timedelta(seconds=120), True),
            ("too_old", NOW - timedelta(hours=24, seconds=1), False),
            ("too_far_future", NOW + timedelta(seconds=121), False),
        ):
            with self.subTest(name=name):
                self.snapshot = make_android_snapshot(collected_at=NOW)
                self.snapshot["events"] = [
                    capability_event(observed_at=observed_at.isoformat())
                ]
                synchronize_collection(self.snapshot)
                if accepted:
                    validate_verified_android_snapshot(self.snapshot)
                else:
                    with self.assertRaisesRegex(ValueError, "Android event"):
                        validate_verified_android_snapshot(self.snapshot)

    def test_metadata_bool_float_and_range_confusion_is_rejected(self) -> None:
        variants = {
            "schema_bool": ("schema_version", True),
            "schema_float": ("schema_version", 1.0),
            "sequence_bool": ("sequence", True),
            "sequence_zero": ("sequence", 0),
            "sequence_large": ("sequence", 1 << 63),
        }
        for name, (field, value) in variants.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.snapshot)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    validate_verified_android_snapshot(candidate)

    def test_mesh_and_collection_numeric_types_are_strict(self) -> None:
        mutations = (
            ("mesh", "enabled", 0),
            ("mesh", "peer_count", False),
            ("mesh", "signed_updates_only", 1),
            ("collection", "event_limit", 500.0),
            ("collection", "events_emitted", False),
            ("posture_evidence", "security_patch_policy_max_age_days", 120.0),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                candidate = copy.deepcopy(self.snapshot)
                candidate[section][field] = value
                with self.assertRaises(ValueError):
                    validate_verified_android_snapshot(candidate)

    def test_event_limit_is_enforced(self) -> None:
        self.snapshot["events"] = [capability_event()] * (MAX_EVENT_COUNT + 1)
        self.snapshot["collection"]["events_emitted"] = MAX_EVENT_COUNT + 1
        with self.assertRaisesRegex(ValueError, "event collection"):
            validate_verified_android_snapshot(self.snapshot)

    def test_collected_at_is_owned_by_freshness_unless_ingesting(self) -> None:
        self.snapshot.pop("collected_at")
        validate_verified_android_snapshot(self.snapshot)
        with self.assertRaisesRegex(ValueError, "Verified Android"):
            validate_verified_android_snapshot(
                self.snapshot,
                require_collected_at=True,
            )

    def test_posture_claims_are_cross_bound_to_evidence(self) -> None:
        variants = []
        encrypted = copy.deepcopy(self.snapshot)
        encrypted["posture"]["disk_encrypted"] = False
        variants.append(encrypted)
        patch = copy.deepcopy(self.snapshot)
        patch["posture"]["security_updates_current"] = False
        variants.append(patch)
        patch_name = copy.deepcopy(self.snapshot)
        patch_name["posture_evidence"]["security_patch"] = "2026-08-01"
        variants.append(patch_name)
        future_patch = copy.deepcopy(self.snapshot)
        future_patch["collector"]["security_patch"] = "2026-10-01"
        future_patch["posture_evidence"]["security_patch"] = "2026-10-01"
        future_patch["posture_evidence"]["security_patch_age_days"] = 0
        variants.append(future_patch)
        for candidate in variants:
            with self.subTest(candidate=candidate["posture"]):
                with self.assertRaises(ValueError):
                    validate_verified_android_snapshot(candidate)

    def test_network_error_status_and_evidence_are_cross_bound(self) -> None:
        self.snapshot["connectivity"] = {
            "content_observed": False,
            "destinations_observed": False,
            "error": "service_unavailable",
            "scope": "active_transport_only",
            "transports": [],
        }
        self.snapshot["sensors"]["network"]["status"] = "error"
        self.validate()

        self.snapshot["sensors"]["network"]["status"] = "observed"
        with self.assertRaisesRegex(ValueError, "sensor schema"):
            self.validate()

    def test_collection_counts_and_truncation_are_cross_bound(self) -> None:
        self.snapshot["events"] = [capability_event()]
        self.snapshot["collection"]["events_emitted"] = 0
        with self.assertRaisesRegex(ValueError, "collection metadata"):
            validate_verified_android_snapshot(self.snapshot)

        self.snapshot = make_android_snapshot(collected_at=NOW)
        self.snapshot["collection"]["package_deltas_truncated"] = True
        synchronize_collection(self.snapshot)
        with self.assertRaisesRegex(ValueError, "collection metadata"):
            validate_verified_android_snapshot(self.snapshot)

    def test_usage_access_status_and_baseline_are_cross_bound(self) -> None:
        access = copy.deepcopy(self.snapshot)
        access["collector"]["usage_access"] = "not_granted"
        with self.assertRaisesRegex(ValueError, "collection metadata"):
            validate_verified_android_snapshot(access)

        baseline = copy.deepcopy(self.snapshot)
        baseline["permission_posture"]["baseline_initialized"] = False
        baseline["events"] = [permission_event()]
        synchronize_collection(baseline)
        with self.assertRaisesRegex(ValueError, "collection metadata"):
            validate_verified_android_snapshot(baseline)

    def test_usage_history_gap_forces_partial_incomplete_coverage(self) -> None:
        self.snapshot["collection"]["usage_history_gap"] = True
        self.snapshot["collector"]["usage_query_status"] = "partial"
        self.snapshot["sensors"]["process"]["status"] = "partial"
        self.validate()
        self.assertFalse(self.snapshot["collection"]["complete"])

        observed = copy.deepcopy(self.snapshot)
        observed["collector"]["usage_query_status"] = "observed"
        observed["sensors"]["process"]["status"] = "observed"
        with self.assertRaisesRegex(ValueError, "collection metadata"):
            validate_verified_android_snapshot(observed)

        wrong_type = copy.deepcopy(self.snapshot)
        wrong_type["collection"]["usage_history_gap"] = 1
        with self.assertRaisesRegex(ValueError, "collection metadata"):
            validate_verified_android_snapshot(wrong_type)

    def test_package_certificate_presence_never_accepts_legacy_field_name(self) -> None:
        event = capability_event(process=PACKAGE_A, certificate_present=False)
        event["process_signed"] = event.pop("package_has_signing_certificate")
        self.snapshot["events"] = [event]
        synchronize_collection(self.snapshot)
        with self.assertRaisesRegex(ValueError, "Android event"):
            validate_verified_android_snapshot(self.snapshot)


if __name__ == "__main__":
    unittest.main()
