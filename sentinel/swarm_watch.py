from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import Finding, Observation, stable_hash
from .swarm_proof import (
    parse_proof_json,
    validate_proof_hmac_key,
    verify_proof_hmac,
)
from .swarm_schema import (
    MAX_EVENT_COUNT,
    SENSOR_KEYS,
    SENSOR_SOURCE_SCOPES,
    SENSOR_STATUSES,
    android_posture_unknown_controls,
    is_strict_integer,
    parse_aware_timestamp,
    validate_verified_android_snapshot,
)

MAX_SNAPSHOT_BYTES = 512_000
MAX_PROOF_BYTES = 8_192
COHERENT_READ_ATTEMPTS = 4
ALLOWED_MODES = {"shadow", "advisory"}
DEFAULT_MAX_SNAPSHOT_AGE_SECONDS = 3_600
MIN_MAX_SNAPSHOT_AGE_SECONDS = 60
MAX_MAX_SNAPSHOT_AGE_SECONDS = 86_400
TELEMETRY_FUTURE_SKEW_SECONDS = 120
MAX_EVENT_BYTES = (1 << 63) - 1
LEGACY_EVENT_TYPES = {
    "camera_access",
    "microphone_access",
    "identity_event",
    "network_egress",
}
_MISSING = object()


def _sanitize_legacy_event(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Legacy Swarm event must be an object")
    event_type = event.get("type")
    if not isinstance(event_type, str) or event_type not in LEGACY_EVENT_TYPES:
        raise ValueError("Legacy Swarm event type is not allowed")

    process = event.get("process", "unknown")
    if not isinstance(process, str) or len(process) > 1_024:
        raise ValueError("Legacy Swarm process field is invalid")
    process_signed = event.get("process_signed", False)
    sensitive = event.get("sensitive", False)
    baseline = event.get("baseline", "unknown")
    bytes_out = event.get("bytes_out", 0)
    destination = event.get("destination", "")
    evidence_kind = event.get("evidence_kind", "")
    observed_at = event.get("observed_at", "")
    claim = event.get("claim", "")
    permission = event.get("permission", "")
    granted = event.get("granted")
    if not isinstance(process_signed, bool) or not isinstance(sensitive, bool):
        raise ValueError("Legacy Swarm event boolean field is invalid")
    if baseline not in {"initializing", "known", "unexpected", "unknown"}:
        raise ValueError("Legacy Swarm event baseline is invalid")
    if (
        not is_strict_integer(bytes_out)
        or not 0 <= bytes_out <= MAX_EVENT_BYTES
        or not isinstance(destination, str)
        or len(destination) > 2_048
    ):
        raise ValueError("Legacy Swarm event transfer field is invalid")
    for value in (evidence_kind, claim, permission):
        if not isinstance(value, str):
            raise ValueError("Legacy Swarm event text field is invalid")
    if len(evidence_kind) > 40 or len(claim) > 80 or len(permission) > 64:
        raise ValueError("Legacy Swarm event text field is invalid")
    if observed_at:
        if parse_aware_timestamp(observed_at) is None:
            raise ValueError("Legacy Swarm event timestamp is invalid")
    elif not isinstance(observed_at, str):
        raise ValueError("Legacy Swarm event timestamp is invalid")
    if granted is not None and not isinstance(granted, bool):
        raise ValueError("Legacy Swarm event permission state is invalid")

    return {
        "type": event_type,
        "process": f"legacy-sha256:{stable_hash(process)}",
        "process_signed": process_signed,
        "baseline": baseline,
        "sensitive": sensitive,
        "bytes_out": bytes_out,
        "destination_sha256": stable_hash(destination)[:16] if destination else "",
        "evidence_kind": evidence_kind,
        "observed_at": observed_at,
        "claim": claim,
        "permission": permission,
        "granted": granted,
    }


def _sanitize_android_event(event: dict[str, Any]) -> dict[str, Any]:
    destination = event["destination"]
    return {
        "type": event["type"],
        "process": event["process"],
        "package_has_signing_certificate": event[
            "package_has_signing_certificate"
        ],
        "baseline": event["baseline"],
        "sensitive": event["sensitive"],
        "bytes_out": event["bytes_out"],
        "destination_sha256": stable_hash(destination)[:16] if destination else "",
        "evidence_kind": event["evidence_kind"],
        "observed_at": event["observed_at"],
        "claim": event.get("claim", ""),
        "permission": event.get("permission", ""),
        "granted": event.get("granted"),
    }


def _parse_future_expiry(value: Any) -> None:
    if not isinstance(value, str):
        raise ValueError("Swarm authorization requires an expiration time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Swarm authorization expiration must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed <= datetime.now(timezone.utc):
        raise ValueError("Swarm authorization is expired or lacks a timezone")


class SwarmDefenseWatchPack:
    """Evaluates an authorized local device snapshot; never controls the device."""

    kind = "swarm_device"
    allowed_authorization_modes = {"owner", "contract"}

    def __init__(
        self,
        root: str | Path,
        *,
        proof_hmac_key: bytes | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.root = Path(root).resolve()
        self.proof_hmac_key = validate_proof_hmac_key(
            proof_hmac_key,
            required=False,
        )
        self.clock = clock

    def observe(self, target: dict[str, Any]) -> Observation:
        if target.get("enabled") is not True:
            raise ValueError("Swarm Defense target must be explicitly enabled")
        mode = str(target.get("mode", ""))
        if mode not in ALLOWED_MODES:
            raise ValueError("Swarm Defense permits only shadow or advisory mode")
        raw_path = str(target.get("snapshot_path", "")).strip()
        authorization = target.get("authorization")
        if not raw_path:
            raise ValueError("Swarm Defense target requires snapshot_path")
        if not isinstance(authorization, dict) or not authorization.get("id"):
            raise ValueError("Swarm Defense target requires an authorization record id")
        approved_methods = authorization.get("approved_methods", [])
        if (
            not isinstance(approved_methods, list)
            or any(not isinstance(method, str) for method in approved_methods)
            or "read-device-snapshot" not in approved_methods
        ):
            raise ValueError("Swarm authorization must approve read-device-snapshot")
        scope = authorization.get("scope")
        if not isinstance(scope, dict) or scope.get("snapshot_path") != raw_path:
            raise ValueError("Swarm authorization path must exactly match the target")
        if scope.get("device_id") != target.get("device_id"):
            raise ValueError("Swarm authorization device must exactly match the target")
        _parse_future_expiry(authorization.get("expires_at"))
        require_verified_ingestion = self._requires_verified_ingestion(target)

        candidate = (self.root / raw_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError("Swarm snapshot path escapes the configured root")
        if not candidate.is_file():
            raise ValueError("Swarm snapshot does not exist")
        raw, proof_raw = self._read_coherent_snapshot(
            candidate,
            require_matching_proof=require_verified_ingestion,
        )
        snapshot = json.loads(raw.decode("utf-8"))
        if not isinstance(snapshot, dict):
            raise ValueError("Swarm snapshot must contain a JSON object")
        if snapshot.get("device_id") != target.get("device_id"):
            raise ValueError("Swarm snapshot device does not match authorized target")

        sensors = snapshot.get("sensors", {})
        events = snapshot.get("events", [])
        posture = snapshot.get("posture", {})
        mesh = snapshot.get("mesh", {})
        if not isinstance(sensors, dict) or not isinstance(events, list):
            raise ValueError("Swarm snapshot sensors or events have invalid types")
        if not isinstance(posture, dict) or not isinstance(mesh, dict):
            raise ValueError("Swarm snapshot posture or mesh have invalid types")

        object_sensor_schema = any(
            isinstance(sensors.get(key, _MISSING), dict) for key in SENSOR_KEYS
        )
        if object_sensor_schema and not require_verified_ingestion:
            raise ValueError(
                "Swarm object sensor schema requires "
                "require_verified_ingestion: true"
            )

        snapshot_sha256 = hashlib.sha256(raw).hexdigest()
        provenance = self._load_ingest_proof(
            proof_raw,
            snapshot,
            snapshot_sha256,
            target,
            require_verified=require_verified_ingestion,
        )
        verified_android_schema = (
            object_sensor_schema
            and provenance["signature_verified"] is True
        )
        if verified_android_schema:
            validate_verified_android_snapshot(snapshot)
        telemetry = self._telemetry_freshness(
            snapshot,
            provenance,
            target,
            required=(
                object_sensor_schema
                and provenance["signature_verified"] is True
            ),
        )
        sensor_coverage, sensor_schema = self._normalize_sensor_coverage(
            sensors,
            target,
            object_sensor_schema=object_sensor_schema,
            ingestion_verified=provenance["signature_verified"],
        )

        if len(events) > MAX_EVENT_COUNT:
            raise ValueError(f"Swarm snapshot may contain at most {MAX_EVENT_COUNT} events")
        safe_events = (
            [_sanitize_android_event(event) for event in events]
            if verified_android_schema
            else [_sanitize_legacy_event(event) for event in events]
        )

        if verified_android_schema:
            safe_posture = dict(posture)
            posture_unknown = android_posture_unknown_controls(snapshot)
            collection = dict(snapshot["collection"])
            permission_posture = snapshot["permission_posture"]
            connectivity = snapshot["connectivity"]
            android_security = {
                "signing_key_security": snapshot["collector"][
                    "signing_key_security"
                ],
                "adb_enabled": snapshot["posture_evidence"]["adb_enabled"],
                "developer_options": snapshot["posture_evidence"][
                    "developer_options"
                ],
                "connectivity": {
                    "status": "error" if "error" in connectivity else "observed",
                    "error": connectivity.get("error", ""),
                    "validated": connectivity.get("validated"),
                    "captive_portal": connectivity.get("captive_portal"),
                    "metered": connectivity.get("metered"),
                    "transports": list(connectivity["transports"]),
                },
                "permission_posture": {
                    "baseline_initialized": permission_posture[
                        "baseline_initialized"
                    ],
                    "packages_observed": permission_posture["packages_observed"],
                    "inventory_scope": permission_posture["inventory_scope"],
                    "granted_sensitive_permission_counts": dict(
                        permission_posture[
                            "granted_sensitive_permission_counts"
                        ]
                    ),
                },
            }
            android_event_batch_id = (
                stable_hash(
                    f"{snapshot['device_id']}\0{snapshot['sequence']}\0{snapshot_sha256}"
                )[:24]
                if telemetry["fresh"] is True
                else ""
            )
        else:
            safe_posture = {
                key: bool(posture.get(key, False))
                for key in (
                    "disk_encrypted",
                    "secure_boot",
                    "screen_lock",
                    "security_updates_current",
                )
            }
            posture_unknown = {}
            collection = {
                "complete": True,
                "event_limit": MAX_EVENT_COUNT,
                "events_emitted": len(safe_events),
                "package_deltas_truncated": False,
                "permission_deltas_truncated": False,
                "usage_events_truncated": False,
                "usage_history_gap": False,
                "usage_query_available": False,
            }
            android_security = {}
            android_event_batch_id = ""

        facts = {
            "mode": mode,
            "device_id_sha256": stable_hash(str(snapshot["device_id"]))[:16],
            "snapshot_sha256": snapshot_sha256,
            "provenance": provenance,
            "telemetry": telemetry,
            "preserve_prior_active_findings": (
                telemetry["required"] is True
                and telemetry["fresh"] is not True
            ),
            "sensor_schema": sensor_schema,
            "sensor_coverage": sensor_coverage,
            "verified_android_schema": verified_android_schema,
            "posture": safe_posture,
            "posture_unknown": posture_unknown,
            "collection": collection,
            "android_security": android_security,
            # This persisted watermark identifies the exact signed Android
            # event batch that was eligible for evaluation.  Stale batches do
            # not advance it, so they can still alert if the same snapshot
            # later becomes fresh (for example after bounded clock skew).
            "android_event_batch_id": android_event_batch_id,
            "mesh": {
                "enabled": bool(mesh.get("enabled", False)),
                "peer_count": max(0, int(mesh.get("peer_count", 0))),
                "signed_updates_only": bool(mesh.get("signed_updates_only", False)),
                "raw_data_sharing": bool(mesh.get("raw_data_sharing", False)),
            },
            "events": safe_events,
            "actions_executed": False,
        }
        return Observation(target_id=str(target["id"]), kind=self.kind, ok=True, facts=facts, evidence=[f"swarm-snapshot://{candidate.relative_to(self.root).as_posix()}#{facts['snapshot_sha256']}"])

    def _load_ingest_proof(
        self,
        proof_raw: bytes | None,
        snapshot: dict[str, Any],
        snapshot_sha256: str,
        target: dict[str, Any],
        *,
        require_verified: bool,
    ) -> dict[str, Any]:
        if require_verified and self.proof_hmac_key is None:
            raise ValueError(
                "Swarm verified ingestion requires a server proof HMAC key"
            )
        verified = False
        key_id = ""
        received_at = ""
        reason = "proof_missing"
        if proof_raw is not None:
            try:
                proof = parse_proof_json(proof_raw)
            except ValueError:
                proof = None
                reason = "proof_invalid"
            if isinstance(proof, dict):
                if self.proof_hmac_key is None:
                    reason = "proof_key_unavailable"
                elif not verify_proof_hmac(proof, self.proof_hmac_key):
                    reason = "proof_authentication_failed"
                else:
                    key_id_value = proof.get("key_id")
                    key_id = key_id_value if isinstance(key_id_value, str) else ""
                    verified = (
                        proof.get("device_id") == snapshot.get("device_id")
                        and proof.get("sequence") == snapshot.get("sequence")
                        and proof.get("payload_sha256") == snapshot_sha256
                    )
                    received_at_value = proof.get("received_at")
                    received_at = (
                        received_at_value
                        if isinstance(received_at_value, str)
                        else ""
                    )
                    reason = "verified" if verified else "proof_mismatch"

        trusted_key_ids = target.get("trusted_key_ids", [])
        if not isinstance(trusted_key_ids, list) or any(
            not isinstance(item, str) for item in trusted_key_ids
        ):
            raise ValueError("Swarm trusted_key_ids must be a list of strings")
        if verified and trusted_key_ids and key_id not in trusted_key_ids:
            verified = False
            reason = "untrusted_key"
        if require_verified and not trusted_key_ids:
            raise ValueError(
                "Swarm verified ingestion requires at least one trusted key id"
            )
        if require_verified and not verified:
            raise ValueError(
                "Swarm snapshot does not have valid server-verified ingestion provenance"
            )
        return {
            "server_proof_verified": verified,
            "signature_verified": verified,
            "key_id": key_id if verified else "",
            "received_at": received_at if verified else "",
            "status": reason,
        }

    def _read_coherent_snapshot(
        self,
        snapshot_path: Path,
        *,
        require_matching_proof: bool = False,
    ) -> tuple[bytes, bytes | None]:
        proof_path = snapshot_path.with_name(snapshot_path.name + ".proof.json")
        last_stable: tuple[bytes, bytes | None] | None = None
        for attempt in range(COHERENT_READ_ATTEMPTS):
            try:
                snapshot_before = SwarmDefenseWatchPack._read_bounded_file(
                    snapshot_path,
                    MAX_SNAPSHOT_BYTES,
                    "snapshot",
                )
                proof_before = SwarmDefenseWatchPack._read_optional_bounded_file(
                    proof_path,
                    MAX_PROOF_BYTES,
                    "proof",
                )
                snapshot_after = SwarmDefenseWatchPack._read_bounded_file(
                    snapshot_path,
                    MAX_SNAPSHOT_BYTES,
                    "snapshot",
                )
                proof_after = SwarmDefenseWatchPack._read_optional_bounded_file(
                    proof_path,
                    MAX_PROOF_BYTES,
                    "proof",
                )
            except FileNotFoundError:
                snapshot_before = b""
                snapshot_after = b"different"
                proof_before = None
                proof_after = None
            if (
                snapshot_before == snapshot_after
                and proof_before == proof_after
                and snapshot_after
            ):
                last_stable = (snapshot_after, proof_after)
                if not require_matching_proof or (
                    proof_after is not None
                    and self._proof_matches_snapshot(
                        proof_after,
                        snapshot_after,
                    )
                ):
                    return snapshot_after, proof_after
            if attempt + 1 < COHERENT_READ_ATTEMPTS:
                time.sleep(0.005)
        if last_stable is not None:
            return last_stable
        raise ValueError("Swarm snapshot and verification proof changed during read")

    def _proof_matches_snapshot(
        self,
        proof_raw: bytes,
        snapshot_raw: bytes,
    ) -> bool:
        try:
            proof = parse_proof_json(proof_raw)
        except ValueError:
            return False
        return (
            verify_proof_hmac(proof, self.proof_hmac_key)
            and proof.get("payload_sha256")
            == hashlib.sha256(snapshot_raw).hexdigest()
        )

    @staticmethod
    def _read_bounded_file(path: Path, limit: int, label: str) -> bytes:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
        if len(payload) > limit:
            raise ValueError(f"Swarm {label} exceeds {limit} bytes")
        return payload

    @staticmethod
    def _read_optional_bounded_file(
        path: Path,
        limit: int,
        label: str,
    ) -> bytes | None:
        try:
            return SwarmDefenseWatchPack._read_bounded_file(path, limit, label)
        except FileNotFoundError:
            return None

    def _telemetry_freshness(
        self,
        snapshot: dict[str, Any],
        provenance: dict[str, Any],
        target: dict[str, Any],
        *,
        required: bool,
    ) -> dict[str, Any]:
        max_age = target.get(
            "max_snapshot_age_seconds",
            DEFAULT_MAX_SNAPSHOT_AGE_SECONDS,
        )
        if (
            isinstance(max_age, bool)
            or not isinstance(max_age, int)
            or not MIN_MAX_SNAPSHOT_AGE_SECONDS
            <= max_age
            <= MAX_MAX_SNAPSHOT_AGE_SECONDS
        ):
            raise ValueError(
                "Swarm max_snapshot_age_seconds must be an integer from "
                f"{MIN_MAX_SNAPSHOT_AGE_SECONDS} through "
                f"{MAX_MAX_SNAPSHOT_AGE_SECONDS}"
            )
        if not required:
            return {
                "required": False,
                "fresh": None,
                "status": "not_enforced_for_legacy_snapshot",
                "max_age_seconds": max_age,
                "age_seconds": None,
            }

        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("Swarm evaluator clock must return a timezone-aware datetime")
        now = now.astimezone(timezone.utc)
        collected_at = self._parse_telemetry_timestamp(snapshot.get("collected_at"))
        received_at = self._parse_telemetry_timestamp(
            provenance.get("received_at")
        )
        reasons: list[str] = []
        if collected_at is None:
            reasons.append("collected_at_missing_or_invalid")
        if received_at is None:
            reasons.append("received_at_missing_or_invalid")

        future_skew = TELEMETRY_FUTURE_SKEW_SECONDS
        ages: list[float] = []
        if collected_at is not None:
            collected_age = (now - collected_at).total_seconds()
            ages.append(collected_age)
            if collected_age < -future_skew:
                reasons.append("collected_at_in_future")
            elif collected_age > max_age:
                reasons.append("collected_at_stale")
        if received_at is not None:
            received_age = (now - received_at).total_seconds()
            ages.append(received_age)
            if received_age < -future_skew:
                reasons.append("received_at_in_future")
            elif received_age > max_age:
                reasons.append("received_at_stale")
        if (
            collected_at is not None
            and received_at is not None
            and collected_at.timestamp()
            > received_at.timestamp() + future_skew
        ):
            reasons.append("collection_after_receipt")

        fresh = not reasons
        return {
            "required": True,
            "fresh": fresh,
            "status": "fresh" if fresh else "stale_or_invalid",
            "reasons": reasons,
            "max_age_seconds": max_age,
            "age_seconds": (
                max(0, round(max(ages))) if ages else None
            ),
        }

    @staticmethod
    def _parse_telemetry_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _requires_verified_ingestion(target: dict[str, Any]) -> bool:
        values: list[bool] = []
        for key in ("require_verified_ingestion", "require_verified_ingest"):
            if key not in target:
                continue
            value = target[key]
            if not isinstance(value, bool):
                raise ValueError(f"Swarm {key} must be true or false")
            values.append(value)
        if len(set(values)) > 1:
            raise ValueError("Swarm verified-ingestion settings conflict")
        return values[0] if values else False

    @staticmethod
    def _normalize_sensor_coverage(
        sensors: dict[str, Any],
        target: dict[str, Any],
        *,
        object_sensor_schema: bool,
        ingestion_verified: bool,
    ) -> tuple[dict[str, dict[str, Any]], str]:
        requirements = target.get("required_sensor_scopes", {})
        if not isinstance(requirements, dict):
            raise ValueError("Swarm required_sensor_scopes must be an object")
        unknown_requirements = sorted(set(requirements) - set(SENSOR_KEYS))
        if unknown_requirements:
            raise ValueError(
                "Swarm required_sensor_scopes contains unknown sensors: "
                + ", ".join(unknown_requirements)
            )
        for key, value in requirements.items():
            if not isinstance(value, str) or not value or len(value) > 64:
                raise ValueError(
                    f"Swarm required scope for {key} must be 1-64 characters"
                )

        normalized: dict[str, dict[str, Any]] = {}
        saw_legacy = False
        for key in SENSOR_KEYS:
            value = sensors.get(key, _MISSING)
            required_scope = requirements.get(key)
            if value is _MISSING:
                normalized[key] = {
                    "status": "missing",
                    "source": "none",
                    "scope": "none",
                    "provenance": (
                        "verified_ingestion"
                        if object_sensor_schema and ingestion_verified
                        else "legacy"
                    ),
                    "required_scope": required_scope,
                    "meets_required_scope": False,
                }
                continue
            if isinstance(value, bool):
                saw_legacy = True
                normalized[key] = {
                    "status": "legacy_reported" if value else "legacy_unavailable",
                    "source": "legacy_boolean",
                    "scope": "unspecified",
                    "provenance": "legacy",
                    "required_scope": required_scope,
                    "meets_required_scope": None if value else False,
                }
                continue
            if not isinstance(value, dict):
                raise ValueError(
                    f"Swarm sensor {key} must be a boolean or status object"
                )

            status = value.get("status")
            source = value.get("source")
            scope = value.get("scope")
            if (
                not isinstance(status, str)
                or not isinstance(source, str)
                or not isinstance(scope, str)
                or not status
                or not source
                or not scope
                or len(status) > 32
                or len(source) > 64
                or len(scope) > 64
            ):
                raise ValueError(
                    f"Swarm sensor {key} requires bounded status, source, and scope strings"
                )
            if status not in SENSOR_STATUSES:
                raise ValueError(f"Swarm sensor {key} has unsupported status {status!r}")
            allowed_statuses = SENSOR_SOURCE_SCOPES[key].get((source, scope))
            if allowed_statuses is None or status not in allowed_statuses:
                raise ValueError(
                    f"Swarm sensor {key} source/scope/status combination is not allowed"
                )
            if not ingestion_verified:
                raise ValueError(
                    "Swarm object sensor schema requires verified ingestion provenance"
                )
            normalized[key] = {
                "status": status,
                "source": source,
                "scope": scope,
                "provenance": "verified_ingestion",
                "required_scope": required_scope,
                # Scope compatibility is exact by design.  Unrelated Android
                # capabilities are not interchangeable or linearly ordered.
                "meets_required_scope": (
                    None if required_scope is None else scope == required_scope
                ),
            }

        if object_sensor_schema and saw_legacy:
            schema = "mixed"
        elif object_sensor_schema:
            schema = "object_v2"
        else:
            schema = "legacy_boolean"
        return normalized, schema

    def evaluate(self, target: dict[str, Any], current: Observation, previous: Observation | None) -> list[Finding]:
        facts = current.facts
        findings: list[Finding] = []
        telemetry = facts["telemetry"]
        telemetry_stale = (
            telemetry["required"] is True and telemetry["fresh"] is not True
        )
        if telemetry_stale:
            findings.append(
                self._finding(
                    current,
                    "SWARM_TELEMETRY_STALE",
                    "high",
                    "Verified device telemetry is stale or invalid",
                    "The signed collection time or server-authenticated receipt time is missing, stale, inconsistent, or in the future. Event and posture conclusions are suppressed until fresh telemetry arrives.",
                    {
                        "freshness_status": telemetry["status"],
                        "reasons": telemetry["reasons"],
                        "age_seconds": telemetry["age_seconds"],
                        "max_age_seconds": telemetry["max_age_seconds"],
                        "dynamic_conclusions_suppressed": True,
                    },
                    truth="VERIFIED",
                    confidence=100,
                    evidence_grade="A",
                )
            )
        coverage = facts["sensor_coverage"]
        legacy = sorted(
            key
            for key, sensor in coverage.items()
            if sensor["provenance"] == "legacy"
        )
        if legacy:
            findings.append(
                self._finding(
                    current,
                    "SWARM_SENSOR_PROVENANCE_UNVERIFIED",
                    "medium",
                    "Sensor coverage uses legacy, unscoped claims",
                    "Legacy boolean coverage remains readable, but it cannot prove which Android API or scope produced the claim.",
                    {
                        "legacy_sensors": legacy,
                        "coverage_state": "unknown",
                    },
                    evidence_grade="D",
                )
            )
        incomplete_statuses = {
            "missing",
            "legacy_unavailable",
            "partial",
            "not_granted",
            "disabled",
            "error",
        }
        incomplete = {
            key: sensor["status"]
            for key, sensor in coverage.items()
            if sensor["status"] in incomplete_statuses
        }
        for sensor, status in sorted(incomplete.items()):
            incomplete_grade = (
                "D" if coverage[sensor]["provenance"] == "legacy" else "B"
            )
            findings.append(
                self._finding(
                    current,
                    f"SWARM_SENSOR_COVERAGE_INCOMPLETE_{sensor.upper()}",
                    "medium",
                    f"{sensor.title()} visibility is incomplete",
                    "An authorized sensor did not report complete coverage; Watch-Dawg cannot rule out activity it could not observe.",
                    {
                        "sensor": sensor,
                        "status": status,
                    },
                    evidence_grade=incomplete_grade,
                )
            )
        limitations = {
            key: sensor["status"]
            for key, sensor in coverage.items()
            if sensor["status"] in {"unsupported", "enterprise_only"}
        }
        for sensor, status in sorted(limitations.items()):
            required_scope = coverage[sensor]["required_scope"]
            requirement_state = "REQUIRED" if required_scope is not None else "OPTIONAL"
            findings.append(
                self._finding(
                    current,
                    (
                        f"SWARM_SENSOR_PLATFORM_LIMITATION_{sensor.upper()}_"
                        f"{requirement_state}"
                    ),
                    "medium" if required_scope is not None else "info",
                    f"Android limits the {sensor} signal",
                    "The signed collector reported a platform or management limitation. This is a visibility boundary, not evidence of compromise.",
                    {
                        "sensor": sensor,
                        "status": status,
                        "required_scope": required_scope,
                    },
                    evidence_grade="B",
                )
            )
        limited = {
            key: {
                "reported_scope": sensor["scope"],
                "required_scope": sensor["required_scope"],
            }
            for key, sensor in coverage.items()
            if sensor["status"] == "observed"
            and sensor["meets_required_scope"] is False
        }
        for sensor, scopes in sorted(limited.items()):
            findings.append(
                self._finding(
                    current,
                    f"SWARM_SENSOR_SCOPE_LIMITED_{sensor.upper()}",
                    "medium",
                    f"Reported {sensor} scope does not meet the requirement",
                    "A valid collector source reported data, but its exact Android scope does not satisfy the configured requirement.",
                    {"sensor": sensor, **scopes},
                    evidence_grade="B",
                )
            )
        if telemetry_stale:
            return findings
        if facts["verified_android_schema"]:
            collection = facts["collection"]
            collection_gaps = {
                "package_deltas_truncated": (
                    "SWARM_COLLECTION_PACKAGE_DELTAS_TRUNCATED",
                    "Android package-delta collection was truncated",
                ),
                "permission_deltas_truncated": (
                    "SWARM_COLLECTION_PERMISSION_DELTAS_TRUNCATED",
                    "Android permission-delta collection was truncated",
                ),
                "usage_events_truncated": (
                    "SWARM_COLLECTION_USAGE_EVENTS_TRUNCATED",
                    "Android usage-event collection was truncated",
                ),
                "usage_history_gap": (
                    "SWARM_COLLECTION_USAGE_HISTORY_GAP",
                    "Android usage-event history has a coverage gap",
                ),
            }
            for field, (code, title) in collection_gaps.items():
                if collection[field] is True:
                    stateful = field != "usage_history_gap"
                    if not stateful:
                        previous_batch_id = (
                            previous.facts.get("android_event_batch_id", "")
                            if previous is not None
                            else ""
                        )
                        if (
                            not facts["android_event_batch_id"]
                            or facts["android_event_batch_id"] == previous_batch_id
                        ):
                            continue
                    findings.append(
                        self._finding(
                            current,
                            code,
                            "medium",
                            title,
                            (
                                "The signed collector could not cover the complete "
                                "usage-event interval. Findings remain advisory and "
                                "absence of an event is not evidence of absence."
                                if field == "usage_history_gap"
                                else "The signed collector reached its event limit. "
                                "Findings remain advisory and absence of an event is "
                                "not evidence of absence."
                            ),
                            {
                                "collection_gap": field,
                                "events_emitted": collection["events_emitted"],
                                "event_limit": collection["event_limit"],
                            },
                            stateful=stateful,
                            evidence_grade="B",
                        )
                    )
            if (
                collection["complete"] is not True
                and collection["usage_query_available"] is not True
            ):
                findings.append(
                    self._finding(
                        current,
                        "SWARM_COLLECTION_USAGE_QUERY_UNAVAILABLE",
                        "medium",
                        "Android usage-event query was unavailable",
                        "The signed collector could not query Android usage events. Findings remain advisory and absence of an event is not evidence of absence.",
                        {
                            "collection_gap": "usage_query_unavailable",
                            "events_emitted": collection["events_emitted"],
                            "event_limit": collection["event_limit"],
                        },
                        evidence_grade="B",
                    )
                )
        posture_unknown = facts["posture_unknown"]
        for control, status in sorted(posture_unknown.items()):
            severity = (
                "medium"
                if control in {"disk_encrypted", "security_updates_current"}
                else "info"
            )
            findings.append(
                self._finding(
                    current,
                    f"SWARM_POSTURE_VISIBILITY_LIMITED_{control.upper()}",
                    severity,
                    f"Android cannot verify the {control} posture control",
                    "The signed collector reported a platform visibility limitation. An unknown control is not treated as a failed control or evidence of compromise.",
                    {"control": control, "status": status},
                    evidence_grade="B",
                )
            )
        weak_posture = sorted(
            key
            for key, active in facts["posture"].items()
            if not active and key not in posture_unknown
        )
        for control in weak_posture:
            verified_posture = facts["verified_android_schema"]
            findings.append(
                self._finding(
                    current,
                    f"SWARM_DEVICE_POSTURE_WEAK_{control.upper()}",
                    "high",
                    "Device security posture needs attention",
                    "The collector reported that a baseline protection is absent.",
                    {"control": control},
                    truth="VERIFIED" if verified_posture else "INFERENCE",
                    confidence=100 if verified_posture else 35,
                    evidence_grade="B" if verified_posture else "D",
                )
            )
        if facts["verified_android_schema"]:
            security = facts["android_security"]
            signing_key_security = security["signing_key_security"]
            if signing_key_security == "software":
                findings.append(
                    self._finding(
                        current,
                        "SWARM_SIGNING_KEY_SOFTWARE_BACKED",
                        "medium",
                        "Snapshot signing key is software-backed",
                        "The signed collector reported software-backed key storage. This offers less resistance to key extraction than hardware-backed storage, but it is not evidence that the key is compromised.",
                        {"signing_key_security": signing_key_security},
                        evidence_grade="B",
                    )
                )
            elif signing_key_security == "unknown":
                findings.append(
                    self._finding(
                        current,
                        "SWARM_SIGNING_KEY_SECURITY_UNKNOWN",
                        "info",
                        "Snapshot signing-key protection is unknown",
                        "The collector could not establish whether the signing key is hardware-backed. Signature verification still succeeded; this is a key-protection visibility limitation, not evidence of compromise.",
                        {"signing_key_security": signing_key_security},
                        evidence_grade="B",
                    )
                )

            control_findings = {
                "adb_enabled": (
                    "SWARM_ADB_ENABLED",
                    "medium",
                    "Android debugging is enabled",
                    "Android Debug Bridge is enabled. This increases the device's local debugging surface; it does not establish unauthorized access.",
                ),
                "developer_options": (
                    "SWARM_DEVELOPER_OPTIONS_ENABLED",
                    "low",
                    "Android developer options are enabled",
                    "Developer options are enabled. This changes the device's hardening posture but is not evidence of compromise.",
                ),
            }
            for field, (code, severity, title, detail) in control_findings.items():
                if security[field] == "enabled":
                    findings.append(
                        self._finding(
                            current,
                            code,
                            severity,
                            title,
                            detail,
                            {"control": field, "status": "enabled"},
                            evidence_grade="B",
                        )
                    )

            connectivity = security["connectivity"]
            if (
                connectivity["status"] == "observed"
                and connectivity["captive_portal"] is True
            ):
                findings.append(
                    self._finding(
                        current,
                        "SWARM_NETWORK_CAPTIVE_PORTAL",
                        "medium",
                        "Active Android network reports a captive portal",
                        "Android marked the active transport as captive. Treat network access as constrained or interceptable until the portal is cleared; this is not proof of malicious interception.",
                        {
                            "transports": connectivity["transports"],
                            "validated": connectivity["validated"],
                            "captive_portal": True,
                            "metered": connectivity["metered"],
                        },
                        evidence_grade="B",
                    )
                )
            elif (
                connectivity["status"] == "observed"
                and connectivity["transports"]
                and connectivity["validated"] is False
            ):
                findings.append(
                    self._finding(
                        current,
                        "SWARM_NETWORK_UNVALIDATED",
                        "low",
                        "Active Android network is not validated",
                        "Android did not validate the active transport for internet access. This can be transient or expected and is not evidence of compromise.",
                        {
                            "transports": connectivity["transports"],
                            "validated": False,
                            "captive_portal": False,
                            "metered": connectivity["metered"],
                        },
                        evidence_grade="B",
                    )
                )

            permission_posture = security["permission_posture"]
            nonzero_permission_counts = {
                permission: count
                for permission, count in permission_posture[
                    "granted_sensitive_permission_counts"
                ].items()
                if count > 0
            }
            if nonzero_permission_counts:
                findings.append(
                    self._finding(
                        current,
                        "SWARM_SENSITIVE_PERMISSION_FOOTPRINT",
                        "info",
                        "Sensitive Android permission footprint recorded",
                        "The signed collector counted sensitive permissions granted across packages visible to it. This inventory evidence is informational: a grant does not prove use, abuse, or compromise.",
                        {
                            "baseline_initialized": permission_posture[
                                "baseline_initialized"
                            ],
                            "inventory_scope": permission_posture[
                                "inventory_scope"
                            ],
                            "packages_observed": permission_posture[
                                "packages_observed"
                            ],
                            "nonzero_granted_permission_counts": (
                                nonzero_permission_counts
                            ),
                        },
                        evidence_grade="B",
                    )
                )
        mesh = facts["mesh"]
        if mesh["enabled"] and not mesh["signed_updates_only"]:
            findings.append(
                self._finding(
                    current,
                    "SWARM_MESH_UNSIGNED_UPDATES_ALLOWED",
                    "critical",
                    "Private mesh accepts unsigned updates",
                    "Mesh learning must authenticate every update before it can influence local defense state.",
                    {"signed_updates_only": False},
                    truth="INFERENCE",
                    confidence=35,
                    evidence_grade="D",
                )
            )
        if mesh["enabled"] and mesh["raw_data_sharing"]:
            findings.append(
                self._finding(
                    current,
                    "SWARM_MESH_RAW_DATA_SHARING_ENABLED",
                    "critical",
                    "Private mesh shares raw device data",
                    "The mesh trust boundary must exchange bounded derived signals rather than raw device data.",
                    {"raw_data_sharing": True},
                    truth="INFERENCE",
                    confidence=35,
                    evidence_grade="D",
                )
            )

        signed_object_evidence = facts["verified_android_schema"]
        anomaly_grade = "B" if signed_object_evidence else "D"
        anomaly_confidence = 75 if signed_object_evidence else 35
        prior_android_event_batch_id = (
            previous.facts.get("android_event_batch_id", "")
            if previous is not None
            else ""
        )
        emit_android_events = (
            not signed_object_evidence
            or not facts["android_event_batch_id"]
            or facts["android_event_batch_id"] != prior_android_event_batch_id
        )
        for index, event in enumerate(facts["events"]):
            if signed_object_evidence and not emit_android_events:
                continue
            event_type = event["type"]
            event_batch_identity = (
                facts["android_event_batch_id"]
                if signed_object_evidence
                else facts["snapshot_sha256"]
            )
            # The batch digest binds the complete signed snapshot; the ordinal
            # then gives each event a stable identity within that exact batch.
            # Distinct signed sequences cannot reuse a downstream finding id.
            event_key = stable_hash(
                f"{event_batch_identity}\0{index}\0{event_type}"
            )[:12]
            if event_type in {"camera_access", "microphone_access"} and (event["baseline"] == "unexpected" or not event["process_signed"]):
                findings.append(self._finding(current, f"SWARM_UNEXPECTED_SENSOR_ACCESS_{event_key}", "critical", "Potentially unexpected camera or microphone activity", "A local snapshot reported sensor activity outside the learned baseline or associated it with an unsigned process. This is an inference; no blocking action was taken.", {"event_type": event_type, "process": event["process"], "process_signed": event["process_signed"], "baseline": event["baseline"]}, stateful=False, truth="INFERENCE", confidence=anomaly_confidence, evidence_grade=anomaly_grade))
            if event_type in {
                "camera_capable_foreground",
                "microphone_capable_foreground",
            }:
                capability = (
                    "camera"
                    if event_type == "camera_capable_foreground"
                    else "microphone"
                )
                elevated = event["baseline"] == "unexpected"
                findings.append(
                    self._finding(
                        current,
                        f"SWARM_{capability.upper()}_CAPABLE_FOREGROUND_{event_key}",
                        "medium" if elevated else "low",
                        f"{capability.title()}-capable app entered the foreground",
                        f"Android reported that a pseudonymized app with {capability} permission entered the foreground. This correlation does not show that the {capability} was opened or used.",
                        {
                            "event_type": event_type,
                            "package_pseudonym": event["process"],
                            "package_has_signing_certificate": event[
                                "package_has_signing_certificate"
                            ],
                            "baseline": event["baseline"],
                            "evidence_kind": event["evidence_kind"],
                            "observed_at": event["observed_at"],
                            "claim": "foreground_plus_permission_not_sensor_use",
                        },
                        stateful=False,
                        truth="INFERENCE",
                        confidence=60 if signed_object_evidence else 30,
                        evidence_grade=anomaly_grade,
                    )
                )
            if event_type in {"package_added", "package_updated", "package_removed"}:
                action = event_type.removeprefix("package_")
                findings.append(
                    self._finding(
                        current,
                        f"SWARM_PACKAGE_{action.upper()}_{event_key}",
                        "low",
                        "Visible Android package inventory changed",
                        f"The collector reported that a pseudonymized package became {action} relative to its prior visible-package baseline. Android package visibility may be filtered; this is not evidence of compromise.",
                        {
                            "change": action,
                            "package_pseudonym": event["process"],
                            "package_has_signing_certificate": event[
                                "package_has_signing_certificate"
                            ],
                            "evidence_kind": event["evidence_kind"],
                            "observed_at": event["observed_at"],
                        },
                        stateful=False,
                        truth="VERIFIED" if signed_object_evidence else "INFERENCE",
                        confidence=100 if signed_object_evidence else 35,
                        evidence_grade=anomaly_grade,
                    )
                )
            if event_type == "permission_change":
                granted = event["granted"]
                findings.append(
                    self._finding(
                        current,
                        f"SWARM_PERMISSION_CHANGE_{event_key}",
                        "medium" if granted is True else "low",
                        "Sensitive Android permission state changed",
                        "The collector reported a permission-state delta for a pseudonymized visible package. A grant does not prove the permission was exercised.",
                        {
                            "package_pseudonym": event["process"],
                            "permission": event["permission"],
                            "granted": granted,
                            "evidence_kind": event["evidence_kind"],
                            "observed_at": event["observed_at"],
                        },
                        stateful=False,
                        truth="VERIFIED" if signed_object_evidence else "INFERENCE",
                        confidence=100 if signed_object_evidence else 35,
                        evidence_grade=anomaly_grade,
                    )
                )
            if event_type == "identity_event" and event["baseline"] == "unexpected":
                findings.append(self._finding(current, f"SWARM_IDENTITY_ANOMALY_{event_key}", "high", "Potential identity anomaly", "The device reported an identity event outside its local baseline. This is an inference; step-up verification is recommended.", {"process": event["process"], "baseline": event["baseline"]}, stateful=False, truth="INFERENCE", confidence=anomaly_confidence, evidence_grade=anomaly_grade))
            if event_type == "network_egress" and event["sensitive"] and event["baseline"] == "unexpected":
                findings.append(self._finding(current, f"SWARM_SENSITIVE_EGRESS_{event_key}", "critical", "Potential sensitive-data egress", "The snapshot reported an unusual outbound transfer involving data marked sensitive. This is an inference; destination evidence is hashed and containment requires approval.", {"bytes_out": event["bytes_out"], "destination_sha256": event["destination_sha256"]}, stateful=False, truth="INFERENCE", confidence=anomaly_confidence, evidence_grade=anomaly_grade))
        return findings

    @staticmethod
    def _finding(
        current: Observation,
        code: str,
        severity: str,
        title: str,
        detail: str,
        evidence: dict[str, Any],
        *,
        stateful: bool = True,
        truth: str = "VERIFIED",
        confidence: int = 100,
        evidence_grade: str = "A",
    ) -> Finding:
        return Finding(
            target_id=current.target_id,
            code=code,
            severity=severity,
            title=title,
            detail=detail,
            truth=truth,
            confidence=confidence,
            evidence_grade=evidence_grade,
            evidence={
                **evidence,
                "mode": current.facts["mode"],
                "actions_executed": False,
            },
            stateful=stateful,
        )
