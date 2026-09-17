from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Final


MAX_EVENT_COUNT: Final[int] = 500
MAX_SEQUENCE: Final[int] = (1 << 63) - 1
MAX_PACKAGE_COUNT: Final[int] = 1_000_000
MAX_ANDROID_API: Final[int] = 1_000
MAX_ANDROID_EVENT_LOOKBACK: Final[timedelta] = timedelta(hours=24)
MAX_ANDROID_EVENT_FUTURE_SKEW: Final[timedelta] = timedelta(seconds=120)

ANDROID_DEVICE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^android-[0-9a-f]{24}$"
)
PACKAGE_PSEUDONYM_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^pkg-hmac256:[0-9a-f]{64}$"
)
APP_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$"
)
SECURITY_PATCH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:unknown|[0-9]{4}-[0-9]{2}-[0-9]{2})$"
)

SENSOR_KEYS: Final[tuple[str, ...]] = (
    "camera",
    "microphone",
    "identity",
    "process",
    "network",
)
SENSOR_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "observed",
        "partial",
        "not_granted",
        "unsupported",
        "enterprise_only",
        "disabled",
        "error",
    }
)
SENSOR_SOURCE_SCOPES: Final[dict[str, dict[tuple[str, str], set[str]]]] = {
    "camera": {
        ("android_public_api", "direct_cross_app_access"): {
            "unsupported",
            "enterprise_only",
            "error",
        },
        ("android_camera_availability", "device_camera_activity_unattributed"): {
            "observed",
            "disabled",
            "error",
        },
        ("android_appops_self", "self_uid_attributed"): {
            "observed",
            "not_granted",
            "disabled",
            "error",
        },
    },
    "microphone": {
        ("android_public_api", "direct_cross_app_access"): {
            "unsupported",
            "enterprise_only",
            "error",
        },
        ("android_audio_recording", "device_recording_activity_unattributed"): {
            "observed",
            "disabled",
            "error",
        },
        ("android_appops_self", "self_uid_attributed"): {
            "observed",
            "not_granted",
            "disabled",
            "error",
        },
    },
    "identity": {
        ("android_public_api", "device_authentication_events"): {
            "unsupported",
            "enterprise_only",
            "error",
        },
        ("watchdawg_app_auth", "app_account"): {
            "observed",
            "disabled",
            "error",
        },
    },
    "process": {
        ("android_public_api", "live_process_inventory"): {
            "unsupported",
            "enterprise_only",
            "error",
        },
        ("android_usage_stats", "foreground_transitions"): {
            "observed",
            "partial",
            "not_granted",
            "disabled",
            "error",
        },
        ("android_process_self", "self_uid"): {
            "observed",
            "disabled",
            "error",
        },
    },
    "network": {
        ("android_connectivity", "active_transport_only"): {
            "observed",
            "disabled",
            "error",
        },
        ("android_network_stats", "uid_aggregate_history"): {
            "observed",
            "not_granted",
            "disabled",
            "error",
        },
        ("android_vpn_service", "routed_ip_flows_uid"): {
            "observed",
            "not_granted",
            "disabled",
            "error",
        },
    },
}

ANDROID_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "camera_capable_foreground",
        "microphone_capable_foreground",
        "package_added",
        "package_updated",
        "package_removed",
        "permission_change",
    }
)
ANDROID_PERMISSION_NAMES: Final[frozenset[str]] = frozenset(
    {
        "ACCESS_COARSE_LOCATION",
        "ACCESS_FINE_LOCATION",
        "CALL_PHONE",
        "CAMERA",
        "POST_NOTIFICATIONS",
        "READ_CALENDAR",
        "READ_CONTACTS",
        "READ_PHONE_STATE",
        "READ_SMS",
        "RECEIVE_SMS",
        "RECORD_AUDIO",
        "SEND_SMS",
        "WRITE_CALENDAR",
        "WRITE_CONTACTS",
    }
)

ANDROID_TOP_LEVEL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "actions_executed",
        "collected_at",
        "collection",
        "collector",
        "connectivity",
        "device_id",
        "events",
        "limitations",
        "mesh",
        "permission_posture",
        "posture",
        "posture_evidence",
        "schema_version",
        "sensors",
        "sequence",
    }
)
COLLECTOR_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "android_api",
        "app_version",
        "collection_mode",
        "platform",
        "security_patch",
        "signing_key_security",
        "usage_access",
        "usage_query_status",
    }
)
POSTURE_FIELDS: Final[frozenset[str]] = frozenset(
    {"disk_encrypted", "screen_lock", "security_updates_current"}
)
POSTURE_EVIDENCE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adb_enabled",
        "developer_options",
        "disk_encryption_status",
        "secure_boot",
        "security_patch",
        "security_patch_age_days",
        "security_patch_policy_max_age_days",
    }
)
PERMISSION_POSTURE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "baseline_initialized",
        "granted_sensitive_permission_counts",
        "inventory_scope",
        "package_identifiers",
        "packages_observed",
    }
)
COLLECTION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "complete",
        "event_limit",
        "events_emitted",
        "package_deltas_truncated",
        "permission_deltas_truncated",
        "usage_events_truncated",
        "usage_history_gap",
        "usage_query_available",
    }
)
MESH_FIELDS: Final[frozenset[str]] = frozenset(
    {"enabled", "peer_count", "raw_data_sharing", "signed_updates_only"}
)
EVENT_COMMON_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "baseline",
        "bytes_out",
        "destination",
        "evidence_kind",
        "observed_at",
        "package_has_signing_certificate",
        "process",
        "sensitive",
        "type",
    }
)
CAPABILITY_EVENT_FIELDS: Final[frozenset[str]] = EVENT_COMMON_FIELDS | {"claim"}
PERMISSION_EVENT_FIELDS: Final[frozenset[str]] = EVENT_COMMON_FIELDS | {
    "granted",
    "permission",
}

BASE_LIMITATIONS: Final[tuple[str, ...]] = (
    "No root, accessibility, VPN, camera, or microphone permission is used.",
    "Android public APIs do not expose other apps' live camera or microphone use to this app.",
    "Sensor-capability events mean a foreground app held a related permission; they do not prove sensor use.",
    "Connectivity evidence reports active transport metadata only, not destinations or content.",
    "Package identifiers are HMAC-pseudonymized on this device before export.",
    "A package signing certificate is mandatory Android packaging metadata and does not establish publisher trust.",
)
TRUNCATION_LIMITATION: Final[str] = (
    "One or more event streams reached the per-snapshot limit; the signed "
    "collection metadata marks the partial coverage and checkpoints conservatively "
    "for retry."
)
USAGE_HISTORY_GAP_LIMITATION: Final[str] = (
    "UsageStats retention or clock movement left an unobserved history "
    "interval; this snapshot's process coverage is partial."
)


def is_strict_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_aware_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _fail(section: str) -> None:
    # Never interpolate rejected values. In particular, a malformed `process`
    # may contain the raw package identifier this boundary protects.
    raise ValueError(f"Verified Android {section} does not match schema version 1")


def _exact_object(value: Any, fields: frozenset[str], section: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(section)
    return value


def _validate_patch(value: Any, section: str) -> None:
    if not isinstance(value, str) or SECURITY_PATCH_PATTERN.fullmatch(value) is None:
        _fail(section)
    if value != "unknown":
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            _fail(section)


def _validate_collector(snapshot: dict[str, Any]) -> None:
    collector = _exact_object(snapshot.get("collector"), COLLECTOR_FIELDS, "collector")
    if (
        collector.get("platform") != "android"
        or collector.get("collection_mode") != "non_root_public_api"
        or not is_strict_integer(collector.get("android_api"))
        or not 26 <= collector["android_api"] <= MAX_ANDROID_API
        or collector.get("signing_key_security")
        not in {
            "strongbox",
            "trusted_environment",
            "secure_hardware",
            "software",
            "unknown",
        }
        or collector.get("usage_access") not in {"granted", "not_granted"}
        or collector.get("usage_query_status")
        not in {"observed", "partial", "not_granted", "error"}
        or not isinstance(collector.get("app_version"), str)
        or APP_VERSION_PATTERN.fullmatch(collector["app_version"]) is None
    ):
        _fail("collector")
    _validate_patch(collector.get("security_patch"), "collector")


def _validate_sensors(snapshot: dict[str, Any]) -> None:
    sensors = snapshot.get("sensors")
    if not isinstance(sensors, dict) or set(sensors) != set(SENSOR_KEYS):
        _fail("sensor schema")
    connectivity = snapshot.get("connectivity")
    expected_network_status = (
        "error"
        if isinstance(connectivity, dict) and "error" in connectivity
        else "observed"
    )
    expected = {
        "camera": ("unsupported", "android_public_api", "direct_cross_app_access"),
        "microphone": ("unsupported", "android_public_api", "direct_cross_app_access"),
        "identity": ("unsupported", "android_public_api", "device_authentication_events"),
        "network": (
            expected_network_status,
            "android_connectivity",
            "active_transport_only",
        ),
    }
    for key, values in expected.items():
        sensor = _exact_object(
            sensors.get(key), frozenset({"scope", "source", "status"}), "sensor schema"
        )
        if (sensor.get("status"), sensor.get("source"), sensor.get("scope")) != values:
            _fail("sensor schema")
    process = _exact_object(
        sensors.get("process"),
        frozenset({"scope", "source", "status"}),
        "sensor schema",
    )
    if (
        process.get("status") not in {"observed", "partial", "not_granted", "error"}
        or process.get("source") != "android_usage_stats"
        or process.get("scope") != "foreground_transitions"
    ):
        _fail("sensor schema")


def _validate_posture(snapshot: dict[str, Any]) -> None:
    posture = _exact_object(snapshot.get("posture"), POSTURE_FIELDS, "posture")
    if any(not isinstance(posture[key], bool) for key in POSTURE_FIELDS):
        _fail("posture")

    evidence = _exact_object(
        snapshot.get("posture_evidence"), POSTURE_EVIDENCE_FIELDS, "posture evidence"
    )
    secure_boot = _exact_object(
        evidence.get("secure_boot"),
        frozenset({"scope", "source", "status"}),
        "posture evidence",
    )
    if secure_boot != {
        "status": "unsupported",
        "source": "android_public_api",
        "scope": "verified_boot_state",
    }:
        _fail("posture evidence")
    if evidence.get("disk_encryption_status") not in {
        "active",
        "active_default_key",
        "active_per_user",
        "inactive",
        "activating",
        "unsupported_or_unavailable",
    }:
        _fail("posture evidence")
    if evidence.get("developer_options") not in {"enabled", "disabled", "unavailable"}:
        _fail("posture evidence")
    if evidence.get("adb_enabled") not in {"enabled", "disabled", "unavailable"}:
        _fail("posture evidence")
    age = evidence.get("security_patch_age_days")
    if not is_strict_integer(age) or not -1 <= age <= 365_000:
        _fail("posture evidence")
    policy_age = evidence.get("security_patch_policy_max_age_days")
    if not is_strict_integer(policy_age) or policy_age != 120:
        _fail("posture evidence")
    _validate_patch(evidence.get("security_patch"), "posture evidence")
    if evidence["security_patch"] != snapshot["collector"]["security_patch"]:
        _fail("posture evidence")
    if evidence["security_patch"] == "unknown":
        if age != -1:
            _fail("posture evidence")
    else:
        collected_at = parse_aware_timestamp(snapshot.get("collected_at"))
        if collected_at is not None:
            patch_date = datetime.strptime(
                evidence["security_patch"], "%Y-%m-%d"
            ).date()
            expected_age = (collected_at.date() - patch_date).days
            if expected_age < 0:
                _fail("posture evidence")
            if age != expected_age:
                _fail("posture evidence")

    encrypted_statuses = {"active", "active_default_key", "active_per_user"}
    if posture["disk_encrypted"] is not (
        evidence["disk_encryption_status"] in encrypted_statuses
    ):
        _fail("posture")
    patch_is_current = age != -1 and age <= 120
    if posture["security_updates_current"] is not patch_is_current:
        _fail("posture")


def _validate_permission_posture(snapshot: dict[str, Any]) -> None:
    posture = _exact_object(
        snapshot.get("permission_posture"),
        PERMISSION_POSTURE_FIELDS,
        "permission posture",
    )
    packages = posture.get("packages_observed")
    if (
        posture.get("inventory_scope")
        != "installed_packages_visible_to_security_app"
        or posture.get("package_identifiers") != "device_keyed_hmac_sha256"
        or not is_strict_integer(packages)
        or not 0 <= packages <= MAX_PACKAGE_COUNT
        or not isinstance(posture.get("baseline_initialized"), bool)
    ):
        _fail("permission posture")
    counts = posture.get("granted_sensitive_permission_counts")
    if not isinstance(counts, dict) or set(counts) != set(ANDROID_PERMISSION_NAMES):
        _fail("permission posture")
    if any(
        not is_strict_integer(count) or not 0 <= count <= packages
        for count in counts.values()
    ):
        _fail("permission posture")


def _validate_connectivity(snapshot: dict[str, Any]) -> None:
    connectivity = snapshot.get("connectivity")
    normal_fields = {
        "captive_portal",
        "content_observed",
        "destinations_observed",
        "metered",
        "scope",
        "transports",
        "validated",
    }
    error_fields = {
        "content_observed",
        "destinations_observed",
        "error",
        "scope",
        "transports",
    }
    if not isinstance(connectivity, dict) or frozenset(connectivity) not in {
        frozenset(normal_fields),
        frozenset(error_fields),
    }:
        _fail("connectivity")
    if (
        connectivity.get("scope") != "active_transport_only"
        or connectivity.get("destinations_observed") is not False
        or connectivity.get("content_observed") is not False
    ):
        _fail("connectivity")
    transports = connectivity.get("transports")
    allowed_transports = ["wifi", "cellular", "ethernet", "vpn", "bluetooth"]
    if (
        not isinstance(transports, list)
        or any(item not in allowed_transports for item in transports)
        or len(set(transports)) != len(transports)
        or transports != [item for item in allowed_transports if item in transports]
    ):
        _fail("connectivity")
    if "error" in connectivity:
        if connectivity.get("error") not in {
            "permission_unavailable",
            "service_unavailable",
        }:
            _fail("connectivity")
    elif any(
        not isinstance(connectivity[field], bool)
        for field in ("validated", "captive_portal", "metered")
    ):
        _fail("connectivity")


def _validate_android_event(
    event: Any,
    *,
    collected_at: datetime | None,
) -> None:
    if not isinstance(event, dict):
        _fail("event")
    event_type = event.get("type")
    if not isinstance(event_type, str) or event_type not in ANDROID_EVENT_TYPES:
        _fail("event")

    if event_type in {"camera_capable_foreground", "microphone_capable_foreground"}:
        expected_fields = CAPABILITY_EVENT_FIELDS
        expected_kind = "capability_inference"
        allowed_baselines = {"initializing", "known", "unexpected"}
        expected_sensitive = True
    elif event_type in {"package_added", "package_updated", "package_removed"}:
        expected_fields = EVENT_COMMON_FIELDS
        expected_kind = "package_inventory_delta"
        allowed_baselines = {"unexpected"}
        expected_sensitive = False
    else:
        expected_fields = PERMISSION_EVENT_FIELDS
        expected_kind = "permission_inventory_delta"
        allowed_baselines = {"unexpected"}
        expected_sensitive = True

    if set(event) != expected_fields:
        _fail("event")
    process = event.get("process")
    if not isinstance(process, str) or PACKAGE_PSEUDONYM_PATTERN.fullmatch(process) is None:
        _fail("event")
    if not isinstance(event.get("package_has_signing_certificate"), bool):
        _fail("event")
    if event.get("baseline") not in allowed_baselines:
        _fail("event")
    if event.get("sensitive") is not expected_sensitive:
        _fail("event")
    if not is_strict_integer(event.get("bytes_out")) or event.get("bytes_out") != 0:
        _fail("event")
    if event.get("destination") != "" or event.get("evidence_kind") != expected_kind:
        _fail("event")
    observed_at = parse_aware_timestamp(event.get("observed_at"))
    if observed_at is None:
        _fail("event")
    if collected_at is not None and not (
        collected_at - MAX_ANDROID_EVENT_LOOKBACK
        <= observed_at
        <= collected_at + MAX_ANDROID_EVENT_FUTURE_SKEW
    ):
        _fail("event")

    if event_type in {"camera_capable_foreground", "microphone_capable_foreground"}:
        if event.get("claim") != "foreground_transition_plus_granted_permission_not_sensor_use":
            _fail("event")
    elif event_type == "permission_change":
        if event.get("permission") not in ANDROID_PERMISSION_NAMES:
            _fail("event")
        if not isinstance(event.get("granted"), bool):
            _fail("event")


def _validate_collection(snapshot: dict[str, Any], events: list[Any]) -> None:
    collection = _exact_object(
        snapshot.get("collection"), COLLECTION_FIELDS, "collection metadata"
    )
    bool_fields = {
        "complete",
        "package_deltas_truncated",
        "permission_deltas_truncated",
        "usage_events_truncated",
        "usage_history_gap",
        "usage_query_available",
    }
    if any(not isinstance(collection[field], bool) for field in bool_fields):
        _fail("collection metadata")
    event_limit = collection.get("event_limit")
    if not is_strict_integer(event_limit) or event_limit != MAX_EVENT_COUNT:
        _fail("collection metadata")
    emitted = collection.get("events_emitted")
    if not is_strict_integer(emitted) or emitted != len(events):
        _fail("collection metadata")
    truncated = any(
        collection[field]
        for field in (
            "package_deltas_truncated",
            "permission_deltas_truncated",
            "usage_events_truncated",
        )
    )
    if truncated and (collection["complete"] is not False or emitted != MAX_EVENT_COUNT):
        _fail("collection metadata")

    collector = snapshot["collector"]
    process_status = snapshot["sensors"]["process"]["status"]
    if collector["usage_access"] == "not_granted":
        expected_usage_status = "not_granted"
        if collection["usage_events_truncated"] is not False:
            _fail("collection metadata")
    elif collection["usage_query_available"] is not True:
        expected_usage_status = "error"
    elif (
        collection["usage_events_truncated"] is True
        or collection["usage_history_gap"] is True
    ):
        expected_usage_status = "partial"
    else:
        expected_usage_status = "observed"
    expected_query_available = expected_usage_status in {"observed", "partial"}
    if (
        collection["usage_query_available"] is not expected_query_available
        or collector["usage_query_status"] != expected_usage_status
    ):
        _fail("collection metadata")
    if process_status != collector["usage_query_status"]:
        _fail("collection metadata")
    expected_complete = (
        not truncated
        and collection["usage_history_gap"] is False
        and (
            collector["usage_access"] == "not_granted"
            or collection["usage_query_available"] is True
        )
    )
    if collection["complete"] is not expected_complete:
        _fail("collection metadata")

    if snapshot["permission_posture"]["baseline_initialized"] is not True and any(
        event["type"]
        in {"package_added", "package_updated", "package_removed", "permission_change"}
        for event in events
    ):
        _fail("collection metadata")


def _validate_mesh(snapshot: dict[str, Any]) -> None:
    mesh = _exact_object(snapshot.get("mesh"), MESH_FIELDS, "mesh")
    if (
        mesh.get("enabled") is not False
        or not is_strict_integer(mesh.get("peer_count"))
        or mesh.get("peer_count") != 0
        or mesh.get("raw_data_sharing") is not False
        or mesh.get("signed_updates_only") is not True
    ):
        _fail("mesh")


def _validate_limitations(snapshot: dict[str, Any]) -> None:
    limitations = snapshot.get("limitations")
    expected = list(BASE_LIMITATIONS)
    collection = snapshot["collection"]
    if any(
        collection[field]
        for field in (
            "package_deltas_truncated",
            "permission_deltas_truncated",
            "usage_events_truncated",
        )
    ):
        expected.append(TRUNCATION_LIMITATION)
    if collection["usage_history_gap"] is True:
        expected.append(USAGE_HISTORY_GAP_LIMITATION)
    if limitations != expected:
        _fail("limitations")


def validate_verified_android_snapshot(
    snapshot: dict[str, Any],
    *,
    require_collected_at: bool = False,
) -> None:
    """Validate the complete signed Android v1 privacy and type boundary.

    The watch path deliberately allows a missing or malformed ``collected_at``
    value so its freshness evaluator can emit a high-severity, verified stale
    finding. The HTTP ingestion path sets ``require_collected_at=True``.
    """

    if not isinstance(snapshot, dict):
        _fail("snapshot")
    allowed_fields = ANDROID_TOP_LEVEL_FIELDS
    required_fields = allowed_fields if require_collected_at else allowed_fields - {"collected_at"}
    if not required_fields.issubset(snapshot) or not set(snapshot).issubset(allowed_fields):
        _fail("snapshot")
    if require_collected_at and parse_aware_timestamp(snapshot.get("collected_at")) is None:
        _fail("collection timestamp")

    if (
        snapshot.get("schema_version") != 1
        or not is_strict_integer(snapshot.get("schema_version"))
        or not is_strict_integer(snapshot.get("sequence"))
        or not 1 <= snapshot["sequence"] <= MAX_SEQUENCE
        or not isinstance(snapshot.get("device_id"), str)
        or ANDROID_DEVICE_ID_PATTERN.fullmatch(snapshot["device_id"]) is None
        or snapshot.get("actions_executed") is not False
    ):
        _fail("snapshot metadata")

    _validate_collector(snapshot)
    _validate_sensors(snapshot)
    _validate_posture(snapshot)
    _validate_permission_posture(snapshot)
    _validate_connectivity(snapshot)

    events = snapshot.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENT_COUNT:
        _fail("event collection")
    collected_at = parse_aware_timestamp(snapshot.get("collected_at"))
    for event in events:
        _validate_android_event(event, collected_at=collected_at)

    _validate_collection(snapshot, events)
    _validate_mesh(snapshot)
    _validate_limitations(snapshot)


def android_posture_unknown_controls(snapshot: dict[str, Any]) -> dict[str, str]:
    """Return posture controls Android could not establish, after validation."""

    evidence = snapshot["posture_evidence"]
    unknown = {"secure_boot": "unsupported"}
    if evidence["disk_encryption_status"] == "unsupported_or_unavailable":
        unknown["disk_encrypted"] = "unsupported_or_unavailable"
    if (
        evidence["security_patch"] == "unknown"
        or evidence["security_patch_age_days"] == -1
    ):
        unknown["security_updates_current"] = "unknown"
    if evidence["adb_enabled"] == "unavailable":
        unknown["adb_enabled"] = "unavailable"
    if evidence["developer_options"] == "unavailable":
        unknown["developer_options"] = "unavailable"
    return unknown
