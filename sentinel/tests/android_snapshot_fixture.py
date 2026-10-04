from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinel.swarm_schema import (
    ANDROID_PERMISSION_NAMES,
    BASE_LIMITATIONS,
    MAX_EVENT_COUNT,
    TRUNCATION_LIMITATION,
    USAGE_HISTORY_GAP_LIMITATION,
)


ANDROID_DEVICE_ID = "android-" + "a" * 24
PACKAGE_A = "pkg-hmac256:" + "1" * 64
PACKAGE_B = "pkg-hmac256:" + "2" * 64


def make_android_snapshot(
    *,
    collected_at: datetime,
    sequence: int = 7,
    device_id: str = ANDROID_DEVICE_ID,
) -> dict[str, Any]:
    return {
        "actions_executed": False,
        "collected_at": collected_at.isoformat(),
        "collection": {
            "complete": True,
            "event_limit": MAX_EVENT_COUNT,
            "events_emitted": 0,
            "package_deltas_truncated": False,
            "permission_deltas_truncated": False,
            "usage_events_truncated": False,
            "usage_history_gap": False,
            "usage_query_available": True,
        },
        "collector": {
            "android_api": 36,
            "app_version": "1.0.0",
            "collection_mode": "non_root_public_api",
            "platform": "android",
            "security_patch": "2026-09-01",
            "signing_key_security": "trusted_environment",
            "usage_access": "granted",
            "usage_query_status": "observed",
        },
        "connectivity": {
            "captive_portal": False,
            "content_observed": False,
            "destinations_observed": False,
            "metered": False,
            "scope": "active_transport_only",
            "transports": ["wifi"],
            "validated": True,
        },
        "device_id": device_id,
        "events": [],
        "limitations": list(BASE_LIMITATIONS),
        "mesh": {
            "enabled": False,
            "peer_count": 0,
            "raw_data_sharing": False,
            "signed_updates_only": True,
        },
        "permission_posture": {
            "baseline_initialized": True,
            "granted_sensitive_permission_counts": {
                permission: 0 for permission in ANDROID_PERMISSION_NAMES
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
            "disk_encryption_status": "active_per_user",
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
                "status": "observed",
            },
        },
        "sequence": sequence,
    }


def synchronize_collection(snapshot: dict[str, Any]) -> None:
    collection = snapshot["collection"]
    collection["events_emitted"] = len(snapshot["events"])
    truncated = any(
        collection[field]
        for field in (
            "package_deltas_truncated",
            "permission_deltas_truncated",
            "usage_events_truncated",
        )
    )
    collection["complete"] = (
        not truncated
        and collection["usage_history_gap"] is False
        and (
            snapshot["collector"]["usage_access"] == "not_granted"
            or collection["usage_query_available"] is True
        )
    )
    snapshot["limitations"] = list(BASE_LIMITATIONS)
    if truncated:
        snapshot["limitations"].append(TRUNCATION_LIMITATION)
    if collection["usage_history_gap"] is True:
        snapshot["limitations"].append(USAGE_HISTORY_GAP_LIMITATION)


def capability_event(
    event_type: str = "camera_capable_foreground",
    *,
    process: str = PACKAGE_A,
    certificate_present: bool = True,
    baseline: str = "unexpected",
    observed_at: str = "2026-09-17T12:00:00Z",
) -> dict[str, Any]:
    return {
        "baseline": baseline,
        "bytes_out": 0,
        "claim": "foreground_transition_plus_granted_permission_not_sensor_use",
        "destination": "",
        "evidence_kind": "capability_inference",
        "observed_at": observed_at,
        "package_has_signing_certificate": certificate_present,
        "process": process,
        "sensitive": True,
        "type": event_type,
    }


def package_event(
    event_type: str = "package_added",
    *,
    process: str = PACKAGE_A,
    certificate_present: bool = True,
    observed_at: str = "2026-09-17T12:02:00Z",
) -> dict[str, Any]:
    return {
        "baseline": "unexpected",
        "bytes_out": 0,
        "destination": "",
        "evidence_kind": "package_inventory_delta",
        "observed_at": observed_at,
        "package_has_signing_certificate": certificate_present,
        "process": process,
        "sensitive": False,
        "type": event_type,
    }


def permission_event(
    *,
    process: str = PACKAGE_B,
    permission: str = "CAMERA",
    granted: bool = True,
    certificate_present: bool = True,
    observed_at: str = "2026-09-17T12:01:00Z",
) -> dict[str, Any]:
    event = package_event(
        "permission_change",
        process=process,
        certificate_present=certificate_present,
        observed_at=observed_at,
    )
    event.update(
        {
            "evidence_kind": "permission_inventory_delta",
            "granted": granted,
            "permission": permission,
            "sensitive": True,
        }
    )
    return event
