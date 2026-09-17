from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import Finding, Observation, stable_hash

MAX_SNAPSHOT_BYTES = 512_000
ALLOWED_MODES = {"shadow", "advisory"}


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

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

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
        if "read-device-snapshot" not in authorization.get("approved_methods", []):
            raise ValueError("Swarm authorization must approve read-device-snapshot")
        scope = authorization.get("scope")
        if not isinstance(scope, dict) or scope.get("snapshot_path") != raw_path:
            raise ValueError("Swarm authorization path must exactly match the target")
        if scope.get("device_id") != target.get("device_id"):
            raise ValueError("Swarm authorization device must exactly match the target")
        _parse_future_expiry(authorization.get("expires_at"))

        candidate = (self.root / raw_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError("Swarm snapshot path escapes the configured root")
        if not candidate.is_file():
            raise ValueError("Swarm snapshot does not exist")
        if candidate.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise ValueError(f"Swarm snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
        raw = candidate.read_bytes()
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

        safe_events = []
        for event in events[:500]:
            if not isinstance(event, dict):
                continue
            destination = str(event.get("destination", ""))
            safe_events.append({
                "type": str(event.get("type", "unknown"))[:40],
                "process": str(event.get("process", "unknown"))[:100],
                "process_signed": bool(event.get("process_signed", False)),
                "baseline": str(event.get("baseline", "unknown"))[:20],
                "sensitive": bool(event.get("sensitive", False)),
                "bytes_out": max(0, int(event.get("bytes_out", 0))),
                "destination_sha256": stable_hash(destination)[:16] if destination else "",
            })

        facts = {
            "mode": mode,
            "device_id_sha256": stable_hash(str(snapshot["device_id"]))[:16],
            "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
            "sensor_coverage": {key: bool(sensors.get(key, False)) for key in ("camera", "microphone", "identity", "process", "network")},
            "posture": {key: bool(posture.get(key, False)) for key in ("disk_encrypted", "secure_boot", "screen_lock", "security_updates_current")},
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

    def evaluate(self, target: dict[str, Any], current: Observation, previous: Observation | None) -> list[Finding]:
        facts = current.facts
        findings: list[Finding] = []
        missing = sorted(key for key, active in facts["sensor_coverage"].items() if not active)
        if missing:
            findings.append(self._finding(current, "SWARM_SENSOR_COVERAGE_INCOMPLETE", "medium", "Device visibility is incomplete", "One or more authorized local sensors did not report; Watch-Dawg cannot rule out activity it could not observe.", {"missing_sensors": missing}))
        weak_posture = sorted(key for key, active in facts["posture"].items() if not active)
        if weak_posture:
            findings.append(self._finding(current, "SWARM_DEVICE_POSTURE_WEAK", "high", "Device security posture needs attention", "One or more baseline protections are absent or could not be verified.", {"controls": weak_posture}))
        mesh = facts["mesh"]
        if mesh["enabled"] and (not mesh["signed_updates_only"] or mesh["raw_data_sharing"]):
            findings.append(self._finding(current, "SWARM_MESH_TRUST_BOUNDARY_WEAK", "critical", "Private mesh trust boundary is unsafe", "Mesh learning must accept signed updates only and must not share raw device data.", {"signed_updates_only": mesh["signed_updates_only"], "raw_data_sharing": mesh["raw_data_sharing"]}))

        for index, event in enumerate(facts["events"]):
            event_type = event["type"]
            event_key = stable_hash(f"{index}:{event_type}:{event['process']}:{event['destination_sha256']}")[:10]
            if event_type in {"camera_access", "microphone_access"} and (event["baseline"] == "unexpected" or not event["process_signed"]):
                findings.append(self._finding(current, f"SWARM_UNEXPECTED_SENSOR_ACCESS_{event_key}", "critical", "Unexpected camera or microphone access observed", "A local snapshot reported sensor access outside the learned baseline or by an unsigned process. No blocking action was taken.", {"event_type": event_type, "process": event["process"], "process_signed": event["process_signed"], "baseline": event["baseline"]}, stateful=False))
            if event_type == "identity_event" and event["baseline"] == "unexpected":
                findings.append(self._finding(current, f"SWARM_IDENTITY_ANOMALY_{event_key}", "high", "Unusual identity activity observed", "The device reported an identity event outside its local baseline; step-up verification is recommended.", {"process": event["process"], "baseline": event["baseline"]}, stateful=False))
            if event_type == "network_egress" and event["sensitive"] and event["baseline"] == "unexpected":
                findings.append(self._finding(current, f"SWARM_SENSITIVE_EGRESS_{event_key}", "critical", "Unexpected sensitive-data egress observed", "The snapshot reported unusual outbound transfer involving data marked sensitive. Destination evidence is hashed and containment requires approval.", {"bytes_out": event["bytes_out"], "destination_sha256": event["destination_sha256"]}, stateful=False))
        return findings

    @staticmethod
    def _finding(current: Observation, code: str, severity: str, title: str, detail: str, evidence: dict[str, Any], *, stateful: bool = True) -> Finding:
        return Finding(target_id=current.target_id, code=code, severity=severity, title=title, detail=detail, evidence={**evidence, "mode": current.facts["mode"], "actions_executed": False}, stateful=stateful)
