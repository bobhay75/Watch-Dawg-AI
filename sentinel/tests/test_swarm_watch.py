from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sentinel.swarm_watch import SwarmDefenseWatchPack


class SwarmDefenseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.snapshot = {"device_id": "owned-phone", "sensors": {key: True for key in ("camera", "microphone", "identity", "process", "network")}, "posture": {key: True for key in ("disk_encrypted", "secure_boot", "screen_lock", "security_updates_current")}, "mesh": {"enabled": True, "peer_count": 2, "signed_updates_only": True, "raw_data_sharing": False}, "events": []}
        self.target = {"id": "phone-shadow", "kind": "swarm_device", "enabled": True, "mode": "shadow", "device_id": "owned-phone", "snapshot_path": "phone.json", "authorization": {"mode": "owner", "id": "AUTH-1", "approved_methods": ["read-device-snapshot"], "scope": {"device_id": "owned-phone", "snapshot_path": "phone.json"}, "expires_at": "2099-01-01T00:00:00Z"}}

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write(self) -> None:
        (self.root / "phone.json").write_text(json.dumps(self.snapshot), encoding="utf-8")

    def test_safe_snapshot_is_observational_and_has_no_findings(self) -> None:
        self.write()
        pack = SwarmDefenseWatchPack(self.root)
        observation = pack.observe(self.target)
        self.assertFalse(observation.facts["actions_executed"])
        self.assertEqual(pack.evaluate(self.target, observation, None), [])

    def test_camera_microphone_identity_and_egress_anomalies_are_advisory(self) -> None:
        self.snapshot["events"] = [{"type": "camera_access", "process": "unknown.exe", "process_signed": False, "baseline": "unexpected"}, {"type": "microphone_access", "process": "meeting.exe", "process_signed": True, "baseline": "unexpected"}, {"type": "identity_event", "process": "login", "process_signed": True, "baseline": "unexpected"}, {"type": "network_egress", "destination": "sensitive.example", "sensitive": True, "baseline": "unexpected", "bytes_out": 5000}]
        self.write()
        pack = SwarmDefenseWatchPack(self.root)
        observation = pack.observe(self.target)
        findings = pack.evaluate(self.target, observation, None)
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(finding.evidence["actions_executed"] is False for finding in findings))
        output = str(observation.to_dict()) + str([finding.to_dict() for finding in findings])
        self.assertNotIn("sensitive.example", output)
        self.assertIn("destination_sha256", output)

    def test_requires_exact_owner_scope_and_explicit_shadow_mode(self) -> None:
        self.write()
        pack = SwarmDefenseWatchPack(self.root)
        self.target["authorization"]["scope"]["device_id"] = "different-device"
        with self.assertRaisesRegex(ValueError, "device must exactly match"):
            pack.observe(self.target)
        self.target["authorization"]["scope"]["device_id"] = "owned-phone"
        self.target["mode"] = "enforce"
        with self.assertRaisesRegex(ValueError, "shadow or advisory"):
            pack.observe(self.target)
