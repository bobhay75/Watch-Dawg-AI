from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.secret_watch import SecretExposureWatchPack
from sentinel.service_watch import ServiceExposureWatchPack


def service_target() -> dict:
    return {
        "id": "owned-edge",
        "kind": "service_exposure",
        "hostname": "example.gov",
        "ports": [22, 443],
        "authorization": {
            "mode": "owner",
            "id": "ATO-SCOPE-2026-001",
            "approved_methods": ["tcp-connect"],
            "scope": {"hostname": "example.gov", "ports": [22, 443]},
            "expires_at": "2099-01-01T00:00:00Z",
        },
        "checks": {"expected_open_ports": [443]},
    }


class ServiceExposureTests(unittest.TestCase):
    def test_checks_only_explicit_authorized_ports_without_banners(self) -> None:
        calls: list[tuple[str, int, float]] = []

        def connect(hostname: str, port: int, timeout: float) -> bool:
            calls.append((hostname, port, timeout))
            return port in {22, 443}

        pack = ServiceExposureWatchPack(
            resolver=lambda hostname: {"8.8.8.8"},
            connector=connect,
        )
        target = service_target()
        observation = pack.observe(target)
        findings = pack.evaluate(target, observation, None)
        self.assertEqual([call[1] for call in calls], [22, 443])
        self.assertFalse(observation.facts["banner_collection"])
        self.assertFalse(observation.facts["exploitation"])
        self.assertEqual(findings[0].code, "UNEXPECTED_OPEN_PORT_22")

    def test_rejects_scope_mismatch_and_broad_port_lists(self) -> None:
        pack = ServiceExposureWatchPack(
            resolver=lambda hostname: {"8.8.8.8"},
            connector=lambda hostname, port, timeout: False,
        )
        mismatch = service_target()
        mismatch["authorization"]["scope"]["hostname"] = "other.example.gov"
        with self.assertRaisesRegex(ValueError, "hostname does not match"):
            pack.observe(mismatch)

        broad = service_target()
        broad["ports"] = list(range(1, 18))
        broad["authorization"]["scope"]["ports"] = broad["ports"]
        with self.assertRaisesRegex(ValueError, "at most 16"):
            pack.observe(broad)

    def test_rejects_private_addresses_and_expired_authorization(self) -> None:
        private = ServiceExposureWatchPack(
            resolver=lambda hostname: {"127.0.0.1"},
            connector=lambda hostname, port, timeout: False,
        )
        with self.assertRaisesRegex(ValueError, "public addresses"):
            private.observe(service_target())

        expired = service_target()
        expired["authorization"]["expires_at"] = "2020-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "expired"):
            private.observe(expired)


class SecretExposureTests(unittest.TestCase):
    def test_reports_redacted_secret_evidence_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "a-very-sensitive-password"
            (root / "settings.txt").write_text(
                f'password = "{secret}"\n-----BEGIN PRIVATE KEY-----\n',
                encoding="utf-8",
            )
            pack = SecretExposureWatchPack(root)
            target = {
                "id": "owned-source",
                "kind": "secret_exposure",
                "paths": ["settings.txt"],
                "authorization": {
                    "mode": "owner",
                    "id": "REPO-OWNER-2026-001",
                    "approved_methods": ["read-local-files"],
                    "scope": {"paths": ["settings.txt"]},
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            }
            observation = pack.observe(target)
            findings = pack.evaluate(target, observation, None)
            output = str(observation.to_dict()) + str([item.to_dict() for item in findings])
            self.assertEqual(len(findings), 2)
            self.assertNotIn(secret, output)
            self.assertIn("match_sha256", output)
            self.assertIn("settings.txt", output)

    def test_rejects_path_escape_and_missing_approval_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            outside = Path(directory) / "outside.txt"
            outside.write_text("nothing", encoding="utf-8")
            pack = SecretExposureWatchPack(root)
            with self.assertRaisesRegex(ValueError, "escapes"):
                pack.observe({
                    "id": "source",
                    "paths": ["../outside.txt"],
                    "authorization": {
                        "mode": "owner",
                        "id": "A-1",
                        "approved_methods": ["read-local-files"],
                        "scope": {"paths": ["../outside.txt"]},
                        "expires_at": "2099-01-01T00:00:00Z",
                    },
                })

            (root / "safe.txt").write_text("nothing", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "approve read-local-files"):
                pack.observe({
                    "id": "source",
                    "paths": ["safe.txt"],
                    "authorization": {
                        "mode": "owner",
                        "id": "A-1",
                        "scope": {"paths": ["safe.txt"]},
                        "expires_at": "2099-01-01T00:00:00Z",
                    },
                })


if __name__ == "__main__":
    unittest.main()
