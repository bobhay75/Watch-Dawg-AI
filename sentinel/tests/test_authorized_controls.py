from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.verify_supply_chain import inspect_root
from sentinel.ai_system_watch import AiSystemRiskWatchPack
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


class AiSystemRiskTests(unittest.TestCase):
    def _target(self) -> dict:
        return {
            "id": "owned-ai-service",
            "kind": "ai_system",
            "manifest_path": "ai-system.json",
            "authorization": {
                "mode": "owner",
                "id": "AI-SCOPE-2026-001",
                "approved_methods": ["read-ai-manifest"],
                "scope": {"manifest_path": "ai-system.json"},
                "expires_at": "2099-01-01T00:00:00Z",
            },
        }

    def _safe_manifest(self) -> dict:
        return {
            "system_id": "watch-dawg-explainer",
            "version": "1.0.0",
            "owner": "system-owner",
            "purpose": "Explain deterministic findings without taking action",
            "data_classification": "internal",
            "models": [{
                "id": "approved-model",
                "provider": "approved-provider",
                "revision": "a" * 40,
                "trust_remote_code": False,
            }],
            "tools": [{
                "id": "report-writer",
                "operations": ["write"],
                "human_approval": True,
            }],
            "secret_reference": "secret://approved/model-token",
            "controls": {
                "deny_unknown_tools": True,
                "network_egress": "deny-by-default",
                "prompt_injection_defense": True,
                "output_validation": True,
                "secrets_via_broker": True,
                "logging_redaction": True,
                "kill_switch": True,
                "model_change_approval": True,
                "vendor_inventory": True,
                "training_data_provenance": True,
                "resilience": {
                    "incident_runbook": "IR-AI-01",
                    "rto_minutes": 60,
                    "rpo_minutes": 15,
                    "restore_tested_at": datetime.now(timezone.utc).isoformat(),
                },
                "crypto_inventory": [{
                    "use": "artifact integrity",
                    "algorithm": "SHA-256",
                    "owner": "security-owner",
                    "migration_trigger": "NIST deprecation or contract requirement",
                }],
            },
        }

    def test_safe_ai_manifest_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ai-system.json").write_text(
                json.dumps(self._safe_manifest()),
                encoding="utf-8",
            )
            pack = AiSystemRiskWatchPack(root)
            observation = pack.observe(self._target())
            self.assertEqual(pack.evaluate(self._target(), observation, None), [])
            self.assertNotIn("secret://approved/model-token", str(observation.to_dict()))

    def test_flags_unpinned_remote_code_ungated_tools_and_embedded_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._safe_manifest()
            manifest["models"][0]["revision"] = "latest"
            manifest["models"][0]["trust_remote_code"] = True
            manifest["tools"][0]["human_approval"] = False
            manifest["api_token"] = "do-not-leak-this-value"
            manifest["controls"]["network_egress"] = "allow"
            (root / "ai-system.json").write_text(json.dumps(manifest), encoding="utf-8")
            pack = AiSystemRiskWatchPack(root)
            observation = pack.observe(self._target())
            findings = pack.evaluate(self._target(), observation, None)
            codes = {item.code for item in findings}
            self.assertTrue(any(code.startswith("AI_MODEL_UNPINNED") for code in codes))
            self.assertTrue(any(code.startswith("AI_REMOTE_CODE_ENABLED") for code in codes))
            self.assertTrue(any(code.startswith("AI_HIGH_IMPACT_TOOL_UNGATED") for code in codes))
            self.assertIn("AI_EGRESS_NOT_DEFAULT_DENY", codes)
            self.assertTrue(any(code.startswith("AI_SECRET_EMBEDDED") for code in codes))
            output = str(observation.to_dict()) + str([item.to_dict() for item in findings])
            self.assertNotIn("do-not-leak-this-value", output)

    def test_rejects_manifest_outside_exact_authorized_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ai-system.json").write_text(json.dumps(self._safe_manifest()), encoding="utf-8")
            target = self._target()
            target["authorization"]["scope"]["manifest_path"] = "other.json"
            with self.assertRaisesRegex(ValueError, "exactly match"):
                AiSystemRiskWatchPack(root).observe(target)

    def test_shipped_ai_manifest_example_is_a_clean_starting_point(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        config = json.loads(
            (repository / "sentinel/config.ai-security.example.json").read_text(encoding="utf-8")
        )
        target = next(item for item in config["targets"] if item["kind"] == "ai_system")
        pack = AiSystemRiskWatchPack(repository / config["ai_manifest_root"])
        observation = pack.observe(target)
        codes = {finding.code for finding in pack.evaluate(target, observation, None)}
        self.assertLessEqual(codes, {"AI_RESTORE_TEST_STALE"})

    def test_future_restore_date_is_not_accepted_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._safe_manifest()
            manifest["controls"]["resilience"]["restore_tested_at"] = "2099-01-01T00:00:00Z"
            (root / "ai-system.json").write_text(json.dumps(manifest), encoding="utf-8")
            pack = AiSystemRiskWatchPack(root)
            observation = pack.observe(self._target())
            codes = {finding.code for finding in pack.evaluate(self._target(), observation, None)}
            self.assertIn("AI_RESTORE_TEST_STALE", codes)


class SupplyChainVerificationTests(unittest.TestCase):
    def test_current_repository_has_no_supply_chain_errors(self) -> None:
        report = inspect_root(Path(__file__).resolve().parents[2])
        self.assertEqual(report["summary"]["errors"], 0, report["issues"])

    def test_unpinned_action_and_dependency_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/test.yml").write_text(
                "steps:\n  - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")
            report = inspect_root(root)
            codes = {item["code"] for item in report["issues"]}
            self.assertIn("ACTION_NOT_COMMIT_PINNED", codes)
            self.assertIn("PYTHON_DEPENDENCY_NOT_PINNED", codes)
            self.assertEqual(report["status"], "FAIL")

if __name__ == "__main__":
    unittest.main()
