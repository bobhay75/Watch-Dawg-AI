from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.verify_supply_chain import inspect_root
from sentinel.ai_system_watch import (
    MAX_CRYPTO_ENTRIES,
    MAX_FINDINGS,
    MAX_MANIFEST_DEPTH,
    MAX_MANIFEST_NODES,
    MAX_MODELS,
    MAX_SECRET_CANDIDATES,
    MAX_TOOLS,
    AiSystemRiskWatchPack,
)
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
            self.assertIn("occurrence_id", output)
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

    def _observe_manifest(self, root: Path, manifest: dict):
        (root / "ai-system.json").write_text(json.dumps(manifest), encoding="utf-8")
        return AiSystemRiskWatchPack(root).observe(self._target())

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

    def test_tool_operations_require_a_bounded_known_string_list_and_real_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            manifest = self._safe_manifest()
            manifest["tools"][0]["operations"] = "write"
            with self.assertRaisesRegex(ValueError, "operations must be a list of strings"):
                self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            manifest["tools"][0]["human_approval"] = "false"
            with self.assertRaisesRegex(ValueError, "human_approval must be a boolean"):
                self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            manifest["tools"][0]["operations"] = ["invented-capability"]
            with self.assertRaisesRegex(ValueError, "not a recognized operation"):
                self._observe_manifest(root, manifest)

    def test_tool_operation_case_is_normalized_before_gating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._safe_manifest()
            manifest["tools"][0]["operations"] = ["WrItE"]
            manifest["tools"][0]["human_approval"] = False
            observation = self._observe_manifest(root, manifest)
            self.assertEqual(observation.facts["tools"][0]["operations"], ["write"])
            codes = {
                finding.code
                for finding in AiSystemRiskWatchPack(root).evaluate(
                    self._target(), observation, None
                )
            }
            self.assertTrue(any(code.startswith("AI_HIGH_IMPACT_TOOL_UNGATED") for code in codes))

    def test_model_and_control_booleans_reject_truthy_strings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._safe_manifest()
            manifest["models"][0]["trust_remote_code"] = "false"
            with self.assertRaisesRegex(ValueError, "trust_remote_code must be a boolean"):
                self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            manifest["controls"]["kill_switch"] = "true"
            with self.assertRaisesRegex(ValueError, "controls.kill_switch must be a boolean"):
                self._observe_manifest(root, manifest)

    def test_non_object_inventory_entries_are_rejected_instead_of_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ("models", "not-a-model", r"models\[0\] must be an object"),
                ("tools", "not-a-tool", r"tools\[0\] must be an object"),
            )
            for field, value, message in cases:
                with self.subTest(field=field):
                    manifest = self._safe_manifest()
                    manifest[field] = [value]
                    with self.assertRaisesRegex(ValueError, message):
                        self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            manifest["controls"]["crypto_inventory"] = ["not-a-crypto-entry"]
            with self.assertRaisesRegex(ValueError, r"crypto_inventory\[0\] must be an object"):
                self._observe_manifest(root, manifest)

    def test_inventory_entry_limits_reject_oversized_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            manifest = self._safe_manifest()
            template = manifest["models"][0]
            manifest["models"] = [
                {**template, "id": f"model-{index}"}
                for index in range(MAX_MODELS + 1)
            ]
            with self.assertRaisesRegex(ValueError, f"at most {MAX_MODELS} models"):
                self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            template = manifest["tools"][0]
            manifest["tools"] = [
                {**template, "id": f"tool-{index}"}
                for index in range(MAX_TOOLS + 1)
            ]
            with self.assertRaisesRegex(ValueError, f"at most {MAX_TOOLS} tools"):
                self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            template = manifest["controls"]["crypto_inventory"][0]
            manifest["controls"]["crypto_inventory"] = [
                {**template, "use": f"use-{index}"}
                for index in range(MAX_CRYPTO_ENTRIES + 1)
            ]
            with self.assertRaisesRegex(
                ValueError, f"at most {MAX_CRYPTO_ENTRIES} crypto entries"
            ):
                self._observe_manifest(root, manifest)

    def test_manifest_traversal_depth_and_node_count_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._safe_manifest()
            nested: dict = {}
            cursor = nested
            for index in range(MAX_MANIFEST_DEPTH + 1):
                child: dict = {}
                cursor[f"level_{index}"] = child
                cursor = child
            manifest["metadata"] = nested
            with self.assertRaisesRegex(ValueError, "nesting depth"):
                self._observe_manifest(root, manifest)

            manifest = self._safe_manifest()
            manifest["metadata"] = [0] * MAX_MANIFEST_NODES
            with self.assertRaisesRegex(ValueError, "JSON nodes"):
                self._observe_manifest(root, manifest)

    def test_secret_candidates_are_bounded_and_overflow_is_summarized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._safe_manifest()
            secret_count = MAX_SECRET_CANDIDATES + 7
            for index in range(secret_count):
                manifest[f"api_token_{index}"] = f"never-emit-{index}"
            observation = self._observe_manifest(root, manifest)
            self.assertEqual(
                len(observation.facts["embedded_secret_candidates"]),
                MAX_SECRET_CANDIDATES,
            )
            self.assertEqual(
                observation.facts["embedded_secret_candidate_overflow"],
                secret_count - MAX_SECRET_CANDIDATES,
            )
            findings = AiSystemRiskWatchPack(root).evaluate(
                self._target(), observation, None
            )
            self.assertLessEqual(len(findings), MAX_FINDINGS)
            self.assertIn(
                "AI_SECRET_CANDIDATES_TRUNCATED",
                {finding.code for finding in findings},
            )
            output = str(observation.to_dict()) + str(
                [finding.to_dict() for finding in findings]
            )
            self.assertNotIn("never-emit-", output)

    def test_secret_finding_identity_and_evidence_do_not_hash_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def secret_finding(secret: str):
                manifest = self._safe_manifest()
                manifest["api_token"] = secret
                observation = self._observe_manifest(root, manifest)
                finding = next(
                    item
                    for item in AiSystemRiskWatchPack(root).evaluate(
                        self._target(), observation, None
                    )
                    if item.code.startswith("AI_SECRET_EMBEDDED")
                )
                return observation, finding

            first_observation, first = secret_finding("first-secret-value")
            second_observation, second = secret_finding("second-secret-value")
            self.assertEqual(first.fingerprint, second.fingerprint)
            self.assertEqual(first.evidence, second.evidence)
            self.assertEqual(
                first.evidence,
                {
                    "path": "$.api_token",
                    "rule": "sensitive-key-with-inline-string",
                },
            )
            candidate_output = str(
                first_observation.facts["embedded_secret_candidates"]
                + second_observation.facts["embedded_secret_candidates"]
            )
            self.assertNotIn("value_sha256", candidate_output)
            self.assertNotIn("first-secret-value", candidate_output)
            self.assertNotIn("second-secret-value", candidate_output)


class SupplyChainVerificationTests(unittest.TestCase):
    def test_current_repository_has_no_supply_chain_errors(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        report = inspect_root(repository)
        self.assertEqual(report["summary"]["errors"], 0, report["issues"])
        self.assertEqual(report["summary"]["warnings"], 0, report["issues"])
        self.assertEqual(report["status"], "PASS")

        evidence_workflow = (repository / ".github/workflows/government-evidence.yml").read_text(
            encoding="utf-8"
        )
        pull_request_trigger = evidence_workflow.split("pull_request:", 1)[1].split("push:", 1)[0]
        self.assertNotIn("paths:", pull_request_trigger)

    def test_unpinned_action_and_dependency_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/test.yml").write_text(
                "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")
            report = inspect_root(root)
            codes = {item["code"] for item in report["issues"]}
            self.assertIn("ACTION_NOT_COMMIT_PINNED", codes)
            self.assertIn("PYTHON_DEPENDENCY_NOT_PINNED", codes)
            self.assertEqual(report["status"], "FAIL")

    def test_action_scanner_handles_whitespace_quotes_and_composite_actions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/test.yaml").write_text(
                'jobs:\n  test:\n    steps:\n      - "uses" : "actions/checkout@'
                + ("a" * 40) + '" # pinned\n'
                "      - run: |\n"
                "          echo 'uses: text-inside-a-shell-script@v1'\n"
                "          uses: this-is-not-a-workflow-key@v1\n"
                "      - {name: inline, \"uses\" : actions/cache@v4}\n"
                "      - uses: actions/upload-artifact@" + ("A" * 40) + "\n"
                "      - uses: ./../outside\n",
                encoding="utf-8",
            )
            composite = root / ".github/actions/example/action.yml"
            composite.parent.mkdir(parents=True)
            composite.write_text(
                "name: example\ninputs:\n  uses:\n    description: not an action reference\n"
                "runs:\n  using: composite\n  steps:\n"
                "    - uses : actions/setup-python@v5\n",
                encoding="utf-8",
            )

            report = inspect_root(root)

            action_issues = [
                item for item in report["issues"] if item["code"] == "ACTION_NOT_COMMIT_PINNED"
            ]
            self.assertEqual(report["summary"]["actions_checked"], 5)
            self.assertEqual(len(action_issues), 3)
            self.assertEqual(
                {item["path"] for item in action_issues},
                {".github/workflows/test.yaml", ".github/actions/example/action.yml"},
            )
            self.assertIn(
                "LOCAL_ACTION_PATH_INVALID",
                {item["code"] for item in report["issues"]},
            )

    def test_requirements_reject_wildcards_mixed_constraints_and_bad_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_digest = "a" * 64
            (root / "requirements.txt").write_text(
                "safe-package==1.2.3; python_version >= '3.12'\n"
                f"wheel @ https://example.test/wheel.whl#sha256={valid_digest}\n"
                "wildcard==1.*\n"
                "mixed==1.0,>=1.0\n"
                "range>=2.0 # ==2.1 is not a pin\n"
                "short @ https://example.test/short.whl#sha256=abc123\n"
                f"uppercase @ https://example.test/upper.whl#sha256={valid_digest.upper()}\n"
                f"bad-host @ https://@/empty.whl#sha256={valid_digest}\n"
                f"bad-ipv6 @ https://[::1/broken.whl#sha256={valid_digest}\n"
                "bad-marker==1.0; python_version ??? '3.12'\n",
                encoding="utf-8",
            )

            report = inspect_root(root)

            dependency_issues = [
                item for item in report["issues"]
                if item["code"] == "PYTHON_DEPENDENCY_NOT_PINNED"
            ]
            self.assertEqual(report["summary"]["dependencies_checked"], 10)
            self.assertEqual(len(dependency_issues), 8)

    def test_dockerfile_variants_require_exact_lowercase_sha256_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(
                "FROM python:3.12-slim@sha256:" + ("a" * 64) + "\n",
                encoding="utf-8",
            )
            (root / "Dockerfile.dev").write_text(
                "FROM --platform=linux/amd64 python:3.12@sha256:" + ("b" * 63) + "\n",
                encoding="utf-8",
            )
            (root / "Dockerfile.test").write_text("FROM python:3.12-slim\n", encoding="utf-8")
            vendor_dockerfile = root / "vendor/Dockerfile"
            vendor_dockerfile.parent.mkdir()
            vendor_dockerfile.write_text("FROM ignored:latest\n", encoding="utf-8")

            report = inspect_root(root)

            container_issues = [
                item for item in report["issues"]
                if item["code"] == "CONTAINER_BASE_NOT_DIGEST_PINNED"
            ]
            self.assertEqual(report["summary"]["container_bases_checked"], 3)
            self.assertEqual(len(container_issues), 2)
            self.assertEqual(
                {item["path"] for item in container_issues},
                {"Dockerfile.dev", "Dockerfile.test"},
            )

    def test_node_lockfile_requires_integrity_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"example": "1.0.0"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps({
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"example": "1.0.0"}},
                        "node_modules/example": {"version": "1.0.0"},
                    },
                }),
                encoding="utf-8",
            )
            report = inspect_root(root)
            self.assertIn(
                "NODE_LOCKFILE_INVALID",
                {item["code"] for item in report["issues"]},
            )

if __name__ == "__main__":
    unittest.main()
