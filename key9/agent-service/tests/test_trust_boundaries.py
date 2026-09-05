from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
import time
import unittest

from key9_core.broker import CredentialBroker, SandboxSecretProvider
from key9_core.config import session_service_uri


KEY9_ROOT = Path(__file__).resolve().parents[2]


class CountingProvider:
    def __init__(self, *, fail: bool = False) -> None:
        self.access_count = 0
        self.fail = fail
        self.lock = threading.Lock()

    def access(self, alias: str) -> str:
        with self.lock:
            self.access_count += 1
        time.sleep(0.03)
        if self.fail:
            raise RuntimeError("synthetic_provider_failure")
        return "synthetic-test-secret"


def authorized_lease(broker: CredentialBroker) -> str:
    decision, lease_id = broker.authorize(
        alias="drive.receipts",
        target="https://www.googleapis.com",
        scopes=["receipts:read"],
    )
    if not decision.allowed or lease_id is None:
        raise AssertionError("test lease was not authorized")
    return lease_id


class TrustBoundaryTests(unittest.TestCase):
    def test_concurrent_replay_executes_exactly_once(self) -> None:
        provider = CountingProvider()
        broker = CredentialBroker(provider)
        lease_id = authorized_lease(broker)
        start = threading.Barrier(2)
        executions = 0
        execution_lock = threading.Lock()

        def invoke() -> str:
            nonlocal executions
            start.wait()

            def connector(_secret: str) -> dict[str, str]:
                nonlocal executions
                with execution_lock:
                    executions += 1
                return {"status": "success"}

            try:
                broker.invoke(
                    lease_id,
                    target="https://www.googleapis.com",
                    executor=connector,
                )
                return "success"
            except PermissionError as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _index: invoke(), range(2)))

        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(outcomes.count("lease_not_found"), 1)
        self.assertEqual(provider.access_count, 1)
        self.assertEqual(executions, 1)

    def test_provider_failure_cannot_restore_consumed_lease(self) -> None:
        provider = CountingProvider(fail=True)
        broker = CredentialBroker(provider)
        lease_id = authorized_lease(broker)

        with self.assertRaisesRegex(RuntimeError, "synthetic_provider_failure"):
            broker.invoke(
                lease_id,
                target="https://www.googleapis.com",
                executor=lambda _secret: {"status": "should_not_run"},
            )
        with self.assertRaisesRegex(PermissionError, "lease_not_found"):
            broker.invoke(
                lease_id,
                target="https://www.googleapis.com",
                executor=lambda _secret: {"status": "should_not_run"},
            )
        self.assertEqual(provider.access_count, 1)

    def test_invocation_target_mismatch_consumes_lease_without_secret_access(self) -> None:
        provider = CountingProvider()
        broker = CredentialBroker(provider)
        lease_id = authorized_lease(broker)

        with self.assertRaisesRegex(PermissionError, "lease_target_mismatch"):
            broker.invoke(
                lease_id,
                target="https://example.invalid",
                executor=lambda _secret: {"status": "should_not_run"},
            )
        with self.assertRaisesRegex(PermissionError, "lease_not_found"):
            broker.invoke(
                lease_id,
                target="https://www.googleapis.com",
                executor=lambda _secret: {"status": "should_not_run"},
            )
        self.assertEqual(provider.access_count, 0)

    def test_production_rejects_process_local_sessions(self) -> None:
        for uri in (
            "memory://",
            "sqlite:///tmp/key9.db",
            "sqlite+aiosqlite:///tmp/key9.db",
        ):
            with self.subTest(uri=uri):
                with self.assertRaisesRegex(RuntimeError, "persistent_session_required"):
                    session_service_uri(
                        {"KEY9_SANDBOX": "false", "KEY9_SESSION_URI": uri}
                    )
        self.assertEqual(
            session_service_uri(
                {
                    "KEY9_SANDBOX": "false",
                    "KEY9_SESSION_URI": "postgresql://db.invalid/key9",
                }
            ),
            "postgresql://db.invalid/key9",
        )

    def test_context_sources_are_explicit_and_implicit_sources_are_denied(self) -> None:
        manifest = json.loads((KEY9_ROOT / "security/context-manifest.json").read_text())
        sources = manifest["sources"]
        self.assertEqual(len({source["id"] for source in sources}), len(sources))
        for source in sources:
            required = {"origin", "trust", "role", "scope", "mutable_by_agent"}
            self.assertTrue(required <= source.keys())
        self.assertIn("git_commit_metadata", manifest["prohibited_implicit_sources"])
        self.assertIn("third_party_skill_directories", manifest["prohibited_implicit_sources"])
        self.assertEqual(manifest["acs_alignment"], "preview-shaped-not-conformance-tested")

    def test_agent_tool_registry_excludes_owner_approval(self) -> None:
        source = (KEY9_ROOT / "agent-service/agents/key9_agent/agent.py").read_text()
        tree = ast.parse(source)
        tool_names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "tools" and isinstance(keyword.value, ast.List):
                        tool_names.extend(
                            item.id for item in keyword.value.elts if isinstance(item, ast.Name)
                        )
        self.assertEqual(
            tool_names,
            [
                "plan_secure_closeout",
                "read_watchdawg_job",
                "collect_job_receipts",
                "reconcile_job",
                "prepare_accounting_export",
            ],
        )
        self.assertNotIn("approve_accounting_export", tool_names)

    def test_application_package_defines_no_lifecycle_hooks(self) -> None:
        policy = json.loads((KEY9_ROOT / "security/lifecycle-hook-policy.json").read_text())
        package = json.loads((KEY9_ROOT / "package.json").read_text())
        workflow = (KEY9_ROOT.parent / ".github/workflows/key9-security.yml").read_text()
        scripts = package.get("scripts", {})
        forbidden = set(policy["forbidden_npm_lifecycle_scripts"])
        self.assertFalse(forbidden.intersection(scripts))
        self.assertEqual(policy["application_defined_hooks"], [])
        self.assertIn("npm ci --ignore-scripts", workflow)

    def test_public_route_cannot_relay_owner_approval(self) -> None:
        route = (KEY9_ROOT / "app/api/agent/route.ts").read_text()
        self.assertNotIn("x-key9-human-approval", route)
        self.assertNotIn("human_approved: true", route)
        self.assertNotIn("/run_sse", route)
        self.assertIn("${baseUrl}/run", route)
        self.assertIn("sandbox_action_simulated", route)

    def test_production_approval_fails_closed_until_owner_auth_exists(self) -> None:
        main = (KEY9_ROOT / "agent-service/main.py").read_text()
        self.assertIn("production_owner_authentication_required", main)
        self.assertIn("if not sandbox_enabled()", main)

    def test_public_cloud_run_deploy_requires_explicit_sandbox_opt_in(self) -> None:
        deploy = (KEY9_ROOT / "scripts/deploy-cloud-run.sh").read_text()
        bootstrap = (KEY9_ROOT / "scripts/bootstrap-contest-cloud.sh").read_text()
        self.assertIn('KEY9_SANDBOX_DEPLOY:-false', deploy)
        self.assertIn('KEY9_SANDBOX_DEPLOY=true', bootstrap)
        self.assertIn('KEY9_SANDBOX=true', deploy)
        self.assertNotIn('KEY9_SANDBOX=false', deploy)


if __name__ == "__main__":
    unittest.main()
