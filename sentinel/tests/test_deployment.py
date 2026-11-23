from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


SENTINEL_ROOT = Path(__file__).resolve().parents[1]


class StagingDeploymentTests(unittest.TestCase):
    def test_container_state_directory_is_private(self) -> None:
        dockerfile = (SENTINEL_ROOT / "Dockerfile").read_text()
        self.assertIn(
            "install -d -m 0700 -o sentinel -g sentinel /state",
            dockerfile,
        )

    def test_deployment_requires_explicit_staging_opt_in(self) -> None:
        deploy = SENTINEL_ROOT / "scripts/deploy-cloud-run-staging.sh"
        completed = subprocess.run(
            ["bash", str(deploy)],
            capture_output=True,
            check=False,
            env={},
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("SENTINEL_STAGING_DEPLOY=true", completed.stderr)

    def test_staging_profile_is_public_passive_and_bounded(self) -> None:
        profile = json.loads(
            (SENTINEL_ROOT / "examples/black-oak-staging.json").read_text()
        )
        self.assertEqual(len(profile["targets"]), 5)
        for target in profile["targets"]:
            self.assertEqual(target["authorization"]["mode"], "public")
            self.assertLessEqual(target["timeout_seconds"], 5)
        sitemap = next(item for item in profile["targets"] if item["kind"] == "sitemap")
        self.assertLessEqual(sitemap["max_sitemaps"], 2)
        self.assertLessEqual(sitemap["max_urls"], 5)

    def test_deployment_is_private_single_instance_and_scale_to_zero(self) -> None:
        deploy = (SENTINEL_ROOT / "scripts/deploy-cloud-run-staging.sh").read_text()
        self.assertIn('SENTINEL_STAGING_DEPLOY:-false', deploy)
        self.assertIn("--invoker-iam-check", deploy)
        self.assertIn("--min-instances 0", deploy)
        self.assertIn("--max-instances 1", deploy)
        self.assertIn("--concurrency 1", deploy)
        self.assertIn("remove_public_invokers", deploy)
        self.assertIn("allUsers allAuthenticatedUsers", deploy)
        self.assertNotIn("--allow-unauthenticated", deploy)
        self.assertNotIn("--no-invoker-iam-check", deploy)

    def test_secret_is_generated_pinned_and_never_written_to_a_file(self) -> None:
        deploy = (SENTINEL_ROOT / "scripts/deploy-cloud-run-staging.sh").read_text()
        self.assertIn("openssl rand -hex 32", deploy)
        self.assertIn("SENTINEL_SECRET_VERSION_RESOURCE", deploy)
        self.assertIn(
            "SENTINEL_API_TOKEN=${SENTINEL_SECRET_NAME}:${SENTINEL_SECRET_VERSION}",
            deploy,
        )
        self.assertNotIn("SENTINEL_API_TOKEN=${SENTINEL_SECRET_NAME}:latest", deploy)
        self.assertNotIn("staging.env", deploy)

    def test_smoke_test_requires_both_cloud_run_and_application_auth(self) -> None:
        smoke = (SENTINEL_ROOT / "scripts/smoke-cloud-run-staging.sh").read_text()
        self.assertIn("X-Serverless-Authorization: Bearer", smoke)
        self.assertIn("Authorization: Bearer", smoke)
        self.assertIn("SENTINEL_ANONYMOUS_STATUS", smoke)
        self.assertIn("SENTINEL_APPLICATION_STATUS", smoke)
        self.assertIn('!= "403"', smoke)
        self.assertIn('!= "401"', smoke)


if __name__ == "__main__":
    unittest.main()
