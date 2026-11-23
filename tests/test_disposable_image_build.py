"""Regression for cold Mongo image setup exceeding runtime-command limits."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import disposable_images


class DisposableImageBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        executable = self.root / "docker"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys, time\n"
            "pathlib.Path(os.environ['FAKE_DOCKER_ARGS']).write_text(\n"
            "    json.dumps(sys.argv[1:]))\n"
            "time.sleep(float(os.environ.get('FAKE_DOCKER_DELAY', '0')))\n"
            "sys.exit(int(os.environ.get('FAKE_DOCKER_EXIT', '0')))\n"
        )
        executable.chmod(0o700)
        environment = patch.dict(os.environ, {
            "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            "FAKE_DOCKER_ARGS": str(self.root / "args.json"),
            "FAKE_DOCKER_DELAY": "0",
            "FAKE_DOCKER_EXIT": "0",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def test_cold_build_has_own_bounded_setup_budget(self):
        # Simulate a 150-second cold build without actually sleeping. It must
        # pass the build limit that previously killed setup after 120 seconds.
        def cold_build(args, *, check, timeout):
            self.assertTrue(check)
            self.assertGreaterEqual(timeout, 150)
            self.assertLessEqual(timeout, 600)
            self.assertEqual(args[:3], ["docker", "build", "--progress=plain"])
            return subprocess.CompletedProcess(args, 0)

        with patch.object(disposable_images.subprocess, "run", cold_build):
            disposable_images.build_mongo_image()

    def test_success_runs_pinned_dockerfile_without_creating_a_database(self):
        disposable_images.build_mongo_image()
        args = json.loads((self.root / "args.json").read_text())
        self.assertEqual(args, [
            "build", "--progress=plain", "-f",
            str(disposable_images.ROOT
                / "deployment/secure/Mongo.Dockerfile"),
            "-t", disposable_images.MONGO_IMAGE, str(disposable_images.ROOT),
        ])

    def test_stalled_build_is_terminated_and_fails(self):
        os.environ["FAKE_DOCKER_DELAY"] = "10"
        with patch.object(
            disposable_images, "IMAGE_BUILD_TIMEOUT_SECONDS", .1
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                disposable_images.build_mongo_image()

    def test_image_build_failure_still_fails_the_drill(self):
        os.environ["FAKE_DOCKER_EXIT"] = "19"
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            disposable_images.build_mongo_image()
        self.assertEqual(failure.exception.returncode, 19)


if __name__ == "__main__":
    unittest.main()
