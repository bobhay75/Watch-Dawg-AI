from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import generate_government_evidence as evidence  # noqa: E402


class GovernmentEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "repository"
        self.root.mkdir()
        files = {
            ".gitignore": "build/\n",
            "Dockerfile": "# deployment file without a base for the fixture\n",
            "README.md": "fixture\n",
            "index.html": "<!doctype html><title>Watch Dawg</title>\n",
            "styles.css": "body { color: #123; }\n",
            "docs/government-control-matrix.json": '{"controls": []}\n',
        }
        for name, contents in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Evidence Test")
        self._git("add", "--all")
        self._git("commit", "-qm", "fixture")
        self.bundle = self.root / "build" / "evidence"

    def _git(self, *arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=self.root, check=True, capture_output=True)

    def _build(self, *, allow_dirty: bool = False) -> dict[str, object]:
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            return evidence.build_bundle(self.root, self.bundle, allow_dirty=allow_dirty)

    def test_tracks_all_git_files_and_hashes_every_artifact(self) -> None:
        manifest = self._build()
        inventory = json.loads((self.bundle / "source-sha256.json").read_text(encoding="utf-8"))
        paths = {item["path"] for item in inventory["files"]}
        self.assertIn("index.html", paths)
        self.assertIn("styles.css", paths)
        self.assertIn("Dockerfile", paths)

        self.assertIn("not a certification", manifest["claim"])
        self.assertIn("cryptographic signature", manifest["claim"])
        for record in manifest["artifacts"].values():
            artifact = self.bundle / record["path"]
            payload = artifact.read_bytes()
            self.assertEqual(record["bytes"], len(payload))
            self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertTrue(evidence.verify_bundle(self.bundle)["valid"])

    def test_dirty_and_untracked_files_require_explicit_override(self) -> None:
        (self.root / "local-notes.txt").write_text("not evidence\n", encoding="utf-8")
        with self.assertRaisesRegex(evidence.EvidenceError, "working tree is dirty"):
            self._build()

        manifest = self._build(allow_dirty=True)
        inventory = json.loads((self.bundle / "source-sha256.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["workspace_dirty"])
        self.assertNotIn("local-notes.txt", {item["path"] for item in inventory["files"]})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_tracked_external_symlink_is_rejected_without_reading_target(self) -> None:
        external = self.base / "external-secret.txt"
        external.write_text("must not enter evidence\n", encoding="utf-8")
        (self.root / "external-link").symlink_to(external)
        self._git("add", "external-link")
        self._git("commit", "-qm", "track symlink")

        with self.assertRaisesRegex(evidence.EvidenceError, "tracked symlink"):
            self._build()
        self.assertFalse(self.bundle.exists())

    def test_one_byte_artifact_mutation_fails_library_and_cli_verification(self) -> None:
        self._build()
        artifact = self.bundle / "source-sha256.json"
        payload = bytearray(artifact.read_bytes())
        payload[-2] = ord(" ") if payload[-2] != ord(" ") else ord("x")
        artifact.write_bytes(payload)

        report = evidence.verify_bundle(self.bundle)
        self.assertFalse(report["valid"])
        self.assertTrue(any("SHA-256 mismatch" in error for error in report["errors"]))
        with redirect_stdout(StringIO()):
            self.assertEqual(evidence.main(["--verify", str(self.bundle)]), 1)


if __name__ == "__main__":
    unittest.main()
