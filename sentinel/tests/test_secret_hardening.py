from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sentinel.core import stable_hash
from sentinel.secret_watch import SecretExposureWatchPack


def target(path: str) -> dict:
    return {
        "id": "owned-source",
        "kind": "secret_exposure",
        "paths": [path],
        "authorization": {
            "mode": "owner",
            "id": "A-1",
            "approved_methods": ["read-local-files"],
            "scope": {"paths": [path]},
            "expires_at": "2099-01-01T00:00:00Z",
        },
    }


class SecretHardeningTests(unittest.TestCase):
    def test_secret_value_is_not_used_as_an_exported_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "predictable-password-value"
            (root / "settings.txt").write_text(
                f'password = "{secret}"\n',
                encoding="utf-8",
            )
            observation = SecretExposureWatchPack(root).observe(target("settings.txt"))

        rendered = str(observation.to_dict())
        self.assertNotIn(secret, rendered)
        self.assertNotIn(stable_hash(secret)[:16], rendered)
        self.assertIn("occurrence_id", rendered)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_symlink_is_not_followed_even_when_it_points_to_a_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_text('password = "outside-secret-value"\n', encoding="utf-8")
            (root / "linked.txt").symlink_to(outside)

            with self.assertRaisesRegex(ValueError, "safely opened"):
                SecretExposureWatchPack(root).observe(target("linked.txt"))


if __name__ == "__main__":
    unittest.main()
