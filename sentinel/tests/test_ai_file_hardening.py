from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sentinel.ai_system_watch import AiSystemRiskWatchPack


class AiManifestFileHardeningTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_manifest_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            outside = base / "outside.json"
            outside.write_text(json.dumps({"models": [], "tools": [], "controls": {}}))
            (root / "manifest.json").symlink_to(outside)
            target = {
                "id": "owned-ai",
                "manifest_path": "manifest.json",
                "authorization": {
                    "id": "AI-1",
                    "approved_methods": ["read-ai-manifest"],
                    "scope": {"manifest_path": "manifest.json"},
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            }

            with self.assertRaisesRegex(ValueError, "safely opened"):
                AiSystemRiskWatchPack(root).observe(target)


if __name__ == "__main__":
    unittest.main()
