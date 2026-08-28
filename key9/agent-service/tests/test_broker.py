from __future__ import annotations

import unittest

from key9_core.broker import CredentialBroker, SandboxSecretProvider
from key9_core.redaction import redact_text


class BrokerTests(unittest.TestCase):
    def test_secret_is_injected_then_removed_from_result(self) -> None:
        broker = CredentialBroker(SandboxSecretProvider())
        decision, lease_id = broker.authorize(
            alias="drive.receipts",
            target="https://www.googleapis.com",
            scopes=["receipts:read"],
        )
        self.assertTrue(decision.allowed)
        self.assertIsNotNone(lease_id)

        result = broker.invoke(
            lease_id or "",
            lambda secret: {
                "status": "success",
                "debug": f"Bearer {secret}",
                "records": 3,
            },
        )
        self.assertEqual(result["records"], 3)
        self.assertNotIn("sandbox-drive-token", str(result))
        self.assertIn("[REDACTED]", result["debug"])

        with self.assertRaisesRegex(PermissionError, "lease_not_found"):
            broker.invoke(lease_id or "", lambda secret: secret)

    def test_denied_action_never_creates_lease(self) -> None:
        broker = CredentialBroker(SandboxSecretProvider())
        decision, lease_id = broker.authorize(
            alias="drive.receipts",
            target="https://evil.example",
            scopes=["receipts:read"],
        )
        self.assertFalse(decision.allowed)
        self.assertIsNone(lease_id)

    def test_common_secret_shapes_are_redacted(self) -> None:
        text = "password=hunter2 api_key:abc123 Authorization Bearer xyz.987"
        redacted = redact_text(text)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("xyz.987", redacted)


if __name__ == "__main__":
    unittest.main()
