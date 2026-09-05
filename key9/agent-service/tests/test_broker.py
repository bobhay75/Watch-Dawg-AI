from __future__ import annotations

import json
import unittest

from key9_core.broker import CredentialBroker, SandboxSecretProvider
from key9_core.redaction import redact_payload, redact_text


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
            target="https://www.googleapis.com",
            executor=lambda secret: {
                "status": "success",
                "debug": f"Bearer {secret}",
                "records": 3,
            },
        )
        self.assertEqual(result["records"], 3)
        self.assertNotIn("sandbox-drive-token", str(result))
        self.assertIn("[REDACTED]", result["debug"])

        with self.assertRaisesRegex(PermissionError, "lease_not_found"):
            broker.invoke(
                lease_id or "",
                target="https://www.googleapis.com",
                executor=lambda secret: secret,
            )

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

    def test_nested_and_json_escaped_secrets_are_redacted(self) -> None:
        secret = 'quote"line\nback\\slash'
        payload = {
            "outer": [
                {"debug": f"prefix {secret} suffix"},
                (f"Bearer {secret}",),
            ],
            f"key-{secret}": b"token=bytes-value",
        }

        redacted = redact_payload(payload, (secret,))
        self.assertNotIn(secret, str(redacted))
        self.assertNotIn("bytes-value", str(redacted))
        self.assertGreaterEqual(str(redacted).count("[REDACTED]"), 3)

        already_serialized = json.dumps({"opaque": f"value:{secret}"})
        redacted_serialized = redact_payload(already_serialized, (secret,))
        self.assertNotIn(json.dumps(secret)[1:-1], redacted_serialized)
        self.assertIn("[REDACTED]", redacted_serialized)


if __name__ == "__main__":
    unittest.main()
