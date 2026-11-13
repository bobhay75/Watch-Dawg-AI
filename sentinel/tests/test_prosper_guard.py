"""Prosper authorization tests: deny, availability, opt-in and bypass prevention."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.api import ApiError, SentinelApiService
from sentinel.prosper_guard import build_prosper_authorizer


TOKEN = "test-token-with-at-least-thirty-two-characters"


class ProsperGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "approved.json"
        self.config.write_text('{"targets":[]}', encoding="utf-8")
        self.runs = []

    def tearDown(self):
        self.temp.cleanup()

    def service(self, callback):
        def runner(config, state):
            self.runs.append((config, state))
            return {"notify": False}
        return SentinelApiService(
            token=TOKEN,
            profiles={"approved": self.config},
            state_root=self.root / "state",
            runner=runner,
            prosper_authorizer=callback,
        )

    def test_permission_allows_execution(self):
        self.service(lambda: True).run("approved")
        self.assertEqual(len(self.runs), 1)

    def test_permission_denial_prevents_execution(self):
        with self.assertRaises(ApiError) as caught:
            self.service(lambda: False).run("approved")
        self.assertEqual(caught.exception.status, 403)
        self.assertFalse(self.runs)

    def test_gateway_failure_prevents_execution(self):
        def unavailable():
            raise ConnectionError("disconnected")
        with self.assertRaises(ApiError) as caught:
            self.service(unavailable).run("approved")
        self.assertEqual(caught.exception.status, 503)
        self.assertFalse(self.runs)

    def test_unconfigured_gateway_preserves_existing_behavior(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(build_prosper_authorizer())

    def test_invalid_gateway_hostname_rejected(self):
        with patch.dict(os.environ, {
            "PROSPER_GATEWAY_URL": "http://example.com:8080",
            "PROSPER_AGENT_KEY": "fake",
        }):
            with self.assertRaises(ValueError):
                build_prosper_authorizer()

    def test_missing_agent_key_rejected_at_startup(self):
        with patch.dict(os.environ, {"PROSPER_GATEWAY_URL": "http://127.0.0.1:8080"}, clear=True):
            with self.assertRaises(ValueError):
                build_prosper_authorizer()


if __name__ == "__main__":
    unittest.main()
