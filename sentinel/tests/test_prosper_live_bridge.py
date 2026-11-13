"""Live loopback HTTP integration tests for the Prosper -> Sentinel guard.

This exercises the real HTTP adapter and Sentinel service, with a deterministic
mock authorization server. It does not claim to test a deployed Prosper instance.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from sentinel.api import ApiError, SentinelApiService
from sentinel.prosper_guard import build_prosper_authorizer

TOKEN = "sentinel-test-token-with-more-than-32-characters"


class GatewayHandler(BaseHTTPRequestHandler):
    allowed = True
    key = "integration-test-agent-key"
    calls = []

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size))
        type(self).calls.append((self.path, body, self.headers.get("X-Agent-Key")))
        if self.path != "/authorize" or self.headers.get("X-Agent-Key") != self.key:
            self.send_response(401)
            result = {"error": "unauthorized"}
        else:
            self.send_response(200)
            result = {"allowed": type(self).allowed}
        data = json.dumps(result).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class LiveBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = root / "approved.json"
        self.config.write_text('{"targets":[]}', encoding="utf-8")
        self.runs = []
        GatewayHandler.allowed = True
        GatewayHandler.calls = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.env = patch.dict(os.environ, {
            "PROSPER_GATEWAY_URL": f"http://127.0.0.1:{self.server.server_port}",
            "PROSPER_AGENT_KEY": GatewayHandler.key,
        })
        self.env.start()
        self.service = SentinelApiService(
            token=TOKEN,
            profiles={"approved": self.config},
            state_root=root / "state",
            prosper_authorizer=build_prosper_authorizer(),
            runner=lambda *_: self.runs.append("executed") or {"notify": False},
        )

    def tearDown(self):
        self.env.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def test_allow_then_revoke_blocks_execution(self):
        self.service.run("approved")
        self.assertEqual(self.runs, ["executed"])
        GatewayHandler.allowed = False
        with self.assertRaises(ApiError) as caught:
            self.service.run("approved")
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(self.runs, ["executed"])
        self.assertEqual(GatewayHandler.calls, [
            ("/authorize", {"agent_id": "watch-dawg", "action": "sentinel.run"}, GatewayHandler.key),
            ("/authorize", {"agent_id": "watch-dawg", "action": "sentinel.run"}, GatewayHandler.key),
        ])

    def test_unavailable_gateway_fails_closed(self):
        self.server.shutdown()
        self.server.server_close()
        with self.assertRaises(ApiError) as caught:
            self.service.run("approved")
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(self.runs, [])


if __name__ == "__main__":
    unittest.main()
