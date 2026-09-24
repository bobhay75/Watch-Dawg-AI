from __future__ import annotations

import base64
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from sentinel.api import (
    ApiError,
    MAX_REQUEST_BYTES,
    ProfileRateLimiter,
    SentinelApiService,
    build_handler,
    build_service_from_env,
    load_profile_paths,
    validate_api_token,
)


TOKEN = "test-token-with-at-least-thirty-two-characters"


class ManualClock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


class ApiHarness:
    def __init__(self, service: SentinelApiService) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(service))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "ApiHarness":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload=None,
        token: str | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        if raw_body is None and payload is not None:
            raw_body = json.dumps(payload).encode("utf-8")
        if raw_body is not None:
            request_headers.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_port,
            timeout=5,
        )
        connection.request(method, path, body=raw_body, headers=request_headers)
        response = connection.getresponse()
        body = response.read()
        response_headers = {key: value for key, value in response.getheaders()}
        connection.close()
        return response.status, json.loads(body), response_headers


class SentinelApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "approved.json"
        self.config.write_text('{"targets": []}\n', encoding="utf-8")
        self.calls = []

        def fake_runner(config_path: Path, state_path: Path) -> dict:
            self.calls.append((config_path, state_path))
            return {
                "notify": False,
                "targets_checked": 0,
                "new_alert_count": 0,
                "resolved_count": 0,
                "results": [],
                "discernment": {"quiet_is_healthy": True},
            }

        self.clock = ManualClock()
        self.service = SentinelApiService(
            token=TOKEN,
            profiles={"approved": self.config},
            state_root=self.root / "state",
            rate_limiter=ProfileRateLimiter(
                max_per_minute=3,
                cooldown_seconds=30,
                clock=self.clock,
            ),
            runner=fake_runner,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_health_is_public_but_reveals_no_profile_names(self) -> None:
        with ApiHarness(self.service) as api:
            status, body, headers = api.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["profiles_configured"], 1)
        self.assertNotIn("approved", str(body))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_access_log_never_records_query_values_or_unknown_paths(self) -> None:
        secret = "device-token-must-not-appear"
        with self.assertLogs("watch_dawg.sentinel.api", level="INFO") as captured:
            with ApiHarness(self.service) as api:
                status, _, _ = api.request(
                    "GET",
                    f"/unknown/{secret}?token={secret}",
                )
        self.assertEqual(status, 404)
        output = "\n".join(captured.output)
        self.assertNotIn(secret, output)
        self.assertIn("route=<unmatched>", output)

    def test_run_requires_valid_bearer_token(self) -> None:
        with ApiHarness(self.service) as api:
            status, body, headers = api.request(
                "POST",
                "/v1/run",
                payload={"profile": "approved"},
            )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")
        self.assertEqual(headers["WWW-Authenticate"], "Bearer")
        self.assertFalse(self.calls)

    def test_run_uses_only_server_owned_profile_configuration(self) -> None:
        with ApiHarness(self.service) as api:
            status, body, _ = api.request(
                "POST",
                "/v1/run",
                payload={"profile": "approved"},
                token=TOKEN,
            )
        self.assertEqual(status, 200)
        self.assertEqual(body["profile"], "approved")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], self.config)
        self.assertEqual(self.calls[0][1], self.root / "state" / "approved.json")

    def test_caller_supplied_targets_and_urls_are_rejected(self) -> None:
        with ApiHarness(self.service) as api:
            status, body, _ = api.request(
                "POST",
                "/v1/run",
                payload={
                    "profile": "approved",
                    "targets": [{"url": "http://127.0.0.1/admin"}],
                },
                token=TOKEN,
            )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")
        self.assertFalse(self.calls)

    def test_unknown_profile_is_not_run(self) -> None:
        with ApiHarness(self.service) as api:
            status, body, _ = api.request(
                "POST",
                "/v1/run",
                payload={"profile": "not-approved"},
                token=TOKEN,
            )
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "profile_not_found")
        self.assertFalse(self.calls)

    def test_profile_cooldown_returns_retry_after(self) -> None:
        with ApiHarness(self.service) as api:
            first, _, _ = api.request(
                "POST",
                "/v1/run",
                payload={"profile": "approved"},
                token=TOKEN,
            )
            self.clock.value += 0.5
            second, body, headers = api.request(
                "POST",
                "/v1/run",
                payload={"profile": "approved"},
                token=TOKEN,
            )
        self.assertEqual(first, 200)
        self.assertEqual(second, 429)
        self.assertEqual(body["error"]["code"], "rate_limited")
        self.assertEqual(headers["Retry-After"], "30")
        self.assertEqual(len(self.calls), 1)

    def test_process_rate_limit_applies_across_profiles(self) -> None:
        limiter = ProfileRateLimiter(
            max_per_minute=1,
            cooldown_seconds=0,
            clock=self.clock,
        )
        limiter.claim("first")
        with self.assertRaisesRegex(ApiError, "too recently") as raised:
            limiter.claim("second")
        self.assertEqual(raised.exception.status, 429)
        self.assertEqual(raised.exception.headers["Retry-After"], "60")

    def test_large_request_is_rejected_before_json_parsing(self) -> None:
        with ApiHarness(self.service) as api:
            status, body, _ = api.request(
                "POST",
                "/v1/run",
                raw_body=b"x" * (MAX_REQUEST_BYTES + 1),
                token=TOKEN,
            )
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "request_too_large")
        self.assertFalse(self.calls)

    def test_profile_loader_rejects_path_escape(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.json"
        outside.write_text('{"targets": []}\n', encoding="utf-8")
        try:
            with self.assertRaisesRegex(ValueError, "escapes"):
                load_profile_paths('{"bad":"../outside.json"}', self.root)
        finally:
            outside.unlink()

    def test_weak_api_token_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least"):
            validate_api_token("short")

    def test_api_token_with_whitespace_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "whitespace"):
            validate_api_token("x" * 32 + " ")

    def test_swarm_enrollment_requires_exact_proof_hmac_environment_key(self) -> None:
        environment = {
            "SENTINEL_API_TOKEN": TOKEN,
            "SENTINEL_SWARM_ENROLLMENTS_JSON": "{}",
        }
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(ValueError, "PROOF_HMAC_KEY.*required"):
                build_service_from_env()

        environment["SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64"] = base64.b64encode(
            b"too-short"
        ).decode()
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
                build_service_from_env()

        environment["SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64"] = base64.b64encode(
            b"p" * 32
        ).decode()
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(ValueError, "at least one enrolled"):
                build_service_from_env()

    def test_swarm_history_entry_cap_environment_is_forwarded(self) -> None:
        environment = {
            "SENTINEL_API_TOKEN": TOKEN,
            "SENTINEL_SWARM_ENROLLMENTS_JSON": "{}",
            "SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64": base64.b64encode(
                b"p" * 32
            ).decode(),
            "SENTINEL_SWARM_HISTORY_MAX_ENTRIES_PER_DEVICE": "17",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "sentinel.swarm_ingest.load_swarm_enrollment_source",
            return_value={"enrolled": object()},
        ), patch("sentinel.swarm_ingest.SwarmSnapshotIngestor") as ingestor_type:
            build_service_from_env()
        self.assertEqual(
            ingestor_type.call_args.kwargs["history_max_entries_per_device"],
            17,
        )


if __name__ == "__main__":
    unittest.main()
