from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from sentinel.core import Finding, Observation, SentinelEngine, StateStore
from sentinel.http_watch import (
    HttpWatchPack,
    sanitize_http_url_for_evidence,
    validate_public_http_url,
)
from sentinel.log_watch import AccessLogWatchPack


class SequencePack:
    kind = "sequence"
    allowed_authorization_modes = {"owner"}

    def __init__(self, states: list[bool]):
        self.states = iter(states)

    def observe(self, target: dict[str, Any]) -> Observation:
        ok = next(self.states)
        return Observation(target_id=target["id"], kind=self.kind, ok=ok, facts={"ok": ok})

    def evaluate(self, target: dict[str, Any], current: Observation, previous: Observation | None) -> list[Finding]:
        if current.ok:
            return []
        return [Finding(target_id=current.target_id, code="BROKEN", severity="high", title="Broken", detail="Fixture is broken")]


class FakeHttpFetcher:
    def __init__(self, body: str, status: int = 200, final_url: str | None = None):
        self.body = body
        self.status = status
        self.final_url = final_url

    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]:
        return {
            "status": self.status,
            "final_url": self.final_url or url,
            "latency_ms": 25,
            "headers": {"content-type": "text/html"},
            "body": self.body,
            "body_bytes": len(self.body),
            "truncated": False,
        }


class SentinelEngineTests(unittest.TestCase):
    def test_alerts_once_then_emits_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(StateStore(Path(directory) / "state.json"), [SequencePack([True, False, False, True])])
            target = {"id": "fixture", "kind": "sequence", "authorization": {"mode": "owner"}}
            self.assertFalse(engine.run([target])["notify"])
            second = engine.run([target])
            self.assertEqual(second["new_alert_count"], 1)
            third = engine.run([target])
            self.assertFalse(third["notify"])
            fourth = engine.run([target])
            self.assertEqual(fourth["resolved_count"], 1)

    def test_missing_authorization_blocks_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(StateStore(Path(directory) / "state.json"), [SequencePack([True])])
            result = engine.run([{"id": "fixture", "kind": "sequence"}])
            alert = result["results"][0]["new_alerts"][0]
            self.assertEqual(alert["code"], "AUTHORIZATION_REQUIRED")
            self.assertEqual(alert["severity"], "critical")


class HttpWatchTests(unittest.TestCase):
    def test_private_network_target_is_blocked(self) -> None:
        with self.assertRaisesRegex(ValueError, "private"):
            validate_public_http_url("http://127.0.0.1/admin")

    def test_final_url_evidence_strips_credentials_and_rejects_bad_schemes(self) -> None:
        self.assertEqual(
            sanitize_http_url_for_evidence(
                "https://user:secret@example.com/landing?access_token=hidden#token"
            ),
            "https://example.com/landing",
        )
        self.assertEqual(
            sanitize_http_url_for_evidence(
                "file:///etc/passwd",
                fallback="https://example.com/",
            ),
            "https://example.com/",
        )

        observation = HttpWatchPack(
            FakeHttpFetcher(
                "ok",
                final_url=(
                    "https://user:secret@example.com/landing"
                    "?access_token=hidden#token"
                ),
            )
        ).observe({"id": "site", "url": "https://example.com/"})
        self.assertEqual(observation.facts["final_url"], "https://example.com/landing")
        self.assertEqual(observation.evidence, ["https://example.com/landing"])
        self.assertNotIn("secret", str(observation.to_dict()))
        self.assertNotIn("hidden", str(observation.to_dict()))

    def test_detects_zero_jsonld_price_and_missing_marker(self) -> None:
        body = """<html><head><title>Show</title><script type="application/ld+json">{"@type":"Event","offers":{"@type":"Offer","price":0}}</script></head><body>Buy Tickets</body></html>"""
        pack = HttpWatchPack(FakeHttpFetcher(body))
        target = {
            "id": "event",
            "kind": "http",
            "url": "https://example.com/event",
            "checks": {"contains": ["Artist Name"], "jsonld_offer_price_nonzero": True},
        }
        observation = pack.observe(target)
        codes = {finding.code for finding in pack.evaluate(target, observation, None)}
        self.assertIn("JSONLD_OFFER_PRICE_ZERO", codes)
        self.assertTrue(any(code.startswith("REQUIRED_TEXT_MISSING_") for code in codes))

    def test_content_change_is_an_event_not_a_persistent_condition(self) -> None:
        target = {
            "id": "event",
            "kind": "http",
            "url": "https://example.com/event",
            "authorization": {"mode": "public"},
            "checks": {"track_content": True},
        }
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            SentinelEngine(StateStore(state_path), [HttpWatchPack(FakeHttpFetcher("first"))]).run([target])
            changed = SentinelEngine(StateStore(state_path), [HttpWatchPack(FakeHttpFetcher("second"))]).run([target])
            self.assertEqual(changed["new_alert_count"], 1)
            unchanged = SentinelEngine(StateStore(state_path), [HttpWatchPack(FakeHttpFetcher("second"))]).run([target])
            self.assertFalse(unchanged["notify"])
            self.assertEqual(unchanged["resolved_count"], 0)


class AccessLogTests(unittest.TestCase):
    def test_log_path_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pack = AccessLogWatchPack(Path(directory) / "logs")
            with self.assertRaisesRegex(ValueError, "escapes"):
                pack.observe({"id": "web", "path": "../outside.log"})

    def test_detects_errors_and_probe_patterns_without_raw_ips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "access.log"
            log.write_text(
                '203.0.113.10 - - [05/Sep/2026:10:00:00 -0500] "GET /.env HTTP/1.1" 404 10 "-" "bot"\n'
                '203.0.113.11 - - [05/Sep/2026:10:00:01 -0500] "GET / HTTP/1.1" 500 10 "-" "browser"\n',
                encoding="utf-8",
            )
            pack = AccessLogWatchPack(directory)
            target = {"id": "web", "path": "access.log", "checks": {"max_5xx_rate": 0.10}}
            observation = pack.observe(target)
            findings = pack.evaluate(target, observation, None)
            codes = {finding.code for finding in findings}
            self.assertIn("SERVER_ERROR_RATE_HIGH", codes)
            self.assertIn("SUSPICIOUS_PATH_ACTIVITY", codes)
            self.assertNotIn("203.0.113.10", str(observation.facts))


if __name__ == "__main__":
    unittest.main()
