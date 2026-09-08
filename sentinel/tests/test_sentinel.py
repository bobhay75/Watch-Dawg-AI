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
from sentinel.discernment import build_discernment


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
    def test_discernment_exposes_deficits_and_builds_measurable_prosperity_plan(self) -> None:
        result = build_discernment([{
            "target_id": "site",
            "evidence_sources": [],
            "current_findings": [Finding(
                target_id="site",
                code="HTTP_LATENCY_HIGH",
                severity="medium",
                title="Slow",
                detail="Response exceeded the configured threshold.",
            ).to_dict()],
        }])
        self.assertEqual(result["blind_spots"][0]["target_id"], "site")
        self.assertEqual(result["deficit_analysis"][0]["impact_status"], "UNQUANTIFIED")
        self.assertIn("customer friction", result["prosperity_plan"][0]["objective"])
        self.assertIn("before-and-after", result["prosperity_plan"][0]["verification"])
        self.assertEqual(result["prosperity_plan"][0]["financial_claim"], "NOT CALCULATED")

    def test_discernment_uses_conservative_defaults_for_legacy_findings(self) -> None:
        result = build_discernment([{
            "target_id": "legacy",
            "evidence_sources": ["legacy-record"],
            "current_findings": [{
                "target_id": "legacy",
                "code": "LEGACY_FINDING",
                "severity": "medium",
                "title": "Legacy finding",
                "detail": "This record predates truth and confidence fields.",
            }],
        }])
        self.assertEqual(result["deficit_analysis"][0]["truth"], "INFERENCE")
        self.assertEqual(result["deficit_analysis"][0]["confidence"], 0)
        self.assertEqual(result["preventive_priorities"][0]["truth"], "INFERENCE")
        self.assertEqual(result["preventive_priorities"][0]["confidence"], 0)

    def test_finding_rejects_invalid_confidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "confidence"):
            Finding(
                target_id="x",
                code="X",
                severity="low",
                title="x",
                detail="x",
                confidence=101,
            )

    def test_finding_rejects_invalid_evidence_grade(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence grade"):
            Finding(
                target_id="x",
                code="X",
                severity="low",
                title="x",
                detail="x",
                evidence_grade="F",
            )

    def test_alerts_once_then_emits_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(StateStore(Path(directory) / "state.json"), [SequencePack([True, False, False, True])])
            target = {"id": "fixture", "kind": "sequence", "authorization": {"mode": "owner"}}
            self.assertFalse(engine.run([target])["notify"])
            second = engine.run([target])
            self.assertEqual(second["new_alert_count"], 1)
            audit_fields = {
                "deficit",
                "why_it_matters",
                "preventive_action",
                "prosperity_lever",
                "success_metric",
                "verification",
            }
            current = second["results"][0]["current_findings"][0]
            new_alert = second["results"][0]["new_alerts"][0]
            self.assertTrue(audit_fields.issubset(current))
            self.assertTrue(audit_fields.issubset(new_alert))
            self.assertEqual(current["fingerprint"], new_alert["fingerprint"])
            third = engine.run([target])
            self.assertFalse(third["notify"])
            fourth = engine.run([target])
            self.assertEqual(fourth["resolved_count"], 1)
            resolved = fourth["results"][0]["resolved"][0]
            self.assertTrue(audit_fields.issubset(resolved))
            self.assertEqual(new_alert["fingerprint"], resolved["fingerprint"])
            self.assertEqual(resolved["resolved_at"], fourth["results"][0]["observed_at"])

    def test_missing_authorization_blocks_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(StateStore(Path(directory) / "state.json"), [SequencePack([True])])
            result = engine.run([{"id": "fixture", "kind": "sequence"}])
            alert = result["results"][0]["new_alerts"][0]
            self.assertEqual(alert["code"], "AUTHORIZATION_REQUIRED")
            self.assertEqual(alert["severity"], "critical")
            blind_spot = result["discernment"]["blind_spots"][0]
            self.assertIn("no supported authorization mode", blind_spot["gap"])
            self.assertNotIn("No evidence source", blind_spot["gap"])
            self.assertIn("authority before observation", blind_spot["improvement"])

    def test_unsupported_authorization_mode_reports_accurate_blind_spot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(StateStore(Path(directory) / "state.json"), [SequencePack([True])])
            result = engine.run([{
                "id": "fixture",
                "kind": "sequence",
                "authorization": {"mode": "unsupported"},
            }])
            alert = result["results"][0]["new_alerts"][0]
            self.assertEqual(alert["code"], "AUTHORIZATION_REQUIRED")
            self.assertIn("missing or unsupported", alert["title"])
            blind_spot = result["discernment"]["blind_spots"][0]
            self.assertIn("no supported authorization mode", blind_spot["gap"])

    def test_insufficient_authorization_reports_scope_blind_spot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(StateStore(Path(directory) / "state.json"), [SequencePack([True])])
            result = engine.run([{
                "id": "fixture",
                "kind": "sequence",
                "authorization": {"mode": "public"},
            }])
            alert = result["results"][0]["new_alerts"][0]
            self.assertEqual(alert["code"], "AUTHORIZATION_SCOPE_DENIED")
            self.assertIn("does not cover", alert["deficit"])
            self.assertIn("before observation", alert["verification"])
            blind_spot = result["discernment"]["blind_spots"][0]
            self.assertIn("outside this watch pack's allowed scope", blind_spot["gap"])
            self.assertNotIn("No evidence source", blind_spot["gap"])
            self.assertIn("additional methods and scope", blind_spot["improvement"])


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
