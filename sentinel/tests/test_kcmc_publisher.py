import tempfile
import unittest
from pathlib import Path

from sentinel.kcmc_publisher import LOGIN, URL, MinimizedFetcher, run
from unittest.mock import patch


class Fetcher:
    def __init__(self, status=200, landing=LOGIN, body="Staff Sign In", latency=100):
        self.status, self.landing, self.body, self.latency = status, landing, body, latency

    def fetch(self, url, timeout_seconds, max_body_bytes):
        assert url == URL
        return {"status": self.status, "final_url": self.landing, "body": self.body,
                "latency_ms": self.latency, "headers": {}, "body_bytes": len(self.body), "truncated": False}


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state.json"
        self.report = Path(self.temp.name) / "report.json"

    def check(self, fetcher):
        return run(self.state, self.report, fetcher)

    def test_login_is_recorded_but_not_an_outage(self):
        result = self.check(Fetcher())
        self.assertEqual(result["targets_checked"], 1)
        self.assertEqual(result["new_actionable_alert_count"], 0)
        self.assertEqual(result["results"][0]["current_findings"][0]["code"], "PUBLISHER_AUTH_BOUNDARY")
        self.assertFalse(self.check(Fetcher())["notify"])

    def test_failure_deduplication_and_recovery(self):
        self.check(Fetcher())
        failed = self.check(Fetcher(status=503))
        self.assertGreater(failed["new_actionable_alert_count"], 0)
        again = self.check(Fetcher(status=503))
        self.assertEqual(again["new_actionable_alert_count"], 0)
        self.assertGreater(again["operational_finding_count"], 0)
        recovered = self.check(Fetcher())
        self.assertGreater(recovered["resolved_count"], 0)

    def test_unexpected_destination_is_actionable(self):
        self.assertGreater(self.check(Fetcher(landing="https://example.com/"))["new_actionable_alert_count"], 0)

    def test_php_error_and_latency_detected(self):
        result = self.check(Fetcher(body="Fatal error: something", latency=6000))
        self.assertEqual(result["new_actionable_alert_count"], 2)

    def test_network_failure_is_monitor_blind_spot(self):
        class Broken:
            def fetch(self, *args):
                raise TimeoutError("timeout")
        result = self.check(Broken())
        self.assertEqual(result["results"][0]["current_findings"][0]["code"], "HTTP_OBSERVATION_FAILED")

    def test_cookie_headers_removed(self):
        with patch("sentinel.kcmc_publisher.SafeHttpFetcher.fetch", return_value={"headers": {"set-cookie": "secret"}}):
            self.assertEqual(MinimizedFetcher().fetch(URL, 15, 500000)["headers"], {})


if __name__ == "__main__":
    unittest.main()
