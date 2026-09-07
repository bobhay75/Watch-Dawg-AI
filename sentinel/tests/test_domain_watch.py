from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.core import SentinelEngine, StateStore
from sentinel.domain_watch import DnsTlsWatchPack


class FakeInspector:
    def __init__(self, observations):
        self.observations = iter(observations)

    def inspect(self, hostname, port, timeout_seconds):
        return next(self.observations)


def domain_facts(addresses, days=90, tls_version="TLSv1.3"):
    return {
        "addresses": addresses,
        "tls_version": tls_version,
        "cipher": "TLS_AES_256_GCM_SHA384",
        "certificate_subject": {"commonName": "example.com"},
        "certificate_issuer": {"commonName": "Example CA"},
        "certificate_expires_at": "2026-12-05T00:00:00+00:00",
        "certificate_days_remaining": days,
    }


class DnsTlsWatchTests(unittest.TestCase):
    def test_certificate_warning_and_tls_floor(self):
        pack = DnsTlsWatchPack(FakeInspector([domain_facts(["203.0.113.5"], 20, "TLSv1.1")]))
        target = {
            "id": "domain",
            "kind": "dns_tls",
            "hostname": "example.com",
            "checks": {
                "tls_expiry_warning_days": 30,
                "tls_expiry_critical_days": 7,
                "minimum_tls_version": "TLSv1.2",
            },
        }
        observation = pack.observe(target)
        codes = {item.code for item in pack.evaluate(target, observation, None)}
        self.assertEqual(
            codes,
            {"TLS_CERTIFICATE_EXPIRY_WARNING", "TLS_VERSION_BELOW_MINIMUM"},
        )

    def test_dns_change_is_one_time_event_without_false_recovery(self):
        inspector = FakeInspector([
            domain_facts(["203.0.113.5"]),
            domain_facts(["203.0.113.6"]),
            domain_facts(["203.0.113.6"]),
        ])
        target = {
            "id": "domain",
            "kind": "dns_tls",
            "hostname": "example.com",
            "authorization": {"mode": "public"},
        }
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(
                StateStore(Path(directory) / "state.json"),
                [DnsTlsWatchPack(inspector)],
            )
            self.assertFalse(engine.run([target])["notify"])
            changed = engine.run([target])
            self.assertEqual(changed["new_alert_count"], 1)
            unchanged = engine.run([target])
            self.assertFalse(unchanged["notify"])
            self.assertEqual(unchanged["resolved_count"], 0)

    def test_rejects_non_hostname_target(self):
        pack = DnsTlsWatchPack(FakeInspector([]))
        with self.assertRaisesRegex(ValueError, "plain hostname"):
            pack.observe({"id": "domain", "hostname": "https://example.com/path"})


if __name__ == "__main__":
    unittest.main()
