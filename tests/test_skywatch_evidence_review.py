"""Offline provenance review tests."""
import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "skywatch_evidence_review.py"
spec = importlib.util.spec_from_file_location("skywatch_evidence_review", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ReviewTests(unittest.TestCase):
    def record(self, url="https://api.weather.gov/alerts/urn:oid:test"):
        return {"id": "abc", "source": {"name": "NOAA National Weather Service", "url": url},
                "observed_at": "2026-11-17T08:00:00Z",
                "evidence": [{"kind": "primary", "url": url}]}

    def test_documented_is_not_verified(self):
        result = module.review({"observations": [self.record()]})
        self.assertEqual(result["records"][0]["review_status"], "source_documented")
        self.assertFalse(result["records"][0]["independently_corrob_or_verified"])
        self.assertFalse(result["public_release_approved"])

    def test_rejects_lookalike_domain(self):
        result = module.review({"observations": [self.record("https://api.weather.gov.evil.example/alerts/a")]})
        self.assertEqual(result["records"][0]["review_status"], "needs_review")

    def test_requires_evidence(self):
        record = self.record()
        record["evidence"] = []
        self.assertEqual(module.review({"observations": [record]})["records"][0]["review_status"], "needs_review")

    def test_deduplicates(self):
        result = module.review({"observations": [self.record(), self.record()]})
        self.assertEqual(len(result["records"]), 1)

if __name__ == "__main__":
    unittest.main()
