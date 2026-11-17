"""Offline tests for the NOAA ingestion adapter. Run: python3 -m unittest discover -s tests -p 'test_skywatch_noaa.py'"""
import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "skywatch_noaa_ingest.py"
spec = importlib.util.spec_from_file_location("skywatch_noaa_ingest", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class NOAAIngestTests(unittest.TestCase):
    def test_normalizes_and_keeps_human_gate(self):
        identifier = "https://api.weather.gov/alerts/urn:oid:example"
        data = {"type": "FeatureCollection", "features": [
            {"properties": {"id": identifier, "sent": "2026-11-16T00:00:00Z",
                            "headline": "Test alert", "severity": "Moderate"}}]}
        records = mod.normalize(data, "2026-11-16T01:00:00Z")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["claim_status"], "observed")
        self.assertFalse(records[0]["publication_approved"])
        self.assertEqual(records[0]["evidence"][0]["url"], identifier)

    def test_rejects_invalid_source(self):
        data = {"features": [{"properties": {"id": "https://example.org/fake",
                    "sent": "2026-11-16T00:00:00Z"}}]}
        self.assertEqual(mod.normalize(data, "2026-11-16T01:00:00Z"), [])

    def test_rejects_invalid_structure(self):
        with self.assertRaises(ValueError):
            mod.normalize({"features": "not-an-array"}, "2026-11-16T01:00:00Z")

if __name__ == "__main__":
    unittest.main()
