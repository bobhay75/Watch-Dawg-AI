"""Offline report tests. Run: python3 -m unittest discover -s tests -p 'test_skywatch_report.py'"""
import importlib.util
import json
import pathlib
import tempfile
import unittest

module_path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "skywatch_report.py"
spec = importlib.util.spec_from_file_location("skywatch_report", module_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class SkyWatchReportTests(unittest.TestCase):
    def test_source_link_and_human_gate(self):
        data = {"retrieved_at": "2026-11-17T00:00:00Z", "raw_sha256": "abc",
                "observations": [{"id": "1", "category": "atmosphere",
                "severity": "Severe", "headline": "Wind Advisory",
                "source": {"name": "NOAA National Weather Service",
                           "url": "https://api.weather.gov/alerts/test"}}]}
        report = mod.build_report(data)
        self.assertIn("1 unique NOAA alerts", report)
        self.assertIn("Severe: 1", report)
        self.assertIn("Not independently verified", report)
        self.assertIn("https://api.weather.gov/alerts/test", report)

    def test_latest_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "20261117T010000Z-observations.json"
            path.write_text(json.dumps({"observations": []}), encoding="utf-8")
            self.assertEqual(mod.load_latest(folder)[0], path)

    def test_no_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                mod.load_latest(folder)

if __name__ == "__main__":
    unittest.main()
