"""Offline regional dashboard tests."""
import importlib.util
from pathlib import Path
import unittest

p=Path(__file__).resolve().parents[1]/"scripts"/"skywatch_regional_dashboard.py"
spec=importlib.util.spec_from_file_location("skywatch_regional_dashboard",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class RegionalTests(unittest.TestCase):
    def test_missouri_zone(self):
        self.assertTrue(mod.is_missouri({"zones":["https://api.weather.gov/zones/forecast/MOZ088"]}))
        self.assertFalse(mod.is_missouri({"zones":["https://api.weather.gov/zones/forecast/CAZ562"]}))
    def test_groups_and_escapes(self):
        records=[{"event":"Wind <script>","severity":"Severe","zones":[],"headline":"<script>",
                  "source":{"url":"https://api.weather.gov/alerts/test"}}]
        page=mod.render(records,"2026-11-17")
        self.assertIn("1 event groups",page)
        self.assertNotIn("<script></script>",page)
        self.assertIn("&lt;script&gt;",page)
        self.assertIn("PRIVATE DRAFT",page)
    def test_source_host(self):
        self.assertTrue(mod.valid_source("https://api.weather.gov/alerts/test"))
        self.assertFalse(mod.valid_source("https://api.weather.gov.evil.test/alerts/test"))
if __name__=="__main__":
    unittest.main()
