"""Offline tests for NOAA snapshot change detection and HTML escaping."""
import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("skywatch_dashboard",pathlib.Path(__file__).resolve().parents[1]/"scripts"/"skywatch_dashboard.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
class DashboardTests(unittest.TestCase):
    def test_changes(self):
        old=[{"id":"a"},{"id":"b"}]
        new=[{"id":"b"},{"id":"c"}]
        self.assertEqual(mod.changes(old,new),{"new":["c"],"continuing":["b"],"no_longer_active":["a"]})
    def test_escaped_html(self):
        item={"id":"1","severity":"Severe","headline":"<script>alert(1)</script>",
              "source":{"url":"https://api.weather.gov/alerts/test"}}
        page=mod.render([item],{"new":["1"],"continuing":[],"no_longer_active":[]},"2026-11-17")
        self.assertNotIn("<script>",page)
        self.assertIn("&lt;script&gt;",page)
        self.assertIn("PRIVATE DRAFT",page)
    def test_baseline_skips_empty_legacy_snapshots(self):
        snapshots=[("a",{"observations":[]}),("b",{"observations":[{"id":"x"}]}),("c",{"observations":[{"id":"x"},{"id":"y"}]})]
        self.assertEqual(mod.select_baseline(snapshots),snapshots[1][1])

    def test_baseline_unavailable(self):
        snapshots=[("a",{"observations":[]}),("b",{"observations":[{"id":"x"}]})]
        self.assertIsNone(mod.select_baseline(snapshots))

    def test_empty(self):
        page=mod.render([],{"new":[],"continuing":[],"no_longer_active":[]},"now")
        self.assertIn("Current alerts",page)
if __name__=="__main__":
    unittest.main()
