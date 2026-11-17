"""Cross-source coverage audit tests; no unsupported event matching."""
import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/"scripts"/"watchdawg_cross_source.py"
spec=importlib.util.spec_from_file_location("watchdawg_cross_source",path)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class CoverageTests(unittest.TestCase):
    def test_missing_sources_are_not_zero(self):
        result=mod.summarize(None,None,None)
        self.assertIsNone(result["national_noaa"])
        self.assertEqual(result["sources_present"],0)
        self.assertEqual(result["cross_source_event_corroboration"],"not_assessed")
    def test_counts_and_no_corroboration(self):
        result=mod.summarize({"observations":[{},{}]},{"observations":[]},
            {"events":[{"missouri_point_match":True,"ozarks_point_match":True}]})
        self.assertEqual(result["national_noaa"],2)
        self.assertEqual(result["missouri_noaa"],0)
        self.assertEqual(result["nasa_ozarks_point_matches"],1)
        self.assertFalse(result["publication_approved"])
        self.assertIn("NOT ASSESSED",mod.render(result,{"NOAA":"now"}))
    def test_malformed_input(self):
        with self.assertRaises(ValueError):
            mod.summarize({"observations":None},None,None)

if __name__=="__main__":
    unittest.main()
