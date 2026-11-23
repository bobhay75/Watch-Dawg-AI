"""Missouri collector offline unit tests."""
import importlib.util
from pathlib import Path
import sys
import unittest

scripts=Path(__file__).resolve().parents[1]/"scripts"
sys.path.insert(0,str(scripts))
spec=importlib.util.spec_from_file_location("skywatch_missouri",scripts/"skywatch_missouri.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class MissouriTests(unittest.TestCase):
    def test_local_keyword_priority(self):
        self.assertTrue(mod.local_priority({"area":"Taney County, Missouri"}))
        self.assertFalse(mod.local_priority({"area":"Jackson County, Missouri"}))
    def test_empty_feed(self):
        result=mod.render([],"2026-11-17T10:00:00Z")
        self.assertIn("Missouri alerts: 0",result)
        self.assertIn("not a guarantee of safety",result)
    def test_html_escaping(self):
        record={"severity":"Severe","headline":"<unsafe>","area":"Taney",
                "source":{"url":"https://api.weather.gov/alerts/example"}}
        page=mod.render([record],"now")
        self.assertIn("&lt;unsafe&gt;",page)
        self.assertNotIn("<unsafe>",page)
        self.assertIn("OZARKS REVIEW PRIORITY",page)

if __name__=="__main__":
    unittest.main()
