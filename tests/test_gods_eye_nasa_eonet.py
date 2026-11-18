"""Offline tests for NASA EONET adapter."""
import importlib.util
from pathlib import Path
import unittest
p=Path(__file__).resolve().parents[1]/"scripts"/"gods_eye_nasa_eonet.py"
spec=importlib.util.spec_from_file_location("gods_eye_nasa_eonet",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
class NasaTests(unittest.TestCase):
    def test_bounds(self):
        self.assertTrue(mod.in_bounds((-93.2,36.7),mod.OZARKS))
        self.assertFalse(mod.in_bounds((-120,40),mod.MISSOURI))
    def test_normalize_and_no_coordinates(self):
        doc={"events":[{"id":"EONET_1","title":"Example fire","link":"https://eonet.gsfc.nasa.gov/api/v3/events/EONET_1",
             "categories":[{"title":"Wildfires"}],"geometry":[{"type":"Point","coordinates":[-93.2,36.7]}]}]}
        records=mod.normalize(doc,"now")
        self.assertEqual(len(records),1)
        self.assertTrue(records[0]["ozarks_point_match"])
        self.assertNotIn("geometry",records[0])
        self.assertNotIn("coordinates",records[0])
        self.assertIn("cataloged_not_independently_verified",records[0]["evidence_status"])
    def test_reject_malformed(self):
        with self.assertRaises(ValueError):
            mod.normalize({"events":None},"now")
    def test_source_host(self):
        self.assertFalse(mod.valid_link("https://eonet.gsfc.nasa.gov.evil.test/x"))
        self.assertTrue(mod.valid_link("https://eonet.gsfc.nasa.gov/api/v3/events/EONET_1"))
if __name__=="__main__":
    unittest.main()
