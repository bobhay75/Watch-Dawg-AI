"""Conservative cross-source screening tests."""
import importlib.util
from pathlib import Path
import unittest

p=Path(__file__).resolve().parents[1]/"scripts"/"watchdawg_correlate.py"
spec=importlib.util.spec_from_file_location("watchdawg_correlate",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class CorrelateTests(unittest.TestCase):
    def setUp(self):
        self.noaa={"id":"n1","zones":["https://api.weather.gov/zones/forecast/MOZ092"],
                   "observed_at":"2026-11-17T09:00:00Z","headline":"Flood watch",
                   "source":{"url":"https://api.weather.gov/alerts/test"}}
        self.nasa={"id":"e1","missouri_point_match":True,
                   "event_dates":["2026-11-17T12:00:00Z"],"title":"Flooding",
                   "source":{"url":"https://eonet.gsfc.nasa.gov/api/v3/events/1"}}
    def test_candidate_is_not_corroboration(self):
        c=mod.candidate(self.noaa,self.nasa)
        self.assertEqual(c["judgment"],"candidate_only_not_corroborated")
        self.assertEqual(c["time_gap_hours"],3)
    def test_no_date_no_candidate(self):
        self.nasa["event_dates"]=[]
        self.assertIsNone(mod.candidate(self.noaa,self.nasa))
    def test_non_missouri_no_candidate(self):
        self.noaa["zones"]=["https://api.weather.gov/zones/forecast/CAZ562"]
        self.assertIsNone(mod.candidate(self.noaa,self.nasa))
    def test_outside_window(self):
        self.nasa["event_dates"]=["2026-11-01T12:00:00Z"]
        self.assertIsNone(mod.candidate(self.noaa,self.nasa))
    def test_no_missouri_nasa_point(self):
        self.nasa["missouri_point_match"]=False
        self.assertEqual(mod.correlate([self.noaa],[self.nasa]),[])

if __name__=="__main__":
    unittest.main()
