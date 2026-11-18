import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import intelligence_common as common
import watchdawg_correlate as correlate


class ProvenanceCorrelationTests(unittest.TestCase):
    def test_snapshot_references_digests_and_legacy_status(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'test-observations.json'
            raw = Path(folder) / 'test-raw.json'
            raw.write_bytes(b'{}')
            valid = {'raw_file': raw.name, 'raw_sha256': hashlib.sha256(b'{}').hexdigest()}
            path.write_text(json.dumps(valid))
            self.assertEqual(common.load_snapshot(path), valid)
            for changes in [{'raw_sha256': None}, {'raw_sha256': 'bad'},
                            {'raw_file': '../test-raw.json'}, {'raw_file': str(raw)},
                            {'raw_file': 'missing-raw.json'}]:
                path.write_text(json.dumps(dict(valid, **changes)))
                with self.assertRaises((OSError, ValueError)):
                    common.load_snapshot(path)
            path.write_text('{}')
            legacy = common.load_snapshot(path)
            self.assertEqual(common.snapshot_identity(legacy)['provenance_status'], 'legacy_unverified')
            self.assertNotEqual(common.snapshot_identity(valid)['snapshot_sha256'],
                                common.snapshot_identity(dict(valid, source='changed'))['snapshot_sha256'])

    def test_symlink_raw_manifest_and_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / 'original'
            original.write_bytes(b'{}')
            raw = root / 'test-raw.json'
            raw.symlink_to(original)
            path = root / 'test-observations.json'
            path.write_text(json.dumps({'raw_file': raw.name, 'raw_sha256': hashlib.sha256(b'{}').hexdigest()}))
            with self.assertRaises(ValueError):
                common.load_snapshot(path)
            alias = root / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                common.load_snapshot(alias)
            from unittest.mock import patch
            with patch.object(common, 'MAX_BYTES', 1):
                with self.assertRaises(ValueError):
                    common.load_snapshot(path)

    def test_exact_72_hour_boundary_offsets_and_no_mutation(self):
        n = {'id': 'n1', 'zones': ['https://api.weather.gov/zones/forecast/MOZ092'],
             'observed_at': '2026-11-17T09:00:00Z', 'source': {'url': 'https://api.weather.gov/alerts/test'}}
        e = {'id': 'e1', 'missouri_point_match': True,
             'source': {'url': 'https://eonet.gsfc.nasa.gov/api/v3/events/test'}}
        observed = dt.datetime(2026, 11, 17, 9, tzinfo=dt.timezone.utc)
        for delta, matches in [(72*3600, True), (-72*3600, True), (72*3600+1, False), (-72*3600-1, False)]:
            e['missouri_event_dates'] = [(observed + dt.timedelta(seconds=delta)).isoformat()]
            before = copy.deepcopy((n, e))
            result = correlate.candidate(n, e)
            self.assertEqual(result is not None, matches)
            if result:
                self.assertFalse(result['publication_approved'])
                self.assertEqual(result['judgment'], 'candidate_only_not_corroborated')
            self.assertEqual((n, e), before)
        for date in ['2026-11-17T03:00:00-06:00', '2026-11-17T10:00:00+01:00']:
            e['missouri_event_dates'] = [date]
            self.assertEqual(correlate.candidate(n, e)['time_gap_hours'], 0)
        for date in ['2026-11-17T09:00:00', 'garbage', None]:
            e['missouri_event_dates'] = [date]
            self.assertIsNone(correlate.candidate(n, e))
        e['missouri_event_dates'] = [observed.isoformat()]
        for identity in [None, '', ' ', 1]:
            e['id'] = identity
            self.assertIsNone(correlate.candidate(n, e))
