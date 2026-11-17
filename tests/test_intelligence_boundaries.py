"""Regression tests for evidence integrity, untrusted feeds and coarse correlation."""
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import intelligence_common as common
import gods_eye_nasa_eonet as nasa
import skywatch_noaa_ingest as noaa
import watchdawg_correlate as correlation
import watchdawg_cross_source as coverage


class IntelligenceBoundaries(unittest.TestCase):
    def alert(self):
        return {'id': 'n1', 'zones': ['https://api.weather.gov/zones/forecast/MOZ092'],
                'observed_at': '2026-11-17T09:00:00Z',
                'source': {'url': 'https://api.weather.gov/alerts/test'}}

    def test_geometry_date_must_belong_to_missouri(self):
        event = {'id': 'EONET_1', 'geometry': [
            {'type': 'Point', 'coordinates': [-93, 37], 'date': '2026-10-01T12:00:00Z'},
            {'type': 'Point', 'coordinates': [-120, 40], 'date': '2026-11-17T12:00:00Z'}]}
        row = nasa.normalize({'events': [event]}, 'now')[0]
        self.assertIsNone(correlation.candidate(self.alert(), row))
        event['geometry'][0]['date'] = '2026-11-17T12:00:00Z'
        row = nasa.normalize({'events': [event]}, 'now')[0]
        self.assertEqual(correlation.candidate(self.alert(), row)['time_gap_hours'], 3)
        self.assertNotIn('geometry', row)
        self.assertNotIn('coordinates', row)

    def test_legacy_dates_do_not_imply_geographic_time_overlap(self):
        row = {'missouri_point_match': True, 'event_dates': ['2026-11-17T12:00:00Z']}
        self.assertIsNone(correlation.candidate(self.alert(), row))

    def test_source_urls_reject_credentials_ports_controls_and_lookalikes(self):
        for url in ['https://user:pass@api.weather.gov/alerts/test',
                    'https://api.weather.gov:444/alerts/test',
                    'https://api.weather.gov.evil.test/alerts/test',
                    'https://api.weather.gov/alerts/test\n', 'https://[bad/alerts/test']:
            self.assertFalse(common.noaa_url(url), url)
        self.assertTrue(common.noaa_url('https://api.weather.gov/alerts/urn:oid:test'))

    def test_malformed_nested_fields_and_duplicates(self):
        for malformed in [True, 5, 'bad', {'bad': True}, None]:
            row = nasa.normalize({'events': [{'id': 'EONET_1', 'geometry': malformed,
                                             'categories': malformed}]}, 'now')[0]
            self.assertFalse(row['missouri_point_match'])
        feature = {'properties': {'id': 'https://api.weather.gov/alerts/test',
                   'sent': '2026-11-17T09:00:00Z', 'affectedZones': 5}}
        rows = noaa.normalize({'features': [feature, feature]}, 'now')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['zones'], [])
        feature['properties']['sent'] = 'not a date'
        self.assertEqual(noaa.normalize({'features': [feature]}, 'now'), [])
        self.assertEqual(nasa.normalize({'events': [{'id': '../?evil'}]}, 'now'), [])

    def test_point_types_and_untrusted_rendered_source(self):
        for xy in [[True, 37], ['-93', 37], [float('nan'), 37], [float('inf'), 37]]:
            self.assertIsNone(nasa.point({'type': 'Point', 'coordinates': xy}))
        row = nasa.normalize({'events': [{'id': 'EONET_1'}]}, 'now')[0]
        row['source']['url'] = 'javascript:alert(1)'
        self.assertNotIn('javascript:', nasa.render([row], 'now'))

    def test_forged_zone_and_truthy_match_do_not_create_candidate(self):
        row = nasa.normalize({'events': [{'id': 'EONET_1', 'geometry': [
            {'type': 'Point', 'coordinates': [-93, 37], 'date': '2026-11-17T12:00:00Z'}]}]}, 'now')[0]
        alert = self.alert()
        for zones in [['https://evil.test/MOZ092'], ['MOZ092'], ['https://api.weather.gov/zones/forecast/MOZjunk'], 5]:
            alert['zones'] = zones
            self.assertIsNone(correlation.candidate(alert, row))
        row['missouri_point_match'] = 'false'
        self.assertIsNone(correlation.candidate(self.alert(), row))
        result = coverage.summarize(None, None, {'events': [row]})
        self.assertEqual(result['nasa_missouri_point_matches'], 0)
        with self.assertRaises(ValueError):
            coverage.summarize([], None, None)

    def test_exact_raw_bytes_retained_with_unique_private_manifests(self):
        raw = b'{ "events" : [] }\n'
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / 'private'
            for _ in range(2):
                common.save_snapshot(folder, json.loads(raw), {'events': []}, raw)
            files = list(folder.glob('*-observations.json'))
            self.assertEqual(len(files), 2)
            for file in files:
                doc = json.loads(file.read_text())
                self.assertFalse(doc['public_release_approved'])
                self.assertEqual(doc['raw_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual((folder / doc['raw_file']).read_bytes(), raw)
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)

    def test_raw_tampering_stops_snapshot_consumers(self):
        with tempfile.TemporaryDirectory() as temp:
            common.save_snapshot(temp, {}, {'events': []})
            path = next(Path(temp).glob('*-observations.json'))
            doc = common.load_snapshot(path)
            (Path(temp) / doc['raw_file']).write_bytes(b'changed')
            with self.assertRaises(ValueError):
                correlation.load_latest(Path(temp))
            with self.assertRaises(ValueError):
                coverage.latest(temp, '*-observations.json')

    def test_null_offline_fixture_never_falls_back_to_network(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / 'null.json'
            fixture.write_text('null')
            with patch.object(common, 'fetch_json') as fetch:
                doc, raw = common.read_feed(str(fixture), 'https://example.test', 'test')
                self.assertIsNone(doc)
                self.assertEqual(raw, b'null')
                fetch.assert_not_called()
            with self.assertRaises(ValueError):
                noaa.normalize(doc, 'now')

    def test_offline_collectors_and_reports_end_to_end(self):
        scripts = Path(__file__).resolve().parents[1] / 'scripts'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            noaa_doc = {'features': [{'properties': {
                'id': 'https://api.weather.gov/alerts/test',
                'sent': '2026-11-17T09:00:00Z',
                'affectedZones': ['https://api.weather.gov/zones/forecast/MOZ092']}}]}
            nasa_doc = {'events': [{'id': 'EONET_1', 'geometry': [
                {'type': 'Point', 'coordinates': [-93, 37], 'date': '2026-11-17T12:00:00Z'}]}]}
            for script, doc, folder in [
                ('skywatch_noaa_ingest.py', noaa_doc, 'skywatch'),
                ('skywatch_missouri.py', noaa_doc, 'skywatch/missouri'),
                ('gods_eye_nasa_eonet.py', nasa_doc, 'gods-eye')]:
                fixture = root / (script + '.json')
                raw = json.dumps(doc, indent=1).encode()
                fixture.write_bytes(raw)
                subprocess.run([sys.executable, str(scripts / script), '--fixture', str(fixture),
                                '--output-dir', str(root / 'local-data' / folder)],
                               cwd=temp, check=True, capture_output=True, timeout=15)
                snapshot = next((root / 'local-data' / folder).glob('*-observations.json'))
                manifest = common.load_snapshot(snapshot)
                self.assertEqual((snapshot.parent / manifest['raw_file']).read_bytes(), raw)
            for script in ['watchdawg_correlate.py', 'watchdawg_cross_source.py']:
                subprocess.run([sys.executable, str(scripts / script)], cwd=temp,
                               check=True, capture_output=True, timeout=15)
            result = json.loads((root / 'local-data/intelligence/correlation-candidates.json').read_text())
            self.assertEqual(result['candidate_count'], 1)
            self.assertEqual(result['corroborated_event_count'], 0)
            self.assertFalse(result['public_release_approved'])
            self.assertIn('raw_sha256', result['source_snapshots']['nasa'])

    def test_feed_read_is_bounded_and_redirects_rejected(self):
        with patch.object(common.urllib.request, 'build_opener') as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b'x' * (common.MAX_BYTES + 1)
            with self.assertRaises(ValueError):
                common.fetch_json('https://api.weather.gov/alerts/active', 'test')
            response.read.assert_called_once_with(common.MAX_BYTES + 1)
        with self.assertRaises(ValueError):
            common.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://127.0.0.1/')


if __name__ == '__main__':
    unittest.main()
