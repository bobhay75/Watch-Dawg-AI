"""Shared, standard-library trust boundaries for private intelligence snapshots."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request
from urllib.parse import urlsplit
import uuid

MAX_BYTES = 20 * 1024 * 1024


def trusted_url(value, hosts, prefix='/'):
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        return False
    try:
        p = urlsplit(value)
        return (p.scheme == 'https' and p.hostname in hosts and p.port in (None, 443)
                and not p.username and not p.password and not p.fragment
                and p.path.startswith(prefix) and len(p.path) > len(prefix)
                and not any(c in value for c in '<>"\\'))
    except ValueError:
        return False


def noaa_url(value):
    return trusted_url(value, ('api.weather.gov',), '/alerts/')


def missouri_zone(value):
    if not trusted_url(value, ('api.weather.gov',), '/zones/'):
        return False
    return re.fullmatch(r'/zones/(forecast|county)/MO[ZC]\d{3}', urlsplit(value).path) is not None


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(dt.timezone.utc) if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Feed redirects require explicit endpoint review')


def fetch_json(url, user_agent):
    req = urllib.request.Request(url, headers={'User-Agent': user_agent, 'Accept': 'application/geo+json, application/json'})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        if response.status != 200:
            raise ValueError('Unexpected feed status')
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Feed exceeds size limit')
    return json.loads(raw), raw


def save_snapshot(folder, data, report, raw=None):
    """Retain exact network or fixture bytes, never overwrite history.

    The observations manifest is written last, so readers cannot select a half-written
    collection. Raw orphans from interrupted writes are retained for inspection.
    """
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = raw if raw is not None else json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')
    tag = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + uuid.uuid4().hex
    raw_path = folder / (tag + '-raw.json')
    report = dict(report, raw_sha256=hashlib.sha256(raw).hexdigest(), raw_file=raw_path.name,
                  public_release_approved=False)
    for path, content in ((raw_path, raw), (folder / (tag + '-observations.json'),
                           (json.dumps(report, indent=2) + '\n').encode('utf-8'))):
        temp = folder / ('.' + path.name + '.tmp')
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    return report


def snapshot_identity(doc):
    return {'retrieved_at': doc.get('retrieved_at'), 'source': doc.get('source'),
            'raw_sha256': doc.get('raw_sha256'), 'raw_file': doc.get('raw_file'),
            'snapshot_sha256': hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()}


def read_feed(fixture, url, user_agent):
    if fixture is None:
        return fetch_json(url, user_agent)
    with Path(fixture).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Fixture exceeds size limit')
    return json.loads(raw), raw


def load_snapshot(path):
    """Validate retained-byte integrity when a snapshot carries a raw digest.

    Historical snapshots without raw_file use their original paired filename.
    Digests detect corruption; they are not publisher signatures.
    """
    path = Path(path)
    doc = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(doc, dict):
        raise ValueError('Malformed snapshot document')
    digest = doc.get('raw_sha256')
    if digest is not None:
        name = doc.get('raw_file', path.name.replace('-observations.json', '-raw.json'))
        if not isinstance(name, str) or Path(name).name != name or not name.endswith('-raw.json'):
            raise ValueError('Invalid raw snapshot reference')
        raw_path = path.parent / name
        if raw_path.is_symlink() or not raw_path.is_file():
            raise ValueError('Raw evidence missing or linked')
        if hashlib.sha256(raw_path.read_bytes()).hexdigest() != digest:
            raise ValueError('Raw evidence digest mismatch')
    return doc
