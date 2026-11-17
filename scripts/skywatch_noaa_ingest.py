#!/usr/bin/env python3
"""Free-source SkyWatch ingestion: NOAA/NWS active alerts; no third-party dependencies."""
import argparse
import datetime as dt
import hashlib
import pathlib

try:
    from intelligence_common import read_feed, fetch_json, save_snapshot, noaa_url, timestamp
except ModuleNotFoundError:
    from scripts.intelligence_common import read_feed, fetch_json, save_snapshot, noaa_url, timestamp

URL = "https://api.weather.gov/alerts/active?status=actual"
USER_AGENT = "Watch-Dawg-SkyWatch/0.1 (public-source research; bobsome1.com)"
SCHEMA_VERSION = "0.1"


def fetch_alerts():
    return fetch_json(URL, USER_AGENT)[0]



def normalize(data, retrieved_at):
    if not isinstance(data, dict) or not isinstance(data.get("features"), list):
        raise ValueError("Expected GeoJSON FeatureCollection with features array")
    results = []
    seen = set()
    for feature in data["features"]:
        if not isinstance(feature, dict):
            continue
        props = feature.get("properties") or {}
        if not isinstance(props, dict):
            continue
        identifier = props.get("@id") or props.get("id") or feature.get("id")
        observed = props.get("sent")
        if not noaa_url(identifier):
            continue
        if timestamp(observed) is None:
            continue
        if identifier in seen:
            continue
        seen.add(identifier)
        zones = props.get("affectedZones")
        zones = zones if isinstance(zones, list) else []
        results.append({
            "id": hashlib.sha256(identifier.encode("utf-8")).hexdigest(),
            "source": {"name": "NOAA National Weather Service", "url": identifier,
                       "license_status": "review_required",
                       "license_reference": "https://www.weather.gov/documentation/services-web-api"},
            "observed_at": observed,
            "retrieved_at": retrieved_at,
            "category": "atmosphere",
            "region": {"country": "US"},
            "area": str(props.get("areaDesc") or "")[:500],
            "event": str(props.get("event") or "")[:120],
            "zones": [str(z) for z in zones if isinstance(z, str)][:100],
            "claim_status": "observed",
            "evidence": [{"url": identifier, "kind": "primary"}],
            "headline": str(props.get("headline") or props.get("event") or "")[:500],
            "severity": str(props.get("severity") or "Unknown")[:50],
            "publication_approved": False
        })
    return sorted(results, key=lambda item: item["id"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", help="Read a local GeoJSON fixture instead of contacting NOAA")
    parser.add_argument("--output-dir", default="local-data/skywatch")
    args = parser.parse_args()
    data, raw = read_feed(args.fixture, URL, USER_AGENT)
    retrieved = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    observations = normalize(data, retrieved)
    out = pathlib.Path(args.output_dir)
    save_snapshot(out, data, {"schema_version": SCHEMA_VERSION, "retrieved_at": retrieved,
                  "source": URL, "observations": observations}, raw)
    print("Saved", len(observations), "observations to", out)


if __name__ == "__main__":
    main()
