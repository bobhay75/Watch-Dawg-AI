#!/usr/bin/env python3
"""Free-source SkyWatch ingestion: NOAA/NWS active alerts; no third-party dependencies."""
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import urllib.request

URL = "https://api.weather.gov/alerts/active?status=actual"
USER_AGENT = "Watch-Dawg-SkyWatch/0.1 (public-source research; bobsome1.com)"
SCHEMA_VERSION = "0.1"


def fetch_alerts():
    req = urllib.request.Request(URL, headers={"User-Agent": USER_AGENT, "Accept": "application/geo+json"})
    with urllib.request.urlopen(req, timeout=25) as response:
        if response.status != 200:
            raise RuntimeError("Unexpected HTTP status")
        return json.load(response)


def normalize(data, retrieved_at):
    if not isinstance(data, dict) or not isinstance(data.get("features"), list):
        raise ValueError("Expected GeoJSON FeatureCollection with features array")
    results = []
    for feature in data["features"]:
        if not isinstance(feature, dict):
            continue
        props = feature.get("properties") or {}
        if not isinstance(props, dict):
            continue
        identifier = props.get("@id") or props.get("id") or feature.get("id")
        observed = props.get("sent")
        if not isinstance(identifier, str) or not identifier.startswith("https://api.weather.gov/alerts/"):
            continue
        if not isinstance(observed, str) or not observed:
            continue
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
            "zones": [str(z) for z in (props.get("affectedZones") or []) if isinstance(z, str)][:100],
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
    data = json.loads(pathlib.Path(args.fixture).read_text(encoding="utf-8")) if args.fixture else fetch_alerts()
    retrieved = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    observations = normalize(data, retrieved)
    out = pathlib.Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    (out / (stamp + "-raw.json")).write_bytes(raw)
    report = {"schema_version": SCHEMA_VERSION, "retrieved_at": retrieved, "source": URL,
              "raw_sha256": hashlib.sha256(raw).hexdigest(), "observations": observations,
              "public_release_approved": False}
    (out / (stamp + "-observations.json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Saved", len(observations), "observations to", out)


if __name__ == "__main__":
    main()
