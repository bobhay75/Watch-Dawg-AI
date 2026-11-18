#!/usr/bin/env python3
"""Trust-Worthy local evidence review of SkyWatch snapshots. No LLM, no network."""
import argparse
import hashlib
import json
from pathlib import Path

try:
    from intelligence_common import load_snapshot, noaa_url, timestamp
except ModuleNotFoundError:
    from scripts.intelligence_common import load_snapshot, noaa_url, timestamp

def valid_noaa_url(url):
    return noaa_url(url)

def review(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("observations"), list):
        raise ValueError("Expected a SkyWatch observations document")
    rows = []
    seen = set()
    for item in doc["observations"]:
        if not isinstance(item, dict):
            continue
        ident = item.get("id")
        if not isinstance(ident, str) or not ident or ident in seen:
            continue
        seen.add(ident)
        source = item.get("source") or {}
        evidence = item.get("evidence") or []
        url = source.get("url") if isinstance(source, dict) else None
        source_ok = valid_noaa_url(url) and source.get("name") == "NOAA National Weather Service"
        evidence_ok = isinstance(evidence, list) and any(
            isinstance(e, dict) and e.get("kind") == "primary" and e.get("url") == url
            for e in evidence)
        time_ok = timestamp(item.get("observed_at")) is not None
        issues = []
        if not source_ok:
            issues.append("Source URL or publisher invalid")
        if not evidence_ok:
            issues.append("Primary source citation missing")
        if not time_ok:
            issues.append("Observation timestamp missing")
        status = "source_documented" if not issues else "needs_review"
        rows.append({"id": ident, "review_status": status, "issues": issues,
                     "source_url": url if source_ok else None,
                     "claim_status": "observed" if status == "source_documented" else "unresolved",
                     "independently_corrob_or_verified": False,
                     "publication_approved": False})
    return {"review_version": "0.1", "source_snapshot_sha256": hashlib.sha256(
        json.dumps(doc, sort_keys=True).encode()).hexdigest(),
        "records": rows, "public_release_approved": False,
        "limitations": "Source-document checks only. No independent corroboration, physical measurements, or chemical attribution."}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="local-data/skywatch")
    parser.add_argument("--output-dir", default="local-data/skywatch/reviews")
    args = parser.parse_args()
    files = sorted(Path(args.input_dir).glob("*-observations.json"))
    if not files:
        parser.error("No observations found; run skywatch_noaa_ingest.py first")
    doc = load_snapshot(files[-1])
    result = review(doc)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    path = output / files[-1].name.replace("-observations.json", "-evidence-review.json")
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Review saved:", path)
    print("Source documented:", sum(r["review_status"] == "source_documented" for r in result["records"]))
    print("Needs review:", sum(r["review_status"] == "needs_review" for r in result["records"]))
    print("Public release approved: NO")

if __name__ == "__main__":
    main()
