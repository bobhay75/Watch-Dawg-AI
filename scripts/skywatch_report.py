#!/usr/bin/env python3
"""Generate a private NOAA intelligence brief from saved SkyWatch observations."""
import argparse
import collections
import html
from urllib.parse import quote
from pathlib import Path

try:
    from intelligence_common import load_snapshot, noaa_url
except ModuleNotFoundError:
    from scripts.intelligence_common import load_snapshot, noaa_url

def load_latest(folder):
    files = sorted(Path(folder).glob("*-observations.json"))
    if not files:
        raise FileNotFoundError("No observations found; run the NOAA ingester first")
    doc = load_snapshot(files[-1])
    if not isinstance(doc.get("observations"), list):
        raise ValueError("Invalid observations snapshot")
    return files[-1], doc

def build_report(doc):
    items = {x["id"]: x for x in doc["observations"]
             if isinstance(x, dict) and isinstance(x.get("id"), str)
             and x.get("category") == "atmosphere"
             and isinstance(x.get("source"), dict)
             and x["source"].get("name") == "NOAA National Weather Service"}
    severity = collections.Counter(x.get("severity", "Unknown") for x in items.values())
    lines = ["# SkyWatch — NOAA Intelligence Brief (Private Draft)", "",
             "**Not independently verified; not approved for public release.**", "",
             "Snapshot: " + str(doc.get("retrieved_at", "unknown")),
             "Feed: " + str(doc.get("source", "unknown")),
             "Raw SHA-256: " + str(doc.get("raw_sha256", "unknown")), "",
             "## " + str(len(items)) + " unique NOAA alerts", "",
             "Official weather alerts are not evidence of unusual aircraft activity or chemical spraying.", "",
             "### Severity counts", ""]
    lines += ["- " + str(k) + ": " + str(v) for k, v in sorted(severity.items())]
    lines += ["", "### Source-linked alert register", ""]
    for x in sorted(items.values(), key=lambda a: (str(a.get("severity", "")), str(a.get("headline", "")))):
        url = x["source"].get("url", "")
        if not noaa_url(url):
            continue
        headline = str(x.get("headline") or "Untitled").replace("\n", " ").replace("\r", " ")
        headline = headline.replace("[", "(").replace("]", ")")[:250]
        lines.append("- **" + html.escape(str(x.get("severity", "Unknown"))) + "** — " + html.escape(headline) + " — [NOAA source](" + quote(url, safe=":/%?=&") + ")")
    lines += ["", "### Limitations", "",
              "- These are NWS published alerts, not independent field measurements.",
              "- Snapshot counts change; they do not represent unique long-term incidents.",
              "- No aircraft, aerosol, chemical, or satellite measurements were collected here.",
              "- Public release requires source/license review and human approval.",
              "- Private site coordinates are excluded.", ""]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="local-data/skywatch")
    parser.add_argument("--output-dir", default="local-data/skywatch/reports")
    args = parser.parse_args()
    path, doc = load_latest(args.input_dir)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    target = output / path.name.replace("-observations.json", "-brief.md")
    target.write_text(build_report(doc), encoding="utf-8")
    print("Private draft saved:", target)
    print("Input observations:", len(doc["observations"]))

if __name__ == "__main__":
    main()
