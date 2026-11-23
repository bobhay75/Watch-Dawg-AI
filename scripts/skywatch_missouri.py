#!/usr/bin/env python3
"""Missouri NOAA active-alert collector, separate from the national feed. Standard library only."""
import argparse
import datetime as dt
import html
from pathlib import Path

from skywatch_noaa_ingest import USER_AGENT, normalize

try:
    from intelligence_common import read_feed, fetch_json, save_snapshot, noaa_url
except ModuleNotFoundError:
    from scripts.intelligence_common import read_feed, fetch_json, save_snapshot, noaa_url

URL = "https://api.weather.gov/alerts/active?area=MO"
OZARK_TERMS = ("taney", "stone", "christian", "douglas", "ozark", "branson",
               "reeds spring", "kimberling", "hollister", "table rock",
               "forsyth", "springfield", "webster", "wright", "barry", "lawrence")

def fetch():
    return fetch_json(URL, USER_AGENT)[0]

def local_priority(item):
    area=str(item.get("area") or "").lower()
    return any(term in area for term in OZARK_TERMS)

def render(records,stamp):
    ordered=sorted(records,key=lambda x:(not local_priority(x),
        {"Extreme":0,"Severe":1,"Moderate":2,"Minor":3}.get(x.get("severity"),4),
        str(x.get("event") or "")))
    p=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SkyWatch Missouri</title><style>body{font:16px system-ui;background:#111b28;color:#edf4fc;max-width:850px;margin:auto;padding:24px}section,header{background:#213145;border-radius:12px;padding:18px;margin:12px 0}a{color:#8fd9ff}li{margin:14px 0}small{color:#c2ccd7}</style></head><body>',
       '<header><h1>SkyWatch — Missouri / Ozarks</h1><p>PRIVATE DRAFT · Official NOAA alerts · Not independently corroborated</p><small>Snapshot: '+html.escape(stamp)+'</small></header>',
       '<section><h2>Missouri alerts: '+str(len(records))+'</h2><p>Ozarks keyword matches: '+str(sum(local_priority(x) for x in records))+'</p><p>Keyword matches indicate review priority, not verified county boundaries or confirmed local impact.</p></section><section><h2>Source-linked records</h2>']
    if not ordered:
        p.append('<p>No active alerts returned by the Missouri-area NOAA query at collection time. This is not a guarantee of safety; check official local NWS forecasts.</p>')
    p.append('<ul>')
    for item in ordered:
        src=item.get("source") or {}
        url=src.get("url","") if isinstance(src,dict) else ""
        if not noaa_url(url):
            continue
        p.append('<li>'+("OZARKS REVIEW PRIORITY · " if local_priority(item) else "")+
                 html.escape(str(item.get("severity") or "Unknown"))+' · '+
                 html.escape(str(item.get("headline") or item.get("event") or "Alert"))+
                 '<p><small>'+html.escape(str(item.get("area") or "Area unspecified"))+'</small></p>'+
                 '<a href="'+html.escape(url,quote=True)+'" rel="noopener noreferrer">NOAA primary source</a></li>')
    p.append('</ul></section><section><p>Weather alerts only. Not satellite, aviation, aerosol or chemical monitoring. Private site coordinates are not collected. Human review required before publication.</p></section></body></html>')
    return "".join(p)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--fixture",help="Optional local GeoJSON fixture for offline testing")
    ap.add_argument("--output-dir",default="local-data/skywatch/missouri")
    args=ap.parse_args()
    data, raw = read_feed(args.fixture, URL, USER_AGENT)
    stamp=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z")
    records=normalize(data,stamp)
    folder=Path(args.output_dir)
    save_snapshot(folder, data, {"source":URL,"retrieved_at":stamp,"observations":records}, raw)
    (folder/"missouri-dashboard.html").write_text(render(records,stamp),encoding="utf-8")
    print("Missouri NOAA records:",len(records))
    print("Ozarks keyword matches:",sum(local_priority(x) for x in records))
    print("Dashboard:",folder/"missouri-dashboard.html")
    print("Public release approved: NO")

if __name__=="__main__":
    main()
