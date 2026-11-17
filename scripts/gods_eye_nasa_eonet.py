#!/usr/bin/env python3
"""God's Eye v0.1: NASA EONET natural-event catalog, not direct satellite detection."""
import argparse
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
from urllib.parse import urlencode, urlparse
import urllib.request

BASE="https://eonet.gsfc.nasa.gov/api/v3/events"
USER_AGENT="Watch-Dawg-Gods-Eye/0.1 (public-source research; bobsome1.com)"
# Approximate geographic bounds, not private site coordinates.
MISSOURI=(-95.8,35.9,-89.1,40.7)
OZARKS=(-94.8,35.5,-91.0,38.5)

def fetch(limit=100):
    url=BASE+"?"+urlencode({"status":"open","limit":limit})
    req=urllib.request.Request(url,headers={"User-Agent":USER_AGENT,"Accept":"application/json"})
    with urllib.request.urlopen(req,timeout=30) as response:
        if response.status!=200:
            raise RuntimeError("Unexpected NASA EONET HTTP status")
        return json.load(response)

def valid_link(url):
    if not isinstance(url,str):
        return False
    p=urlparse(url)
    return p.scheme=="https" and p.hostname in ("eonet.gsfc.nasa.gov","earthobservatory.nasa.gov")

def point(geometry):
    if not isinstance(geometry,dict) or geometry.get("type")!="Point":
        return None
    xy=geometry.get("coordinates")
    if not isinstance(xy,list) or len(xy)<2:
        return None
    try:
        lon,lat=float(xy[0]),float(xy[1])
    except (ValueError,TypeError):
        return None
    return (lon,lat) if -180<=lon<=180 and -90<=lat<=90 else None

def in_bounds(p,bounds):
    return p is not None and bounds[0]<=p[0]<=bounds[2] and bounds[1]<=p[1]<=bounds[3]

def normalize(doc,retrieved):
    if not isinstance(doc,dict) or not isinstance(doc.get("events"),list):
        raise ValueError("Expected NASA EONET events array")
    out=[]
    for e in doc["events"]:
        if not isinstance(e,dict) or not isinstance(e.get("id"),str):
            continue
        geom=e.get("geometry") or []
        points=[p for p in (point(g) for g in geom) if p is not None]
        cats=[str(c.get("title") or "") for c in e.get("categories",[]) if isinstance(c,dict)]
        link=e.get("link")
        if not valid_link(link):
            link=BASE+"/"+e["id"]
        out.append({"id":hashlib.sha256(("NASA-EONET:"+e["id"]).encode()).hexdigest(),
            "external_id":e["id"],"title":str(e.get("title") or "Untitled")[:300],
            "categories":cats,"source":{"name":"NASA EONET","url":link},
            "event_dates":[str(g.get("date")) for g in geom if isinstance(g,dict) and isinstance(g.get("date"),str)][:30],
            "retrieved_at":retrieved,"geometry_type":"Point" if points else "unsupported_or_missing",
            "missouri_point_match":any(in_bounds(p,MISSOURI) for p in points),
            "ozarks_point_match":any(in_bounds(p,OZARKS) for p in points),
            "coordinates_in_private_output":False,
            "evidence_status":"cataloged_not_independently_verified","publication_approved":False})
    return out

def render(records,stamp):
    sorted_records=sorted(records,key=lambda x:(not x["ozarks_point_match"],not x["missouri_point_match"],x["title"]))
    p=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gods Eye NASA EONET</title><style>body{font:16px system-ui;background:#101c29;color:#f2f6fc;max-width:900px;margin:auto;padding:22px}section,header{background:#203245;padding:20px;border-radius:12px;margin:12px 0}a{color:#9cddff}li{margin:12px 0}</style></head><body>',
       '<header><h1>God\'s Eye — NASA Natural Events</h1><p>PRIVATE DRAFT · NASA EONET catalog · Not direct satellite-image analysis</p><p>Snapshot: '+html.escape(stamp)+'</p></header>',
       '<section><h2>'+str(len(records))+' catalog events</h2><p>Missouri point matches: '+str(sum(x["missouri_point_match"] for x in records))+' · Ozarks point matches: '+str(sum(x["ozarks_point_match"] for x in records))+'</p></section>',
       '<section><h2>Source-linked events</h2><ul>']
    for r in sorted_records:
        tag="OZARKS REVIEW · " if r["ozarks_point_match"] else ("MISSOURI REVIEW · " if r["missouri_point_match"] else "")
        p.append('<li>'+tag+html.escape(r["title"])+' · '+html.escape(", ".join(r["categories"]))+
                 ' · <a rel="noopener noreferrer" href="'+html.escape(r["source"]["url"],quote=True)+'">NASA event record</a></li>')
    p.append('</ul></section><section><p>EONET is a curated natural-event catalog, not a comprehensive live wildfire-detection feed or proof of satellite detection. Geographic point matches are approximate and exclude non-point geometries. No private archaeological coordinates are used or published. Human corroboration required.</p></section></body></html>')
    return "".join(p)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--fixture")
    ap.add_argument("--output-dir",default="local-data/gods-eye")
    args=ap.parse_args()
    data=json.loads(Path(args.fixture).read_text(encoding="utf-8")) if args.fixture else fetch()
    stamp=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z")
    records=normalize(data,stamp)
    folder=Path(args.output_dir)
    folder.mkdir(parents=True,exist_ok=True)
    tag=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw=json.dumps(data,sort_keys=True).encode()
    (folder/(tag+"-raw.json")).write_bytes(raw)
    (folder/(tag+"-observations.json")).write_text(json.dumps({"source":BASE,"retrieved_at":stamp,
       "raw_sha256":hashlib.sha256(raw).hexdigest(),"events":records,"public_release_approved":False},indent=2)+"\n")
    (folder/"nasa-dashboard.html").write_text(render(records,stamp),encoding="utf-8")
    print("NASA EONET events:",len(records))
    print("Missouri point matches:",sum(r["missouri_point_match"] for r in records))
    print("Ozarks point matches:",sum(r["ozarks_point_match"] for r in records))
    print("Dashboard:",folder/"nasa-dashboard.html")
    print("Public release approved: NO")

if __name__=="__main__":
    main()
