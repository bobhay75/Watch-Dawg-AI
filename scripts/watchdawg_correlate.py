#!/usr/bin/env python3
"""Conservative NASA/NOAA candidate screening. No automatic corroboration."""
import datetime as dt
import html
import json
from pathlib import Path

ROOT=Path("local-data")
MAX_HOURS=72

def parse_date(value):
    if not isinstance(value,str):
        return None
    try:
        d=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
        return d.astimezone(dt.timezone.utc) if d.tzinfo else None
    except ValueError:
        return None

def candidate(noaa,nasa):
    """Candidate only when Missouri location and observation times are compatible.
    This is NOT event identity or independent corroboration."""
    if not isinstance(noaa,dict) or not isinstance(nasa,dict):
        return None
    if not nasa.get("missouri_point_match"):
        return None
    zones=noaa.get("zones") or []
    mo_zone=any(isinstance(z,str) and z.rsplit("/",1)[-1].startswith(("MOZ","MOC")) for z in zones)
    if not mo_zone:
        return None
    observed=parse_date(noaa.get("observed_at"))
    dates=[parse_date(x) for x in (nasa.get("event_dates") or [])]
    dates=[x for x in dates if x is not None]
    if observed is None or not dates:
        return None
    diff=min(abs((observed-x).total_seconds()) for x in dates)/3600
    if diff>MAX_HOURS:
        return None
    return {"noaa_id":noaa.get("id"),"nasa_id":nasa.get("id"),
            "noaa_headline":str(noaa.get("headline") or "")[:180],
            "nasa_title":str(nasa.get("title") or "")[:180],
            "time_gap_hours":round(diff,1),
            "noaa_source":(noaa.get("source") or {}).get("url"),
            "nasa_source":(nasa.get("source") or {}).get("url"),
            "judgment":"candidate_only_not_corroborated",
            "limitations":"Missouri statewide coarse overlap; event identities and spatial footprints unverified"}

def correlate(noaa,events):
    result=[]
    for n in noaa:
        for e in events:
            c=candidate(n,e)
            if c:
                result.append(c)
    return result

def load_latest(folder):
    paths=sorted(folder.glob("*-observations.json"))
    if not paths:
        return None
    return json.loads(paths[-1].read_text(encoding="utf-8"))

def main():
    noaa=load_latest(ROOT/"skywatch"/"missouri")
    nasa=load_latest(ROOT/"gods-eye")
    if noaa is None or nasa is None:
        raise SystemExit("Missing saved Missouri NOAA or NASA observations; run both collectors first")
    alerts=noaa.get("observations")
    events=nasa.get("events")
    if not isinstance(alerts,list) or not isinstance(events,list):
        raise SystemExit("Malformed source snapshot")
    results=correlate(alerts,events)
    output=ROOT/"intelligence"
    output.mkdir(parents=True,exist_ok=True)
    report={"source_timestamps":{"noaa":noaa.get("retrieved_at"),"nasa":nasa.get("retrieved_at")},
            "candidate_count":len(results),"candidates":results,
            "corroborated_event_count":0,"corroboration_assessed":False,
            "public_release_approved":False}
    (output/"correlation-candidates.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    lines=['<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Watch-Dawg Correlation Review</title><style>body{font:16px system-ui;max-width:850px;margin:auto;padding:24px;background:#111b28;color:#eef4fa}section{background:#203144;padding:20px;border-radius:12px;margin:15px 0}</style></head><body><h1>Watch-Dawg Correlation Candidates</h1><p>PRIVATE REVIEW · NOT VERIFIED · NOT FOR PUBLIC RELEASE</p><section><h2>'+str(len(results))+' screening candidates</h2><p>Zero candidates does not establish that no shared event occurred. Screening requires Missouri NOAA zone, NASA Missouri point and an observation-date gap of 72 hours or less. Corroboration is never automatically granted.</p></section>']
    for c in results[:100]:
        lines.append("<section><strong>"+html.escape(c["noaa_headline"])+"</strong><p>"+html.escape(c["nasa_title"])+"</p><p>Temporal gap: "+str(c["time_gap_hours"])+" hours · candidate only</p></section>")
    lines.append("<section><p>Different event definitions and approximate geography can cause false matches. NOAA issuance times are not necessarily event occurrence times. NASA event geometry dates are not guaranteed detection times. Event identity, independent evidence and spatial footprints require human review.</p></section></body></html>")
    (output/"correlation-candidates.html").write_text("".join(lines),encoding="utf-8")
    print("Screening candidates:",len(results))
    print("Corroborated events: 0 (NOT ASSESSED)")
    print("Report:",output/"correlation-candidates.html")
    print("Public release approved: NO")

if __name__=="__main__":
    main()
