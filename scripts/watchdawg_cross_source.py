#!/usr/bin/env python3
"""Private cross-source coverage audit. Never infer event corroboration from catalog counts."""
import argparse
import datetime as dt
import html
import json
from pathlib import Path

try:
    from intelligence_common import load_snapshot, snapshot_identity
except ModuleNotFoundError:
    from scripts.intelligence_common import load_snapshot, snapshot_identity

def latest(folder, pattern):
    paths=sorted(Path(folder).glob(pattern))
    if not paths:
        return None
    doc=load_snapshot(paths[-1])
    if not isinstance(doc,dict):
        raise ValueError("Malformed snapshot document")
    return doc

def summarize(national, missouri, nasa):
    def records(doc,key):
        if doc is None:
            return None
        if not isinstance(doc,dict):
            raise ValueError("Malformed snapshot document")
        value=doc.get(key)
        if not isinstance(value,list):
            raise ValueError("Malformed "+key+" collection")
        return value
    nat=records(national,"observations")
    mo=records(missouri,"observations")
    events=records(nasa,"events")
    return {"national_noaa":len(nat) if nat is not None else None,
            "missouri_noaa":len(mo) if mo is not None else None,
            "nasa_eonet":len(events) if events is not None else None,
            "nasa_missouri_point_matches":sum((x.get("missouri_point_match") is True) for x in events if isinstance(x,dict)) if events is not None else None,
            "nasa_ozarks_point_matches":sum((x.get("ozarks_point_match") is True) for x in events if isinstance(x,dict)) if events is not None else None,
            "sources_present":sum(x is not None for x in (nat,mo,events)),
            "cross_source_event_corroboration":"not_assessed",
            "publication_approved":False}

def render(summary, stamps):
    page=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Watch-Dawg Evidence Coverage</title><style>body{font:16px system-ui;background:#111b28;color:#f0f5fa;max-width:860px;margin:auto;padding:24px}section,header{background:#213246;padding:18px;margin:12px 0;border-radius:12px}li{margin:12px 0}</style></head><body>',
          '<header><h1>Watch-Dawg + God\'s Eye</h1><p>PRIVATE CROSS-SOURCE COVERAGE AUDIT · NOT A CORROBORATION REPORT</p></header><section><h2>Saved observations</h2><ul>']
    for key,label in (("national_noaa","NOAA nationwide alerts"),("missouri_noaa","NOAA Missouri-area alerts"),
                      ("nasa_eonet","NASA EONET catalog events"),("nasa_missouri_point_matches","NASA Missouri point matches"),
                      ("nasa_ozarks_point_matches","NASA Ozarks point matches")):
        v=summary[key]
        page.append("<li>"+html.escape(label)+": "+("missing snapshot" if v is None else str(v))+"</li>")
    page.append('</ul></section><section><h2>Collection timestamps (UTC)</h2><ul>')
    for label,value in stamps.items():
        page.append("<li>"+html.escape(label)+": "+html.escape(str(value or "not collected"))+"</li>")
    page.append('</ul></section><section><h2>Evidence judgment</h2><p>These datasets have different coverage, update schedules, event definitions and geographic representations. NOAA alerts are forecasts/warnings; EONET is a curated event catalog. No matching event identities, times, or spatial footprints have been verified. Therefore independent corroboration is NOT ASSESSED. A zero count or point match is not evidence of safety or event absence. Private site coordinates are not used. Human review is required before publication.</p></section></body></html>')
    return "".join(page)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",default="local-data")
    args=p.parse_args()
    root=Path(args.root)
    docs={"NOAA nationwide":latest(root/"skywatch","*-observations.json"),
          "NOAA Missouri":latest(root/"skywatch"/"missouri","*-observations.json"),
          "NASA EONET":latest(root/"gods-eye","*-observations.json")}
    result=summarize(docs["NOAA nationwide"],docs["NOAA Missouri"],docs["NASA EONET"])
    stamps={k:(v or {}).get("retrieved_at") for k,v in docs.items()}
    output=root/"intelligence"/"cross-source-coverage.html"
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(render(result,stamps),encoding="utf-8")
    audit={"generated_at":dt.datetime.now(dt.timezone.utc).isoformat(),"summary":result,
           "source_snapshots":{k:snapshot_identity(v) if v is not None else None for k,v in docs.items()},"public_release_approved":False}
    (output.parent/"cross-source-coverage.json").write_text(json.dumps(audit,indent=2)+"\n",encoding="utf-8")
    print("Coverage report:",output)
    print("Sources present:",result["sources_present"],"of 3")
    print("Event corroboration: NOT ASSESSED")
    print("Public release approved: NO")

if __name__=="__main__":
    main()
