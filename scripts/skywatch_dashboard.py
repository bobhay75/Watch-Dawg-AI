#!/usr/bin/env python3
"""Compare SkyWatch NOAA snapshots, generate a private, self-contained HTML dashboard."""
import argparse
import collections
import html
from pathlib import Path

try:
    from intelligence_common import load_snapshot, noaa_url
except ModuleNotFoundError:
    from scripts.intelligence_common import load_snapshot, noaa_url

def read_snapshots(folder):
    paths = sorted(Path(folder).glob("*-observations.json"))
    if not paths:
        raise FileNotFoundError("No NOAA snapshots; run skywatch_noaa_ingest.py")
    snapshots = [(p, load_snapshot(p)) for p in paths]
    for _, doc in snapshots:
        if not isinstance(doc.get("observations"), list):
            raise ValueError("Malformed observations snapshot")
    return snapshots

def select_baseline(snapshots):
    """Use last nonempty prior snapshot; do not mistake empty legacy runs for zero alerts."""
    if len(snapshots) < 2:
        return None
    for _, doc in reversed(snapshots[:-1]):
        if doc["observations"]:
            return doc
    return None

def changes(previous, current):
    old = {x["id"]: x for x in previous if isinstance(x, dict) and x.get("id")}
    new = {x["id"]: x for x in current if isinstance(x, dict) and x.get("id")}
    return {"new": sorted(new.keys() - old.keys()), "continuing": sorted(new.keys() & old.keys()),
            "no_longer_active": sorted(old.keys() - new.keys())}

def render(current, delta, stamp):
    records = [x for x in current if isinstance(x, dict)]
    counts = collections.Counter(str(x.get("severity", "Unknown")) for x in records)
    head = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SkyWatch | Private NOAA Brief</title><style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:auto;padding:24px;background:#101923;color:#edf2f7}a{color:#86d6ff}header,section{background:#1b2937;padding:20px;border-radius:12px;margin:14px 0}h1{margin:0}small,.muted{color:#bdc9d4}.stats{display:flex;gap:12px;flex-wrap:wrap}.stat{background:#273a4d;padding:16px;border-radius:8px;min-width:140px}.stat strong{font-size:26px;display:block}li{margin:10px 0;overflow-wrap:anywhere}code{overflow-wrap:anywhere}</style></head><body>"""
    page = [head, "<header><h1>SkyWatch — U.S. NOAA Intelligence</h1><p>PRIVATE DRAFT — Source documented, not independently corroborated or approved for publication.</p><small>Snapshot: "+html.escape(str(stamp))+"</small></header>"]
    page.append('<section class="stats">')
    for label, value in [("Current alerts",len(records)),("New",len(delta["new"])),("Continuing",len(delta["continuing"])),("No longer active",len(delta["no_longer_active"]))]:
        page.append('<div class="stat"><strong>'+str(value)+'</strong>'+html.escape(label)+'</div>')
    page.append("</section><section><h2>Severity</h2><ul>")
    for severity, number in sorted(counts.items()):
        page.append("<li>"+html.escape(severity)+": "+str(number)+"</li>")
    page.append("</ul></section><section><h2>Source-linked alerts</h2><ul>")
    for item in sorted(records,key=lambda x: (str(x.get("severity","")),str(x.get("headline","")))):
        src = item.get("source") or {}
        url = src.get("url", "") if isinstance(src,dict) else ""
        if not noaa_url(url):
            continue
        label = html.escape(str(item.get("headline") or "NOAA alert")[:300])
        page.append('<li><b>'+html.escape(str(item.get("severity","Unknown")))+'</b> — '+label+' — <a rel="noopener noreferrer" href="'+html.escape(url,quote=True)+'">NOAA source</a></li>')
    page.append("</ul></section><section><h2>Evidence limitations</h2><p>Changes compare the latest two saved snapshots, not all historical events. “No longer active” means absent from the latest feed, not necessarily that the hazard ended. This is weather-alert data, not aircraft, aerosol, chemical, or satellite monitoring. Private site coordinates are excluded. Human review is required before publication.</p></section></body></html>")
    return "".join(page)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input-dir",default="local-data/skywatch")
    p.add_argument("--output",default="local-data/skywatch/dashboard.html")
    args=p.parse_args()
    snapshots=read_snapshots(args.input_dir)
    latest=snapshots[-1][1]
    current=latest["observations"]
    baseline=select_baseline(snapshots)
    previous=baseline["observations"] if baseline else []
    delta=changes(previous,current)
    if baseline is None:
        delta={"new":[],"continuing":[],"no_longer_active":[]}
    print("Comparison baseline:",baseline.get("retrieved_at","unknown") if baseline else "unavailable; counts suppressed")
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    page=render(current,delta,latest.get("retrieved_at","unknown"))
    if baseline is None:
        page=page.replace("<section class=\"stats\">", "<section><strong>Baseline unavailable:</strong> change counts are not meaningful until two nonempty snapshots exist.</section><section class=\"stats\">", 1)
    output.write_text(page,encoding="utf-8")
    print("Dashboard saved:",output)
    print("Snapshots compared:",len(snapshots))
    print("Current:",len(current),"New:",len(delta["new"]),"Continuing:",len(delta["continuing"]),"No longer active:",len(delta["no_longer_active"]))
    print("Public release approved: NO")

if __name__=="__main__":
    main()
