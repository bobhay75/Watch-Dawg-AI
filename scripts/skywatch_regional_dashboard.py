#!/usr/bin/env python3
"""Generate a private searchable, grouped NOAA dashboard from locally saved observations."""
import html
from pathlib import Path

try:
    from intelligence_common import load_snapshot, missouri_zone, noaa_url
except ModuleNotFoundError:
    from scripts.intelligence_common import load_snapshot, missouri_zone, noaa_url

ROOT = Path("local-data/skywatch")
SEVERITY_ORDER = {"Extreme": 0, "Severe": 1, "Moderate": 2, "Minor": 3, "Unknown": 4}

def is_missouri(record):
    zones = record.get("zones")
    return isinstance(zones, list) and any(missouri_zone(z) for z in zones)

def valid_source(url):
    return noaa_url(url)

def group_records(records):
    groups = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        event = str(record.get("event") or record.get("headline") or "Unknown event")[:120]
        severity = str(record.get("severity") or "Unknown")[:50]
        key = (severity, event, is_missouri(record))
        groups.setdefault(key, []).append(record)
    return sorted(groups.items(), key=lambda item:
                  (not item[0][2], SEVERITY_ORDER.get(item[0][0], 5), -len(item[1]), item[0][1]))

def render(records, timestamp):
    groups = group_records(records)
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SkyWatch Regional Brief</title>',
           '<style>body{font:16px system-ui;background:#111c29;color:#f0f5fa;max-width:1000px;margin:auto;padding:22px}section,header{background:#203144;padding:18px;margin:12px 0;border-radius:12px}input,select{padding:10px;font-size:16px;margin:6px;background:#fff;color:#111}a{color:#91ddff}summary{cursor:pointer;font-weight:bold;padding:8px}details{border-top:1px solid #526476;padding:7px}small{color:#c8d1db}.count{font-size:26px;font-weight:bold}</style></head><body>',
           '<header><h1>SkyWatch — U.S. Regional Intelligence</h1><p>PRIVATE DRAFT · NOAA records only · Not independently corroborated · Not approved for publication</p>',
           '<small>Snapshot: '+html.escape(str(timestamp))+'</small><p class="count">'+str(len(records))+' source records · '+str(len(groups))+' event groups</p></header>',
           '<section><label>Search <input id="search" placeholder="Event, region, severity"></label> <label>Priority <select id="priority"><option value="all">All regions</option><option value="mo">Missouri zone records</option></select></label><p id="shown"></p></section>',
           '<section id="groups">']
    for (severity,event,mo), items in groups:
        area = "; ".join(sorted({str(x.get("area") or "") for x in items if x.get("area")})[:3])
        searchable = (severity+" "+event+" "+area).lower()
        out.append('<details class="group" data-mo="'+("yes" if mo else "no")+'" data-search="'+html.escape(searchable, quote=True)+'"><summary>'+
                   ("MISSOURI · " if mo else "")+html.escape(severity)+" · "+html.escape(event)+" — "+str(len(items))+" records</summary>")
        if area:
            out.append("<p><small>Affected areas (sample): "+html.escape(area[:500])+"</small></p>")
        out.append("<ul>")
        for item in items[:8]:
            source = item.get("source") or {}
            url = source.get("url") if isinstance(source,dict) else None
            if valid_source(url):
                out.append('<li><a rel="noopener noreferrer" href="'+html.escape(url,quote=True)+'">'+html.escape(str(item.get("headline") or event)[:180])+'</a></li>')
        if len(items)>8:
            out.append("<li>"+str(len(items)-8)+" additional records in this group (retained in local source snapshot)</li>")
        out.append("</ul></details>")
    out.append('</section><section><h2>Interpretation</h2><p>Groups combine similar NOAA alert records, not necessarily one physical event. Missouri matching uses NWS zone identifiers and may omit marine or unusually coded alerts. Older snapshots without zone metadata will not match Missouri. This is not satellite, aviation, aerosol, or chemical evidence. Human review required.</p></section>')
    out.append("""<script>
const search=document.getElementById('search'),priority=document.getElementById('priority'),shown=document.getElementById('shown');
function filter(){let count=0;document.querySelectorAll('.group').forEach(g=>{const ok=g.dataset.search.includes(search.value.toLowerCase())&&(priority.value==='all'||g.dataset.mo==='yes');g.hidden=!ok;if(ok)count++;});shown.textContent=count+' groups shown';}
search.addEventListener('input',filter);priority.addEventListener('change',filter);filter();
</script></body></html>""")
    return "".join(out)

def main():
    paths=sorted(ROOT.glob("*-observations.json"))
    if not paths:
        raise SystemExit("No saved observations; run skywatch_noaa_ingest.py")
    doc=load_snapshot(paths[-1])
    records=doc.get("observations")
    if not isinstance(records,list):
        raise SystemExit("Malformed snapshot")
    output=ROOT/"regional-dashboard.html"
    output.write_text(render(records,doc.get("retrieved_at","unknown")),encoding="utf-8")
    print("Saved:",output)
    print("Records:",len(records),"Event groups:",len(group_records(records)))
    print("Missouri zone records:",sum(is_missouri(x) for x in records if isinstance(x,dict)))
    print("Public release approved: NO")

if __name__=="__main__":
    main()
