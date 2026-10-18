"""Cloud-ready, credential-free Sentinel profile for KCMC Publisher only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from .core import Finding, SentinelEngine, StateStore
from .http_watch import HttpWatchPack, SafeHttpFetcher

URL = "https://bobsome1.com/kcmc-connect/admin/publication-designer.php"
LOGIN = "https://bobsome1.com/kcmc-connect/member/login.php"
TARGET = {
    "id": "kcmc-publication-designer", "kind": "http", "url": URL,
    "authorization": {"mode": "owner", "note": "Owner authorized Publisher-only passive monitoring."},
    "timeout_seconds": 15, "max_body_bytes": 500000,
    "checks": {"allowed_statuses": [200], "max_latency_ms": 5000,
               "not_contains": ["Fatal error:", "Parse error:", "Uncaught Error"],
               "track_content": False},
}


class MinimizedFetcher(SafeHttpFetcher):
    def fetch(self, url, timeout_seconds, max_body_bytes):
        result = super().fetch(url, timeout_seconds, max_body_bytes)
        result["headers"] = {}  # Never store cookies or header values in public evidence.
        return result


class PublisherWatch(HttpWatchPack):
    def evaluate(self, target, current, previous):
        findings = super().evaluate(target, current, previous)
        if current.ok:
            landing = current.facts.get("final_url")
            if landing == LOGIN:
                # Known access boundary, not an outage or reason to bypass authentication.
                findings.append(Finding(
                    target_id=current.target_id, code="PUBLISHER_AUTH_BOUNDARY", severity="info",
                    title="Signed-in Publisher functionality is unverified",
                    detail="The public request reaches Staff Sign In. No credentials or private controls are accessed.",
                    evidence={"final_url": landing},
                ))
            elif landing != URL:
                findings.append(Finding(
                    target_id=current.target_id, code="PUBLISHER_UNEXPECTED_DESTINATION", severity="high",
                    title="Publisher has an unexpected destination",
                    detail="The request ended outside the approved Publisher or staff login URL.",
                    evidence={"final_url": landing},
                ))
        return findings


def run(state_path, report_path, fetcher=None):
    engine = SentinelEngine(StateStore(state_path), [PublisherWatch(fetcher or MinimizedFetcher())])
    report = engine.run([TARGET])
    report["coverage"] = "Public reachability/errors/latency/redirects only; signed-in controls and server hashes are not verified."
    result = report["results"][0]
    actionable = [f for f in result["new_alerts"] if f["code"] != "PUBLISHER_AUTH_BOUNDARY"]
    report["new_actionable_alert_count"] = len(actionable)
    report["operational_finding_count"] = sum(f["code"] != "PUBLISHER_AUTH_BOUNDARY" for f in result["current_findings"])
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path(".sentinel/kcmc/state.json"))
    parser.add_argument("--report", type=Path, default=Path(".sentinel/kcmc/report.json"))
    args = parser.parse_args()
    report = run(args.state, args.report)
    result = report["results"][0]
    # Summary uses only fixed labels/codes, never website text as Markdown/commands.
    lines = ["## Watch-Dawg: KCMC Publisher", "", f"Observed: {report['generated_at']}",
             f"Targets checked: {report['targets_checked']}",
             f"New operational alerts: {report['new_actionable_alert_count']}",
             f"Current operational findings: {report['operational_finding_count']}",
             f"Resolved findings: {report['resolved_count']}", "", report["coverage"], "",
             "An unchanged finding is suppressed; a successful run does not prove the Publisher is fully healthy.",
             "Cache loss can cause a finding to be reported again."]
    for label, findings in (("Current", result["current_findings"]), ("New", result["new_alerts"]), ("Resolved", result["resolved"])):
        lines.extend(f"- {label}: {f['code']} ({f['severity']})" for f in findings)
    summary = "\n".join(lines) + "\n"
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(summary)
    # Persist/report first; workflow raises a failure after evidence and cache save.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
