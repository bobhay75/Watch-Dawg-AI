from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Final, Iterable
from urllib.parse import urlsplit

from .axe_adapter import verify_axe_analysis
from .browser_capture import BrowserCaptureError, capture_browser_evidence, verify_browser_package
from .website_audit_bundle import export_browser_audit


SITE_AUDIT_SCHEMA: Final[str] = "watch-dawg-site-audit/v1"
MAX_SITE_PAGES: Final[int] = 12
IMPACT_RANK: Final[dict[str | None, int]] = {
    None: 0,
    "minor": 1,
    "moderate": 2,
    "serious": 3,
    "critical": 4,
}


class SiteAuditError(RuntimeError):
    """Raised when a bounded multi-page audit cannot be completed safely."""


def _write_new(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise SiteAuditError(f"refusing to overwrite site audit file: {path.name}") from exc


def _slug_for_url(url: str, index: int) -> str:
    parsed = urlsplit(url)
    raw = parsed.path.strip("/") or "home"
    if parsed.query:
        raw += "-query"
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", raw).strip("-") or "page"
    return f"{index:02d}-{slug[:80]}"


def validate_site_urls(urls: Iterable[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    origin: tuple[str, str, int] | None = None
    for raw in urls:
        if not isinstance(raw, str) or not raw.strip():
            raise SiteAuditError("site audit URL must be non-empty text")
        value = raw.strip()
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise SiteAuditError("site audit URLs must be absolute https:// URLs")
        if parsed.username or parsed.password or parsed.fragment:
            raise SiteAuditError("site audit URLs may not contain credentials or fragments")
        port = parsed.port or 443
        current_origin = (parsed.scheme.lower(), parsed.hostname.lower(), port)
        if origin is None:
            origin = current_origin
        elif current_origin != origin:
            raise SiteAuditError("all site audit URLs must share one HTTPS origin")
        if value not in seen:
            seen.add(value)
            ordered.append(value)
        if len(ordered) > MAX_SITE_PAGES:
            raise SiteAuditError(f"site audit is capped at {MAX_SITE_PAGES} explicitly scoped pages")
    if not ordered:
        raise SiteAuditError("at least one site audit URL is required")
    return ordered


def classify_network_policy(network: dict[str, Any], console: dict[str, Any]) -> dict[str, Any]:
    """Separate scanner-induced blocking from site-originated network failures.

    The classification is deterministic and intentionally conservative. A
    request_failed event is policy-attributed only when its method+URL exactly
    match a request recorded in blocked_requests. Console errors that contain
    Chromium's ERR_BLOCKED_BY_CLIENT marker are counted separately when at
    least one policy block was recorded; they are not labeled as site errors.
    """
    blocked = [item for item in network.get("blocked_requests", []) if isinstance(item, dict)]
    blocked_keys = {
        (str(item.get("method", "")).upper(), str(item.get("url", "")))
        for item in blocked
        if item.get("method") and item.get("url")
    }
    policy_failed: list[dict[str, Any]] = []
    site_failed: list[dict[str, Any]] = []
    for event in network.get("events", []):
        if not isinstance(event, dict) or event.get("event") != "request_failed":
            continue
        key = (str(event.get("method", "")).upper(), str(event.get("url", "")))
        if key in blocked_keys:
            policy_failed.append(event)
        else:
            site_failed.append(event)

    policy_console = 0
    unattributed_console = 0
    for event in console.get("events", []):
        if not isinstance(event, dict) or event.get("type") not in {"error", "pageerror"}:
            continue
        text = str(event.get("text", ""))
        if blocked and "ERR_BLOCKED_BY_CLIENT" in text:
            policy_console += 1
        else:
            unattributed_console += 1

    return {
        "watch_dawg_policy_blocks": blocked,
        "watch_dawg_policy_block_count": len(blocked),
        "policy_attributed_request_failures": policy_failed,
        "policy_attributed_request_failure_count": len(policy_failed),
        "site_network_failures": site_failed,
        "site_network_failure_count": len(site_failed),
        "console_errors_matching_policy_block_pattern": policy_console,
        "console_errors_unattributed": unattributed_console,
        "note": (
            "Policy-attributed failures are scanner-induced observations caused by the configured passive boundary; "
            "they are not evidence that the website endpoint itself failed."
        ),
    }


def _impact_max(left: str | None, right: str | None) -> str | None:
    return right if IMPACT_RANK.get(right, 0) > IMPACT_RANK.get(left, 0) else left


def aggregate_page_findings(page_summaries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, dict[tuple[str, str], dict[str, Any]]] = {
        "deterministic": {},
        "manual_review": {},
    }
    for page in page_summaries:
        if page.get("status") != "REVIEW_READY":
            continue
        for bucket, source_key in (("deterministic", "deterministic_findings"), ("manual_review", "manual_review")):
            for finding in page.get(source_key, []):
                if not isinstance(finding, dict):
                    continue
                key = (str(finding.get("source", "unknown")), str(finding.get("rule_id", "unknown")))
                current = grouped[bucket].get(key)
                if current is None:
                    current = {
                        "source": key[0],
                        "rule_id": key[1],
                        "classification": finding.get("classification"),
                        "impact": finding.get("impact"),
                        "help": finding.get("help"),
                        "pages": [],
                        "total_nodes_observed": 0,
                    }
                    grouped[bucket][key] = current
                current["impact"] = _impact_max(current.get("impact"), finding.get("impact"))
                current["pages"].append(
                    {
                        "url": page.get("url"),
                        "analysis_ref": finding.get("analysis_ref"),
                        "node_count": finding.get("node_count"),
                    }
                )
                try:
                    current["total_nodes_observed"] += int(finding.get("node_count") or 0)
                except (TypeError, ValueError):
                    pass
    return {
        "deterministic": sorted(grouped["deterministic"].values(), key=lambda item: (-(IMPACT_RANK.get(item.get("impact"), 0)), item["rule_id"])),
        "manual_review": sorted(grouped["manual_review"].values(), key=lambda item: (-(IMPACT_RANK.get(item.get("impact"), 0)), item["rule_id"])),
    }


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SiteAuditError(f"expected JSON object in {path}")
    return value


def run_site_audit(
    *,
    urls: Iterable[str],
    evidence_root: str | Path,
    export_root: str | Path,
    axe_script_path: str | Path,
    site_id: str,
) -> dict[str, Any]:
    scoped_urls = validate_site_urls(urls)
    evidence = Path(evidence_root)
    export = Path(export_root)
    if export.exists() and any(export.iterdir()):
        raise SiteAuditError("site audit export root must be absent or empty")
    export.mkdir(parents=True, exist_ok=True)
    pages_root = export / "pages"
    pages_root.mkdir(parents=True, exist_ok=True)

    page_summaries: list[dict[str, Any]] = []
    for index, url in enumerate(scoped_urls, start=1):
        slug = _slug_for_url(url, index)
        page_dir = pages_root / slug
        target_id = f"{site_id}:{slug}"
        try:
            capture = capture_browser_evidence(
                evidence_root=evidence,
                url=url,
                target_id=target_id,
                axe_script_path=axe_script_path,
            )
            package_ref = str(capture["package_ref"])
            browser_verification = verify_browser_package(evidence, package_ref)
            axe = capture.get("derived_analyses", {}).get("axe")
            if not isinstance(axe, dict) or not axe.get("analysis_ref"):
                raise SiteAuditError("axe analysis reference missing from captured page")
            axe_ref = str(axe["analysis_ref"])
            axe_verification = verify_axe_analysis(evidence, axe_ref)
            if axe_verification.get("status") != "VERIFIED_AXE_ANALYSIS":
                raise SiteAuditError("axe analysis failed independent verification")
            export_browser_audit(
                evidence_root=evidence,
                browser_package_ref=package_ref,
                axe_analysis_ref=axe_ref,
                destination=page_dir,
            )
            audit = _load_json(page_dir / "audit.json")
            network = _load_json(page_dir / "network.json")
            console = _load_json(page_dir / "console.json")
            policy = classify_network_policy(network, console)
            page_summaries.append(
                {
                    "status": "REVIEW_READY",
                    "url": url,
                    "final_url": audit.get("subject", {}).get("source"),
                    "title": audit.get("observed", {}).get("title"),
                    "main_status": audit.get("observed", {}).get("main_status"),
                    "browser_package_ref": package_ref,
                    "browser_verification_status": browser_verification.get("status"),
                    "axe_analysis_ref": axe_ref,
                    "axe_verification_status": axe_verification.get("status"),
                    "deterministic_findings": audit.get("deterministic_findings", []),
                    "manual_review": audit.get("manual_review", []),
                    "policy_classification": policy,
                    "export_dir": str(page_dir.relative_to(export)),
                }
            )
        except (BrowserCaptureError, SiteAuditError, OSError, ValueError) as exc:
            page_summaries.append(
                {
                    "status": "CAPTURE_FAILED",
                    "url": url,
                    "error": str(exc),
                    "export_dir": str(page_dir.relative_to(export)),
                }
            )

    completed = [page for page in page_summaries if page.get("status") == "REVIEW_READY"]
    failed = [page for page in page_summaries if page.get("status") != "REVIEW_READY"]
    if not completed:
        raise SiteAuditError("all explicitly scoped pages failed capture")
    grouped = aggregate_page_findings(page_summaries)
    total_policy_blocks = sum(
        int(page.get("policy_classification", {}).get("watch_dawg_policy_block_count", 0))
        for page in completed
    )
    total_site_failures = sum(
        int(page.get("policy_classification", {}).get("site_network_failure_count", 0))
        for page in completed
    )
    site = {
        "schema": SITE_AUDIT_SCHEMA,
        "status": "SITE_REVIEW_READY" if not failed else "SITE_PARTIAL_REVIEW",
        "site_id": site_id,
        "origin": f"https://{urlsplit(scoped_urls[0]).hostname}",
        "scope": {
            "requested_pages": scoped_urls,
            "requested_page_count": len(scoped_urls),
            "completed_page_count": len(completed),
            "failed_page_count": len(failed),
            "authenticated": False,
            "clicks_or_form_submissions": False,
            "active_security_testing": False,
        },
        "summary": {
            "unique_deterministic_rule_count": len(grouped["deterministic"]),
            "unique_manual_review_rule_count": len(grouped["manual_review"]),
            "watch_dawg_policy_block_count": total_policy_blocks,
            "site_network_failure_count": total_site_failures,
            "aggregate_score": None,
        },
        "deterministic_findings": grouped["deterministic"],
        "manual_review": grouped["manual_review"],
        "pages": page_summaries,
        "interpretation": {
            "ai_generated": False,
            "note": "Repeated rule findings are grouped across pages. Watch-Dawg policy blocks are separated from site-originated network failures and must not be reported as website defects.",
        },
        "limitations": [
            "Only the explicitly listed public pages were tested.",
            "No login, click, form submission, exploit attempt, mutation, credential guessing, port scan, or remediation occurred.",
            "axe-core findings are deterministic tool results; incomplete rules require manual review and do not establish legal compliance.",
            "SITE_REVIEW_READY and SITE_PARTIAL_REVIEW are coverage/export states, not whole-site pass/fail judgments.",
            "No opaque aggregate score is calculated.",
        ],
    }
    _write_new(export / "SITE_AUDIT.json", json.dumps(site, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    _write_new(export / "SITE_AUDIT.md", render_site_markdown(site))
    return site


def render_site_markdown(site: dict[str, Any]) -> str:
    scope = site["scope"]
    summary = site["summary"]
    lines = [
        "# Watch-Dawg Multi-Page Website Evidence Audit",
        "",
        f"Status: `{site['status']}`",
        "",
        "This report groups repeated deterministic findings across explicitly scoped public pages. Scanner-policy blocks are separated from site-originated failures. No aggregate score is calculated.",
        "",
        "## Scope",
        "",
        f"- Origin: {site['origin']}",
        f"- Pages requested: {scope['requested_page_count']}",
        f"- Pages completed: {scope['completed_page_count']}",
        f"- Pages failed: {scope['failed_page_count']}",
        "- Authenticated: no",
        "- Clicks/form submissions: no",
        "- Active security testing: no",
        "",
        "## Summary",
        "",
        f"- Unique deterministic rule findings: {summary['unique_deterministic_rule_count']}",
        f"- Unique manual-review rule families: {summary['unique_manual_review_rule_count']}",
        f"- Watch-Dawg policy blocks: {summary['watch_dawg_policy_block_count']}",
        f"- Site-originated network failures: {summary['site_network_failure_count']}",
        "- Aggregate score: none",
        "",
        "## Deterministic findings",
        "",
    ]
    findings = site.get("deterministic_findings") or []
    if not findings:
        lines.append("No deterministic tool findings were attached across completed pages.")
    for item in findings:
        lines.extend(
            [
                f"### {item.get('source')} — {item.get('rule_id')}",
                "",
                f"- Impact: `{item.get('impact')}`",
                f"- Total nodes observed across pages: {item.get('total_nodes_observed')}",
                f"- Pages affected: {len(item.get('pages') or [])}",
                f"- Finding: {item.get('help')}",
                "",
            ]
        )
        for page in item.get("pages") or []:
            lines.append(f"  - {page.get('url')} — nodes: {page.get('node_count')} — `{page.get('analysis_ref')}`")
        lines.append("")

    lines.extend(["## Manual review", ""])
    review = site.get("manual_review") or []
    if not review:
        lines.append("No attached rule family was classified as requiring manual review.")
    for item in review:
        lines.append(
            f"- `{item.get('rule_id')}` ({item.get('source')}, impact `{item.get('impact')}`): "
            f"{item.get('help')} — pages affected: {len(item.get('pages') or [])}"
        )

    lines.extend(["", "## Watch-Dawg policy boundary", ""])
    lines.append(
        "Requests deliberately blocked by Watch-Dawg are scanner-induced policy events, not website defects. "
        "Exact blocked method/URL pairs are retained in each page packet."
    )
    for page in site.get("pages") or []:
        if page.get("status") != "REVIEW_READY":
            continue
        policy = page.get("policy_classification", {})
        if policy.get("watch_dawg_policy_block_count") or policy.get("site_network_failure_count"):
            lines.append(
                f"- {page.get('url')}: policy blocks={policy.get('watch_dawg_policy_block_count', 0)}, "
                f"site network failures={policy.get('site_network_failure_count', 0)}, "
                f"policy-pattern console errors={policy.get('console_errors_matching_policy_block_pattern', 0)}"
            )

    lines.extend(["", "## Page coverage", ""])
    for page in site.get("pages") or []:
        if page.get("status") == "REVIEW_READY":
            lines.append(
                f"- ✅ {page.get('url')} — HTTP {page.get('main_status')} — "
                f"`{page.get('browser_verification_status')}` / `{page.get('axe_verification_status')}`"
            )
        else:
            lines.append(f"- ⚠️ {page.get('url')} — capture failed: {page.get('error')}")

    lines.extend(["", "## Limitations", ""])
    for item in site.get("limitations") or []:
        lines.append(f"- {item}")
    return "\n".join(lines).rstrip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a bounded multi-page Watch-Dawg website audit")
    parser.add_argument("--url", action="append", required=True, dest="urls")
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--axe-script", required=True, type=Path)
    parser.add_argument("--site-id", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = run_site_audit(
            urls=args.urls,
            evidence_root=args.evidence_root,
            export_root=args.export,
            axe_script_path=args.axe_script,
            site_id=args.site_id,
        )
    except (SiteAuditError, OSError, ValueError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "SITE_REVIEW_READY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
