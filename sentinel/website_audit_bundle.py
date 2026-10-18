from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Final

from .axe_adapter import AxeAdapterError, verify_axe_analysis
from .browser_capture import BrowserCaptureError, verify_browser_package
from .evidence_verify import artifact_path, read_verified_artifact, read_verified_json


AUDIT_SCHEMA: Final[str] = "watch-dawg-website-audit/v1"
MAX_REPORT_FINDINGS: Final[int] = 500


class WebsiteAuditBundleError(RuntimeError):
    """Raised when a reviewable website audit bundle cannot be built safely."""


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError as exc:
        raise WebsiteAuditBundleError(f"refusing to overwrite audit export file: {path.name}") from exc


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _markdown_table(rows: list[tuple[str, str]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    for key, value in rows:
        clean = str(value).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {key} | {clean} |")
    return "\n".join(lines)


def _untested_scope(coverage: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    if not coverage.get("authenticated"):
        gaps.append("Authenticated areas were not tested.")
    gaps.extend(
        [
            "No clicks, form submissions, credential injection, exploit attempts, credential guessing, mutation, or automatic remediation were performed.",
            "Browser network evidence is bounded metadata, not a complete HAR or archive of every subresource response body.",
            "The screenshot is viewport-bounded, not a full-page archival capture.",
            "Accessibility automation does not replace manual accessibility review.",
        ]
    )
    return gaps


def build_browser_audit(
    *,
    evidence_root: str | Path,
    browser_package_ref: str,
    axe_analysis_ref: str | None = None,
) -> dict[str, Any]:
    root = Path(evidence_root)
    try:
        browser = verify_browser_package(root, browser_package_ref)
    except BrowserCaptureError as exc:
        raise WebsiteAuditBundleError(f"browser evidence did not verify: {exc}") from exc

    capture = read_verified_json(root, browser["capture_ref"])
    artifacts = capture.get("artifacts")
    if not isinstance(artifacts, dict):
        raise WebsiteAuditBundleError("browser capture artifact map is missing")

    network_ref = artifacts.get("network", {}).get("ref")
    console_ref = artifacts.get("console", {}).get("ref")
    egress_ref = artifacts.get("egress", {}).get("ref")
    screenshot_ref = artifacts.get("screenshot", {}).get("ref")
    dom_ref = artifacts.get("rendered_dom", {}).get("ref")
    refs = [network_ref, console_ref, egress_ref, screenshot_ref, dom_ref]
    if any(not isinstance(ref, str) for ref in refs):
        raise WebsiteAuditBundleError("browser capture is missing required evidence references")

    network = json.loads(read_verified_artifact(root, network_ref).decode("utf-8"))
    console = json.loads(read_verified_artifact(root, console_ref).decode("utf-8"))
    egress = json.loads(read_verified_artifact(root, egress_ref).decode("utf-8"))

    deterministic_findings: list[dict[str, Any]] = []
    manual_review: list[dict[str, Any]] = []
    derived: dict[str, Any] = {}

    if axe_analysis_ref is not None:
        try:
            axe_verification = verify_axe_analysis(root, axe_analysis_ref)
        except AxeAdapterError as exc:
            raise WebsiteAuditBundleError(f"axe analysis did not verify: {exc}") from exc
        if axe_verification.get("browser_package_ref") != browser_package_ref:
            raise WebsiteAuditBundleError("axe analysis is not bound to the requested browser package")
        axe = read_verified_json(root, axe_analysis_ref)
        violations = axe.get("violations") if isinstance(axe.get("violations"), list) else []
        incomplete = axe.get("incomplete") if isinstance(axe.get("incomplete"), list) else []
        for item in violations[:MAX_REPORT_FINDINGS]:
            if isinstance(item, dict):
                deterministic_findings.append(
                    {
                        "source": "axe-core",
                        "classification": "DETERMINISTIC_TOOL_FINDING",
                        "rule_id": item.get("id"),
                        "impact": item.get("impact"),
                        "help": item.get("help"),
                        "help_url": item.get("help_url"),
                        "node_count": item.get("node_count"),
                        "analysis_ref": axe_analysis_ref,
                    }
                )
        for item in incomplete[:MAX_REPORT_FINDINGS]:
            if isinstance(item, dict):
                manual_review.append(
                    {
                        "source": "axe-core",
                        "classification": "MANUAL_REVIEW_REQUIRED",
                        "rule_id": item.get("id"),
                        "impact": item.get("impact"),
                        "help": item.get("help"),
                        "node_count": item.get("node_count"),
                        "analysis_ref": axe_analysis_ref,
                    }
                )
        derived["axe"] = {
            "verification_status": axe_verification.get("status"),
            "analysis_ref": axe_analysis_ref,
            "engine": axe_verification.get("engine"),
            "counts": axe_verification.get("counts"),
            "truncated": axe_verification.get("truncated"),
        }

    coverage = browser.get("coverage") if isinstance(browser.get("coverage"), dict) else {}
    egress_summary = egress.get("summary") if isinstance(egress.get("summary"), dict) else {}
    audit = {
        "schema": AUDIT_SCHEMA,
        "status": "REVIEW_READY",
        "subject": {
            "target_id": browser.get("target_id"),
            "source": browser.get("final_url"),
            "observed_at": browser.get("observed_at"),
        },
        "integrity": {
            "browser_evidence_status": browser.get("status"),
            "browser_package_ref": browser_package_ref,
            "browser_capture_ref": browser.get("capture_ref"),
            "derived_analyses": derived,
        },
        "observed": {
            "main_status": browser.get("main_status"),
            "title": capture.get("title"),
            "navigation_elapsed_ms": capture.get("navigation_elapsed_ms"),
            "requests_seen": network.get("requests_seen"),
            "network_events_recorded": network.get("events_recorded"),
            "console_events_recorded": console.get("events_recorded"),
            "egress_attempts_recorded": egress_summary.get("attempts_recorded"),
            "egress_allowed_attempts": egress_summary.get("allowed_attempts"),
            "egress_blocked_attempts": egress_summary.get("blocked_attempts"),
        },
        "coverage": coverage,
        "deterministic_findings": deterministic_findings,
        "manual_review": manual_review,
        "untested_or_out_of_scope": _untested_scope(coverage),
        "evidence_refs": {
            "rendered_dom": dom_ref,
            "screenshot": screenshot_ref,
            "console": console_ref,
            "network": network_ref,
            "egress": egress_ref,
        },
        "interpretation": {
            "ai_generated": False,
            "note": "This audit bundle contains verified observations and deterministic tool results only. Business impact, root cause, and remediation priority require separate interpretation.",
        },
        "limitations": [
            "REVIEW_READY is an export state, not a claim that the website passed or failed an overall audit.",
            "No opaque aggregate score is calculated.",
            "Cryptographic integrity and deterministic tool findings do not establish intent, causation, legal compliance, or the truth of a business allegation.",
        ],
    }
    return audit


def render_markdown(audit: dict[str, Any]) -> str:
    subject = audit["subject"]
    observed = audit["observed"]
    integrity = audit["integrity"]
    lines = [
        "# Watch-Dawg Website Evidence Audit",
        "",
        "This review packet separates verified observations, deterministic tool findings, manual-review items, and untested scope. It does not provide an opaque score.",
        "",
        "## Subject",
        "",
        _markdown_table(
            [
                ("Target", subject.get("target_id")),
                ("Source", subject.get("source")),
                ("Observed at", subject.get("observed_at")),
                ("Main HTTP status", observed.get("main_status")),
                ("Page title", observed.get("title")),
            ]
        ),
        "",
        "## Integrity",
        "",
        _markdown_table(
            [
                ("Browser evidence", integrity.get("browser_evidence_status")),
                ("Browser package", integrity.get("browser_package_ref")),
                ("Browser capture", integrity.get("browser_capture_ref")),
            ]
        ),
        "",
        "## Observed",
        "",
        _markdown_table([(key.replace("_", " ").title(), value) for key, value in observed.items()]),
        "",
        "## Deterministic findings",
        "",
    ]

    findings = audit.get("deterministic_findings") or []
    if findings:
        for index, item in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {item.get('source')} — {item.get('rule_id')}",
                    "",
                    f"- Classification: `{item.get('classification')}`",
                    f"- Impact: `{item.get('impact')}`",
                    f"- Nodes observed: {item.get('node_count')}",
                    f"- Finding: {item.get('help')}",
                    f"- Evidence analysis ref: `{item.get('analysis_ref')}`",
                    "",
                ]
            )
    else:
        lines.extend(["No deterministic tool findings were attached to this packet.", ""])

    lines.extend(["## Manual review", ""])
    review = audit.get("manual_review") or []
    if review:
        for item in review:
            lines.append(
                f"- `{item.get('rule_id')}` ({item.get('source')}): {item.get('help')} — `{item.get('analysis_ref')}`"
            )
    else:
        lines.append("No attached tool result was classified as requiring manual review.")

    lines.extend(["", "## Untested / out of scope", ""])
    for item in audit.get("untested_or_out_of_scope") or []:
        lines.append(f"- {item}")

    lines.extend(["", "## Evidence references", ""])
    for name, reference in audit.get("evidence_refs", {}).items():
        lines.append(f"- {name}: `{reference}`")

    lines.extend(["", "## Interpretation boundary", "", audit["interpretation"]["note"], ""])
    return "\n".join(lines).rstrip() + "\n"


def export_browser_audit(
    *,
    evidence_root: str | Path,
    browser_package_ref: str,
    destination: str | Path,
    axe_analysis_ref: str | None = None,
) -> dict[str, Any]:
    root = Path(evidence_root)
    output = Path(destination)
    if output.exists() and any(output.iterdir()):
        raise WebsiteAuditBundleError("audit export destination must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)

    audit = build_browser_audit(
        evidence_root=root,
        browser_package_ref=browser_package_ref,
        axe_analysis_ref=axe_analysis_ref,
    )
    capture = read_verified_json(root, audit["integrity"]["browser_capture_ref"])
    artifacts = capture["artifacts"]

    copies = {
        "rendered-dom.html": artifacts["rendered_dom"]["ref"],
        "screenshot.png": artifacts["screenshot"]["ref"],
        "console.json": artifacts["console"]["ref"],
        "network.json": artifacts["network"]["ref"],
        "egress.json": artifacts["egress"]["ref"],
    }
    for filename, reference in copies.items():
        shutil.copyfile(artifact_path(root, reference), output / filename)

    if axe_analysis_ref is not None:
        shutil.copyfile(artifact_path(root, axe_analysis_ref), output / "axe-analysis.json")

    _write_new(output / "audit.json", _json_bytes(audit))
    _write_new(output / "AUDIT.md", render_markdown(audit).encode("utf-8"))
    _write_new(
        output / "README.txt",
        (
            "Watch-Dawg Website Evidence Audit\n\n"
            "Start with AUDIT.md. audit.json contains the machine-readable review packet.\n"
            "The accompanying evidence files are copied only after their parent package verifies.\n"
            "This export does not provide a single pass/fail score and does not authorize remediation.\n"
        ).encode("utf-8"),
    )
    return {
        "status": "AUDIT_EXPORTED",
        "destination": str(output),
        "browser_package_ref": browser_package_ref,
        "axe_analysis_ref": axe_analysis_ref,
        "files": sorted(path.name for path in output.iterdir() if path.is_file()),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a human-reviewable Watch-Dawg website evidence audit")
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--browser-package-ref", required=True)
    parser.add_argument("--axe-analysis-ref")
    parser.add_argument("--export", required=True, type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = export_browser_audit(
            evidence_root=args.evidence_root,
            browser_package_ref=args.browser_package_ref,
            axe_analysis_ref=args.axe_analysis_ref,
            destination=args.export,
        )
    except (OSError, ValueError, WebsiteAuditBundleError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
