from __future__ import annotations

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

from .evidence_store import ContentAddressedEvidenceStore
from .evidence_verify import (
    PackageVerificationError,
    read_verified_artifact,
    read_verified_json,
    verify_package,
)
from .http_watch import sanitize_http_url_for_evidence


ANALYSIS_SCHEMA: Final[str] = "watch-dawg-page-analysis/v1"
MAX_REFERENCES: Final[int] = 1_000
ACTIVE_RESOURCE_TAGS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("script", "src"),
        ("iframe", "src"),
        ("object", "data"),
        ("embed", "src"),
    }
)
PASSIVE_RESOURCE_TAGS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("img", "src"),
        ("audio", "src"),
        ("video", "src"),
        ("source", "src"),
        ("track", "src"),
        ("video", "poster"),
    }
)


class PageAnalysisError(RuntimeError):
    """Raised when deterministic page analysis cannot be completed safely."""


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, hostname, port


def _safe_resolved_url(base_url: str, value: str) -> str:
    try:
        resolved = urljoin(base_url, value)
    except ValueError:
        return "<invalid-url>"
    return sanitize_http_url_for_evidence(resolved)


def _is_http_url(value: str) -> bool:
    try:
        return urlsplit(value).scheme.lower() == "http"
    except ValueError:
        return False


class _PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_depth = 0
        self.title_parts: list[str] = []
        self.references: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self._form_stack: list[int] = []
        self._reference_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.lower()
        attributes = {key.lower(): value for key, value in attrs}
        if normalized_tag == "title":
            self.title_depth += 1

        if normalized_tag == "form":
            raw_action = attributes.get("action") or ""
            resolved_action = urljoin(self.base_url, raw_action) if raw_action else self.base_url
            self.forms.append(
                {
                    "method": (attributes.get("method") or "get").lower(),
                    "action": sanitize_http_url_for_evidence(resolved_action),
                    "password_inputs": 0,
                }
            )
            self._form_stack.append(len(self.forms) - 1)

        if normalized_tag == "input" and self._form_stack:
            input_type = (attributes.get("type") or "text").lower()
            if input_type == "password":
                self.forms[self._form_stack[-1]]["password_inputs"] += 1

        candidates: list[tuple[str, str]] = []
        if (normalized_tag, "src") in ACTIVE_RESOURCE_TAGS | PASSIVE_RESOURCE_TAGS:
            candidates.append(("src", attributes.get("src") or ""))
        if (normalized_tag, "poster") in PASSIVE_RESOURCE_TAGS:
            candidates.append(("poster", attributes.get("poster") or ""))
        if (normalized_tag, "data") in ACTIVE_RESOURCE_TAGS:
            candidates.append(("data", attributes.get("data") or ""))
        if normalized_tag == "link":
            rel = (attributes.get("rel") or "").lower().split()
            href = attributes.get("href") or ""
            if href and any(item in {"stylesheet", "preload", "modulepreload", "icon"} for item in rel):
                candidates.append(("href", href))

        for attribute, raw_value in candidates:
            if not raw_value or self._reference_count >= MAX_REFERENCES:
                continue
            resolved = _safe_resolved_url(self.base_url, raw_value)
            if resolved == "<invalid-url>":
                continue
            self.references.append(
                {
                    "tag": normalized_tag,
                    "attribute": attribute,
                    "url": resolved,
                    "class": "active" if (normalized_tag, attribute) in ACTIVE_RESOURCE_TAGS else "passive",
                }
            )
            self._reference_count += 1

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag == "title" and self.title_depth:
            self.title_depth -= 1
        if normalized_tag == "form" and self._form_stack:
            self._form_stack.pop()

    def handle_data(self, data: str) -> None:
        if self.title_depth:
            self.title_parts.append(data)


def analyze_package(evidence_root: str | Path, package_ref: str) -> dict[str, Any]:
    root = Path(evidence_root)
    try:
        verification = verify_package(root, package_ref)
        capture = read_verified_json(root, verification["capture_ref"])
        body = capture.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("ref"), str):
            raise PageAnalysisError("capture body reference is missing")
        body_bytes = read_verified_artifact(root, body["ref"])
    except PackageVerificationError as exc:
        raise PageAnalysisError(f"evidence package failed verification: {exc}") from exc

    source = capture.get("final_url")
    if not isinstance(source, str):
        raise PageAnalysisError("capture final_url is missing")
    content_type = str(capture.get("headers", {}).get("content-type", ""))
    if "html" not in content_type.lower():
        raise PageAnalysisError("deterministic page checks require an HTML capture")

    try:
        charset = "utf-8"
        for part in content_type.split(";")[1:]:
            name, _, value = part.strip().partition("=")
            if name.lower() == "charset" and value:
                charset = value.strip().strip('"')
                break
        html = body_bytes.decode(charset, errors="replace")
    except LookupError:
        html = body_bytes.decode("utf-8", errors="replace")

    parser = _PageParser(source)
    parser.feed(html)

    source_scheme, source_host, source_port = _origin(source)
    findings: list[dict[str, Any]] = []
    mixed_active = [
        item for item in parser.references
        if source_scheme == "https" and _is_http_url(item["url"]) and item["class"] == "active"
    ]
    mixed_passive = [
        item for item in parser.references
        if source_scheme == "https" and _is_http_url(item["url"]) and item["class"] == "passive"
    ]
    if mixed_active:
        findings.append(
            {
                "code": "MIXED_CONTENT_ACTIVE",
                "severity": "high",
                "truth": "VERIFIED",
                "title": "HTTPS page references active content over HTTP",
                "detail": f"Observed {len(mixed_active)} active resource reference(s) using HTTP from an HTTPS page.",
                "evidence": {"references": mixed_active[:50]},
            }
        )
    if mixed_passive:
        findings.append(
            {
                "code": "MIXED_CONTENT_PASSIVE",
                "severity": "medium",
                "truth": "VERIFIED",
                "title": "HTTPS page references passive content over HTTP",
                "detail": f"Observed {len(mixed_passive)} passive resource reference(s) using HTTP from an HTTPS page.",
                "evidence": {"references": mixed_passive[:50]},
            }
        )

    insecure_forms: list[dict[str, Any]] = []
    password_get_forms: list[dict[str, Any]] = []
    cross_origin_forms: list[dict[str, Any]] = []
    for form in parser.forms:
        action = str(form["action"])
        if source_scheme == "https" and _is_http_url(action):
            insecure_forms.append(form)
        if form["password_inputs"] and form["method"] == "get":
            password_get_forms.append(form)
        try:
            if _origin(action) != (source_scheme, source_host, source_port):
                cross_origin_forms.append(form)
        except ValueError:
            continue

    if insecure_forms:
        findings.append(
            {
                "code": "FORM_INSECURE_TRANSPORT",
                "severity": "high",
                "truth": "VERIFIED",
                "title": "HTTPS page contains a form that submits over HTTP",
                "detail": f"Observed {len(insecure_forms)} form(s) whose resolved action uses HTTP.",
                "evidence": {"forms": insecure_forms[:50]},
            }
        )
    if password_get_forms:
        findings.append(
            {
                "code": "PASSWORD_FORM_USES_GET",
                "severity": "high",
                "truth": "VERIFIED",
                "title": "Password field is submitted with GET",
                "detail": f"Observed {len(password_get_forms)} form(s) containing a password input while using GET.",
                "evidence": {"forms": password_get_forms[:50]},
            }
        )
    if cross_origin_forms:
        findings.append(
            {
                "code": "FORM_CROSS_ORIGIN_ACTION",
                "severity": "info",
                "truth": "VERIFIED",
                "title": "Form submits to a different origin",
                "detail": f"Observed {len(cross_origin_forms)} form(s) posting or navigating to another origin. This is a review signal, not proof of a flaw.",
                "evidence": {"forms": cross_origin_forms[:50]},
            }
        )

    title = " ".join("".join(parser.title_parts).split())
    if not title:
        findings.append(
            {
                "code": "PAGE_TITLE_MISSING",
                "severity": "low",
                "truth": "VERIFIED",
                "title": "HTML page has no non-empty title",
                "detail": "The captured HTML did not contain a non-empty title element.",
                "evidence": {},
            }
        )

    counts = {
        "high": sum(item["severity"] == "high" for item in findings),
        "medium": sum(item["severity"] == "medium" for item in findings),
        "low": sum(item["severity"] == "low" for item in findings),
        "info": sum(item["severity"] == "info" for item in findings),
    }
    return {
        "schema": ANALYSIS_SCHEMA,
        "status": "DETERMINISTIC_ANALYSIS",
        "package_ref": package_ref,
        "capture_ref": verification["capture_ref"],
        "body_ref": verification["body_ref"],
        "source": source,
        "target_id": verification.get("target_id"),
        "observed_at": verification.get("observed_at"),
        "coverage": {
            **verification.get("coverage", {}),
            "html_parser": "python-html.parser",
            "resource_references_examined": len(parser.references),
            "forms_examined": len(parser.forms),
            "reference_limit": MAX_REFERENCES,
            "network_requests_added_by_analysis": 0,
        },
        "finding_counts": counts,
        "findings": findings,
        "limitations": [
            "This analysis examines only the exact captured HTML bytes; it does not execute JavaScript.",
            "Resource URLs and form actions are parsed from markup but are not fetched by this analysis step.",
            "Cross-origin form submission is reported as an informational review signal, not a vulnerability claim.",
        ],
    }


def store_analysis(evidence_root: str | Path, analysis: dict[str, Any]) -> dict[str, Any]:
    source = analysis.get("source")
    observed_at = analysis.get("observed_at")
    if not isinstance(source, str) or not isinstance(observed_at, str):
        raise PageAnalysisError("analysis source and observed_at are required for storage")
    store = ContentAddressedEvidenceStore(evidence_root)
    artifact = store.put_json(
        analysis,
        source=source,
        observed_at=observed_at,
        artifact_type="deterministic-page-analysis",
    )
    return {**analysis, "analysis_ref": artifact["ref"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run deterministic passive page checks over a verified Watch-Dawg evidence package"
    )
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--package-ref", required=True)
    parser.add_argument("--store-result", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        analysis = analyze_package(args.evidence_root, args.package_ref)
        if args.store_result:
            analysis = store_analysis(args.evidence_root, analysis)
    except (OSError, PageAnalysisError) as exc:
        print(json.dumps({
            "schema": ANALYSIS_SCHEMA,
            "status": "FAILED",
            "error": str(exc),
        }, indent=2, sort_keys=True))
        return 2
    print(json.dumps(analysis, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
