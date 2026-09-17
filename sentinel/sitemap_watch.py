from __future__ import annotations

import hashlib
import time
from typing import Any, Protocol
from urllib.parse import urlsplit
from xml.etree import ElementTree

from .core import Finding, Observation
from .http_watch import (
    MAX_BODY_BYTES,
    SafeHttpFetcher,
    sanitize_http_url_for_evidence,
    validate_http_url_syntax,
)


MAX_SITEMAPS = 3
MAX_URLS = 25
MAX_RUN_SECONDS = 120.0


class SitemapFetcher(Protocol):
    def fetch(self, url: str, timeout_seconds: float, max_body_bytes: int) -> dict[str, Any]: ...


def _locations(xml_text: str) -> tuple[str, list[str]]:
    root = ElementTree.fromstring(xml_text)
    root_name = root.tag.rsplit("}", 1)[-1].lower()
    locations = [
        (node.text or "").strip()
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1].lower() == "loc" and (node.text or "").strip()
    ]
    return root_name, locations


def _same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)
    return (
        a.scheme.lower(),
        (a.hostname or "").lower(),
        a.port or (443 if a.scheme.lower() == "https" else 80),
    ) == (
        b.scheme.lower(),
        (b.hostname or "").lower(),
        b.port or (443 if b.scheme.lower() == "https" else 80),
    )


class SitemapWatchPack:
    kind = "sitemap"
    allowed_authorization_modes = {"public", "owner", "contract"}

    def __init__(self, fetcher: SitemapFetcher | None = None):
        self.fetcher = fetcher or SafeHttpFetcher()

    def observe(self, target: dict[str, Any]) -> Observation:
        target_id = str(target["id"])
        sitemap_url = str(target["url"])
        safe_sitemap_url = sanitize_http_url_for_evidence(sitemap_url)
        validate_http_url_syntax(sitemap_url)
        timeout = min(max(float(target.get("timeout_seconds", 10)), 1), 15)
        run_timeout = min(
            max(float(target.get("run_timeout_seconds", 60)), 1),
            MAX_RUN_SECONDS,
        )
        deadline = time.monotonic() + run_timeout
        max_urls = min(max(int(target.get("max_urls", 25)), 1), MAX_URLS)
        max_sitemaps = min(max(int(target.get("max_sitemaps", 3)), 1), MAX_SITEMAPS)
        max_xml_bytes = min(
            max(int(target.get("max_xml_bytes", 500_000)), 1_000),
            MAX_BODY_BYTES,
        )

        def bounded_fetch(url: str, max_body_bytes: int) -> dict[str, Any]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("sitemap run deadline exceeded")
            return self.fetcher.fetch(url, min(timeout, remaining), max_body_bytes)

        root_response = bounded_fetch(sitemap_url, max_xml_bytes)
        root_body = str(root_response.pop("body"))
        root_type, root_locations = _locations(root_body)
        page_urls: list[str] = []
        child_maps_checked = 0
        sitemap_statuses = {safe_sitemap_url: int(root_response["status"])}

        if root_type == "sitemapindex":
            for child_url in root_locations[:max_sitemaps]:
                if not _same_origin(sitemap_url, child_url):
                    continue
                validate_http_url_syntax(child_url)
                child = bounded_fetch(child_url, max_xml_bytes)
                child_body = str(child.pop("body"))
                sitemap_statuses[
                    sanitize_http_url_for_evidence(child_url)
                ] = int(child["status"])
                child_type, child_locations = _locations(child_body)
                child_maps_checked += 1
                if child_type == "urlset":
                    page_urls.extend(child_locations)
                if len(page_urls) >= max_urls:
                    break
        elif root_type == "urlset":
            page_urls = root_locations
        else:
            raise ValueError(f"unsupported sitemap root element: {root_type}")

        normalized_urls = []
        seen_urls = set()
        skipped_cross_origin = []
        for page_url in page_urls:
            if page_url in seen_urls:
                continue
            seen_urls.add(page_url)
            if not _same_origin(sitemap_url, page_url):
                skipped_cross_origin.append(sanitize_http_url_for_evidence(page_url))
                continue
            validate_http_url_syntax(page_url)
            normalized_urls.append(page_url)
            if len(normalized_urls) >= max_urls:
                break

        statuses = {}
        final_urls = {}
        for page_url in normalized_urls:
            response = bounded_fetch(page_url, 1_000)
            safe_page_url = sanitize_http_url_for_evidence(page_url)
            statuses[safe_page_url] = int(response["status"])
            final_urls[safe_page_url] = sanitize_http_url_for_evidence(
                response.get("final_url", page_url),
                fallback=safe_page_url,
            )

        safe_urls = [sanitize_http_url_for_evidence(url) for url in normalized_urls]
        url_set_hash = hashlib.sha256(
            "\0".join(sorted(safe_urls)).encode("utf-8")
        ).hexdigest()
        facts = {
            "sitemap_url": safe_sitemap_url,
            "sitemap_root_type": root_type,
            "sitemap_statuses": sitemap_statuses,
            "child_sitemaps_checked": child_maps_checked,
            "urls_checked": len(normalized_urls),
            "urls": safe_urls,
            "url_set_sha256": url_set_hash,
            "statuses": statuses,
            "final_urls": final_urls,
            "skipped_cross_origin": skipped_cross_origin[:10],
            "request_budget": 1 + max_sitemaps + max_urls,
            "requests_made": 1 + child_maps_checked + len(normalized_urls),
            "run_deadline_seconds": run_timeout,
        }
        return Observation(
            target_id=target_id,
            kind=self.kind,
            ok=True,
            facts=facts,
            evidence=[safe_sitemap_url],
        )

    def evaluate(self, target, current, previous):
        checks = target.get("checks", {})
        facts = current.facts
        findings = []

        broken_statuses = {
            url: status
            for url, status in facts["statuses"].items()
            if status >= 400 or status < 200
        }
        if broken_statuses:
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="SITEMAP_URLS_BROKEN",
                    severity="high",
                    title="Sitemap contains unavailable pages",
                    detail=f"{len(broken_statuses)} checked sitemap URL(s) returned an error status.",
                    evidence={"broken": broken_statuses},
                )
            )

        off_origin_redirects = {
            url: final_url
            for url, final_url in facts["final_urls"].items()
            if not _same_origin(facts["sitemap_url"], final_url)
        }
        if off_origin_redirects:
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="SITEMAP_OFF_ORIGIN_REDIRECTS",
                    severity="medium",
                    title="Sitemap pages redirect off-site",
                    detail="One or more checked URLs landed on a different origin.",
                    evidence={"redirects": off_origin_redirects},
                )
            )

        if facts["skipped_cross_origin"]:
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="SITEMAP_CROSS_ORIGIN_ENTRIES",
                    severity="low",
                    title="Cross-origin sitemap entries were skipped",
                    detail="Sentinel did not follow sitemap entries outside the configured origin.",
                    evidence={"urls": facts["skipped_cross_origin"]},
                )
            )

        minimum_urls = int(checks.get("minimum_urls", 1))
        if facts["urls_checked"] < minimum_urls:
            findings.append(
                Finding(
                    target_id=current.target_id,
                    code="SITEMAP_URL_COUNT_LOW",
                    severity="medium",
                    title="Sitemap URL count is below the configured minimum",
                    detail=f"Checked {facts['urls_checked']} URL(s); expected at least {minimum_urls}.",
                    evidence={
                        "observed": facts["urls_checked"],
                        "minimum": minimum_urls,
                    },
                )
            )

        if previous and previous.ok:
            before_hash = previous.facts.get("url_set_sha256")
            after_hash = facts.get("url_set_sha256")
            if before_hash != after_hash:
                findings.append(
                    Finding(
                        target_id=current.target_id,
                        code="SITEMAP_URL_SET_CHANGED",
                        severity="info",
                        title="Sitemap URL set changed",
                        detail="The bounded sitemap URL set changed since the prior observation.",
                        evidence={
                            "before_count": previous.facts.get("urls_checked"),
                            "after_count": facts["urls_checked"],
                            "before_hash": before_hash,
                            "after_hash": after_hash,
                        },
                        stateful=False,
                    )
                )
        return findings
