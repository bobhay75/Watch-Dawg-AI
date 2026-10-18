from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final

from .evidence_verify import (
    PackageVerificationError,
    parse_sha256_ref,
    read_verified_artifact,
    read_verified_json,
)


AXE_ANALYSIS_SCHEMA: Final[str] = "watch-dawg-axe-analysis/v1"
AXE_ENGINE_NAME: Final[str] = "axe-core"
MAX_AXE_SCRIPT_BYTES: Final[int] = 2_000_000
MAX_AXE_RESULT_BYTES: Final[int] = 4_000_000
MAX_RULE_NODES: Final[int] = 50
MAX_TOTAL_NODES: Final[int] = 500
MAX_TEXT: Final[int] = 4_000


class AxeAdapterError(RuntimeError):
    """Raised when deterministic axe analysis cannot be produced or verified."""


def load_axe_source(path: str | Path) -> bytes:
    source_path = Path(path)
    try:
        payload = source_path.read_bytes()
    except OSError as exc:
        raise AxeAdapterError("axe-core script could not be read") from exc
    if not payload or len(payload) > MAX_AXE_SCRIPT_BYTES:
        raise AxeAdapterError("axe-core script is empty or exceeds the configured size limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AxeAdapterError("axe-core script must be UTF-8 JavaScript") from exc
    if "axe.run" not in text and "axe=" not in text and "axe =" not in text:
        raise AxeAdapterError("axe-core script does not contain the expected engine symbols")
    return payload


def run_axe_on_page(page: Any, source: bytes, *, timeout_ms: int = 10_000) -> dict[str, Any]:
    """Inject pinned axe-core bytes into an already loaded page and run locally.

    Iframe traversal and preload are disabled so this analysis does not initiate
    a second crawl or fetch cross-origin CSS assets. The result is still a tool
    finding, not a legal WCAG compliance determination.
    """
    timeout_ms = min(max(int(timeout_ms), 1_000), 20_000)
    try:
        script_text = source.decode("utf-8")
        page.add_script_tag(content=script_text)
        result = page.evaluate(
            """
            async ({ timeoutMs }) => {
              if (!globalThis.axe || typeof globalThis.axe.run !== 'function')
                throw new Error('axe-core did not initialize');
              const audit = globalThis.axe.run(document, {
                iframes: false,
                preload: false,
                resultTypes: ['violations', 'incomplete']
              });
              const timeout = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('axe-core timed out')), timeoutMs));
              return await Promise.race([audit, timeout]);
            }
            """,
            {"timeoutMs": timeout_ms},
        )
    except Exception as exc:
        raise AxeAdapterError(f"axe-core execution failed: {str(exc)[:500]}") from exc
    if not isinstance(result, dict):
        raise AxeAdapterError("axe-core returned an unexpected result type")
    return result


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    rendered = str(value or "")
    return rendered if len(rendered) <= limit else rendered[:limit] + "…"


def _normalize_node(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {"target": [], "html": "", "failure_summary": ""}
    target = node.get("target")
    if not isinstance(target, list):
        target = []
    return {
        "impact": node.get("impact"),
        "target": [_text(item, 1_000) for item in target[:8]],
        "html": _text(node.get("html"), 2_000),
        "failure_summary": _text(node.get("failureSummary"), 4_000),
    }


def _normalize_rules(values: Any, node_budget: list[int]) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(values, list):
        return [], False
    normalized: list[dict[str, Any]] = []
    truncated = False
    for value in values:
        if not isinstance(value, dict):
            continue
        nodes = value.get("nodes") if isinstance(value.get("nodes"), list) else []
        remaining = max(0, MAX_TOTAL_NODES - node_budget[0])
        keep = min(len(nodes), MAX_RULE_NODES, remaining)
        selected = [_normalize_node(node) for node in nodes[:keep]]
        node_budget[0] += keep
        if keep < len(nodes):
            truncated = True
        normalized.append(
            {
                "id": _text(value.get("id"), 200),
                "impact": value.get("impact"),
                "tags": [_text(tag, 200) for tag in (value.get("tags") or [])[:50]],
                "description": _text(value.get("description")),
                "help": _text(value.get("help")),
                "help_url": _text(value.get("helpUrl"), 1_000),
                "node_count": len(nodes),
                "nodes": selected,
            }
        )
        if node_budget[0] >= MAX_TOTAL_NODES and any(
            isinstance(other, dict) and other.get("nodes") for other in values[len(normalized):]
        ):
            truncated = True
    return normalized, truncated


def build_axe_analysis(
    *,
    raw_results: dict[str, Any],
    browser_package_ref: str,
    browser_capture_ref: str,
    engine_script_artifact: dict[str, Any],
    target_id: str,
    source: str,
    observed_at: str,
) -> dict[str, Any]:
    engine = raw_results.get("testEngine") if isinstance(raw_results.get("testEngine"), dict) else {}
    engine_version = _text(engine.get("version"), 100)
    if not engine_version:
        raise AxeAdapterError("axe-core result did not identify its engine version")

    node_budget = [0]
    violations, violation_truncated = _normalize_rules(raw_results.get("violations"), node_budget)
    incomplete, incomplete_truncated = _normalize_rules(raw_results.get("incomplete"), node_budget)
    passes = raw_results.get("passes") if isinstance(raw_results.get("passes"), list) else []
    inapplicable = raw_results.get("inapplicable") if isinstance(raw_results.get("inapplicable"), list) else []

    analysis = {
        "schema": AXE_ANALYSIS_SCHEMA,
        "status": "DETERMINISTIC_TOOL_ANALYSIS",
        "tool": {
            "name": AXE_ENGINE_NAME,
            "version": engine_version,
            "script_ref": engine_script_artifact.get("ref"),
            "script_sha256": engine_script_artifact.get("sha256"),
            "script_size_bytes": engine_script_artifact.get("size_bytes"),
        },
        "subject": {
            "browser_package_ref": browser_package_ref,
            "browser_capture_ref": browser_capture_ref,
            "target_id": target_id,
            "source": source,
            "observed_at": observed_at,
        },
        "options": {
            "iframes": False,
            "preload": False,
            "result_types": ["violations", "incomplete"],
            "additional_network_requests_expected": 0,
        },
        "counts": {
            "violation_rules": len(raw_results.get("violations") or []),
            "incomplete_rules": len(raw_results.get("incomplete") or []),
            "pass_rules": len(passes),
            "inapplicable_rules": len(inapplicable),
            "reported_nodes": node_budget[0],
        },
        "violations": violations,
        "incomplete": incomplete,
        "truncated": bool(violation_truncated or incomplete_truncated),
        "limits": {
            "max_rule_nodes": MAX_RULE_NODES,
            "max_total_nodes": MAX_TOTAL_NODES,
            "max_serialized_bytes": MAX_AXE_RESULT_BYTES,
        },
        "limitations": [
            "Axe output is deterministic tool analysis of the rendered page state, not a legal WCAG compliance determination.",
            "Incomplete results require human review and are not treated as confirmed violations.",
            "Iframe traversal and axe asset preloading are disabled for this passive audit profile.",
            "Axe findings may contain false positives or omit issues requiring manual accessibility testing.",
        ],
    }
    serialized = json.dumps(analysis, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(serialized) > MAX_AXE_RESULT_BYTES:
        raise AxeAdapterError("normalized axe-core result exceeds the configured evidence size limit")
    return analysis


def verify_axe_analysis(evidence_root: str | Path, analysis_ref: str) -> dict[str, Any]:
    root = Path(evidence_root)
    try:
        analysis = read_verified_json(root, analysis_ref)
    except PackageVerificationError as exc:
        raise AxeAdapterError(f"axe analysis failed hash verification: {exc}") from exc
    if analysis.get("schema") != AXE_ANALYSIS_SCHEMA:
        raise AxeAdapterError("unsupported axe analysis schema")
    if analysis.get("status") != "DETERMINISTIC_TOOL_ANALYSIS":
        raise AxeAdapterError("axe analysis status is invalid")

    tool = analysis.get("tool")
    subject = analysis.get("subject")
    if not isinstance(tool, dict) or not isinstance(subject, dict):
        raise AxeAdapterError("axe analysis tool or subject metadata is missing")
    script_ref = tool.get("script_ref")
    package_ref = subject.get("browser_package_ref")
    capture_ref = subject.get("browser_capture_ref")
    if not isinstance(script_ref, str) or not isinstance(package_ref, str) or not isinstance(capture_ref, str):
        raise AxeAdapterError("axe analysis references are incomplete")

    try:
        script = read_verified_artifact(root, script_ref)
    except PackageVerificationError as exc:
        raise AxeAdapterError(f"axe engine script failed verification: {exc}") from exc
    if tool.get("script_sha256") != parse_sha256_ref(script_ref):
        raise AxeAdapterError("axe engine script SHA-256 metadata does not match its reference")
    if tool.get("script_size_bytes") != len(script):
        raise AxeAdapterError("axe engine script size metadata does not match stored bytes")
    if hashlib.sha256(script).hexdigest() != tool.get("script_sha256"):
        raise AxeAdapterError("axe engine script digest does not match analysis metadata")

    from .browser_capture import verify_browser_package

    browser_verification = verify_browser_package(root, package_ref)
    if browser_verification.get("capture_ref") != capture_ref:
        raise AxeAdapterError("axe analysis capture reference does not match browser package")
    if browser_verification.get("target_id") != subject.get("target_id"):
        raise AxeAdapterError("axe analysis target does not match browser package")
    if browser_verification.get("final_url") != subject.get("source"):
        raise AxeAdapterError("axe analysis source does not match browser package")
    if browser_verification.get("observed_at") != subject.get("observed_at"):
        raise AxeAdapterError("axe analysis timestamp does not match browser package")

    return {
        "schema": "watch-dawg-axe-analysis-verification/v1",
        "status": "VERIFIED_AXE_ANALYSIS",
        "analysis_ref": analysis_ref,
        "browser_package_ref": package_ref,
        "browser_evidence_status": browser_verification.get("status"),
        "engine": tool,
        "counts": analysis.get("counts"),
        "truncated": analysis.get("truncated"),
        "limitations": analysis.get("limitations"),
    }
