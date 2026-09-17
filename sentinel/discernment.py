from __future__ import annotations

from typing import Any


ACTION_CATALOG: dict[str, dict[str, str]] = {
    "AUTHORIZATION_REQUIRED": {
        "deficit": "Evidence access and accountability are undefined.",
        "why_it_matters": "The target cannot be inspected safely without declared authority.",
        "preventive_action": "Record the owner, scope, permitted methods, and expiration before enabling observation.",
        "prosperity_lever": "Restore safe visibility so preventable loss can be measured and managed.",
        "success_metric": "A current authorization record exists and the assigned watch pack completes successfully.",
        "verification": "Run the pack again and retain the authorization and observation receipts.",
    },
    "AUTHORIZATION_SCOPE_DENIED": {
        "deficit": "The declared authority does not cover this watch pack's observation methods.",
        "why_it_matters": "Running the pack would exceed the recorded monitoring scope.",
        "preventive_action": "Use a permitted watch pack or obtain and record authorization for the additional methods and scope.",
        "prosperity_lever": "Restore accountable visibility without crossing the approved boundary.",
        "success_metric": "The authorization record covers the selected pack, target, methods, and duration.",
        "verification": "Confirm the authorization record against the pack's allowed modes before observation.",
    },
    "HTTP_OBSERVATION_FAILED": {
        "deficit": "The target has an active monitoring blind spot.",
        "why_it_matters": "A monitoring blind spot can hide both outages and recovery.",
        "preventive_action": "Verify DNS, TLS, reachability, and the monitor's network path, then restore observation.",
        "prosperity_lever": "Reduce undetected downtime and the customer loss that may occur during it.",
        "success_metric": "Consecutive scheduled observations complete with evidence.",
        "verification": "Confirm successful observations across at least two monitoring intervals.",
    },
    "HTTP_STATUS_UNEXPECTED": {
        "deficit": "The intended customer or integration route is not returning its approved status.",
        "why_it_matters": "Visitors or integrations may not reach the intended resource.",
        "preventive_action": "Confirm the intended route, redirect chain, deployment health, and rollback path.",
        "prosperity_lever": "Recover reachable traffic and completed customer journeys.",
        "success_metric": "The route returns the approved status and destination without an unintended redirect.",
        "verification": "Repeat the same request and retain the final URL and status receipt.",
    },
    "HTTP_LATENCY_HIGH": {
        "deficit": "Response time exceeds the target's approved performance threshold.",
        "why_it_matters": "Slow responses increase abandonment risk and can precede capacity failures.",
        "preventive_action": "Measure origin, database, asset, and third-party timing before the next traffic peak.",
        "prosperity_lever": "Remove customer friction and increase the share of visits able to complete the intended action.",
        "success_metric": "Measured response time remains below the configured threshold during comparable traffic.",
        "verification": "Compare before-and-after latency over the same routes and observation window.",
    },
    "JSONLD_OFFER_PRICE_ZERO": {
        "deficit": "Machine-readable pricing contradicts the visible authorized offer.",
        "why_it_matters": "Search platforms may display misleading ticket information.",
        "preventive_action": "Make structured pricing match the visible authorized offer and validate it after publishing.",
        "prosperity_lever": "Improve buyer confidence and preserve qualified search traffic.",
        "success_metric": "Visible, structured, and primary-source prices agree.",
        "verification": "Re-fetch the page, validate its structured data, and compare it with the primary checkout.",
    },
    "REQUIRED_TEXT_MISSING": {
        "deficit": "Approved information required for the customer, safety, or operating journey is absent.",
        "why_it_matters": "A required sales, safety, or operational message may have disappeared.",
        "preventive_action": "Restore the approved content and add a release check for the marker.",
        "prosperity_lever": "Reduce confusion and restore the intended conversion or operating step.",
        "success_metric": "The approved message is visible at the required step and survives the next release.",
        "verification": "Re-observe the page after release and again after the next deployment.",
    },
    "SERVER_ERROR_RATE_HIGH": {
        "deficit": "The service is losing an unacceptable share of requests to server errors.",
        "why_it_matters": "Repeated server failures can interrupt customer and staff workflows.",
        "preventive_action": "Trace the failing routes, correlate deploy and resource events, and set an error-budget threshold.",
        "prosperity_lever": "Recover successful transactions and reduce avoidable support and rework.",
        "success_metric": "The comparable 5xx rate remains below the configured error budget.",
        "verification": "Compare matched traffic windows before and after the correction.",
    },
    "AUTH_FAILURES_HIGH": {
        "deficit": "Authentication failures exceed the approved operating threshold.",
        "why_it_matters": "The pattern may indicate user friction, broken authentication, or hostile automation.",
        "preventive_action": "Separate users from automation, verify login health, and apply rate controls without locking out valid users.",
        "prosperity_lever": "Recover legitimate access while reducing support load and hostile resource use.",
        "success_metric": "Legitimate login success improves while abusive attempts are contained.",
        "verification": "Compare authenticated success, failure reasons, and support incidents over matched periods.",
    },
    "SUSPICIOUS_PATH_ACTIVITY": {
        "deficit": "The exposed surface is attracting requests associated with common automated probes.",
        "why_it_matters": "Common probe traffic reveals exposed attack surface even when no compromise is proven.",
        "preventive_action": "Confirm sensitive files are absent, patch exposed software, and tune edge blocking with human review.",
        "prosperity_lever": "Lower preventable security exposure and the operating cost of malicious traffic.",
        "success_metric": "Sensitive resources remain unavailable and repeat probe traffic is contained without blocking valid users.",
        "verification": "Recheck exposed paths, patch state, blocked events, and legitimate-user error rates.",
    },
    "UNEXPECTED_OPEN_PORT": {
        "deficit": "A reachable network service is outside the approved service baseline.",
        "why_it_matters": "Unnecessary exposed services increase attack surface and operating uncertainty.",
        "preventive_action": "Confirm ownership and purpose, then close, restrict, or formally approve the service through change control.",
        "prosperity_lever": "Reduce avoidable exposure and the support cost of undocumented infrastructure.",
        "success_metric": "Every reachable service is documented, necessary, owner-approved, and access-restricted.",
        "verification": "Repeat the same authorized TCP checks and compare them with the approved service inventory.",
    },
    "EXPECTED_SERVICE_UNREACHABLE": {
        "deficit": "An approved network service is not reachable at its expected endpoint.",
        "why_it_matters": "The condition may represent an outage, routing change, or stale service inventory.",
        "preventive_action": "Confirm intended availability, routing, firewall policy, and the approved service baseline.",
        "prosperity_lever": "Restore dependable service delivery or remove obsolete operating assumptions.",
        "success_metric": "The service is reachable as approved or the baseline is updated through change control.",
        "verification": "Repeat the authorized check after the service or baseline correction.",
    },
    "SECRET_EXPOSURE": {
        "deficit": "Potential credential material exists in a reviewed file.",
        "why_it_matters": "Stored credentials can enable unauthorized access and complicate incident containment.",
        "preventive_action": "Validate the match privately, revoke or rotate confirmed credentials, remove them from source and history, and use an approved secret store.",
        "prosperity_lever": "Reduce breach exposure and avoid preventable incident and recovery costs.",
        "success_metric": "The credential is invalidated, absent from reviewed files, and supplied only through the approved secret boundary.",
        "verification": "Re-run the redacted exposure check and retain rotation and removal records without storing the credential.",
    },
}


DEFAULT_ACTION = {
    "deficit": "The observed condition differs from the approved or efficient operating state.",
    "why_it_matters": "The observation differs from the expected operating condition.",
    "preventive_action": "Verify the evidence, identify the accountable owner, and correct the smallest upstream cause.",
    "prosperity_lever": "Remove measurable friction, waste, risk, or lost opportunity from the operating path.",
    "success_metric": "A named before-and-after measure reaches its approved target.",
    "verification": "Repeat the original observation and compare it with the retained baseline.",
}


def explain_finding(finding: dict[str, Any]) -> dict[str, Any]:
    code = str(finding.get("code", ""))
    match = ACTION_CATALOG.get(code)
    if match is None:
        match = next(
            (value for prefix, value in ACTION_CATALOG.items() if code.startswith(prefix)),
            DEFAULT_ACTION,
        )
    return {**finding, **match}


def build_discernment(results: list[dict[str, Any]]) -> dict[str, Any]:
    findings = [
        explain_finding(item)
        for result in results
        for item in result.get("current_findings", [])
    ]
    blind_spots: list[dict[str, str]] = []
    for result in results:
        if not result.get("evidence_sources"):
            finding_codes = {
                str(item.get("code", ""))
                for item in result.get("current_findings", [])
            }
            if "AUTHORIZATION_REQUIRED" in finding_codes:
                gap = "Evidence collection was not attempted because no supported authorization mode was declared."
                improvement = "Record a supported public, owner, or contract authority before observation."
            elif "AUTHORIZATION_SCOPE_DENIED" in finding_codes:
                gap = "Evidence collection was not attempted because the declared authority is outside this watch pack's allowed scope."
                improvement = "Use a permitted watch pack or obtain and record authorization for the additional methods and scope."
            else:
                gap = "No evidence source was captured for this observation."
                improvement = "Attach an authoritative URL, file, log, or connector receipt."
            blind_spots.append({
                "target_id": result["target_id"],
                "gap": gap,
                "improvement": improvement,
            })
    ranked = sorted(
        findings,
        key=lambda item: (
            {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(item["severity"], 0),
            item.get("confidence", 0),
        ),
        reverse=True,
    )
    return {
        "blind_spots": blind_spots,
        "deficit_analysis": [
            {
                "target_id": item["target_id"],
                "finding": item["title"],
                "deficit": item["deficit"],
                "current_condition": item.get("detail", ""),
                "truth": item.get("truth", "INFERENCE"),
                "confidence": item.get("confidence", 0),
                "evidence": item.get("evidence", {}),
                "impact_status": "UNQUANTIFIED",
                "measurement_needed": "Attach a baseline, volume, cost, revenue, time, or conversion measure before assigning financial impact.",
            }
            for item in ranked
        ],
        "preventive_priorities": [
            {
                "target_id": item["target_id"],
                "finding": item["title"],
                "truth": item.get("truth", "INFERENCE"),
                "confidence": item.get("confidence", 0),
                "why_it_matters": item["why_it_matters"],
                "preventive_action": item["preventive_action"],
            }
            for item in ranked[:5]
        ],
        "prosperity_plan": [
            {
                "priority": position,
                "target_id": item["target_id"],
                "objective": item["prosperity_lever"],
                "action": item["preventive_action"],
                "success_metric": item["success_metric"],
                "verification": item["verification"],
                "financial_claim": "NOT CALCULATED",
            }
            for position, item in enumerate(ranked[:5], start=1)
        ],
        "quiet_is_healthy": not findings and not blind_spots,
    }
