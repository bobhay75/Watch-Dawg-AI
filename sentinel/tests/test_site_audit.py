from __future__ import annotations

import unittest

from sentinel.site_audit import (
    SiteAuditError,
    aggregate_page_findings,
    classify_network_policy,
    validate_site_urls,
)


class SiteAuditPolicyTests(unittest.TestCase):
    def test_policy_block_is_not_counted_as_site_failure(self) -> None:
        network = {
            "blocked_requests": [
                {
                    "method": "POST",
                    "url": "https://example.com/analytics",
                    "reason": "non_passive_method",
                }
            ],
            "events": [
                {
                    "event": "request_failed",
                    "method": "POST",
                    "url": "https://example.com/analytics",
                    "failure": "net::ERR_BLOCKED_BY_CLIENT.Inspector",
                },
                {
                    "event": "request_failed",
                    "method": "GET",
                    "url": "https://example.com/missing.js",
                    "failure": "net::ERR_CONNECTION_RESET",
                },
            ],
        }
        console = {
            "events": [
                {"type": "error", "text": "Failed to load resource: net::ERR_BLOCKED_BY_CLIENT.Inspector"},
                {"type": "pageerror", "text": "real page error"},
            ]
        }
        result = classify_network_policy(network, console)
        self.assertEqual(result["watch_dawg_policy_block_count"], 1)
        self.assertEqual(result["policy_attributed_request_failure_count"], 1)
        self.assertEqual(result["site_network_failure_count"], 1)
        self.assertEqual(result["console_errors_matching_policy_block_pattern"], 1)
        self.assertEqual(result["console_errors_unattributed"], 1)

    def test_site_urls_must_share_https_origin(self) -> None:
        self.assertEqual(
            validate_site_urls(["https://example.com/", "https://example.com/a"]),
            ["https://example.com/", "https://example.com/a"],
        )
        with self.assertRaisesRegex(SiteAuditError, "share one HTTPS origin"):
            validate_site_urls(["https://example.com/", "https://www.example.com/"])
        with self.assertRaisesRegex(SiteAuditError, "absolute https"):
            validate_site_urls(["http://example.com/"])

    def test_repeated_findings_are_grouped_across_pages(self) -> None:
        pages = [
            {
                "status": "REVIEW_READY",
                "url": "https://example.com/",
                "deterministic_findings": [
                    {
                        "source": "axe-core",
                        "rule_id": "image-alt",
                        "classification": "DETERMINISTIC_TOOL_FINDING",
                        "impact": "critical",
                        "help": "Images must have alternate text",
                        "node_count": 2,
                        "analysis_ref": "sha256:a",
                    }
                ],
                "manual_review": [],
            },
            {
                "status": "REVIEW_READY",
                "url": "https://example.com/book/",
                "deterministic_findings": [
                    {
                        "source": "axe-core",
                        "rule_id": "image-alt",
                        "classification": "DETERMINISTIC_TOOL_FINDING",
                        "impact": "serious",
                        "help": "Images must have alternate text",
                        "node_count": 3,
                        "analysis_ref": "sha256:b",
                    }
                ],
                "manual_review": [],
            },
        ]
        grouped = aggregate_page_findings(pages)
        self.assertEqual(len(grouped["deterministic"]), 1)
        item = grouped["deterministic"][0]
        self.assertEqual(item["rule_id"], "image-alt")
        self.assertEqual(item["impact"], "critical")
        self.assertEqual(item["total_nodes_observed"], 5)
        self.assertEqual(len(item["pages"]), 2)


if __name__ == "__main__":
    unittest.main()
