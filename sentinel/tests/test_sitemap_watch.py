from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.core import SentinelEngine, StateStore
from sentinel.sitemap_watch import SitemapWatchPack


def xml_urlset(*urls):
    rows = "".join(f"<url><loc>{url}</loc></url>" for url in urls)
    return f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{rows}</urlset>'


def xml_index(*urls):
    rows = "".join(f"<sitemap><loc>{url}</loc></sitemap>" for url in urls)
    return f'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{rows}</sitemapindex>'


class FakeFetcher:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def fetch(self, url, timeout_seconds, max_body_bytes):
        self.calls.append(url)
        response = dict(self.responses[url])
        response.setdefault("status", 200)
        response.setdefault("final_url", url)
        response.setdefault("headers", {})
        response.setdefault("latency_ms", 1)
        response.setdefault("body_bytes", len(response.get("body", "")))
        response.setdefault("truncated", False)
        return response


class SitemapWatchTests(unittest.TestCase):
    def test_bounded_index_detects_broken_page(self):
        root = "https://example.com/sitemap.xml"
        child = "https://example.com/posts.xml"
        good = "https://example.com/good"
        bad = "https://example.com/gone"
        fetcher = FakeFetcher({
            root: {"body": xml_index(child)},
            child: {"body": xml_urlset(good, bad)},
            good: {"body": "ok", "status": 200},
            bad: {"body": "gone", "status": 404},
        })
        pack = SitemapWatchPack(fetcher)
        target = {"id": "site", "url": root, "max_urls": 2, "max_sitemaps": 1}
        observation = pack.observe(target)
        findings = pack.evaluate(target, observation, None)
        self.assertEqual(fetcher.calls, [root, child, good, bad])
        self.assertIn("SITEMAP_URLS_BROKEN", {item.code for item in findings})
        self.assertLessEqual(
            observation.facts["requests_made"],
            observation.facts["request_budget"],
        )

    def test_cross_origin_entries_are_never_fetched(self):
        root = "https://example.com/sitemap.xml"
        local = "https://example.com/page"
        outside = "https://outside.example/page"
        fetcher = FakeFetcher({
            root: {"body": xml_urlset(local, outside)},
            local: {"body": "ok"},
        })
        pack = SitemapWatchPack(fetcher)
        observation = pack.observe({"id": "site", "url": root})
        self.assertNotIn(outside, fetcher.calls)
        codes = {item.code for item in pack.evaluate({"checks": {}}, observation, None)}
        self.assertIn("SITEMAP_CROSS_ORIGIN_ENTRIES", codes)

    def test_url_set_change_is_one_time_event(self):
        root = "https://example.com/sitemap.xml"
        first = "https://example.com/one"
        second = "https://example.com/two"
        fetcher = FakeFetcher({
            root: {"body": xml_urlset(first)},
            first: {"body": "ok"},
        })
        target = {
            "id": "site",
            "kind": "sitemap",
            "url": root,
            "authorization": {"mode": "public"},
        }
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.json")
            engine = SentinelEngine(state, [SitemapWatchPack(fetcher)])
            self.assertFalse(engine.run([target])["notify"])
            fetcher.responses[root]["body"] = xml_urlset(first, second)
            fetcher.responses[second] = {"body": "ok"}
            self.assertEqual(engine.run([target])["new_alert_count"], 1)
            self.assertFalse(engine.run([target])["notify"])


if __name__ == "__main__":
    unittest.main()
