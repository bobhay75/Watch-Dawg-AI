from __future__ import annotations

import ssl
import unittest
from email.message import Message
from unittest.mock import patch

from sentinel.domain_watch import SocketDomainInspector
from sentinel.http_watch import (
    MAX_REDIRECTS,
    HttpWatchPack,
    SafeHttpFetcher,
    _PinnedHTTPSConnection,
    _read_response_body,
)
from sentinel.service_watch import ServiceExposureWatchPack
from sentinel.sitemap_watch import SitemapWatchPack


class _FakeHttpResponse:
    def __init__(
        self,
        status: int,
        body: bytes = b"ok",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


def _connection_double(responses, calls):
    class FakeConnection:
        def __init__(self, hostname, port, pinned_address, timeout, *args):
            calls.append({
                "hostname": hostname,
                "port": port,
                "address": pinned_address,
                "timeout": timeout,
            })

        def request(self, method, path, headers):
            calls[-1].update({"method": method, "path": path, "headers": headers})

        def getresponse(self):
            return responses.pop(0)

        def close(self):
            return None

    return FakeConnection


class HttpNetworkBoundaryTests(unittest.TestCase):
    def test_dns_is_resolved_once_and_only_vetted_ip_is_connected(self):
        resolver_calls = []
        connection_calls = []

        def rebinding_resolver(hostname, port):
            resolver_calls.append((hostname, port))
            return {"8.8.8.8"} if len(resolver_calls) == 1 else {"127.0.0.1"}

        fake_connection = _connection_double(
            [_FakeHttpResponse(200, headers={"Content-Type": "text/plain"})],
            connection_calls,
        )
        fetcher = SafeHttpFetcher(resolver=rebinding_resolver)
        with patch("sentinel.http_watch._PinnedHTTPConnection", fake_connection):
            response = fetcher.fetch("http://example.com/check?probe=1", 2, 100)

        self.assertEqual(response["status"], 200)
        self.assertEqual(resolver_calls, [("example.com", 80)])
        self.assertEqual(connection_calls[0]["address"], "8.8.8.8")
        self.assertEqual(connection_calls[0]["hostname"], "example.com")
        self.assertEqual(connection_calls[0]["headers"]["Host"], "example.com")

    def test_same_origin_redirect_is_revalidated_and_rebinding_is_blocked(self):
        resolver_calls = []
        connection_calls = []

        def rebinding_resolver(hostname, port):
            resolver_calls.append((hostname, port))
            return {"8.8.8.8"} if len(resolver_calls) == 1 else {"127.0.0.1"}

        fake_connection = _connection_double(
            [_FakeHttpResponse(302, headers={"Location": "/next"})],
            connection_calls,
        )
        fetcher = SafeHttpFetcher(resolver=rebinding_resolver)
        with patch("sentinel.http_watch._PinnedHTTPConnection", fake_connection):
            with self.assertRaisesRegex(ValueError, "private"):
                fetcher.fetch("http://example.com/start", 2, 100)

        self.assertEqual(len(resolver_calls), 2)
        self.assertEqual([call["address"] for call in connection_calls], ["8.8.8.8"])

    def test_mixed_public_and_private_answer_is_rejected_before_contact(self):
        connection_calls = []
        fake_connection = _connection_double(
            [_FakeHttpResponse(200)],
            connection_calls,
        )
        fetcher = SafeHttpFetcher(
            resolver=lambda hostname, port: {"8.8.8.8", "127.0.0.1"}
        )
        with patch("sentinel.http_watch._PinnedHTTPConnection", fake_connection):
            with self.assertRaisesRegex(ValueError, "private"):
                fetcher.fetch("http://example.com/", 2, 100)
        self.assertEqual(connection_calls, [])

    def test_cross_origin_redirect_is_rejected_before_contact(self):
        resolver_calls = []
        connection_calls = []

        def resolver(hostname, port):
            resolver_calls.append((hostname, port))
            return {"8.8.8.8"}

        fake_connection = _connection_double(
            [_FakeHttpResponse(302, headers={"Location": "http://other.example/private"})],
            connection_calls,
        )
        fetcher = SafeHttpFetcher(resolver=resolver)
        with patch("sentinel.http_watch._PinnedHTTPConnection", fake_connection):
            with self.assertRaisesRegex(ValueError, "cross-origin"):
                fetcher.fetch("http://example.com/start", 2, 100)

        self.assertEqual(resolver_calls, [("example.com", 80)])
        self.assertEqual(len(connection_calls), 1)

    def test_redirect_count_is_bounded(self):
        connection_calls = []
        fake_connection = _connection_double(
            [
                _FakeHttpResponse(302, headers={"Location": "/again"})
                for _ in range(MAX_REDIRECTS + 1)
            ],
            connection_calls,
        )
        fetcher = SafeHttpFetcher(resolver=lambda hostname, port: {"8.8.8.8"})
        with patch("sentinel.http_watch._PinnedHTTPConnection", fake_connection):
            with self.assertRaisesRegex(ValueError, "redirect limit"):
                fetcher.fetch("http://example.com/start", 2, 100)
        self.assertEqual(len(connection_calls), MAX_REDIRECTS + 1)

    def test_https_socket_uses_pinned_ip_and_hostname_sni(self):
        class RawSocket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class TlsContext:
            def __init__(self):
                self.calls = []

            def wrap_socket(self, raw, server_hostname):
                self.calls.append((raw, server_hostname))
                return object()

        raw = RawSocket()
        context = TlsContext()
        connection = _PinnedHTTPSConnection(
            "example.com", 443, "8.8.8.8", 3, context  # type: ignore[arg-type]
        )
        with patch("sentinel.http_watch.socket.create_connection", return_value=raw) as connect:
            connection.connect()

        connect.assert_called_once_with(
            ("8.8.8.8", 443), timeout=3, source_address=None
        )
        self.assertEqual(context.calls, [(raw, "example.com")])

        default_context = SafeHttpFetcher().tls_context
        self.assertTrue(default_context.check_hostname)
        self.assertEqual(default_context.verify_mode, ssl.CERT_REQUIRED)

    def test_only_allowlisted_headers_are_persisted(self):
        class Fetcher:
            def fetch(self, url, timeout_seconds, max_body_bytes):
                return {
                    "status": 200,
                    "final_url": url,
                    "latency_ms": 1,
                    "headers": {
                        "Content-Type": "text/plain",
                        "Strict-Transport-Security": "max-age=31536000",
                        "Set-Cookie": "session=secret",
                        "Authorization": "Bearer secret",
                    },
                    "body": "ok",
                    "body_bytes": 2,
                    "truncated": False,
                }

        observation = HttpWatchPack(Fetcher()).observe({
            "id": "site",
            "url": "https://example.com/?token=secret#fragment",
        })

        self.assertEqual(
            observation.facts["headers"],
            {
                "content-type": "text/plain",
                "strict-transport-security": "max-age=31536000",
            },
        )
        self.assertNotIn("secret", str(observation.to_dict()))

    def test_response_body_uses_one_absolute_deadline(self):
        class Socket:
            def __init__(self):
                self.timeouts = []

            def settimeout(self, value):
                self.timeouts.append(value)

        class Connection:
            def __init__(self):
                self.sock = Socket()

        class SlowResponse:
            def __init__(self):
                self.reads = 0

            def read1(self, amount):
                self.reads += 1
                return b"x"

        connection = Connection()
        response = SlowResponse()
        with patch("sentinel.http_watch.time.monotonic", side_effect=[0.5, 1.0]):
            with self.assertRaisesRegex(TimeoutError, "response deadline"):
                _read_response_body(
                    response,
                    connection,  # type: ignore[arg-type]
                    deadline=1.0,
                    max_body_bytes=10,
                )

        self.assertEqual(response.reads, 1)
        self.assertEqual(connection.sock.timeouts, [0.5])


class DomainNetworkBoundaryTests(unittest.TestCase):
    def test_tls_inspection_connects_to_vetted_ip_with_hostname_sni(self):
        resolver_calls = []
        connector_calls = []

        class RawSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class SecuredSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def getpeercert(self):
                return {"notAfter": "Jan  1 00:00:00 2099 GMT"}

            def cipher(self):
                return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

            def version(self):
                return "TLSv1.3"

        class TlsContext:
            def __init__(self):
                self.server_names = []

            def wrap_socket(self, raw, server_hostname):
                self.server_names.append(server_hostname)
                return SecuredSocket()

        def resolver(hostname, port):
            resolver_calls.append((hostname, port))
            return {"8.8.8.8"} if len(resolver_calls) == 1 else {"127.0.0.1"}

        def connector(address, port, timeout):
            connector_calls.append((address, port, timeout))
            return RawSocket()

        context = TlsContext()
        inspector = SocketDomainInspector(
            resolver=resolver,
            connector=connector,
            tls_context=context,  # type: ignore[arg-type]
        )
        facts = inspector.inspect("example.com", 443, 2)

        self.assertEqual(resolver_calls, [("example.com", 443)])
        self.assertEqual(connector_calls[0][0:2], ("8.8.8.8", 443))
        self.assertEqual(context.server_names, ["example.com"])
        self.assertEqual(facts["addresses"], ["8.8.8.8"])

    def test_any_non_global_tls_address_blocks_all_connections(self):
        connector_calls = []
        inspector = SocketDomainInspector(
            resolver=lambda hostname, port: {"8.8.8.8", "127.0.0.1"},
            connector=lambda address, port, timeout: connector_calls.append(address),
        )
        with self.assertRaisesRegex(ValueError, "non-public"):
            inspector.inspect("example.com", 443, 2)
        self.assertEqual(connector_calls, [])


class ServiceNetworkBoundaryTests(unittest.TestCase):
    @staticmethod
    def _target():
        return {
            "id": "owned-edge",
            "hostname": "example.com",
            "ports": [22, 443],
            "authorization": {
                "id": "SCOPE-1",
                "approved_methods": ["tcp-connect"],
                "scope": {"hostname": "example.com", "ports": [22, 443]},
                "expires_at": "2099-01-01T00:00:00Z",
            },
        }

    def test_service_connector_never_receives_hostname(self):
        resolver_calls = []
        connector_calls = []

        def resolver(hostname):
            resolver_calls.append(hostname)
            return {"8.8.8.8"} if len(resolver_calls) == 1 else {"127.0.0.1"}

        def connector(address, port, timeout):
            connector_calls.append((address, port, timeout))
            return False

        observation = ServiceExposureWatchPack(
            resolver=resolver,
            connector=connector,
        ).observe(self._target())

        self.assertEqual(resolver_calls, ["example.com"])
        self.assertEqual([call[0] for call in connector_calls], ["8.8.8.8", "8.8.8.8"])
        self.assertEqual(observation.facts["resolved_addresses"], ["8.8.8.8"])

    def test_service_mixed_dns_answer_is_rejected_before_contact(self):
        connector_calls = []
        pack = ServiceExposureWatchPack(
            resolver=lambda hostname: {"8.8.8.8", "127.0.0.1"},
            connector=lambda address, port, timeout: connector_calls.append(address),
        )
        with self.assertRaisesRegex(ValueError, "public addresses"):
            pack.observe(self._target())
        self.assertEqual(connector_calls, [])


class SitemapNetworkBoundaryTests(unittest.TestCase):
    def test_budget_is_capped_and_persisted_urls_drop_sensitive_components(self):
        root = "https://example.com/sitemap.xml?access_token=secret#fragment"
        page = "https://example.com/page?session=hidden#section"

        class Fetcher:
            def __init__(self):
                self.calls = []

            def fetch(self, url, timeout_seconds, max_body_bytes):
                self.calls.append(url)
                body = (
                    f"<urlset><url><loc>{page}</loc></url></urlset>"
                    if url == root
                    else "ok"
                )
                return {
                    "status": 200,
                    "final_url": url,
                    "headers": {},
                    "latency_ms": 1,
                    "body": body,
                    "body_bytes": len(body),
                    "truncated": False,
                }

        fetcher = Fetcher()
        observation = SitemapWatchPack(fetcher).observe({
            "id": "site",
            "url": root,
            "max_sitemaps": 1_000,
            "max_urls": 1_000,
        })

        self.assertEqual(observation.facts["request_budget"], 29)
        self.assertNotIn("secret", str(observation.to_dict()))
        self.assertNotIn("hidden", str(observation.to_dict()))
        self.assertEqual(
            observation.evidence,
            ["https://example.com/sitemap.xml"],
        )

    def test_absolute_run_deadline_stops_before_another_request(self):
        root = "https://example.com/sitemap.xml"
        child = "https://example.com/child.xml"

        class Fetcher:
            def __init__(self):
                self.calls = []

            def fetch(self, url, timeout_seconds, max_body_bytes):
                self.calls.append(url)
                return {
                    "status": 200,
                    "final_url": url,
                    "headers": {},
                    "latency_ms": 1,
                    "body": f"<sitemapindex><sitemap><loc>{child}</loc></sitemap></sitemapindex>",
                    "body_bytes": 10,
                    "truncated": False,
                }

        fetcher = Fetcher()
        with patch("sentinel.sitemap_watch.time.monotonic", side_effect=[0, 0, 61]):
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                SitemapWatchPack(fetcher).observe({
                    "id": "site",
                    "url": root,
                    "run_timeout_seconds": 60,
                })
        self.assertEqual(fetcher.calls, [root])


if __name__ == "__main__":
    unittest.main()
