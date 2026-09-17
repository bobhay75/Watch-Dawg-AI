"""Offline tests: rejected requests must never reach a parser or model."""
import unittest

from backend.request_boundary import PaidAIBoundary

TOKEN = 'local-test-credential-' * 3
AUTH = (b'authorization', ('Bearer ' + TOKEN).encode())


class RequestBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, chunks, headers=(), path='/api/ai/audit',
                       token=TOKEN, disconnected=False):
        self.calls = []
        self.reads = 0
        self.responses = []

        async def downstream(scope, receive, send):
            self.calls.append(await receive())
            await send({'type': 'http.response.start', 'status': 200})

        async def receive():
            self.reads += 1
            if disconnected:
                return {'type': 'http.disconnect'}
            index = self.reads - 1
            return {'type': 'http.request', 'body': chunks[index],
                    'more_body': index < len(chunks) - 1}

        async def send(message):
            self.responses.append(message)

        await PaidAIBoundary(downstream, token)(
            {'type': 'http', 'path': path, 'method': 'POST',
             'headers': list(headers)}, receive, send)
        return self.responses[0]['status'] if self.responses else None

    async def test_anonymous_rejected_before_body_read(self):
        self.assertEqual(await self.exercise([b'invalid JSON']), 401)
        self.assertEqual((self.reads, self.calls), (0, []))

    async def test_wrong_or_duplicate_credentials_rejected(self):
        for headers in [(AUTH, AUTH), ((b'authorization', b'Bearer wrong'),)]:
            self.assertEqual(await self.exercise([b'{}'], headers), 401)
            self.assertEqual(self.calls, [])

    async def test_missing_configuration_fails_closed(self):
        self.assertEqual(await self.exercise([b'{}'], (AUTH,), token=''), 503)
        self.assertEqual(self.reads, 0)

    async def test_declared_oversize_rejected_before_read(self):
        headers = (AUTH, (b'content-length', b'64001'))
        self.assertEqual(await self.exercise([b'{}'], headers), 413)
        self.assertEqual((self.reads, self.calls), (0, []))

    async def test_chunked_oversize_rejected_before_parser(self):
        status = await self.exercise([b'x' * 32000, b'x' * 32001], (AUTH,))
        self.assertEqual(status, 413)
        self.assertEqual(self.calls, [])

    async def test_actual_bytes_enforced_even_with_small_declared_size(self):
        headers = (AUTH, (b'content-length', b'2'))
        self.assertEqual(await self.exercise([b'x' * 64001], headers), 413)
        self.assertEqual(self.calls, [])

    async def test_unknown_fields_and_whitespace_count_toward_limit(self):
        body = b'{"unknown":"' + b'x' * 64000 + b'"}'
        self.assertEqual(await self.exercise([body], (AUTH,)), 413)
        self.assertEqual(self.calls, [])

    async def test_exact_limit_delivered_intact(self):
        body = b'x' * 64000
        status = await self.exercise([body[:5], body[5:]], (AUTH,))
        self.assertEqual(status, 200)
        self.assertEqual(self.calls[0]['body'], body)
        self.assertFalse(self.calls[0]['more_body'])

    async def test_trailing_slash_does_not_bypass_authentication(self):
        status = await self.exercise([b'{}'], path='/api/ai/audit/')
        self.assertEqual(status, 401)
        self.assertEqual(self.calls, [])

    async def test_disconnect_never_invokes_downstream(self):
        self.assertIsNone(await self.exercise([], (AUTH,), disconnected=True))
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
