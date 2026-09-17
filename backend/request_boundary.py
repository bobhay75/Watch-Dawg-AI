"""Authenticate and bound API bodies before FastAPI parses them."""

import hmac
import json


class PaidAIBoundary:
    def __init__(self, app, token, maximum=64_000):
        self.app = app
        self.token = token
        self.maximum = maximum

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope['path'].startswith('/api/'):
            return await self.app(scope, receive, send)
        # Only this exact read-only endpoint is public.
        if scope['path'] == '/api/health' and scope['method'] == 'GET':
            return await self.app(scope, receive, send)
        if (not self.token or len(self.token) < 32
                or any(c.isspace() for c in self.token)):
            return await self.reject(send, 503, 'Auth not configured')
        values = [v for k, v in scope['headers']
                  if k.lower() == b'authorization']
        expected = ('Bearer ' + self.token).encode('utf-8')
        if len(values) != 1 or not hmac.compare_digest(values[0], expected):
            return await self.reject(send, 401, 'Valid bearer token required')
        lengths = [v for k, v in scope['headers']
                   if k.lower() == b'content-length']
        if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
            return await self.reject(send, 400, 'Invalid content length')
        if lengths and (len(lengths[0]) > 6 or int(lengths[0]) > self.maximum):
            return await self.reject(send, 413, 'Body too large')
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            if len(body) + len(chunk) > self.maximum:
                return await self.reject(send, 413, 'Body too large')
            body.extend(chunk)
            if not message.get('more_body', False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {'type': 'http.request', 'body': bytes(body),
                    'more_body': False}

        await self.app(scope, bounded_receive, send)

    @staticmethod
    async def reject(send, status, detail):
        headers = [(b'content-type', b'application/json')]
        if status == 401:
            headers.append((b'www-authenticate', b'Bearer'))
        await send({'type': 'http.response.start', 'status': status,
                    'headers': headers})
        await send({'type': 'http.response.body',
                    'body': json.dumps({'detail': detail}).encode()})
