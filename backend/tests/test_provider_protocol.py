import asyncio

import httpx
import pytest

from backend.providers import CompatibleProvider
from backend.server import Settings, select_provider


def collect(response):
    requests = []

    def handle(request):
        requests.append(request)
        return response

    async def run():
        provider = CompatibleProvider(
            "https://synthetic.invalid/v1",
            "synthetic-key",
            "synthetic-model",
            httpx.MockTransport(handle),
        )
        return [
            delta
            async for delta in provider.stream("synthetic", "test", "test")
        ]

    return asyncio.run(run()), requests


def test_protocol_and_completion():
    response = httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        content=(
            b": comment\r\n\r\n"
            b'data: {"choices":[{"delta":{"content":"synthetic"}}]}\r\n\r\n'
            b'data: {"choices":[]}\n\ndata: [DONE]\n\n'
        ),
    )
    result, requests = collect(response)
    assert result == ["synthetic"]
    assert requests[0].url == "https://synthetic.invalid/v1/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer synthetic-key"


@pytest.mark.parametrize(
    "content",
    [
        b"data: not-json\n\n",
        b'data: {"choices":false}\n\n',
        b'data: {"choices":[{"delta":{"content":42}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n',
        b"x" * 65537,
    ],
)
def test_malformed_incomplete_and_oversized_streams_fail(content):
    with pytest.raises((ValueError, TypeError)):
        collect(
            httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=content,
            )
        )


@pytest.mark.parametrize("status", [302, 401, 429, 500])
def test_http_errors_are_not_success(status):
    with pytest.raises(httpx.HTTPStatusError):
        collect(
            httpx.Response(
                status,
                headers={"location": "https://other.invalid"},
                content=b"sensitive",
            )
        )


def test_explicit_config_and_no_unsafe_synthetic_fallback():
    assert not select_provider(Settings("", "")).ready
    with pytest.raises(ValueError):
        select_provider(Settings("", "", provider="synthetic"))
    for url in [
        "http://example.test/v1",
        "https://key@example.test/v1",
        "https://example.test/v1?secret=x",
    ]:
        with pytest.raises(ValueError):
            CompatibleProvider(url, "test", "test")
    assert "synthetic-key" not in repr(
        Settings("mongodb://user:password@host", "", api_key="synthetic-key")
    )


def test_provider_read_timeout_is_propagated_without_retry():
    attempts = []

    def timeout(request):
        attempts.append(request)
        raise httpx.ReadTimeout("synthetic-sensitive-detail")

    async def run():
        provider = CompatibleProvider(
            "https://synthetic.invalid/v1",
            "test",
            "test",
            httpx.MockTransport(timeout),
        )
        return [
            delta async for delta in provider.stream("test", "test", "test")
        ]

    with pytest.raises(httpx.ReadTimeout):
        asyncio.run(run())
    assert len(attempts) == 1


@pytest.mark.parametrize(
    "option",
    [
        "tlsInsecure=true",
        "tlsAllowInvalidCertificates=true",
        "tlsAllowInvalidHostnames=true",
        "tls=false",
        "ssl=false",
    ],
)
def test_mongo_tls_bypass_options_are_rejected(option):
    with pytest.raises(ValueError):
        Settings(
            "mongodb://127.0.0.1/test?" + option, "watchdawg_test_synthetic"
        )


def test_small_delta_is_delivered_before_more_network_bytes_arrive():
    class PausedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'
            await asyncio.Event().wait()

    async def run():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=PausedStream(),
            )
        )
        provider = CompatibleProvider(
            "https://synthetic.invalid/v1",
            "test",
            "test",
            transport,
        )
        stream = provider.stream("test", "test", "test")
        try:
            assert (
                await asyncio.wait_for(anext(stream), timeout=0.5) == "first"
            )
        finally:
            await stream.aclose()

    asyncio.run(run())


@pytest.mark.parametrize(
    "url",
    [
        "https://@synthetic.invalid/v1",
        "https://:@synthetic.invalid/v1",
    ],
)
def test_provider_rejects_empty_userinfo_authorities(url):
    with pytest.raises(ValueError):
        CompatibleProvider(url, "synthetic-key", "synthetic-model")
