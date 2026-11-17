"""Provider boundary. No vendor SDK or live provider enabled by default."""

from collections.abc import AsyncIterator
import json
from urllib.parse import urlsplit

import httpx


class DisabledProvider:
    ready = False

    async def stream(
        self, prompt: str, session_id: str, system: str
    ) -> AsyncIterator[str]:
        raise RuntimeError("provider disabled")
        yield ""


class SyntheticProvider:
    """Synthetic data only; selected explicitly by test configuration."""

    ready = True

    async def stream(
        self, prompt: str, session_id: str, system: str
    ) -> AsyncIterator[str]:
        yield "SYNTHETIC TEST OUTPUT — REVIEW. "
        yield "No external verification or publication approval."


class CompatibleProvider:
    """OpenAI-compatible SSE protocol usable with free self-hosted models.

    URLs and credentials are server configuration, never caller-controlled.
    TLS is verified; redirects and ambient proxy settings are disabled.
    """

    ready = True

    def __init__(
        self, base_url: str, api_key: str, model: str, transport=None
    ):
        url = urlsplit(base_url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or not api_key
            or not model
        ):
            raise ValueError(
                "Explicit HTTPS provider configuration is required"
            )
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.model = model
        self.transport = transport

    async def stream(
        self, prompt: str, session_id: str, system: str
    ) -> AsyncIterator[str]:
        async with httpx.AsyncClient(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(60, connect=10),
            transport=self.transport,
        ) as client:
            async with client.stream(
                "POST",
                self.url,
                headers={
                    "Authorization": "Bearer " + self.api_key,
                    "Accept": "text/event-stream",
                },
                json={
                    "model": self.model,
                    "stream": True,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                },
            ) as response:
                response.raise_for_status()
                if not response.headers.get("content-type", "").startswith(
                    "text/event-stream"
                ):
                    raise ValueError("Expected provider SSE response")
                buffer = b""
                total = 0
                data = []
                # Do not ask HTTPX to accumulate 8 KiB before yielding.
                # Parse small deltas immediately, but bound parser slices.
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > 2 * 1024 * 1024:
                        raise ValueError("Provider response exceeds limit")
                    for offset in range(0, len(chunk), 8192):
                        end = offset + 8192
                        buffer += chunk[offset:end]
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            if len(line) > 65536:
                                raise ValueError(
                                    "Provider frame exceeds limit"
                                )
                            line = line.rstrip(b"\r")
                            if line.startswith(b"data:"):
                                data.append(line[5:].lstrip(b" "))
                            elif not line and data:
                                payload = b"\n".join(data).decode("utf-8")
                                data = []
                                if payload == "[DONE]":
                                    return
                                event = json.loads(payload)
                                choices = event.get("choices")
                                if not isinstance(choices, list):
                                    raise ValueError(
                                        "Malformed provider event"
                                    )
                                if not choices:
                                    continue  # usage-only event
                                delta = (
                                    choices[0].get("delta", {}).get("content")
                                )
                                if delta is not None:
                                    if not isinstance(delta, str):
                                        raise ValueError(
                                            "Malformed provider content"
                                        )
                                    yield delta
                            if sum(map(len, data)) > 65536:
                                raise ValueError(
                                    "Provider event exceeds limit"
                                )
                        if len(buffer) > 65536:
                            raise ValueError("Provider frame exceeds limit")
                raise ValueError("Provider stream ended without completion")
