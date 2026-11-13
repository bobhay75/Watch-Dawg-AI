"""Opt-in, fail-closed authorization bridge to the local Prosper AI Gateway.

Prototype limitation: the authorization request and Sentinel execution are not atomic.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def build_prosper_authorizer() -> Callable[[], bool] | None:
    """Return an authorization callback when PROSPER_GATEWAY_URL is configured."""
    url = os.environ.get("PROSPER_GATEWAY_URL", "").rstrip("/")
    if not url:
        return None
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("PROSPER_GATEWAY_URL must be a loopback HTTP address with a port")
    key = os.environ.get("PROSPER_AGENT_KEY", "")
    if not key:
        raise ValueError("PROSPER_AGENT_KEY is required when the gateway is enabled")
    agent_id = "watch-dawg"
    action = "sentinel.run"

    def authorize() -> bool:
        payload = json.dumps({"agent_id": agent_id, "action": action}).encode("utf-8")
        request = Request(
            url + "/authorize",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "X-Agent-Key": key},
        )
        try:
            with urlopen(request, timeout=2) as response:
                result = json.load(response)
        except HTTPError as exc:
            if exc.code in (401, 403):
                return False
            raise RuntimeError("Prosper Gateway unavailable") from exc
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Prosper Gateway unavailable") from exc
        return result.get("allowed") is True if isinstance(result, dict) else False

    return authorize
