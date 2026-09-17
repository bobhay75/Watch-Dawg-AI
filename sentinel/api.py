from __future__ import annotations

import hmac
import json
import logging
import math
import os
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from .ai_system_watch import AiSystemRiskWatchPack
from .cli import load_config
from .core import SentinelEngine, StateStore
from .domain_watch import DnsTlsWatchPack
from .http_watch import HttpWatchPack
from .log_watch import AccessLogWatchPack
from .secret_watch import SecretExposureWatchPack
from .service_watch import ServiceExposureWatchPack
from .sitemap_watch import SitemapWatchPack


LOGGER = logging.getLogger("watch_dawg.sentinel.api")
PROFILE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MAX_PROFILE_COUNT: Final[int] = 50
MAX_REQUEST_BYTES: Final[int] = 2_048
MIN_TOKEN_LENGTH: Final[int] = 32
DEFAULT_RATE_LIMIT_PER_MINUTE: Final[int] = 10
DEFAULT_PROFILE_COOLDOWN_SECONDS: Final[int] = 60
Runner = Callable[[Path, Path], dict[str, Any]]


class ApiError(Exception):
    def __init__(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = dict(headers or {})


class ProfileRateLimiter:
    """Small in-process global rate limit plus per-profile cooldown."""

    def __init__(
        self,
        max_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE,
        cooldown_seconds: int = DEFAULT_PROFILE_COOLDOWN_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_per_minute < 1:
            raise ValueError("max_per_minute must be positive")
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds cannot be negative")
        self.max_per_minute = max_per_minute
        self.cooldown_seconds = cooldown_seconds
        self.clock = clock
        self._recent: deque[float] = deque()
        self._profile_last_run: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, profile: str) -> None:
        now = self.clock()
        with self._lock:
            while self._recent and now - self._recent[0] >= 60:
                self._recent.popleft()

            retry_after = 0
            if len(self._recent) >= self.max_per_minute:
                retry_after = max(1, math.ceil(60 - (now - self._recent[0])))

            last_run = self._profile_last_run.get(profile)
            if last_run is not None:
                retry_after = max(
                    retry_after,
                    max(0, math.ceil(self.cooldown_seconds - (now - last_run))),
                )

            if retry_after > 0:
                raise ApiError(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "rate_limited",
                    "This approved profile was checked too recently.",
                    headers={"Retry-After": str(retry_after)},
                )

            self._recent.append(now)
            self._profile_last_run[profile] = now


def validate_api_token(token: str | None) -> str:
    if not token or len(token) < MIN_TOKEN_LENGTH:
        raise ValueError(
            f"SENTINEL_API_TOKEN must contain at least {MIN_TOKEN_LENGTH} characters"
        )
    if any(character.isspace() for character in token):
        raise ValueError("SENTINEL_API_TOKEN must not contain whitespace")
    return token


def load_profile_paths(raw: str | None, config_root: Path) -> dict[str, Path]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SENTINEL_PROFILES_JSON must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("SENTINEL_PROFILES_JSON must be a JSON object")
    if len(payload) > MAX_PROFILE_COUNT:
        raise ValueError(f"at most {MAX_PROFILE_COUNT} profiles may be configured")

    root = config_root.resolve()
    profiles: dict[str, Path] = {}
    for profile, relative_path in payload.items():
        if not isinstance(profile, str) or not PROFILE_PATTERN.fullmatch(profile):
            raise ValueError(f"invalid profile name: {profile!r}")
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError(f"profile {profile!r} requires a configuration filename")
        candidate = (root / relative_path).resolve()
        if not candidate.is_relative_to(root):
            raise ValueError(f"profile {profile!r} escapes SENTINEL_CONFIG_ROOT")
        if candidate.suffix.lower() != ".json":
            raise ValueError(f"profile {profile!r} must reference a JSON file")
        if not candidate.is_file():
            raise ValueError(f"profile {profile!r} configuration does not exist")
        profiles[profile] = candidate
    return profiles


def run_profile(config_path: Path, state_path: Path) -> dict[str, Any]:
    config = load_config(config_path)
    log_root = Path(config.get("log_root", "."))
    secret_root = Path(config.get("secret_root", "."))
    ai_manifest_root = Path(config.get("ai_manifest_root", "."))
    engine = SentinelEngine(
        StateStore(state_path),
        [
            HttpWatchPack(),
            DnsTlsWatchPack(),
            SitemapWatchPack(),
            AccessLogWatchPack(log_root),
            ServiceExposureWatchPack(),
            SecretExposureWatchPack(secret_root),
            AiSystemRiskWatchPack(ai_manifest_root),
        ],
    )
    return engine.run(config["targets"])


class SentinelApiService:
    def __init__(
        self,
        *,
        token: str,
        profiles: Mapping[str, Path],
        state_root: Path,
        rate_limiter: ProfileRateLimiter | None = None,
        runner: Runner = run_profile,
    ) -> None:
        self.token = validate_api_token(token)
        self.profiles = dict(profiles)
        self.state_root = state_root
        self.rate_limiter = rate_limiter or ProfileRateLimiter()
        self.runner = runner
        self._run_locks = {
            profile: threading.Lock()
            for profile in self.profiles
        }

    def run(self, profile: str) -> dict[str, Any]:
        if not PROFILE_PATTERN.fullmatch(profile):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_profile",
                "Profile names may contain lowercase letters, numbers, and hyphens.",
            )
        config_path = self.profiles.get(profile)
        if config_path is None:
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "profile_not_found",
                "The requested profile is not approved on this service.",
            )

        run_lock = self._run_locks[profile]
        if not run_lock.acquire(blocking=False):
            raise ApiError(
                HTTPStatus.CONFLICT,
                "profile_busy",
                "The requested profile is already being checked.",
            )
        try:
            self.rate_limiter.claim(profile)
            self.state_root.mkdir(parents=True, exist_ok=True)
            result = self.runner(config_path, self.state_root / f"{profile}.json")
            return {"profile": profile, "result": result}
        finally:
            run_lock.release()


def build_handler(service: SentinelApiService) -> type[BaseHTTPRequestHandler]:
    class SentinelRequestHandler(BaseHTTPRequestHandler):
        server_version = "WatchDawgSentinel/1.0"
        sys_version = ""

        def do_GET(self) -> None:
            if self._path() != "/healthz":
                self._send_error(
                    ApiError(HTTPStatus.NOT_FOUND, "not_found", "Route not found.")
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "watch-dawg-sentinel-api",
                    "profiles_configured": len(service.profiles),
                },
            )

        def do_POST(self) -> None:
            try:
                if self._path() != "/v1/run":
                    raise ApiError(
                        HTTPStatus.NOT_FOUND,
                        "not_found",
                        "Route not found.",
                    )
                self._require_authentication()
                payload = self._read_json_body()
                if set(payload) != {"profile"}:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_request",
                        "The request must contain only the profile field.",
                    )
                profile = payload.get("profile")
                if not isinstance(profile, str):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_profile",
                        "The profile field must be a string.",
                    )
                response = service.run(profile)
                status = (
                    HTTPStatus.OK
                    if response["result"].get("complete", True)
                    else HTTPStatus.FAILED_DEPENDENCY
                )
                self._send_json(status, response)
            except ApiError as exc:
                self._send_error(exc)
            except Exception:
                LOGGER.exception("Sentinel API request failed")
                self._send_error(
                    ApiError(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "The approved profile could not be checked.",
                    )
                )

        def do_PUT(self) -> None:
            self._method_not_allowed()

        def do_PATCH(self) -> None:
            self._method_not_allowed()

        def do_DELETE(self) -> None:
            self._method_not_allowed()

        def do_OPTIONS(self) -> None:
            self._method_not_allowed()

        def do_HEAD(self) -> None:
            self._method_not_allowed()

        def do_TRACE(self) -> None:
            self._method_not_allowed()

        def do_CONNECT(self) -> None:
            self._method_not_allowed()

        def _method_not_allowed(self) -> None:
            self._send_error(
                ApiError(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "Method not allowed.",
                    headers={"Allow": "GET, POST"},
                )
            )

        def _path(self) -> str:
            return urlsplit(self.path).path

        def _require_authentication(self) -> None:
            value = self.headers.get("Authorization", "")
            prefix = "Bearer "
            supplied = value[len(prefix):] if value.startswith(prefix) else ""
            if not supplied or not hmac.compare_digest(supplied, service.token):
                raise ApiError(
                    HTTPStatus.UNAUTHORIZED,
                    "unauthorized",
                    "A valid bearer token is required.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        def _read_json_body(self) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ApiError(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    "Content-Type must be application/json.",
                )
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise ApiError(
                    HTTPStatus.LENGTH_REQUIRED,
                    "length_required",
                    "Content-Length is required.",
                )
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_content_length",
                    "Content-Length must be an integer.",
                ) from exc
            if length < 1:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "empty_request",
                    "A JSON request body is required.",
                )
            if length > MAX_REQUEST_BYTES:
                raise ApiError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "request_too_large",
                    f"Request bodies may not exceed {MAX_REQUEST_BYTES} bytes.",
                )
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_json",
                    "The request body must contain valid UTF-8 JSON.",
                ) from exc
            if not isinstance(payload, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "The JSON request body must be an object.",
                )
            return payload

        def _send_error(self, error: ApiError) -> None:
            self._send_json(
                error.status,
                {"error": {"code": error.code, "message": error.message}},
                headers=error.headers,
            )

        def _send_json(
            self,
            status: HTTPStatus,
            payload: Mapping[str, Any],
            *,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, message_format: str, *args: Any) -> None:
            LOGGER.info(
                "request from %s: %s",
                self.client_address[0],
                message_format % args,
            )

    return SentinelRequestHandler


def build_service_from_env() -> SentinelApiService:
    token = validate_api_token(os.environ.get("SENTINEL_API_TOKEN"))
    config_root = Path(os.environ.get("SENTINEL_CONFIG_ROOT", "sentinel/examples"))
    profiles = load_profile_paths(
        os.environ.get("SENTINEL_PROFILES_JSON"),
        config_root,
    )
    state_root = Path(os.environ.get("SENTINEL_STATE_ROOT", ".sentinel/api-state"))
    max_per_minute = int(
        os.environ.get(
            "SENTINEL_RATE_LIMIT_PER_MINUTE",
            str(DEFAULT_RATE_LIMIT_PER_MINUTE),
        )
    )
    cooldown_seconds = int(
        os.environ.get(
            "SENTINEL_PROFILE_COOLDOWN_SECONDS",
            str(DEFAULT_PROFILE_COOLDOWN_SECONDS),
        )
    )
    return SentinelApiService(
        token=token,
        profiles=profiles,
        state_root=state_root,
        rate_limiter=ProfileRateLimiter(max_per_minute, cooldown_seconds),
    )


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    service = build_service_from_env()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), build_handler(service))
    LOGGER.info(
        "Sentinel API listening on %s:%s with %s approved profile(s)",
        host,
        port,
        len(service.profiles),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
