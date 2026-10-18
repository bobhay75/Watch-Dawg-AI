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
from typing import Any, Final, Protocol
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
from .swarm_proof import load_proof_hmac_key
from .swarm_watch import SwarmDefenseWatchPack


LOGGER = logging.getLogger("watch_dawg.sentinel.api")
PROFILE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MAX_PROFILE_COUNT: Final[int] = 50
MAX_REQUEST_BYTES: Final[int] = 2_048
MAX_SWARM_REQUEST_BYTES: Final[int] = 512_000
MIN_TOKEN_LENGTH: Final[int] = 32
DEFAULT_RATE_LIMIT_PER_MINUTE: Final[int] = 10
DEFAULT_PROFILE_COOLDOWN_SECONDS: Final[int] = 60
DEFAULT_REQUEST_TIMEOUT_SECONDS: Final[float] = 15.0
Runner = Callable[[Path, Path], dict[str, Any]]


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


class SwarmIngestor(Protocol):
    enrollments: Mapping[str, Any]

    def preauthenticate(self, device_id: str, bearer_token: str) -> None: ...

    def ingest(
        self,
        envelope: Mapping[str, Any],
        bearer_token: str,
        *,
        preauthenticated_device_id: str | None = None,
    ) -> dict[str, Any]: ...


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


class SentinelHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        if not 1 <= request_timeout <= 120:
            raise ValueError("request_timeout must be between 1 and 120 seconds")
        self.request_timeout = request_timeout
        super().__init__(server_address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.request_timeout)
        return connection, address


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
    swarm_snapshot_root = Path(config.get("swarm_snapshot_root", "."))
    proof_hmac_key = load_proof_hmac_key(
        os.environ.get("SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64"),
        required=False,
    )
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
            SwarmDefenseWatchPack(
                swarm_snapshot_root,
                proof_hmac_key=proof_hmac_key,
            ),
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
        swarm_ingestor: SwarmIngestor | None = None,
    ) -> None:
        self.token = validate_api_token(token)
        self.profiles = dict(profiles)
        self.state_root = state_root
        self.rate_limiter = rate_limiter or ProfileRateLimiter()
        self.runner = runner
        self.swarm_ingestor = swarm_ingestor
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
                path = self._path()
                if path == "/v1/swarm/snapshot":
                    if service.swarm_ingestor is None:
                        raise ApiError(
                            HTTPStatus.NOT_FOUND,
                            "not_found",
                            "Route not found.",
                        )
                    device_id = self._single_header("X-WatchDawg-Device-ID")
                    bearer_token = self._bearer_token()
                    service.swarm_ingestor.preauthenticate(
                        device_id,
                        bearer_token,
                    )
                    payload = self._read_json_body(MAX_SWARM_REQUEST_BYTES)
                    result = service.swarm_ingestor.ingest(
                        payload,
                        bearer_token,
                        preauthenticated_device_id=device_id,
                    )
                    self._send_json(HTTPStatus.CREATED, result)
                    return
                if path != "/v1/run":
                    raise ApiError(
                        HTTPStatus.NOT_FOUND,
                        "not_found",
                        "Route not found.",
                    )
                self._require_authentication()
                payload = self._read_json_body(MAX_REQUEST_BYTES)
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
                self._send_json(HTTPStatus.OK, service.run(profile))
            except ApiError as exc:
                self._send_error(exc)
            except TimeoutError:
                self._send_error(
                    ApiError(
                        HTTPStatus.REQUEST_TIMEOUT,
                        "request_timeout",
                        "The request body was not received within the time limit.",
                    )
                )
            except Exception:
                LOGGER.exception("Sentinel API request failed")
                self._send_error(
                    ApiError(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "The Sentinel request could not be completed.",
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
            supplied = self._bearer_token()
            if not supplied or not hmac.compare_digest(supplied, service.token):
                raise ApiError(
                    HTTPStatus.UNAUTHORIZED,
                    "unauthorized",
                    "A valid bearer token is required.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        def _bearer_token(self) -> str:
            value = self._single_header("Authorization")
            prefix = "Bearer "
            return value[len(prefix):] if value.startswith(prefix) else ""

        def _single_header(self, name: str) -> str:
            values = self.headers.get_all(name, [])
            return values[0] if len(values) == 1 else ""

        def _read_json_body(self, max_bytes: int) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ApiError(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    "Content-Type must be application/json.",
                )
            if self.headers.get("Transfer-Encoding") is not None:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "unsupported_transfer_encoding",
                    "Transfer-Encoding is not accepted; send one Content-Length.",
                )
            length_values = self.headers.get_all("Content-Length", [])
            if not length_values:
                raise ApiError(
                    HTTPStatus.LENGTH_REQUIRED,
                    "length_required",
                    "Content-Length is required.",
                )
            if len(length_values) != 1:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_content_length",
                    "Exactly one Content-Length header is required.",
                )
            raw_length = length_values[0]
            if re.fullmatch(r"[0-9]+", raw_length) is None:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_content_length",
                    "Content-Length must contain only ASCII decimal digits.",
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
            if length > max_bytes:
                raise ApiError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "request_too_large",
                    f"Request bodies may not exceed {max_bytes} bytes.",
                )
            body = self.rfile.read(length)
            try:
                payload = json.loads(
                    body.decode("utf-8"),
                    object_pairs_hook=_strict_json_object,
                    parse_constant=_reject_nonfinite_json,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
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
            path = self._path()
            route = (
                path
                if path in {"/healthz", "/v1/run", "/v1/swarm/snapshot"}
                else "<unmatched>"
            )
            status = str(args[1]) if len(args) > 1 else "unknown"
            LOGGER.info(
                "request from %s: method=%s route=%s status=%s",
                self.client_address[0],
                self.command,
                route,
                status,
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
    swarm_ingestor = None
    enrollment_json = os.environ.get("SENTINEL_SWARM_ENROLLMENTS_JSON")
    enrollment_file = os.environ.get("SENTINEL_SWARM_ENROLLMENTS_FILE")
    proof_hmac_key = load_proof_hmac_key(
        os.environ.get("SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64"),
        required=bool(enrollment_json or enrollment_file),
    )
    if enrollment_json or enrollment_file:
        assert proof_hmac_key is not None
        from .swarm_ingest import (
            DEFAULT_DEVICE_COOLDOWN_SECONDS,
            DEFAULT_HISTORY_MAX_ENTRIES_PER_DEVICE,
            DEFAULT_INGEST_RATE_LIMIT_PER_MINUTE,
            SwarmIngestRateLimiter,
            SwarmSnapshotIngestor,
            load_swarm_enrollment_source,
        )

        snapshot_root = Path(
            os.environ.get(
                "SENTINEL_SWARM_SNAPSHOT_ROOT",
                str(state_root / "swarm-snapshots"),
            )
        )
        enrollments = load_swarm_enrollment_source(
            inline_json=enrollment_json,
            file_path=enrollment_file,
            snapshot_root=snapshot_root,
        )
        if not enrollments:
            raise ValueError(
                "Swarm ingestion requires at least one enrolled device"
            )
        replay_state_path = Path(
            os.environ.get(
                "SENTINEL_SWARM_REPLAY_STATE_PATH",
                str(state_root / "swarm-replay.sqlite3"),
            )
        )
        history_max_entries_per_device = int(
            os.environ.get(
                "SENTINEL_SWARM_HISTORY_MAX_ENTRIES_PER_DEVICE",
                str(DEFAULT_HISTORY_MAX_ENTRIES_PER_DEVICE),
            )
        )
        ingest_rate_limit = int(
            os.environ.get(
                "SENTINEL_SWARM_RATE_LIMIT_PER_MINUTE",
                str(DEFAULT_INGEST_RATE_LIMIT_PER_MINUTE),
            )
        )
        device_cooldown_seconds = float(
            os.environ.get(
                "SENTINEL_SWARM_DEVICE_COOLDOWN_SECONDS",
                str(DEFAULT_DEVICE_COOLDOWN_SECONDS),
            )
        )
        swarm_ingestor = SwarmSnapshotIngestor(
            enrollments=enrollments,
            replay_state_path=replay_state_path,
            proof_hmac_key=proof_hmac_key,
            history_max_entries_per_device=history_max_entries_per_device,
            rate_limiter=SwarmIngestRateLimiter(
                ingest_rate_limit,
                device_cooldown_seconds,
            ),
        )
    return SentinelApiService(
        token=token,
        profiles=profiles,
        state_root=state_root,
        rate_limiter=ProfileRateLimiter(max_per_minute, cooldown_seconds),
        swarm_ingestor=swarm_ingestor,
    )


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    service = build_service_from_env()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    request_timeout = float(
        os.environ.get(
            "SENTINEL_REQUEST_TIMEOUT_SECONDS",
            str(DEFAULT_REQUEST_TIMEOUT_SECONDS),
        )
    )
    server = SentinelHttpServer(
        (host, port),
        build_handler(service),
        request_timeout=request_timeout,
    )
    LOGGER.info(
        "Sentinel API listening on %s:%s with %s approved profile(s)",
        host,
        port,
        len(service.profiles),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
