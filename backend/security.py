"""Service authentication, shared abuse controls and private logs."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import stat
import sys
import time
from urllib.parse import urlsplit
import uuid

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from starlette.responses import JSONResponse, Response

LOG = logging.getLogger("watchdawg.security")
if not LOG.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)
LOG.propagate = False
SCOPES = frozenset({"health:read", "audit:run"})
ROUTES = {
    ("GET", "/api/health"): "health:read",
    ("POST", "/api/ai/audit"): "audit:run",
}


def private_bytes(path, limit=65536):
    """Only a regular, privately owned, non-linked POSIX file is accepted."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("Secret file ownership or permissions are unsafe")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Secret file exceeds limit")
    return data


def secret_value(name):
    path = os.getenv(name + "_FILE")
    value = os.getenv(name, "")
    if path:
        if value:
            raise ValueError(
                "Secret must use exactly one configuration source"
            )
        try:
            value = private_bytes(path, 8192).decode("utf-8").strip()
        except (OSError, UnicodeError, ValueError):
            raise ValueError("Secret file cannot be loaded safely") from None
    return value


@dataclass(frozen=True)
class Principal:
    name: str
    scopes: frozenset
    hashes: tuple = field(repr=False)
    expires: datetime


@dataclass(frozen=True)
class Policy:
    principals: tuple = field(repr=False)
    hmac_key: bytes = field(repr=False)
    hosts: tuple
    networks: tuple
    origins: tuple = ()
    transport: str = "https"
    proxies: tuple = ()
    window: int = 60
    global_limit: int = 600
    network_limit: int = 120
    principal_limit: int = 30
    global_streams: int = 4
    principal_streams: int = 2
    lease_seconds: int = 120

    @classmethod
    def load(cls, path):
        if not path:
            raise ValueError("BACKEND_SECURITY_FILE is required")
        try:
            return cls.parse(json.loads(private_bytes(path)))
        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
        ):
            raise ValueError(
                "Security policy cannot be loaded safely"
            ) from None

    @classmethod
    def parse(cls, doc):
        if not isinstance(doc, dict):
            raise ValueError("Invalid security policy")
        key = doc.get("rate_hmac_key", "")
        if not re.fullmatch("[0-9a-f]{64}", key):
            raise ValueError("A 256-bit rate HMAC key is required")
        records = doc.get("principals", [])
        if not isinstance(records, list) or not 1 <= len(records) <= 128:
            raise ValueError("Invalid principal registry")
        principals, names, hashes = [], set(), set()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid principal registry")
            name = record.get("id", "")
            scopes = record.get("scopes", [])
            digests = record.get("token_sha256", [])
            if not isinstance(scopes, list):
                raise ValueError("Scopes must be a list")
            expires = datetime.fromisoformat(
                record.get("expires_at", "").replace("Z", "+00:00")
            )
            if (
                not re.fullmatch("[A-Za-z0-9_-]{1,64}", name)
                or name in names
                or not scopes
                or not set(scopes) <= SCOPES
                or not isinstance(digests, list)
                or not 1 <= len(digests) <= 4
                or not expires.tzinfo
            ):
                raise ValueError("Invalid principal privileges or expiry")
            for digest in digests:
                if (
                    not isinstance(digest, str)
                    or not re.fullmatch("[0-9a-f]{64}", digest)
                    or digest in hashes
                ):
                    raise ValueError("Invalid or duplicate credential digest")
                hashes.add(digest)
            names.add(name)
            principals.append(
                Principal(name, frozenset(scopes), tuple(digests), expires)
            )
        hosts = doc.get("allowed_hosts", [])
        if not isinstance(hosts, list):
            raise ValueError("Allowed hosts must be a list")
        if not hosts or any(
            not isinstance(host, str)
            or not re.fullmatch("[a-z0-9.:-]{1,253}", host)
            or "*" in host
            for host in hosts
        ):
            raise ValueError("Explicit exact allowed hosts are required")
        networks = tuple(
            ipaddress.ip_network(n, strict=True)
            for n in doc.get("allowed_networks", [])
        )
        proxies = tuple(
            ipaddress.ip_network(n, strict=True)
            for n in doc.get("trusted_proxy_networks", [])
        )
        if not networks or any(
            n.prefixlen == 0 for n in (*networks, *proxies)
        ):
            raise ValueError("Explicit restricted peer networks are required")
        origins = doc.get("allowed_origins", [])
        if not isinstance(origins, list):
            raise ValueError("Origins must be a list")
        for origin in origins:
            p = urlsplit(origin)
            if (
                p.scheme != "https"
                or not p.hostname
                or p.username is not None
                or p.password is not None
                or p.path
                or p.query
                or p.fragment
                or "*" in origin
            ):
                raise ValueError("CORS origins must be exact HTTPS origins")
        mode = doc.get("transport", "https")
        if mode not in {"https", "proxy", "loopback", "test"} or (
            mode == "proxy" and not proxies
        ):
            raise ValueError("Invalid transport boundary")
        rates = doc.get("rates", {})
        allowed = {
            "window",
            "global_limit",
            "network_limit",
            "principal_limit",
            "global_streams",
            "principal_streams",
        }
        if set(rates) - allowed or any(
            type(v) is not int or not 1 <= v <= 10000 for v in rates.values()
        ):
            raise ValueError("Invalid rate policy")
        if (
            rates.get("global_streams", 4) > 64
            or rates.get("principal_streams", 2) > 64
        ):
            raise ValueError("Stream concurrency exceeds safety limit")
        return cls(
            tuple(principals),
            bytes.fromhex(key),
            tuple(hosts),
            networks,
            tuple(origins),
            mode,
            proxies,
            **rates
        )

    def ref(self, value):
        return hmac.new(
            self.hmac_key, value.encode(), hashlib.sha256
        ).hexdigest()

    def authenticate(self, authorization, now=None):
        parts = authorization.split(" ")
        if (
            len(parts) != 2
            or parts[0].lower() != "bearer"
            or not re.fullmatch("[A-Za-z0-9_-]{43,128}", parts[1])
        ):
            return None
        digest = hashlib.sha256(parts[1].encode()).hexdigest()
        match = None
        for principal in self.principals:
            if any(
                hmac.compare_digest(digest, stored)
                for stored in principal.hashes
            ):
                match = principal
        now = now or datetime.now(timezone.utc)
        return match if match and match.expires > now else None


class Limited(Exception):
    pass


class MongoSecurityStore:
    """Atomic per-window budgets and expiring leases shared by all workers."""

    def __init__(self, database):
        self.windows = database.security_windows
        self.leases = database.security_leases

    async def initialize(self):
        for collection in (self.windows, self.leases):
            await collection.create_index("expires_at", expireAfterSeconds=0)

    async def take(self, key, limit, expires):
        try:
            await self.windows.find_one_and_update(
                {"_id": key, "count": {"$lt": limit}},
                {
                    "$inc": {"count": 1},
                    "$setOnInsert": {"expires_at": expires},
                },
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError:
            raise Limited from None

    async def acquire(self, key, limit, seconds):
        now = datetime.now(timezone.utc)
        token = uuid.uuid4().hex
        for slot in range(limit):
            identity = key + ":" + str(slot)
            try:
                await self.leases.find_one_and_update(
                    {"_id": identity, "expires_at": {"$lte": now}},
                    {
                        "$set": {
                            "expires_at": now + timedelta(seconds=seconds),
                            "token": token,
                        }
                    },
                    upsert=True,
                    return_document=ReturnDocument.AFTER,
                )
                return identity, token
            except DuplicateKeyError:
                continue
        raise Limited

    async def release(self, handle):
        identity, token = handle
        await self.leases.update_one(
            {"_id": identity, "token": token},
            {"$set": {"expires_at": datetime.now(timezone.utc)}},
        )


class Security:
    def __init__(self, policy, store):
        self.policy, self.store = policy, store

    async def budget(self, subject, limit):
        now = time.time()
        window = int(now // self.policy.window)
        key = self.policy.ref("window:" + subject + ":" + str(window))
        expires = datetime.fromtimestamp(
            (window + 2) * self.policy.window, timezone.utc
        )
        await self.store.take(key, limit, expires)

    async def reserve(self, principal):
        handles = []
        try:
            async with asyncio.timeout(5):
                for subject, limit in (
                    ("global", self.policy.global_streams),
                    (
                        "principal:" + principal.name,
                        self.policy.principal_streams,
                    ),
                ):
                    handles.append(
                        await self.store.acquire(
                            self.policy.ref("lease:" + subject),
                            limit,
                            self.policy.lease_seconds,
                        )
                    )
        except BaseException:
            # Cancellation must release every slot already acknowledged.
            await self.release(handles)
            raise
        return handles

    async def release(self, handles):
        for handle in handles:
            try:
                await self.store.release(handle)
            except Exception:
                # Expiring leases fail closed if storage becomes unavailable.
                pass


def audit(request_id, route, status, principal="anonymous"):
    LOG.info(
        json.dumps(
            {
                "event": "backend_request",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "route": route,
                "status": status,
                "principal_ref": principal,
            },
            separators=(",", ":"),
        )
    )


class SecurityMiddleware:
    """Authenticate before parsing. Ignore client identity/IP headers."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex
        route = {"/api/health": "health", "/api/ai/audit": "audit"}.get(
            scope["path"], "other"
        )
        subject = "anonymous"
        scope.setdefault("state", {})["request_id"] = request_id
        origin = None
        policy = None
        started = False

        async def output(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in {b"cache-control", b"x-request-id"}
                ]
                headers += [
                    (b"x-request-id", request_id.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"cache-control", b"no-store"),
                ]
                if origin and policy and origin in policy.origins:
                    headers += [
                        (b"access-control-allow-origin", origin.encode()),
                        (b"vary", b"Origin"),
                    ]
                message = dict(message, headers=headers)
                audit(request_id, route, message["status"], subject)
            await send(message)

        async def deny(status, detail):
            headers = (
                {"Retry-After": str(policy.window)}
                if status == 429 and policy
                else {}
            )
            if status == 401:
                headers["WWW-Authenticate"] = "Bearer"
            await JSONResponse(
                {"detail": detail}, status_code=status, headers=headers
            )(scope, receive, output)

        try:
            security = scope["app"].state.security
            policy = security.policy
            values = {}
            if sum(len(k) + len(v) for k, v in scope["headers"]) > 32768:
                return await deny(431, "Request headers too large")
            for key, value in scope["headers"]:
                key = key.lower()
                if key in {
                    b"host",
                    b"authorization",
                    b"origin",
                    b"x-forwarded-proto",
                }:
                    if key in values:
                        return await deny(400, "Ambiguous request headers")
                    if any(byte < 32 or byte == 127 for byte in value):
                        return await deny(400, "Malformed request boundary")
                    values[key] = value.decode("latin1")
            peer = ipaddress.ip_address(scope.get("client", ("", 0))[0])
            if not any(peer in n for n in policy.networks):
                return await deny(403, "Peer network is not allowed")
            host = urlsplit("//" + values.get(b"host", ""))
            port = host.port
            if port is not None and not 1 <= port <= 65535:
                return await deny(400, "Host is not allowed")
            if (
                host.username is not None
                or host.password is not None
                or host.path
                or host.query
                or host.fragment
                or host.hostname not in policy.hosts
            ):
                return await deny(400, "Host is not allowed")
            secure = scope.get("scheme") == "https"
            if policy.transport == "proxy":
                secure = (
                    any(peer in n for n in policy.proxies)
                    and values.get(b"x-forwarded-proto") == "https"
                )
            elif policy.transport == "loopback":
                secure = secure or peer.is_loopback
            elif policy.transport == "test":
                secure = (
                    True  # Startup restricts this mode to synthetic tests.
                )
            if not secure:
                return await deny(403, "Secure transport is required")
            await security.budget("global", policy.global_limit)
            await security.budget("peer:" + str(peer), policy.network_limit)
            origin = values.get(b"origin")
            if origin and origin not in policy.origins:
                return await deny(403, "Origin is not allowed")
            if scope["method"] == "OPTIONS":
                headers = {
                    k.lower(): v.decode("latin1") for k, v in scope["headers"]
                }
                requested = headers.get(b"access-control-request-method", "")
                requested_headers = {
                    s.strip().lower()
                    for s in headers.get(
                        b"access-control-request-headers", ""
                    ).split(",")
                    if s.strip()
                }
                if (
                    not origin
                    or (requested, scope["path"]) not in ROUTES
                    or not requested_headers
                    <= {"authorization", "content-type"}
                ):
                    return await deny(403, "Preflight is not allowed")
                return await Response(
                    status_code=204,
                    headers={
                        "Access-Control-Allow-Methods": requested,
                        "Access-Control-Allow-Headers": (
                            "Authorization, Content-Type"
                        ),
                        "Access-Control-Max-Age": "600",
                    },
                )(scope, receive, output)
            principal = policy.authenticate(values.get(b"authorization", ""))
            if not principal:
                return await deny(401, "Authentication required")
            subject = policy.ref("principal:" + principal.name)
            required = ROUTES.get((scope["method"], scope["path"]))
            if not required:
                return await deny(404, "Not found")
            if required not in principal.scopes:
                return await deny(403, "Insufficient privilege")
            await security.budget(
                "principal:" + principal.name, policy.principal_limit
            )
            scope.setdefault("state", {})["principal"] = principal
        except Limited:
            return await deny(429, "Request budget exceeded")
        except (ValueError, UnicodeError):
            return await deny(400, "Malformed request boundary")
        except Exception:
            return await deny(503, "Security service unavailable")
        try:
            await self.app(scope, receive, output)
        except (RecursionError, UnicodeDecodeError):
            if not started:
                await deny(400, "Malformed request")
        except Exception:
            # Suppress private exception details before server error logging.
            if not started:
                await deny(500, "Backend request failed")
            else:
                audit_outcome(request_id, "failed", subject)


def audit_outcome(request_id, outcome, principal_ref):
    if outcome not in {"completed", "failed", "cancelled"}:
        raise ValueError("Invalid audit outcome")
    LOG.info(
        json.dumps(
            {
                "event": "backend_stream",
                "request_id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "outcome": outcome,
                "principal_ref": principal_ref,
            },
            separators=(",", ":"),
        )
    )
