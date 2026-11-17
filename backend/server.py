"""Private audit API with explicit providers and async MongoDB lifecycle."""

import asyncio
import json
import os
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from pymongo import AsyncMongoClient

if __package__:
    from .security import (
        Policy,
        Security,
        MongoSecurityStore,
        SecurityMiddleware,
        Limited,
        secret_value,
        audit_outcome,
    )
    from .providers import (
        CompatibleProvider,
        DisabledProvider,
        SyntheticProvider,
    )
else:
    from security import (
        Policy,
        Security,
        MongoSecurityStore,
        SecurityMiddleware,
        Limited,
        secret_value,
        audit_outcome,
    )
    from providers import (
        CompatibleProvider,
        DisabledProvider,
        SyntheticProvider,
    )

SYSTEM_MESSAGE: Final[str] = (
    "You are Watch-Dawg AI, a careful financial transaction audit assistant. "
    "Explain deterministic audit findings, recommend concrete next actions, "
    "and produce concise review-ready summaries. "
    "Never invent balances or facts."
)
SSE_HEADERS: Final[dict[str, str]] = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
}


class LimitRequestBody:
    """Bound request memory before parsing JSON or writing evidence."""

    def __init__(self, app, limit=256 * 1024):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        deadline = asyncio.get_running_loop().time() + 10
        while True:
            try:
                remaining = max(
                    0, deadline - asyncio.get_running_loop().time()
                )
                async with asyncio.timeout(remaining):
                    message = await receive()
            except TimeoutError:
                return await JSONResponse(
                    {"detail": "Request body timeout"},
                    status_code=408,
                )(scope, receive, send)
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.limit:
                response = JSONResponse(
                    {"detail": "Request body too large"}, status_code=413
                )
                return await response(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {
                "type": "http.request",
                "body": bytes(body),
                "more_body": False,
            }

        await self.app(scope, replay, send)


@dataclass(frozen=True)
class Settings:
    mongo_url: str = field(repr=False)
    db_name: str
    provider: str = "disabled"
    test_mode: bool = False
    base_url: str = ""
    api_key: str = field(default="", repr=False)
    model: str = ""
    security_file: str = field(default="", repr=False)

    def __post_init__(self):
        options = dict(parse_qsl(urlsplit(self.mongo_url).query))
        for key, value in options.items():
            unsafe = (
                key.casefold()
                in {
                    "tlsinsecure",
                    "tlsallowinvalidcertificates",
                    "tlsallowinvalidhostnames",
                }
                and value.casefold() != "false"
            )
            disabled = (
                key.casefold() in {"tls", "ssl"}
                and value.casefold() == "false"
            )
            if unsafe or disabled:
                raise ValueError("MongoDB TLS bypass options are prohibited")

    @classmethod
    def from_env(cls):
        return cls(
            secret_value("MONGO_URL"),
            os.getenv("DB_NAME", ""),
            os.getenv("LLM_PROVIDER", "disabled"),
            os.getenv("WATCHDAWG_TEST_MODE") == "true",
            os.getenv("LLM_BASE_URL", ""),
            secret_value("LLM_API_KEY"),
            os.getenv("LLM_MODEL", ""),
            os.getenv("BACKEND_SECURITY_FILE", ""),
        )


class MongoStore:
    def __init__(self, collection):
        self.collection = collection

    async def append(self, session_id, role, content):
        await self.collection.insert_one(
            {
                "session_id": session_id,
                "role": role,
                "content": content,
                "created_at": utc_now_iso(),
            }
        )


def select_provider(settings):
    if settings.provider == "disabled":
        return DisabledProvider()
    if settings.provider == "synthetic" and settings.test_mode:
        return SyntheticProvider()
    if settings.provider == "openai_compatible":
        return CompatibleProvider(
            settings.base_url, settings.api_key, settings.model
        )
    raise ValueError("Unsupported or unsafe provider configuration")


def create_app(
    settings=None, store=None, provider=None, policy=None, security_store=None
):
    @asynccontextmanager
    async def lifespan(application):
        config = settings or Settings.from_env()
        active_policy = policy or Policy.load(config.security_file)
        active_provider = (
            provider if provider is not None else select_provider(config)
        )
        if active_policy.transport == "test" and (
            not config.test_mode
            or not isinstance(active_provider, SyntheticProvider)
        ):
            raise ValueError("Test transport requires explicit synthetic mode")
        if (
            active_policy.transport == "test"
            and store is None
            and not config.db_name.startswith("watchdawg_test_")
        ):
            raise ValueError("Test transport requires a disposable database")
        application.state.provider = active_provider
        if store is not None:
            if security_store is None:
                raise ValueError("Injected storage requires a security store")
            application.state.store = store
            application.state.security = Security(
                active_policy, security_store
            )
            yield
            return
        if not config.mongo_url or not config.db_name:
            raise RuntimeError("MONGO_URL and DB_NAME are required")
        client = AsyncMongoClient(
            config.mongo_url,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            timeoutMS=5000,
        )
        try:
            try:
                await client.admin.command("ping")
                database = client[config.db_name]
                shared_security = MongoSecurityStore(database)
                await shared_security.initialize()
                application.state.store = MongoStore(
                    database.ai_audit_messages
                )
                application.state.security = Security(
                    active_policy, shared_security
                )
            except Exception:
                raise RuntimeError(
                    "Backend database initialization failed"
                ) from None
            yield
        finally:
            await client.close()

    application = FastAPI(
        title="Watch-Dawg AI API",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.add_middleware(LimitRequestBody)
    application.add_middleware(SecurityMiddleware)

    @application.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    @application.get("/api/health")
    async def health():
        return {"status": "ok", "service": "watch-dawg-ai"}

    @application.post("/api/ai/audit")
    async def ai_audit(request: AIAnalyzeRequest, http_request: Request):
        active_provider = application.state.provider
        if not active_provider.ready:
            raise HTTPException(
                status_code=500, detail="AI key is not configured"
            )
        session_id = build_session_id()
        prompt = build_audit_prompt(request)
        active_store = application.state.store
        security = application.state.security
        try:
            leases = await security.reserve(http_request.state.principal)
        except Limited:
            raise HTTPException(
                status_code=429,
                detail="Stream budget exceeded",
                headers={"Retry-After": "120"},
            ) from None
        except Exception:
            raise HTTPException(
                status_code=503, detail="Security service unavailable"
            ) from None
        try:
            await active_store.append(session_id, "user", prompt)
        except asyncio.CancelledError:
            await security.release(leases)
            audit_outcome(
                http_request.state.request_id,
                "cancelled",
                security.policy.ref(
                    "principal:" + http_request.state.principal.name
                ),
            )
            raise
        except Exception:
            await security.release(leases)
            raise HTTPException(
                status_code=500, detail="Audit storage is unavailable"
            ) from None

        recorded = False

        def record_result(outcome):
            nonlocal recorded
            recorded = True
            audit_outcome(
                http_request.state.request_id,
                outcome,
                security.policy.ref(
                    "principal:" + http_request.state.principal.name
                ),
            )

        async def guarded_stream():
            try:
                async with aclosing(
                    stream_ai_audit_events(
                        active_provider,
                        active_store,
                        session_id,
                        prompt,
                        outcome=record_result,
                    )
                ) as stream:
                    async for event in stream:
                        yield event
            finally:
                if not recorded:
                    record_result("cancelled")
                await security.release(leases)

        return format_sse_response(guarded_stream())

    return application


class AIAnalyzeRequest(BaseModel):
    payload: Any = Field(...)
    deterministic_result: dict[str, Any] = Field(...)
    report: str = Field(..., max_length=12000)


def build_session_id() -> str:
    return f"watch-dawg-{uuid.uuid4()}"


def build_audit_prompt(request: AIAnalyzeRequest) -> str:
    compact_payload = compact_json(request.payload, limit=6000)
    compact_result = compact_json(request.deterministic_result, limit=9000)
    return build_audit_message(
        compact_payload,
        compact_result,
        request.report[:4000],
    )


def compact_json(value: Any, limit: int) -> str:
    return json.dumps(value, ensure_ascii=False)[:limit]


def build_audit_message(
    compact_payload: str,
    compact_result: str,
    report_excerpt: str,
) -> str:
    return (
        "Analyze this Watch-Dawg deterministic audit result.\n\n"
        "Return exactly these sections with short bullets:\n"
        "1. Executive Summary\n"
        "2. Findings Explained\n"
        "3. Recommended Next Actions\n"
        "4. Review-Ready Report\n\n"
        "Rules: stay under 220 words, use plain English, mention if the "
        "deterministic verdict is VERIFIED or REVIEW, "
        "and do not claim external system access.\n\n"
        f"Original transaction or ledger JSON:\n{compact_payload}\n\n"
        f"Deterministic Watch-Dawg result:\n{compact_result}\n\n"
        f"Existing deterministic report:\n{report_excerpt}"
    )


async def stream_ai_audit_events(
    provider, store, session_id, prompt, outcome=None
) -> AsyncIterator[str]:
    collected = []
    length = 0
    try:
        async with asyncio.timeout(90), aclosing(
            provider.stream(prompt, session_id, SYSTEM_MESSAGE)
        ) as deltas:
            async for delta in deltas:
                if not isinstance(delta, str):
                    raise ValueError("Malformed provider content")
                length += len(delta)
                if length > 1000000:
                    raise ValueError("Provider output exceeds limit")
                collected.append(delta)
                yield format_sse_event({"delta": delta})
        await store.append(session_id, "assistant", "".join(collected))
        if outcome:
            outcome("completed")
        yield format_sse_event({"done": True, "session_id": session_id})
    except Exception:
        if outcome:
            outcome("failed")
        # Never retain exception text/types: providers may embed
        # keys, URLs or prompts.
        yield format_sse_event(
            {"error": "AI analysis failed. Please run the audit again."}
        )
        try:
            await store.append(
                session_id,
                "system",
                "AI stream error: provider_or_storage_failure",
            )
        except Exception:
            # Never emit done if the failure record cannot be stored.
            pass


def format_sse_event(payload: Mapping[str, Any]) -> str:
    return f"data: {json.dumps(dict(payload))}\n\n"


def format_sse_response(events: AsyncIterator[str]) -> StreamingResponse:
    return StreamingResponse(
        events,
        media_type="text/event-stream",
        headers=SSE_HEADERS,
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


app = create_app()
