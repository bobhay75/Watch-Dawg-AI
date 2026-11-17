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

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from pymongo import AsyncMongoClient

if __package__:
    from .providers import (
        CompatibleProvider,
        DisabledProvider,
        SyntheticProvider,
    )
else:
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
        while True:
            message = await receive()
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
            os.getenv("MONGO_URL", ""),
            os.getenv("DB_NAME", ""),
            os.getenv("LLM_PROVIDER", "disabled"),
            os.getenv("WATCHDAWG_TEST_MODE") == "true",
            os.getenv("LLM_BASE_URL", ""),
            os.getenv("LLM_API_KEY", ""),
            os.getenv("LLM_MODEL", ""),
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


def create_app(settings=None, store=None, provider=None):
    @asynccontextmanager
    async def lifespan(application):
        config = settings or Settings.from_env()
        application.state.provider = (
            provider if provider is not None else select_provider(config)
        )
        if store is not None:
            application.state.store = store
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
            await client.admin.command("ping")
            application.state.store = MongoStore(
                client[config.db_name].ai_audit_messages
            )
            yield
        finally:
            await client.close()

    application = FastAPI(title="Watch-Dawg AI API", lifespan=lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.add_middleware(LimitRequestBody)

    @application.get("/api/health")
    async def health():
        return {"status": "ok", "service": "watch-dawg-ai"}

    @application.post("/api/ai/audit")
    async def ai_audit(request: AIAnalyzeRequest):
        active_provider = application.state.provider
        if not active_provider.ready:
            raise HTTPException(
                status_code=500, detail="AI key is not configured"
            )
        session_id = build_session_id()
        prompt = build_audit_prompt(request)
        active_store = application.state.store
        try:
            await active_store.append(session_id, "user", prompt)
        except Exception:
            raise HTTPException(
                status_code=500, detail="Audit storage is unavailable"
            ) from None
        return format_sse_response(
            stream_ai_audit_events(
                active_provider,
                active_store,
                session_id,
                prompt,
            )
        )

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
    provider, store, session_id, prompt
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
        yield format_sse_event({"done": True, "session_id": session_id})
    except Exception:
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
