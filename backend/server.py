import json
import os
import uuid
from collections.abc import AsyncIterator, Mapping
from datetime import datetime, timezone
from typing import Any, Final

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

from emergentintegrations.llm.chat import (  # type: ignore[import-untyped]
    LlmChat,
    StreamDone,
    TextDelta,
    UserMessage,
)

load_dotenv()

MONGO_URL: str | None = os.environ.get("MONGO_URL")
DB_NAME: str | None = os.environ.get("DB_NAME")
EMERGENT_LLM_KEY: str | None = os.environ.get("EMERGENT_LLM_KEY")
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

if not MONGO_URL or not DB_NAME:
    raise RuntimeError("MONGO_URL and DB_NAME are required")

app = FastAPI(title="Watch-Dawg AI API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

mongo = AsyncIOMotorClient(MONGO_URL)
db = mongo[DB_NAME]


class AIAnalyzeRequest(BaseModel):
    payload: Any = Field(...)
    deterministic_result: dict[str, Any] = Field(...)
    report: str = Field(..., max_length=12000)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "watch-dawg-ai"}


@app.post("/api/ai/audit")
async def ai_audit(request: AIAnalyzeRequest) -> StreamingResponse:
    api_key = validate_ai_configuration(EMERGENT_LLM_KEY)
    validated_request = validate_ai_audit_request(request)
    session_id = build_session_id()
    prompt = build_audit_prompt(validated_request)

    await persist_ai_message(
        session_id=session_id,
        role="user",
        content=prompt,
    )
    return format_sse_response(
        stream_ai_audit_events(api_key, session_id, prompt)
    )


def validate_ai_configuration(api_key: str | None) -> str:
    if not api_key:
        raise HTTPException(status_code=500, detail="AI key is not configured")
    return api_key


def validate_ai_audit_request(request: AIAnalyzeRequest) -> AIAnalyzeRequest:
    return request


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


def build_chat_client(api_key: str, session_id: str) -> LlmChat:
    chat = LlmChat(
        api_key=api_key,
        session_id=session_id,
        system_message=SYSTEM_MESSAGE,
    )
    return chat.with_model(
        "openai", "gpt-5.4-mini"
    )


async def stream_ai_audit_events(
    api_key: str,
    session_id: str,
    prompt: str,
) -> AsyncIterator[str]:
    collected: list[str] = []
    try:
        chat = build_chat_client(api_key, session_id)
        async for event in chat.stream_message(UserMessage(text=prompt)):
            if isinstance(event, TextDelta):
                collected.append(event.content)
                yield format_sse_event({"delta": event.content})
            elif isinstance(event, StreamDone):
                break

        await persist_ai_message(
            session_id=session_id,
            role="assistant",
            content="".join(collected),
        )
        yield format_sse_event({"done": True, "session_id": session_id})
    except Exception as exc:
        yield format_sse_event(
            {"error": "AI analysis failed. Please run the audit again."}
        )
        await persist_ai_message(
            session_id=session_id,
            role="system",
            content=f"AI stream error: {type(exc).__name__}: {exc}",
        )


async def persist_ai_message(session_id: str, role: str, content: str) -> None:
    await db.ai_audit_messages.insert_one(
        {
            "session_id": session_id,
            "role": role,
            "content": content,
            "created_at": utc_now_iso(),
        }
    )


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
