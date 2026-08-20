import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

from emergentintegrations.llm.chat import LlmChat, StreamDone, TextDelta, UserMessage

load_dotenv()

MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME")
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")

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
    deterministic_result: Dict[str, Any] = Field(...)
    report: str = Field(..., max_length=12000)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "watch-dawg-ai"}


@app.post("/api/ai/audit")
async def ai_audit(request: AIAnalyzeRequest):
    if not EMERGENT_LLM_KEY:
        raise HTTPException(status_code=500, detail="AI key is not configured")

    session_id = f"watch-dawg-{uuid.uuid4()}"
    created_at = datetime.now(timezone.utc).isoformat()
    prompt = build_audit_prompt(request)

    await db.ai_audit_messages.insert_one(
        {
            "session_id": session_id,
            "role": "user",
            "content": prompt,
            "created_at": created_at,
        }
    )

    async def stream_events():
        collected = []
        try:
            chat = LlmChat(
                api_key=EMERGENT_LLM_KEY,
                session_id=session_id,
                system_message=(
                    "You are Watch-Dawg AI, a careful financial transaction audit assistant. "
                    "Explain deterministic audit findings, recommend concrete next actions, "
                    "and produce concise review-ready summaries. Never invent balances or facts."
                ),
            ).with_model("openai", "gpt-5.4-mini")

            async for event in chat.stream_message(UserMessage(text=prompt)):
                if isinstance(event, TextDelta):
                    collected.append(event.content)
                    yield f"data: {json.dumps({'delta': event.content})}\n\n"
                elif isinstance(event, StreamDone):
                    break

            assistant_text = "".join(collected)
            await db.ai_audit_messages.insert_one(
                {
                    "session_id": session_id,
                    "role": "assistant",
                    "content": assistant_text,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            yield f"data: {json.dumps({'done': True, 'session_id': session_id})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': 'AI analysis failed. Please run the audit again.'})}\n\n"
            await db.ai_audit_messages.insert_one(
                {
                    "session_id": session_id,
                    "role": "system",
                    "content": f"AI stream error: {type(exc).__name__}: {exc}",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )

    return StreamingResponse(
        stream_events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def build_audit_prompt(request: AIAnalyzeRequest) -> str:
    compact_payload = json.dumps(request.payload, ensure_ascii=False)[:6000]
    compact_result = json.dumps(request.deterministic_result, ensure_ascii=False)[:9000]
    return (
        "Analyze this Watch-Dawg deterministic audit result.\n\n"
        "Return exactly these sections with short bullets:\n"
        "1. Executive Summary\n"
        "2. Findings Explained\n"
        "3. Recommended Next Actions\n"
        "4. Review-Ready Report\n\n"
        "Rules: stay under 220 words, use plain English, mention if the deterministic verdict is VERIFIED or REVIEW, "
        "and do not claim external system access.\n\n"
        f"Original transaction or ledger JSON:\n{compact_payload}\n\n"
        f"Deterministic Watch-Dawg result:\n{compact_result}\n\n"
        f"Existing deterministic report:\n{request.report[:4000]}"
    )
