"""API regression tests for health and AI audit streaming + persistence."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import requests
from dotenv import load_dotenv
from pymongo import MongoClient

ROOT_DIR = Path(__file__).resolve().parents[2]
DONE_EVENT_VALUE = True

load_dotenv(ROOT_DIR / "backend" / ".env")
load_dotenv(ROOT_DIR / "frontend" / ".env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME")
SseEvent = dict[str, Any]


@pytest.fixture(scope="session")
def api_base_url() -> str:
    if not BASE_URL:
        pytest.skip("REACT_APP_BACKEND_URL is not set")
    return BASE_URL.rstrip("/")


@pytest.fixture(scope="session")
def mongo_collection() -> Any:
    if not MONGO_URL or not DB_NAME:
        pytest.skip("MONGO_URL or DB_NAME is not set")
    client: MongoClient[dict[str, Any]] = MongoClient(MONGO_URL)
    collection = client[DB_NAME]["ai_audit_messages"]
    yield collection
    client.close()


@pytest.fixture(scope="module")
def review_payload() -> dict[str, Any]:
    deterministic_result: dict[str, Any] = {
        "mode": "transaction",
        "status": "REVIEW",
        "score": 0,
        "audit": {
            "expectedSpend": None,
            "expectedVault": None,
            "issues": ["Invalid JSON: deterministic test payload"],
        },
        "report": "Invalid JSON: deterministic test payload",
    }
    return {
        "payload": {"broken": True, "reason": "deterministic review check"},
        "deterministic_result": deterministic_result,
        "report": deterministic_result["report"],
    }


@pytest.fixture(scope="module")
def ai_stream_result(
    api_base_url: str,
    review_payload: dict[str, Any],
) -> dict[str, Any]:
    before = datetime.now(timezone.utc).isoformat()
    response = post_ai_audit(api_base_url, review_payload)
    events = parse_sse_events(response)
    done = find_done_event(events)
    return {
        "before": before,
        "response": response,
        "events": events,
        "session_id": done.get("session_id"),
    }


@pytest.fixture(scope="module")
def persisted_docs(
    mongo_collection: Any,
    ai_stream_result: dict[str, Any],
) -> list[dict[str, Any]]:
    session_id = ai_stream_result["session_id"]
    return list(mongo_collection.find({"session_id": session_id}, {"_id": 0}))


def post_ai_audit(
    api_base_url: str,
    payload: dict[str, Any],
) -> requests.Response:
    return requests.post(
        f"{api_base_url}/api/ai/audit",
        json=payload,
        stream=True,
        timeout=120,
    )


def parse_sse_events(response: requests.Response) -> list[SseEvent]:
    events: list[SseEvent] = []
    for raw_line in response.iter_lines(decode_unicode=True):
        if not is_sse_data_line(raw_line):
            continue
        event = json.loads(raw_line[6:])
        if event.get("error"):
            pytest.fail(f"AI stream returned error event: {event['error']}")
        events.append(event)
        if is_done_event(event):
            break
    return events


def is_sse_data_line(raw_line: str | bytes | None) -> bool:
    return isinstance(raw_line, str) and raw_line.startswith("data: ")


def is_done_event(event: SseEvent) -> bool:
    return event.get("done") == DONE_EVENT_VALUE


def find_done_event(events: list[SseEvent]) -> SseEvent:
    for event in events:
        if is_done_event(event):
            return event
    pytest.fail("AI stream did not include a done event")


def delta_events(events: list[SseEvent]) -> list[SseEvent]:
    return [event for event in events if event.get("delta")]


def docs_with_role(
    docs: list[dict[str, Any]],
    role: str,
) -> list[dict[str, Any]]:
    return [doc for doc in docs if doc.get("role") == role]


def test_health_ok(api_base_url: str) -> None:
    response = requests.get(f"{api_base_url}/api/health", timeout=15)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "watch-dawg-ai"


def test_ai_audit_returns_sse_response(
    ai_stream_result: dict[str, Any],
) -> None:
    response = ai_stream_result["response"]

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")


def test_ai_audit_streams_delta_events(
    ai_stream_result: dict[str, Any],
) -> None:
    assert delta_events(ai_stream_result["events"])


def test_ai_audit_streams_done_session_id(
    ai_stream_result: dict[str, Any],
) -> None:
    session_id = ai_stream_result["session_id"]

    assert isinstance(session_id, str)
    assert session_id.startswith("watch-dawg-")


def test_ai_stream_contains_no_error_events(
    ai_stream_result: dict[str, Any],
) -> None:
    assert not [
        event for event in ai_stream_result["events"] if event.get("error")
    ]


def test_ai_request_creates_mongo_records(
    persisted_docs: list[dict[str, Any]],
) -> None:
    assert len(persisted_docs) >= 2


def test_ai_user_message_persisted(
    persisted_docs: list[dict[str, Any]],
) -> None:
    user_docs = docs_with_role(persisted_docs, "user")

    assert len(user_docs) == 1
    assert (
        "Analyze this Watch-Dawg deterministic audit result"
        in user_docs[0]["content"]
    )


def test_ai_assistant_message_persisted(
    persisted_docs: list[dict[str, Any]],
) -> None:
    assistant_docs = docs_with_role(persisted_docs, "assistant")

    assert len(assistant_docs) == 1
    assert len(assistant_docs[0]["content"]) > 0


def test_ai_stored_field_values(
    persisted_docs: list[dict[str, Any]],
    ai_stream_result: dict[str, Any],
) -> None:
    session_id = ai_stream_result["session_id"]
    before = ai_stream_result["before"]

    for doc in persisted_docs:
        assert doc.get("session_id") == session_id
        assert doc.get("role") in {"user", "assistant"}
        assert doc.get("created_at")
        assert doc.get("created_at") >= before
        assert isinstance(doc.get("content"), str)
        assert len(doc.get("content", "")) > 0
