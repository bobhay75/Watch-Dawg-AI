"""API regression tests for health and AI audit streaming + persistence."""

import json
import os
from datetime import datetime, timezone

import pytest
import requests
from pymongo import MongoClient


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME")


@pytest.fixture(scope="session")
def api_base_url():
    if not BASE_URL:
        pytest.skip("REACT_APP_BACKEND_URL is not set")
    return BASE_URL.rstrip("/")


@pytest.fixture(scope="session")
def mongo_collection():
    if not MONGO_URL or not DB_NAME:
        pytest.skip("MONGO_URL or DB_NAME is not set")
    client = MongoClient(MONGO_URL)
    collection = client[DB_NAME]["ai_audit_messages"]
    yield collection
    client.close()


@pytest.fixture
def review_payload():
    deterministic_result = {
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


def test_health_ok(api_base_url):
    """Health endpoint basic status and payload shape."""
    response = requests.get(f"{api_base_url}/api/health", timeout=15)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "watch-dawg-ai"


def test_ai_audit_sse_stream_and_done_event(api_base_url, review_payload):
    """AI audit should stream SSE deltas and finish with done event + session id."""
    response = requests.post(
        f"{api_base_url}/api/ai/audit",
        json=review_payload,
        stream=True,
        timeout=120,
    )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")

    saw_delta = False
    saw_done = False
    session_id = None

    for raw_line in response.iter_lines(decode_unicode=True):
        if not raw_line or not raw_line.startswith("data: "):
            continue

        payload = json.loads(raw_line[6:])
        if payload.get("delta"):
            saw_delta = True
        if payload.get("done") is True:
            saw_done = True
            session_id = payload.get("session_id")
            break
        if payload.get("error"):
            pytest.fail(f"AI stream returned error event: {payload['error']}")

    assert saw_delta is True
    assert saw_done is True
    assert isinstance(session_id, str)
    assert session_id.startswith("watch-dawg-")


def test_ai_messages_persisted_to_mongodb(api_base_url, mongo_collection, review_payload):
    """AI request/response messages should persist in ai_audit_messages collection."""
    before = datetime.now(timezone.utc).isoformat()
    response = requests.post(
        f"{api_base_url}/api/ai/audit",
        json=review_payload,
        stream=True,
        timeout=120,
    )

    assert response.status_code == 200

    session_id = None
    for raw_line in response.iter_lines(decode_unicode=True):
        if not raw_line or not raw_line.startswith("data: "):
            continue
        payload = json.loads(raw_line[6:])
        if payload.get("done") is True:
            session_id = payload.get("session_id")
            break
        if payload.get("error"):
            pytest.fail(f"AI stream returned error event: {payload['error']}")

    assert isinstance(session_id, str)

    docs = list(mongo_collection.find({"session_id": session_id}, {"_id": 0}))
    assert len(docs) >= 2

    roles = {doc.get("role") for doc in docs}
    assert "user" in roles
    assert "assistant" in roles or "system" in roles

    for doc in docs:
        assert doc.get("created_at")
        assert doc.get("created_at") >= before
        assert isinstance(doc.get("content"), str)
        assert len(doc.get("content")) > 0
