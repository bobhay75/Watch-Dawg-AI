"""Real ASGI routes with synthetic provider/storage; no service access.

These tests gate framework migrations, not MongoDB or vendor SDK compatibility.
"""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from backend.server import create_app, Settings
from backend.providers import SyntheticProvider


class MemoryStore:
    def __init__(self):
        self.rows = []

    async def append(self, session_id, role, content):
        self.rows.append(
            {
                "session_id": session_id,
                "role": role,
                "content": content,
                "created_at": "2026-11-17T00:00:00+00:00",
            }
        )


@pytest.fixture
def service():
    store = MemoryStore()
    provider = SyntheticProvider()
    app = create_app(Settings("", ""), store, provider)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield app, client, store.rows


def payload():
    return {
        "payload": {"synthetic": True},
        "deterministic_result": {"status": "REVIEW"},
        "report": "Synthetic review",
    }


def events(response):
    return [
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]


def test_health_stream_and_persistence_contract(service):
    _, client, rows = service
    assert client.get("/api/health").json()["status"] == "ok"
    response = client.post("/api/ai/audit", json=payload())
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    result = events(response)
    assert result[0]["delta"].startswith("SYNTHETIC TEST OUTPUT")
    assert result[-1]["done"] is True
    assert [row["role"] for row in rows] == ["user", "assistant"]
    assert {row["session_id"] for row in rows} == {result[-1]["session_id"]}
    assert all(row["created_at"].endswith("+00:00") for row in rows)
    assert rows[-1]["content"] == "".join(
        e["delta"] for e in result if "delta" in e
    )


def test_validation_and_missing_key_do_not_write(service, monkeypatch):
    module, client, rows = service
    assert client.post("/api/ai/audit", json={}).status_code == 422
    assert (
        client.post(
            "/api/ai/audit", json=dict(payload(), report="x" * 12001)
        ).status_code
        == 422
    )
    monkeypatch.setattr(module.state.provider, "ready", False)
    assert client.post("/api/ai/audit", json=payload()).status_code == 500
    assert rows == []


def test_provider_error_is_not_done_or_disclosed_to_client(
    service, monkeypatch
):
    module, client, rows = service

    def fail(*args):
        raise RuntimeError("synthetic-sensitive-detail")

    monkeypatch.setattr(module.state.provider, "stream", fail)
    response = client.post("/api/ai/audit", json=payload())
    assert "synthetic-sensitive-detail" not in response.text
    assert any("error" in event for event in events(response))
    assert not any(event.get("done") for event in events(response))
    assert [row["role"] for row in rows] == ["user", "system"]
    assert "synthetic-sensitive-detail" not in json.dumps(rows)
    assert (
        rows[-1]["content"] == "AI stream error: provider_or_storage_failure"
    )


def test_initial_storage_failure_cannot_claim_success(service, monkeypatch):
    module, client, _ = service

    async def fail(*args):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(module.state.store, "append", fail)
    assert client.post("/api/ai/audit", json=payload()).status_code == 500


def test_partial_failure_and_error_storage_failure_never_claim_done(
    service, monkeypatch
):
    app, client, rows = service

    async def broken(*args):
        yield "partial synthetic"
        raise RuntimeError("secret-key synthetic-sensitive-detail")

    monkeypatch.setattr(app.state.provider, "stream", broken)
    response = client.post("/api/ai/audit", json=payload())
    result = events(response)
    assert result[0]["delta"] == "partial synthetic"
    assert result[-1].get("error")
    assert not any(row.get("done") for row in result)
    assert "secret-key" not in json.dumps(rows) + response.text
    assert not any(row["role"] == "assistant" for row in rows)

    original = app.state.store.append

    async def storage_failure(session, role, content):
        if role != "user":
            raise RuntimeError("storage-secret")
        await original(session, role, content)

    monkeypatch.setattr(app.state.store, "append", storage_failure)
    response = client.post("/api/ai/audit", json=payload())
    assert events(response)[-1].get("error")
    assert "storage-secret" not in response.text


def test_stream_cancellation_closes_provider_without_assistant_record():
    from backend.server import stream_ai_audit_events

    closed = []

    class SlowProvider:
        async def stream(self, *args):
            try:
                yield "synthetic partial"
                await asyncio.sleep(100)
            finally:
                closed.append(True)

    async def run():
        store = MemoryStore()
        stream = stream_ai_audit_events(SlowProvider(), store, "test", "test")
        assert "delta" in await anext(stream)
        task = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert store.rows == []
        assert closed == [True]

    asyncio.run(run())


def test_oversized_and_chunked_json_are_rejected_before_storage(service):
    _, client, rows = service
    assert (
        client.post(
            "/api/ai/audit", json=dict(payload(), payload="x" * 262144)
        ).status_code
        == 413
    )
    chunks = (b"x" * 100000 for _ in range(3))
    assert (
        client.post(
            "/api/ai/audit",
            content=chunks,
            headers={"content-type": "application/json"},
        ).status_code
        == 413
    )
    assert rows == []
    assert (
        client.post(
            "/api/ai/audit",
            content=b"{bad",
            headers={"content-type": "application/json"},
        ).status_code
        == 422
    )
    assert rows == []


def test_prompt_limits_and_cors_behavior_are_preserved(service):
    app, client, rows = service
    response = client.options(
        "/api/ai/audit",
        headers={
            "origin": "https://synthetic.invalid",
            "access-control-request-method": "POST",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in response.headers
    data = payload()
    data["payload"] = "x" * 10000
    data["report"] = "r" * 10000
    assert client.post("/api/ai/audit", json=data).status_code == 200
    assert len(rows[0]["content"]) < 20000


def test_closing_response_after_first_delta_closes_provider():
    from backend.server import stream_ai_audit_events

    closed = []

    class Provider:
        async def stream(self, *args):
            try:
                yield "synthetic partial"
                yield "never committed"
            finally:
                closed.append(True)

    async def run():
        store = MemoryStore()
        stream = stream_ai_audit_events(Provider(), store, "test", "test")
        await anext(stream)
        await stream.aclose()
        assert closed == [True]
        assert store.rows == []

    asyncio.run(run())
