"""MongoDB/HTTP contracts on the disposable runner's loopback test DB."""

from concurrent.futures import ThreadPoolExecutor
import os
from urllib.parse import urlsplit
import uuid

from fastapi.testclient import TestClient
from pymongo import MongoClient
import pytest
import requests

from backend.server import create_app, Settings


@pytest.fixture
def database():
    uri = os.getenv("MONGO_URL", "")
    name = os.getenv("DB_NAME", "")
    if not uri or not name:
        if os.getenv("WATCHDAWG_REQUIRE_INTEGRATION") == "true":
            pytest.fail("Disposable database is required")
        pytest.skip(
            "Run scripts/test_backend_disposable.py for real MongoDB tests"
        )
    if (
        os.getenv("WATCHDAWG_TEST_MODE") != "true"
        or urlsplit(uri).hostname not in {"127.0.0.1", "localhost"}
        or not os.getenv("WATCHDAWG_DISPOSABLE_RUN")
        or name
        != "watchdawg_test_" + os.getenv("WATCHDAWG_DISPOSABLE_RUN", "")
    ):
        pytest.fail("Only the disposable runner database is allowed")
    with MongoClient(uri, serverSelectionTimeoutMS=2000) as client:
        yield client[name]


def payload():
    return {
        "payload": {"synthetic": True},
        "deterministic_result": {"status": "REVIEW"},
        "report": "Synthetic data only",
    }


def api_url():
    value = os.environ["REACT_APP_BACKEND_URL"]
    assert urlsplit(value).hostname in {"127.0.0.1", "localhost"}
    return value


def test_concurrent_sessions_are_independent(database):
    def request(_):
        response = requests.post(
            api_url() + "/api/ai/audit", json=payload(), timeout=15
        )
        assert response.status_code == 200
        import json

        return [
            json.loads(line[6:])
            for line in response.text.splitlines()
            if line.startswith("data: ")
        ][-1]["session_id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        sessions = list(pool.map(request, range(8)))
    assert len(set(sessions)) == 8
    for session in sessions:
        rows = list(database.ai_audit_messages.find({"session_id": session}))
        assert [row["role"] for row in rows] == ["user", "assistant"]
        assert all(row["created_at"].endswith("+00:00") for row in rows)


def test_real_insert_failure_partial_stream_and_recovery(database):
    # Affect only this runner's disposable database, never an operator-
    # provided DB.
    for rejected_role in ("user", "assistant"):
        database.command(
            "collMod",
            "ai_audit_messages",
            validator={"role": {"$ne": rejected_role}},
            validationLevel="strict",
        )
        try:
            response = requests.post(
                api_url() + "/api/ai/audit", json=payload(), timeout=15
            )
            if rejected_role == "user":
                assert response.status_code == 500
                assert (
                    response.json()["detail"] == "Audit storage is unavailable"
                )
            else:
                assert response.status_code == 200
                assert '"error"' in response.text
                assert '"done"' not in response.text
                assert database.ai_audit_messages.find_one(
                    {
                        "role": "system",
                        "content": (
                            "AI stream error: provider_or_storage_failure"
                        ),
                    }
                )
        finally:
            database.command(
                "collMod",
                "ai_audit_messages",
                validator={},
                validationLevel="off",
            )
        response = requests.post(
            api_url() + "/api/ai/audit", json=payload(), timeout=15
        )
        assert '"done": true' in response.text


def test_async_driver_lifecycle_reopens_without_changing_records(database):
    uri = os.environ["MONGO_URL"]
    name = os.environ["DB_NAME"]
    marker = "watchdawg-test-marker-" + uuid.uuid4().hex
    database.ai_audit_messages.insert_one(
        {"session_id": marker, "role": "synthetic-marker"}
    )
    for _ in range(2):
        config = Settings(uri, name, provider="synthetic", test_mode=True)
        with TestClient(create_app(config)) as client:
            assert client.get("/api/health").status_code == 200
            assert (
                '"done": true'
                in client.post("/api/ai/audit", json=payload()).text
            )
    assert (
        database.ai_audit_messages.count_documents({"session_id": marker}) == 1
    )


def test_unavailable_database_fails_startup():
    import socket
    from pymongo.errors import ServerSelectionTimeoutError

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        # Keep the port reserved but not listening: there is no
        # external target.
        config = Settings(
            "mongodb://127.0.0.1:" + str(sock.getsockname()[1]),
            "watchdawg_test_unavailable",
            provider="synthetic",
            test_mode=True,
        )
        with pytest.raises(ServerSelectionTimeoutError):
            with TestClient(create_app(config)):
                pass
