"""Real ASGI routes with synthetic provider/storage boundaries; no service access.

These tests gate framework migrations, not MongoDB or vendor SDK compatibility.
"""
import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def service(monkeypatch):
    rows = []

    class Collection:
        async def insert_one(self, doc):
            rows.append(doc)

    class Client:
        def __init__(self, *args):
            pass

        def __getitem__(self, name):
            return types.SimpleNamespace(ai_audit_messages=Collection())

    class Message:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class TextDelta(Message):
        pass

    class StreamDone:
        pass

    class Chat:
        def __init__(self, **kwargs):
            pass

        def with_model(self, *args):
            return self

        async def stream_message(self, message):
            yield TextDelta(content='Synthetic review')
            yield StreamDone()

    for name in ('motor', 'motor.motor_asyncio', 'emergentintegrations',
                 'emergentintegrations.llm', 'emergentintegrations.llm.chat', 'dotenv'):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setattr(sys.modules['motor.motor_asyncio'], 'AsyncIOMotorClient', Client, raising=False)
    vendor = sys.modules['emergentintegrations.llm.chat']
    for name, value in dict(LlmChat=Chat, TextDelta=TextDelta, StreamDone=StreamDone, UserMessage=Message).items():
        setattr(vendor, name, value)
    sys.modules['dotenv'].load_dotenv = lambda *args: None
    for key, value in dict(MONGO_URL='mongodb://synthetic.invalid', DB_NAME='synthetic', EMERGENT_LLM_KEY='synthetic').items():
        monkeypatch.setenv(key, value)
    spec = importlib.util.spec_from_file_location('migration_contract_backend', Path(__file__).parents[1] / 'server.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app, raise_server_exceptions=False) as client:
        yield module, client, rows


def payload():
    return {'payload': {'synthetic': True}, 'deterministic_result': {'status': 'REVIEW'}, 'report': 'Synthetic review'}


def events(response):
    return [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ')]


def test_health_stream_and_persistence_contract(service):
    _, client, rows = service
    assert client.get('/api/health').json()['status'] == 'ok'
    response = client.post('/api/ai/audit', json=payload())
    assert response.status_code == 200
    assert response.headers['content-type'].startswith('text/event-stream')
    assert response.headers['cache-control'] == 'no-cache'
    result = events(response)
    assert result[0] == {'delta': 'Synthetic review'}
    assert result[-1]['done'] is True
    assert [row['role'] for row in rows] == ['user', 'assistant']
    assert {row['session_id'] for row in rows} == {result[-1]['session_id']}
    assert all(row['created_at'].endswith('+00:00') for row in rows)
    assert rows[-1]['content'] == 'Synthetic review'


def test_validation_and_missing_key_do_not_write(service, monkeypatch):
    module, client, rows = service
    assert client.post('/api/ai/audit', json={}).status_code == 422
    assert client.post('/api/ai/audit', json=dict(payload(), report='x'*12001)).status_code == 422
    monkeypatch.setattr(module, 'EMERGENT_LLM_KEY', None)
    assert client.post('/api/ai/audit', json=payload()).status_code == 500
    assert rows == []


def test_provider_error_is_not_done_or_disclosed_to_client(service, monkeypatch):
    module, client, rows = service

    def fail(*args):
        raise RuntimeError('synthetic-sensitive-detail')

    monkeypatch.setattr(module, 'build_chat_client', fail)
    response = client.post('/api/ai/audit', json=payload())
    assert 'synthetic-sensitive-detail' not in response.text
    assert any('error' in event for event in events(response))
    assert not any(event.get('done') for event in events(response))
    assert [row['role'] for row in rows] == ['user', 'system']


def test_initial_storage_failure_cannot_claim_success(service, monkeypatch):
    module, client, _ = service

    async def fail(**kwargs):
        raise RuntimeError('storage unavailable')

    monkeypatch.setattr(module, 'persist_ai_message', fail)
    assert client.post('/api/ai/audit', json=payload()).status_code == 500
