"""Security boundary tests use fake credentials and no live providers."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone, timedelta
import json
import logging

from fastapi.testclient import TestClient
import pytest

from backend.providers import SyntheticProvider
from backend.security import LOG, Limited, Policy, private_bytes, secret_value
from backend.server import Settings, create_app
from backend.tests.security_helpers import (
    TOKEN,
    READ_TOKEN,
    ROTATED_TOKEN,
    MemorySecurityStore,
    unit_policy,
    policy_document,
)
from backend.tests.test_backend_migration_contract import MemoryStore, payload


def client_for(policy=None, storage=None, peer="127.0.0.1", provider=None):
    store = MemoryStore()
    app = create_app(
        Settings("", "", test_mode=True),
        store,
        provider or SyntheticProvider(),
        policy=policy or unit_policy(),
        security_store=storage or MemorySecurityStore(),
    )
    return (
        app,
        store,
        TestClient(app, client=(peer, 1234), raise_server_exceptions=False),
    )


def headers(token=TOKEN):
    return {"Authorization": "Bearer " + token}


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Basic abc",
        "Bearer short",
        "Bearer  " + TOKEN,
        "Bearer " + "x" * 48,
    ],
)
def test_unauthorized_requests_do_not_parse_store_or_call_provider(
    authorization,
):
    _, store, context = client_for()
    with context as client:
        hdrs = (
            {} if authorization is None else {"Authorization": authorization}
        )
        response = client.post(
            "/api/ai/audit", content=b"{bad secret", headers=hdrs
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert store.rows == []
        assert client.get("/api/health").status_code == 401


def test_scopes_cannot_be_escalated_by_headers_body_or_query():
    _, store, context = client_for()
    with context as client:
        assert (
            client.get("/api/health", headers=headers(READ_TOKEN)).status_code
            == 200
        )
        attack = dict(
            payload(),
            scopes=["audit:run"],
            role="admin",
            publication_approved=True,
        )
        response = client.post(
            "/api/ai/audit?role=admin",
            json=attack,
            headers=dict(
                headers(READ_TOKEN),
                **{"X-Role": "admin", "X-Scopes": "audit:run"}
            ),
        )
        assert response.status_code == 403
        assert store.rows == []
        for path in ["/api/publish", "/api/approve", "/docs", "/openapi.json"]:
            assert client.post(path, headers=headers()).status_code == 404
        assert (
            client.post(
                "/api/ai/audit", json=payload(), headers=headers()
            ).status_code
            == 200
        )


def test_expired_token_rejected_and_rotation_shares_principal_budget():
    p = unit_policy()
    expired = replace(
        p.principals[0],
        expires=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    _, _, context = client_for(replace(p, principals=(expired,)))
    with context as client:
        assert client.get("/api/health", headers=headers()).status_code == 401
    _, _, context = client_for(replace(p, principal_limit=1))
    with context as client:
        assert client.get("/api/health", headers=headers()).status_code == 200
        response = client.get(
            "/api/health?different=1", headers=headers(ROTATED_TOKEN)
        )
        assert response.status_code == 429
        assert int(response.headers["retry-after"]) > 0


def test_forwarded_ip_and_rotated_credentials_do_not_bypass_peer_limit():
    _, _, context = client_for(replace(unit_policy(), network_limit=1))
    with context as client:
        assert client.get("/api/health", headers=headers()).status_code == 200
        response = client.get(
            "/api/health",
            headers=dict(
                headers(READ_TOKEN),
                **{
                    "X-Forwarded-For": "203.0.113.1",
                    "X-Real-IP": "203.0.113.2",
                    "Forwarded": "for=203.0.113.3",
                    "User-Agent": "new-agent",
                }
            ),
        )
        assert response.status_code == 429


def test_global_budget_is_shared_across_clients_and_apps():
    store = MemorySecurityStore()
    policy = replace(unit_policy(), global_limit=2)
    _, _, first = client_for(policy, store)
    _, _, second = client_for(policy, store)
    with first as a, second as b:
        assert a.get("/api/health").status_code == 401
        assert b.get("/api/health", headers=headers()).status_code == 200
        assert (
            a.get("/api/health", headers=headers(READ_TOKEN)).status_code
            == 429
        )


@pytest.mark.parametrize(
    "peer,host,origin",
    [
        ("203.0.113.1", "testserver", None),
        ("127.0.0.1", "evil.invalid", None),
        ("127.0.0.1", "testserver", "https://evil.invalid"),
        ("127.0.0.1", "testserver", "null"),
    ],
)
def test_network_host_and_origin_restrictions(peer, host, origin):
    _, store, context = client_for(peer=peer)
    with context as client:
        h = dict(headers(), Host=host)
        if origin:
            h["Origin"] = origin
        assert client.post(
            "/api/ai/audit", json=payload(), headers=h
        ).status_code in {400, 403}
        assert store.rows == []


def test_duplicate_credentials_and_bad_host_are_rejected():
    _, store, context = client_for()
    with context as client:
        response = client.post(
            "/api/ai/audit",
            content=b"{}",
            headers=[
                ("authorization", "Bearer " + TOKEN),
                ("authorization", "Bearer " + READ_TOKEN),
            ],
        )
        assert response.status_code == 400
        assert (
            client.get(
                "/api/health", headers=dict(headers(), Host="localhost:bad")
            ).status_code
            == 400
        )
        assert store.rows == []


def test_restricted_preflight_and_actual_cors_headers():
    _, _, context = client_for()
    with context as client:
        preflight = {
            "Origin": "https://synthetic.invalid",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        }
        assert (
            client.options("/api/ai/audit", headers=preflight).status_code
            == 204
        )
        preflight["Access-Control-Request-Headers"] = "X-Role"
        assert (
            client.options("/api/ai/audit", headers=preflight).status_code
            == 403
        )
        response = client.post(
            "/api/ai/audit",
            json=payload(),
            headers=dict(headers(), Origin="https://synthetic.invalid"),
        )
        assert (
            response.headers["access-control-allow-origin"]
            == "https://synthetic.invalid"
        )
        assert "access-control-allow-credentials" not in response.headers
        assert response.headers["cache-control"] == "no-store"


def test_https_and_proxy_trust_cannot_be_spoofed():
    import ipaddress

    policy = replace(unit_policy(), transport="https")
    _, _, context = client_for(policy)
    with context as client:
        assert (
            client.get(
                "/api/health",
                headers=dict(headers(), **{"X-Forwarded-Proto": "https"}),
            ).status_code
            == 403
        )
    policy = replace(
        policy,
        transport="proxy",
        proxies=(ipaddress.ip_network("127.0.0.2/32"),),
    )
    _, _, context = client_for(policy)
    with context as client:
        assert (
            client.get(
                "/api/health",
                headers=dict(headers(), **{"X-Forwarded-Proto": "https"}),
            ).status_code
            == 403
        )
    policy = replace(policy, proxies=(ipaddress.ip_network("127.0.0.1/32"),))
    _, _, context = client_for(policy)
    with context as client:
        assert (
            client.get(
                "/api/health",
                headers=dict(headers(), **{"X-Forwarded-Proto": "https"}),
            ).status_code
            == 200
        )


def test_rate_store_outage_fails_closed_before_evidence_write():
    store = MemorySecurityStore()

    async def fail(*args):
        raise RuntimeError("sensitive connection string")

    store.take = fail
    _, evidence, context = client_for(storage=store)
    with context as client:
        response = client.post(
            "/api/ai/audit", json=payload(), headers=headers()
        )
        assert response.status_code == 503
        assert "sensitive" not in response.text
        assert evidence.rows == []


def test_concurrent_stream_admission_and_release():
    async def run():
        from backend.security import Security

        policy = replace(unit_policy(), global_streams=1, principal_streams=1)
        storage = MemorySecurityStore()
        security = Security(policy, storage)
        principal = policy.principals[0]
        first = await security.reserve(principal)
        with pytest.raises(Limited):
            await security.reserve(principal)
        await security.release(first)
        second = await security.reserve(principal)
        await security.release(second)
        assert storage.leases == {}

    asyncio.run(run())


def test_private_audit_logs_do_not_include_secrets_or_request_data(caplog):
    LOG.addHandler(caplog.handler)
    try:
        caplog.set_level(logging.INFO, logger=LOG.name)
        _, _, context = client_for()
        with context as client:
            client.post(
                "/api/ai/audit?private_query=secret",
                json=dict(payload(), payload="synthetic-private-site"),
                headers=dict(
                    headers(), **{"X-Request-ID": "client-injected-secret"}
                ),
            )
            client.get("/private-secret-path", headers=headers())
        records = [
            json.loads(r.message) for r in caplog.records if r.name == LOG.name
        ]
        assert any(r.get("outcome") == "completed" for r in records)
        text = json.dumps(records)
        for private in [
            TOKEN,
            "synthetic-private-site",
            "private_query",
            "private-secret-path",
            "client-injected-secret",
            "127.0.0.1",
        ]:
            assert private not in text
        assert all(len(r["request_id"]) == 32 for r in records)
    finally:
        LOG.removeHandler(caplog.handler)


def test_secret_permissions_symlinks_and_ambiguous_sources(
    tmp_path, monkeypatch
):
    secret = tmp_path / "secret"
    secret.write_text("synthetic-secret")
    secret.chmod(0o600)
    assert private_bytes(secret) == b"synthetic-secret"
    monkeypatch.setenv("LLM_API_KEY_FILE", str(secret))
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    assert secret_value("LLM_API_KEY") == "synthetic-secret"
    monkeypatch.setenv("LLM_API_KEY", "another-secret")
    with pytest.raises(ValueError):
        secret_value("LLM_API_KEY")
    secret.chmod(0o644)
    with pytest.raises(ValueError):
        private_bytes(secret)
    secret.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(secret)
    with pytest.raises(OSError):
        private_bytes(link)


@pytest.mark.parametrize(
    "change",
    [
        {"principals": []},
        {"allowed_hosts": ["*"]},
        {"allowed_networks": ["0.0.0.0/0"]},
        {"allowed_origins": ["*"]},
        {"transport": "proxy"},
        {"rates": {"principal_limit": 0}},
    ],
)
def test_invalid_policy_cannot_start(change):
    doc = policy_document()
    doc.update(change)
    with pytest.raises(ValueError):
        Policy.parse(doc)


def test_publication_scope_is_never_a_valid_privilege():
    doc = policy_document()
    doc["principals"][0]["scopes"].append("intelligence:publish")
    with pytest.raises(ValueError):
        Policy.parse(doc)


def test_missing_policy_and_test_transport_in_production_fail_closed():
    with pytest.raises(ValueError):
        Policy.load("")
    with pytest.raises(ValueError, match="synthetic"):
        with TestClient(
            create_app(
                Settings("", ""),
                MemoryStore(),
                SyntheticProvider(),
                policy=unit_policy(),
                security_store=MemorySecurityStore(),
            )
        ):
            pass


def test_bootstrap_utility_creates_private_files_without_printing_token(
    tmp_path,
):
    import hashlib
    import subprocess
    import sys
    from pathlib import Path

    output = tmp_path / "private"
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts/create_backend_security.py"
    )
    command = [
        sys.executable,
        str(script),
        "--output-dir",
        str(output),
        "--principal",
        "synthetic-bootstrap",
        "--scope",
        "health:read",
        "--host",
        "localhost",
        "--network",
        "127.0.0.1/32",
        "--transport",
        "loopback",
    ]
    result = subprocess.run(
        command, check=True, capture_output=True, text=True
    )
    token = (output / "token").read_text().strip()
    loaded = Policy.load(output / "security.json")
    assert loaded.authenticate("Bearer " + token).scopes == {"health:read"}
    assert token not in result.stdout + result.stderr
    assert (
        hashlib.sha256(token.encode()).hexdigest()
        in (output / "security.json").read_text()
    )
    assert (output / "token").stat().st_mode & 0o777 == 0o600
    assert (output / "security.json").stat().st_mode & 0o777 == 0o600
    original = (output / "token").read_bytes()
    refused = subprocess.run(command, capture_output=True)
    assert refused.returncode == 1
    assert (output / "token").read_bytes() == original


def test_deeply_nested_malformed_json_is_rejected_without_evidence():
    _, store, context = client_for()
    with context as client:
        response = client.post(
            "/api/ai/audit",
            content=b"[" * 10000 + b"]" * 10000,
            headers=dict(headers(), **{"Content-Type": "application/json"}),
        )
        assert response.status_code in {400, 422}
        assert store.rows == []


def test_unhandled_private_exception_is_not_returned_or_server_logged(caplog):
    app, store, context = client_for()

    # Force an unhandled failure before response headers in the existing route.
    class BrokenProvider:
        @property
        def ready(self):
            raise RuntimeError("synthetic-credential-and-private-data")

    with context as client:
        app.state.provider = BrokenProvider()
        response = client.post(
            "/api/ai/audit", json=payload(), headers=headers()
        )
        assert response.status_code == 500
        assert "synthetic-credential" not in response.text + caplog.text
        assert store.rows == []


def test_test_transport_cannot_start_against_an_ordinary_database():
    config = Settings(
        "mongodb://unused.invalid",
        "production",
        provider="synthetic",
        test_mode=True,
    )
    with pytest.raises(ValueError, match="disposable"):
        with TestClient(create_app(config, policy=unit_policy())):
            pass


def test_stream_failures_release_admission_leases():
    app, store, context = client_for()
    with context as client:

        async def failed(*args):
            yield "synthetic partial"
            raise RuntimeError("private exception text")

        app.state.provider.stream = failed
        response = client.post(
            "/api/ai/audit", json=payload(), headers=headers()
        )
        assert '"error"' in response.text
        assert app.state.security.store.leases == {}
        assert not any(row["role"] == "assistant" for row in store.rows)


def test_cancellation_during_reservation_releases_acquired_slots():
    from backend.security import Security

    class CancelStore(MemorySecurityStore):
        async def acquire(self, key, limit, seconds):
            if self.leases:
                raise asyncio.CancelledError
            return await super().acquire(key, limit, seconds)

    async def run():
        policy = unit_policy()
        storage = CancelStore()
        security = Security(policy, storage)
        with pytest.raises(asyncio.CancelledError):
            await security.reserve(policy.principals[0])
        assert storage.leases == {}

    asyncio.run(run())


def test_host_with_empty_userinfo_is_not_an_allowed_authority():
    _, store, context = client_for()
    with context as client:
        for host in ("@testserver", ":@testserver"):
            response = client.post(
                "/api/ai/audit",
                json=payload(),
                headers=dict(headers(), Host=host),
            )
            assert response.status_code == 400
        assert store.rows == []


def test_cancelled_initial_write_releases_stream_slots():
    from types import SimpleNamespace
    from backend.server import AIAnalyzeRequest

    app, store, context = client_for()
    with context:

        async def cancel(*args):
            raise asyncio.CancelledError

        store.append = cancel
        endpoint = next(
            r.endpoint for r in app.routes if r.path == "/api/ai/audit"
        )
        principal = app.state.security.policy.principals[0]
        request = SimpleNamespace(
            state=SimpleNamespace(
                principal=principal,
                security=app.state.security,
                request_id="a" * 32,
            )
        )

        async def run():
            with pytest.raises(asyncio.CancelledError):
                await endpoint(AIAnalyzeRequest(**payload()), request)
            assert app.state.security.store.leases == {}

        asyncio.run(run())


@pytest.mark.parametrize(
    "origin",
    [
        "https://@synthetic.invalid",
        "https://:@synthetic.invalid",
    ],
)
def test_empty_userinfo_is_not_a_valid_origin_configuration(origin):
    doc = policy_document()
    doc["allowed_origins"] = [origin]
    with pytest.raises(ValueError):
        Policy.parse(doc)
