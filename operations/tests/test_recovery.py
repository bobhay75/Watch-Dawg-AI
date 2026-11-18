import json
import os
from pathlib import Path
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from backend.audit import AuditJournal, AuditUnavailable
from backend.server import create_app, Settings
from backend.providers import SyntheticProvider
from backend.tests.security_helpers import (
    TOKEN,
    policy_document,
    MemorySecurityStore,
)
from backend.tests.test_backend_migration_contract import MemoryStore
from operations.backups import backup, restore
from operations.cli import synthetic_drill
from operations.files import write_new, canonical, digest
from operations.tokens import prepare_rotation, stage_revocation, install
from operations.review_records import append, verify


def setup_archive(tmp_path):
    source = tmp_path / "evidence"
    source.mkdir(mode=0o700)
    write_new(
        source / "synthetic.json",
        b'{"synthetic":true,"public_release_approved":false}',
    )
    key = tmp_path / "key"
    write_new(key, secrets.token_bytes(32))
    encrypted = tmp_path / "archive.wdb"
    backup(source, key, encrypted)
    return source, key, encrypted


def test_encrypted_backup_restore_and_no_overwrite(tmp_path):
    source, key, encrypted = setup_archive(tmp_path)
    assert b"synthetic" not in encrypted.read_bytes()
    restored = tmp_path / "restored"
    restore(encrypted, key, restored, str(encrypted) + ".receipt.json")
    assert (restored / "synthetic.json").read_bytes() == (
        source / "synthetic.json"
    ).read_bytes()
    assert (restored / "synthetic.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        restore(encrypted, key, restored, str(encrypted) + ".receipt.json")
    with pytest.raises(FileExistsError):
        backup(source, key, encrypted)


def test_wrong_key_corruption_and_symlink_fail_without_restore(tmp_path):
    source, key, encrypted = setup_archive(tmp_path)
    wrong = tmp_path / "wrong"
    write_new(wrong, secrets.token_bytes(32))
    for candidate in (wrong, key):
        if candidate == key:
            raw = bytearray(encrypted.read_bytes())
            raw[-20] ^= 1
            encrypted.write_bytes(raw)
        target = tmp_path / "refused"
        with pytest.raises(Exception):
            restore(
                encrypted, candidate, target, str(encrypted) + ".receipt.json"
            )
        assert not target.exists()
    (source / "link").symlink_to(key)
    with pytest.raises((ValueError, OSError)):
        backup(source, key, tmp_path / "refused.wdb")


def test_synthetic_drill_is_self_contained(tmp_path):
    assert synthetic_drill(tmp_path)["synthetic_drill"] == "passed"
    assert list(tmp_path.iterdir()) == []


def test_backup_refuses_incomplete_directory_walk(tmp_path, monkeypatch):
    source, key, _ = setup_archive(tmp_path)
    unreadable = source / "unreadable"
    unreadable.mkdir()
    real_scandir = os.scandir

    def scandir(path):
        if path == str(unreadable):
            raise PermissionError("Cannot enumerate evidence directory")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    destination = tmp_path / "incomplete.wdb"
    with pytest.raises(PermissionError, match="Cannot enumerate"):
        backup(source, key, destination)
    assert not destination.exists()
    assert not destination.with_suffix(".wdb.receipt.json").exists()


def event():
    return {
        "event": "backend_request",
        "timestamp": "2026-11-17T00:00:00+00:00",
        "request_id": "a" * 32,
        "principal_ref": "anonymous",
        "route": "audit",
        "status": 401,
    }


def test_audit_rotation_capacity_retention_and_privacy(tmp_path):
    journal = AuditJournal(
        tmp_path, segment_bytes=1024, max_segments=2, min_free_bytes=0
    )
    try:
        for _ in range(6):
            journal.write(event())
        with pytest.raises(AuditUnavailable):
            for _ in range(10):
                journal.write(event())
        assert sum(p.stat().st_size for p in tmp_path.glob("audit-*")) <= 2048
        for p in tmp_path.glob("audit-*"):
            os.utime(p, (1, 1))
        journal.write(event())
        assert len(list(tmp_path.glob("audit-*"))) == 1
        with pytest.raises(AuditUnavailable):
            journal.write(dict(event(), token="private-secret"))
        assert all(
            "private-secret" not in p.read_text()
            for p in tmp_path.glob("audit-*")
        )
    finally:
        journal.close()
    # A fresh writer resumes the fsynced journal, not a new empty log.
    resumed = AuditJournal(tmp_path, min_free_bytes=0)
    resumed.write(event())
    resumed.close()


def test_audit_does_not_adopt_evidence_directory(tmp_path):
    write_new(tmp_path / "evidence.json", b"{}")
    with pytest.raises(AuditUnavailable):
        AuditJournal(tmp_path)
    assert (tmp_path / "evidence.json").read_bytes() == b"{}"


def test_live_rotation_revocation_and_bad_policy_fail_closed(tmp_path):
    policy = tmp_path / "security.json"
    write_new(policy, canonical(policy_document()))
    staged = tmp_path / "rotation"
    receipt = prepare_rotation(policy, "synthetic-analysis", staged)
    new_token = (staged / "token").read_text().strip()
    app = create_app(
        Settings("", "", test_mode=True, security_file=str(policy)),
        MemoryStore(),
        SyntheticProvider(),
        security_store=MemorySecurityStore(),
    )
    with TestClient(app, client=("127.0.0.1", 1)) as client:

        def call(token):
            return client.get(
                "/api/health", headers={"Authorization": "Bearer " + token}
            )

        assert call(TOKEN).status_code == 200
        install(staged / "overlap.json", policy, receipt["previous_sha256"])
        assert call(TOKEN).status_code == call(new_token).status_code == 200
        install(staged / "final.json", policy, receipt["overlap_sha256"])
        assert call(TOKEN).status_code == 401
        assert call(new_token).status_code == 200
        revoked = tmp_path / "revoked.json"
        stage_revocation(policy, "synthetic-analysis", revoked)
        install(revoked, policy, receipt["final_sha256"])
        assert call(new_token).status_code == 401
        changed = json.loads(policy.read_bytes())
        changed["allowed_hosts"].append("unexpected.invalid")
        policy.write_bytes(canonical(changed))
        assert call(new_token).status_code == 503
        policy.write_text("{broken")
        assert call(new_token).status_code == 503
        policy.unlink()
        assert call(new_token).status_code == 503


def test_stale_rotation_cannot_overwrite_new_policy(tmp_path):
    policy = tmp_path / "policy"
    write_new(policy, canonical(policy_document()))
    receipt = prepare_rotation(
        policy, "synthetic-analysis", tmp_path / "staged"
    )
    install(
        tmp_path / "staged/overlap.json", policy, receipt["previous_sha256"]
    )
    before = policy.read_bytes()
    with pytest.raises(ValueError):
        install(
            tmp_path / "staged/final.json", policy, receipt["previous_sha256"]
        )
    assert policy.read_bytes() == before


def test_signed_private_review_chain_and_no_publication(tmp_path):
    key = Ed25519PrivateKey.generate()
    registry = {"synthetic-reviewer": key.public_key().public_bytes_raw()}
    path = tmp_path / "reviews.jsonl"
    kwargs = dict(
        path=path,
        reviewer="synthetic-reviewer",
        private_key=key.private_bytes_raw(),
        reviewers=registry,
        evidence_sha256="a" * 64,
        note_sha256="b" * 64,
        decision="reviewed_private",
        human_confirmation="REVIEW " + "a" * 64,
    )
    append(**kwargs)
    append(**dict(kwargs, decision="needs_more_evidence"))
    rows = verify(path.read_bytes(), registry)
    assert len(rows) == 2
    head = digest(canonical(rows[-1]))
    assert verify(path.read_bytes(), registry, expected_head=head) == rows
    with pytest.raises(ValueError):
        verify(canonical(rows[0]) + b"\n", registry, expected_head=head)
    assert all(
        row["record"]["public_release_approved"] is False for row in rows
    )
    with pytest.raises(ValueError):
        append(**dict(kwargs, decision="publish"))
    with pytest.raises(ValueError):
        append(**dict(kwargs, human_confirmation=""))
    tampered = json.loads(path.read_bytes().splitlines()[0])
    tampered["record"]["public_release_approved"] = True
    with pytest.raises(Exception):
        verify(canonical(tampered) + b"\n", registry)
    with pytest.raises(Exception):
        verify(
            b"\n".join(reversed(path.read_bytes().splitlines())) + b"\n",
            registry,
        )


def test_audit_capacity_failure_blocks_work(tmp_path):
    from backend.tests.security_helpers import unit_policy

    directory = tmp_path / "audit"
    directory.mkdir(mode=0o700)
    store = MemoryStore()
    app = create_app(
        Settings(
            "",
            "",
            test_mode=True,
            audit_dir=str(directory),
            audit_segment_bytes=1024,
            audit_max_segments=2,
        ),
        store,
        SyntheticProvider(),
        policy=unit_policy(),
        security_store=MemorySecurityStore(),
    )
    with TestClient(app, client=("127.0.0.1", 1)) as client:
        while True:
            try:
                app.state.audit_sink.write(event())
            except AuditUnavailable:
                break
        response = client.post(
            "/api/ai/audit",
            json={
                "payload": {},
                "deterministic_result": {},
                "report": "synthetic",
            },
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert response.status_code == 503
        assert store.rows == []
        # Error responses must also fail safely if the journal is full.
        assert client.get("/api/health").status_code == 503


def test_forged_receipt_cannot_bypass_authenticated_encryption(tmp_path):
    from operations.files import digest

    _, key, encrypted = setup_archive(tmp_path)
    raw = bytearray(encrypted.read_bytes())
    raw[-20] ^= 1
    encrypted.write_bytes(raw)
    receipt = Path(str(encrypted) + ".receipt.json")
    data = json.loads(receipt.read_text())
    data["ciphertext_sha256"] = digest(raw)
    receipt.write_text(json.dumps(data))
    with pytest.raises(Exception):
        restore(encrypted, key, tmp_path / "never", receipt)
    assert not (tmp_path / "never").exists()


def test_concurrent_audit_writes_are_complete_and_bounded(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    journal = AuditJournal(
        tmp_path, segment_bytes=4096, max_segments=8, min_free_bytes=0
    )
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: journal.write(event()), range(40)))
    finally:
        journal.close()
    records = [
        json.loads(line)
        for file in tmp_path.glob("audit-*")
        for line in file.read_text().splitlines()
    ]
    assert len(records) == 40
    assert sum(p.stat().st_size for p in tmp_path.glob("audit-*")) <= 4096 * 8


def test_role_provisioning_validates_before_mutation():
    from operations.mongo_roles import provision, roles

    class Database:
        name = "synthetic_test"

        def command(self, *args, **kwargs):
            raise AssertionError("No partial provisioning on invalid input")

    with pytest.raises(ValueError):
        provision(Database(), {"watchdawg_app": "short"})
    documents = roles("synthetic_test")
    assert all(item["roles"] == [] for item in documents)
    assert documents[1]["privileges"][0]["actions"] == ["find"]
    with pytest.raises(ValueError):
        roles("admin.$cmd")


@pytest.mark.parametrize("member", ["../outside", "/absolute", "a\\escape"])
def test_authenticated_archive_still_rejects_unsafe_paths(tmp_path, member):
    import io
    import zipfile
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from operations.backups import MAGIC, MANIFEST

    key_bytes = secrets.token_bytes(32)
    key = tmp_path / "key"
    write_new(key, key_bytes)
    content = b"synthetic only"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        zipped.writestr(member, content)
        zipped.writestr(
            MANIFEST,
            canonical(
                {
                    "version": 1,
                    "public_release_approved": False,
                    "files": [
                        {
                            "path": member,
                            "bytes": len(content),
                            "sha256": digest(content),
                        }
                    ],
                }
            ),
        )
    nonce = secrets.token_bytes(12)
    archive = tmp_path / "archive"
    ciphertext = (
        MAGIC
        + nonce
        + AESGCM(key_bytes).encrypt(nonce, buffer.getvalue(), MAGIC)
    )
    write_new(archive, ciphertext)
    receipt = tmp_path / "receipt"
    write_new(receipt, canonical({"ciphertext_sha256": digest(ciphertext)}))
    with pytest.raises(ValueError):
        restore(archive, key, tmp_path / "restored", receipt)
    assert not (tmp_path / "restored").exists()
    assert not (tmp_path / "outside").exists()


def test_audit_partial_tail_fails_closed(tmp_path):
    journal = AuditJournal(tmp_path, min_free_bytes=0)
    journal.write(event())
    path = next(tmp_path.glob("audit-*.jsonl"))
    path.write_bytes(path.read_bytes()[:-1])
    try:
        with pytest.raises(AuditUnavailable):
            journal.write(event())
    finally:
        journal.close()


@pytest.mark.parametrize("rotation", ["size", "day", "expired"])
def test_audit_partial_tail_cannot_escape_through_rotation(tmp_path, rotation):
    journal = AuditJournal(tmp_path, segment_bytes=1024, min_free_bytes=0)
    journal.write(event())
    path = next(tmp_path.glob("audit-*.jsonl"))
    if rotation == "size":
        path.write_bytes(b"x" * 1023)
    else:
        path.write_bytes(path.read_bytes()[:-1])
        if rotation == "day":
            path = path.rename(
                tmp_path
                / ("audit-20000101000000000000-" + "a" * 32 + ".jsonl")
            )
        else:
            os.utime(path, (1, 1))
    before = path.read_bytes()
    try:
        with pytest.raises(AuditUnavailable):
            journal.write(event())
        assert path.read_bytes() == before
        assert len(list(tmp_path.glob("audit-*.jsonl"))) == 1
    finally:
        journal.close()
    with pytest.raises(AuditUnavailable):
        AuditJournal(tmp_path, segment_bytes=1024, min_free_bytes=0)


def test_compose_isolation_contract():
    import shutil
    import subprocess

    if not shutil.which("docker"):
        pytest.skip("Docker Compose configuration parser unavailable")
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-f",
            "deployment/secure/compose.yaml",
            "--profile",
            "local-replica",
            "config",
            "--format",
            "json",
        ],
        env={
            **os.environ,
            "WATCHDAWG_SECRETS": "/tmp/synthetic-secrets",
            "WATCHDAWG_AUDIT": "/tmp/synthetic-audit",
        },
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    config = json.loads(result.stdout)
    assert config["networks"]["api"]["internal"]
    assert config["networks"]["data"]["internal"]
    services = config["services"]
    assert set(services) == {"proxy", "backend", "mongo1", "mongo2", "mongo3"}
    for name, service in services.items():
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        if name != "proxy":
            assert not service.get("ports")
    assert services["proxy"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert (
        "watchdawg_backend"
        in services["backend"]["networks"]["api"]["aliases"]
    )
    command = services["backend"]["command"]
    assert command[command.index("--ssl-cert-reqs") + 1] == "2"
    assert "--no-proxy-headers" in command


def test_backup_cannot_write_inside_evidence(tmp_path):
    source, key, encrypted = setup_archive(tmp_path)
    before = sorted(p.name for p in source.iterdir())
    with pytest.raises(ValueError):
        backup(source, key, source / "recursive.wdb")
    assert sorted(p.name for p in source.iterdir()) == before


def test_backup_refuses_manifest_too_large_to_restore(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    nested = source / ("d" * 200)
    nested.mkdir(mode=0o700)
    # Within the 4096-file and 64 MiB limits, but long legal paths make
    # the manifest exceed the restore parser's separate 1 MiB limit.
    for index in range(2048):
        write_new(nested / (str(index).zfill(4) + "x" * 236), b"")
    key = tmp_path / "key"
    write_new(key, secrets.token_bytes(32))
    destination = tmp_path / "archive.wdb"
    with pytest.raises(ValueError, match="manifest"):
        backup(source, key, destination)
    assert not destination.exists()
    assert not Path(str(destination) + ".receipt.json").exists()


def test_response_audit_failure_releases_unstarted_stream_leases():
    from backend.tests.security_helpers import unit_policy

    class FailingResponseJournal:
        def write(self, row):
            if row["event"] == "backend_request":
                raise AuditUnavailable("synthetic response write failure")

    security_store = MemorySecurityStore()
    app = create_app(
        Settings("", "", test_mode=True),
        MemoryStore(),
        SyntheticProvider(),
        policy=unit_policy(),
        security_store=security_store,
    )
    with TestClient(app, client=("127.0.0.1", 1)) as client:
        app.state.audit_sink = FailingResponseJournal()
        response = client.post(
            "/api/ai/audit",
            json={
                "payload": {},
                "deterministic_result": {},
                "report": "synthetic",
            },
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert response.status_code == 503
        assert security_store.leases == {}
