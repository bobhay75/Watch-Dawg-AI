"""Offline staged rotation/revocation; no process restart or deployment
action.
"""

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile

from backend.security import Policy
from .files import (
    canonical,
    digest,
    read_private,
    private_directory,
    write_new,
)


def prepare_rotation(policy_file, principal_id, output):
    raw = read_private(policy_file)
    doc = json.loads(raw)
    policy = Policy.parse(doc)
    principal = next(p for p in policy.principals if p.name == principal_id)
    if (principal.expires - datetime.now(timezone.utc)).total_seconds() < 1800:
        raise ValueError("Insufficient existing expiry for a safe overlap")
    if len(principal.hashes) >= 4:
        raise ValueError("Overlap capacity exhausted")
    output = Path(output)
    directory = private_directory(output, create=True)
    os.close(directory)
    token = "wd_" + secrets.token_urlsafe(32)
    new_hash = hashlib.sha256(token.encode()).hexdigest()
    overlap = json.loads(raw)
    final = json.loads(raw)
    for item in overlap["principals"]:
        if item["id"] == principal_id:
            item["token_sha256"].append(new_hash)
    for item in final["principals"]:
        if item["id"] == principal_id:
            item["token_sha256"] = [new_hash]
    Policy.parse(overlap)
    Policy.parse(final)
    write_new(output / "token", (token + "\n").encode())
    write_new(output / "overlap.json", canonical(overlap))
    write_new(output / "final.json", canonical(final))
    receipt = {
        "previous_sha256": digest(raw),
        "overlap_sha256": digest(canonical(overlap)),
        "final_sha256": digest(canonical(final)),
        "public_release_approved": False,
    }
    write_new(output / "receipt.json", canonical(receipt))
    return receipt


def stage_revocation(policy_file, principal_id, output):
    doc = json.loads(read_private(policy_file))
    target = next(p for p in doc["principals"] if p["id"] == principal_id)
    # Expire the principal rather than removing the final registry entry.
    target["expires_at"] = "1970-01-01T00:00:00Z"
    Policy.parse(doc)
    write_new(output, canonical(doc))


def install(staged, target, expected_sha256):
    """Explicit local CAS only. Never signals workers or calls a remote
    service.
    """
    candidate = read_private(staged)
    Policy.parse(json.loads(candidate))
    target = Path(target)
    directory = private_directory(target.parent)
    lock = os.open(
        ".policy.lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = read_private(target)
        if digest(current) != expected_sha256:
            raise ValueError("Policy changed; refusing stale rotation")
        before, after = json.loads(current), json.loads(candidate)
        if {k: v for k, v in before.items() if k != "principals"} != {
            k: v for k, v in after.items() if k != "principals"
        }:
            raise ValueError(
                "Rotation cannot change network, HMAC or rate policy"
            )
        with tempfile.NamedTemporaryFile(
            dir=target.parent, delete=False
        ) as stream:
            os.chmod(stream.name, 0o600)
            temp = stream.name
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.replace(temp, target)
            os.fsync(directory)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    finally:
        os.close(lock)
        os.close(directory)
