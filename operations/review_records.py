"""Signed private review records. There is deliberately no publication
action.
"""

from datetime import datetime, timezone
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from .files import canonical, digest, private_directory

DECISIONS = {"reviewed_private", "needs_more_evidence", "rejected"}


def verify(raw, reviewers, expected_head=None):
    previous = "0" * 64
    rows = []
    if raw and not raw.endswith(b"\n"):
        raise ValueError("Incomplete journal requires human recovery")
    for line in raw.splitlines():
        row = json.loads(line)
        if set(row) != {"record", "signature"}:
            raise ValueError("Unsigned fields in review record")
        body = row["record"]
        if (
            set(body)
            != {
                "id",
                "sequence",
                "reviewer",
                "evidence_sha256",
                "note_sha256",
                "decision",
                "timestamp",
                "previous",
                "public_release_approved",
            }
            or body["sequence"] != len(rows) + 1
            or body["previous"] != previous
            or body["decision"] not in DECISIONS
            or body["public_release_approved"] is not False
            or not re.fullmatch("[0-9a-f]{64}", body["evidence_sha256"])
            or not re.fullmatch("[0-9a-f]{64}", body["note_sha256"])
        ):
            raise ValueError("Invalid private review chain")
        key = Ed25519PublicKey.from_public_bytes(reviewers[body["reviewer"]])
        key.verify(
            base64.b64decode(row["signature"], validate=True), canonical(body)
        )
        previous = digest(canonical(row))
        rows.append(row)
    if expected_head is not None and previous != expected_head:
        raise ValueError("Review head does not match independent checkpoint")
    return rows


def append(
    path,
    reviewer,
    private_key,
    reviewers,
    evidence_sha256,
    note_sha256,
    decision,
    human_confirmation,
):
    if (
        human_confirmation != "REVIEW " + evidence_sha256
        or decision not in DECISIONS
    ):
        raise ValueError(
            "Explicit human confirmation and private decision required"
        )
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    if key.public_key().public_bytes_raw() != reviewers[reviewer]:
        raise ValueError("Unregistered reviewer key")
    directory = private_directory(Path(path).parent)
    os.close(directory)
    fd = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("Unsafe review journal")
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), "rb") as inp:
            raw = inp.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("Review journal requires a new signed volume")
        rows = verify(raw, reviewers)
        body = {
            "id": uuid.uuid4().hex,
            "sequence": len(rows) + 1,
            "reviewer": reviewer,
            "evidence_sha256": evidence_sha256,
            "note_sha256": note_sha256,
            "decision": decision,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous": digest(canonical(rows[-1])) if rows else "0" * 64,
            "public_release_approved": False,
        }
        row = {
            "record": body,
            "signature": base64.b64encode(key.sign(canonical(body))).decode(),
        }
        verify(raw + canonical(row) + b"\n", reviewers)
        os.lseek(fd, 0, os.SEEK_END)
        pending = canonical(row) + b"\n"
        if len(raw) + len(pending) > 16 * 1024 * 1024:
            raise ValueError("Review journal requires a new signed volume")
        while pending:
            count = os.write(fd, pending)
            if not count:
                raise OSError("Incomplete review write")
            pending = pending[count:]
        os.fsync(fd)
        directory = private_directory(Path(path).parent)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return row
    finally:
        os.close(fd)
