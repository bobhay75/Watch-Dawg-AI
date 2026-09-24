from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable, Final, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .api import ApiError
from .swarm_auth import is_valid_device_token
from .swarm_proof import (
    parse_proof_json,
    proof_hmac_sha256,
    validate_proof_hmac_key,
    verify_proof_hmac,
)
from .swarm_schema import (
    ANDROID_DEVICE_ID_PATTERN,
    validate_verified_android_snapshot,
)
from .swarm_watch import MAX_SNAPSHOT_BYTES


MAX_SWARM_REQUEST_BYTES: Final[int] = 512_000
MAX_PROOF_BYTES: Final[int] = 8_192
MAX_DEVICE_COUNT: Final[int] = 1_000
DEFAULT_INGEST_RATE_LIMIT_PER_MINUTE: Final[int] = 120
DEFAULT_DEVICE_COOLDOWN_SECONDS: Final[float] = 1.0
DEFAULT_HISTORY_MAX_ENTRIES_PER_DEVICE: Final[int] = 2_048
MAX_HISTORY_MAX_ENTRIES_PER_DEVICE: Final[int] = 100_000
MAX_SEQUENCE: Final[int] = (1 << 63) - 1
KEY_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
ALGORITHM: Final[str] = "SHA256withECDSA"
ENVELOPE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "device_id",
        "key_id",
        "algorithm",
        "signed_payload",
        "signature",
    }
)
SQLITE_AUXILIARY_SUFFIXES: Final[tuple[str, ...]] = ("-journal", "-wal", "-shm")
HISTORY_SNAPSHOT_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9]{19}-[a-f0-9]{64}\.snapshot\.json$"
)


@dataclass(frozen=True)
class SwarmEnrollment:
    device_id: str
    token_sha256: str
    key_id: str
    public_key: ec.EllipticCurvePublicKey
    snapshot_path: Path


def _proof_path(snapshot_path: Path) -> Path:
    return snapshot_path.with_name(snapshot_path.name + ".proof.json")


def _history_root(snapshot_path: Path) -> Path:
    return snapshot_path.with_name(snapshot_path.name + ".history")


def _history_paths(
    snapshot_path: Path,
    sequence: int,
    snapshot_sha256: str,
) -> tuple[Path, Path, Path]:
    stem = f"{sequence:019d}-{snapshot_sha256}"
    root = _history_root(snapshot_path)
    history_snapshot = root / f"{stem}.snapshot.json"
    return (
        history_snapshot,
        _proof_path(history_snapshot),
        root / f"{stem}.signature.der",
    )


def _decode_base64(value: Any, field: str, *, max_bytes: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_envelope",
            f"{field} must be non-empty base64 text.",
        )
    if len(value) > ((max_bytes + 2) // 3) * 4 + 4:
        raise ApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request_too_large",
            f"Decoded {field} may not exceed {max_bytes} bytes.",
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_envelope",
            f"{field} must be valid base64.",
        ) from exc
    if not decoded:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_envelope",
            f"Decoded {field} must not be empty.",
        )
    if len(decoded) > max_bytes:
        raise ApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request_too_large",
            f"Decoded {field} may not exceed {max_bytes} bytes.",
        )
    return decoded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def _reject_json_float(value: str) -> None:
    raise ValueError(f"floating-point JSON number {value!r} is not allowed")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r} is not allowed")
        result[key] = value
    return result


def parse_canonical_snapshot(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_signed_payload",
            "The signed payload must be valid UTF-8 JSON with unique object keys.",
        ) from exc
    if not isinstance(value, dict):
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_signed_payload",
            "The signed payload must contain a JSON object.",
        )
    try:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_signed_payload",
            "The signed payload contains an unsupported JSON value.",
        ) from exc
    if not hmac.compare_digest(raw, canonical):
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "noncanonical_payload",
            "The signed payload must use Watch-Dawg canonical JSON encoding.",
        )
    return value


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_snapshot",
            "collected_at must be an ISO-8601 timestamp.",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_snapshot",
            "collected_at must be an ISO-8601 timestamp.",
        ) from exc
    if parsed.tzinfo is None:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_snapshot",
            "collected_at must include a timezone.",
        )
    return parsed.astimezone(timezone.utc)


def _validate_token_hash(token_hash: Any, *, device_id: str) -> str:
    if not isinstance(token_hash, str) or not KEY_ID_PATTERN.fullmatch(token_hash):
        raise ValueError(
            f"swarm enrollment {device_id!r} token_sha256 must be "
            "64 lowercase hex characters"
        )
    return token_hash


def load_swarm_enrollments(
    raw: str,
    snapshot_root: Path,
) -> dict[str, SwarmEnrollment]:
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("swarm enrollment configuration must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("swarm enrollment configuration must be a JSON object")
    if len(payload) > MAX_DEVICE_COUNT:
        raise ValueError(f"at most {MAX_DEVICE_COUNT} swarm devices may be enrolled")

    resolved_root = snapshot_root.resolve()
    enrollments: dict[str, SwarmEnrollment] = {}
    assigned_paths: dict[Path, str] = {}
    assigned_key_ids: dict[str, str] = {}
    assigned_token_hashes: dict[str, str] = {}
    required_fields = {
        "token_sha256",
        "key_id",
        "public_key_der_base64",
        "snapshot_path",
    }
    for device_id, entry in payload.items():
        if (
            not isinstance(device_id, str)
            or not ANDROID_DEVICE_ID_PATTERN.fullmatch(device_id)
        ):
            raise ValueError(f"invalid swarm device id: {device_id!r}")
        if not isinstance(entry, dict) or set(entry) != required_fields:
            raise ValueError(
                f"swarm enrollment {device_id!r} must contain exactly "
                f"{sorted(required_fields)}"
            )
        token_sha256 = _validate_token_hash(
            entry["token_sha256"],
            device_id=device_id,
        )
        key_id = entry["key_id"]
        if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError(
                f"swarm enrollment {device_id!r} key_id must be 64 lowercase hex characters"
            )
        try:
            public_der = base64.b64decode(
                entry["public_key_der_base64"],
                validate=True,
            )
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ValueError(
                f"swarm enrollment {device_id!r} public key must be valid base64"
            ) from exc
        computed_key_id = hashlib.sha256(public_der).hexdigest()
        if not hmac.compare_digest(key_id, computed_key_id):
            raise ValueError(
                f"swarm enrollment {device_id!r} key_id does not match its public key"
            )
        expected_device_id = f"android-{key_id[:24]}"
        if not hmac.compare_digest(device_id, expected_device_id):
            raise ValueError(
                f"swarm enrollment {device_id!r} device id does not match its key id"
            )
        try:
            public_key = serialization.load_der_public_key(public_der)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"swarm enrollment {device_id!r} public key is invalid"
            ) from exc
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError(
                f"swarm enrollment {device_id!r} must use an ECDSA P-256 public key"
            )

        relative_path = entry["snapshot_path"]
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError(
                f"swarm enrollment {device_id!r} requires a snapshot path"
            )
        candidate = (resolved_root / relative_path).resolve()
        if candidate == resolved_root or not candidate.is_relative_to(resolved_root):
            raise ValueError(
                f"swarm enrollment {device_id!r} snapshot path escapes its root"
            )
        if candidate.suffix.lower() != ".json":
            raise ValueError(
                f"swarm enrollment {device_id!r} snapshot path must end in .json"
            )
        proof_candidate = _proof_path(candidate)
        history_candidate = _history_root(candidate)
        for proposed in (candidate, proof_candidate, history_candidate):
            for assigned, assigned_device in assigned_paths.items():
                if (
                    proposed == assigned
                    or proposed.is_relative_to(assigned)
                    or assigned.is_relative_to(proposed)
                ):
                    raise ValueError(
                        f"swarm enrollment {device_id!r} snapshot/proof/history path "
                        f"intersects enrollment {assigned_device!r}"
                    )
        duplicate_key_device = assigned_key_ids.get(key_id)
        if duplicate_key_device is not None:
            raise ValueError(
                f"swarm enrollment {device_id!r} reuses key_id from "
                f"{duplicate_key_device!r}"
            )
        duplicate_token_device = assigned_token_hashes.get(token_sha256)
        if duplicate_token_device is not None:
            raise ValueError(
                f"swarm enrollment {device_id!r} reuses token_sha256 from "
                f"{duplicate_token_device!r}"
            )
        enrollments[device_id] = SwarmEnrollment(
            device_id=device_id,
            token_sha256=token_sha256,
            key_id=key_id,
            public_key=public_key,
            snapshot_path=candidate,
        )
        assigned_paths[candidate] = device_id
        assigned_paths[proof_candidate] = device_id
        assigned_paths[history_candidate] = device_id
        assigned_key_ids[key_id] = device_id
        assigned_token_hashes[token_sha256] = device_id
    return enrollments


def load_swarm_enrollment_source(
    *,
    inline_json: str | None,
    file_path: str | None,
    snapshot_root: Path,
) -> dict[str, SwarmEnrollment]:
    if inline_json and file_path:
        raise ValueError(
            "configure only one of SENTINEL_SWARM_ENROLLMENTS_JSON or "
            "SENTINEL_SWARM_ENROLLMENTS_FILE"
        )
    if not inline_json and not file_path:
        return {}
    if file_path:
        source = Path(file_path)
        if not source.is_file():
            raise ValueError("SENTINEL_SWARM_ENROLLMENTS_FILE does not exist")
        if source.stat().st_size > MAX_SWARM_REQUEST_BYTES:
            raise ValueError("swarm enrollment configuration is too large")
        inline_json = source.read_text(encoding="utf-8")
    assert inline_json is not None
    return load_swarm_enrollments(inline_json, snapshot_root)


class SwarmIngestRateLimiter:
    """Bound in-process authenticated ingestion work before signature checks."""

    def __init__(
        self,
        max_per_minute: int = DEFAULT_INGEST_RATE_LIMIT_PER_MINUTE,
        device_cooldown_seconds: float = DEFAULT_DEVICE_COOLDOWN_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_per_minute < 1:
            raise ValueError("ingest max_per_minute must be positive")
        if device_cooldown_seconds < 0:
            raise ValueError("ingest device cooldown cannot be negative")
        self.max_per_minute = max_per_minute
        self.device_cooldown_seconds = device_cooldown_seconds
        self.clock = clock
        self._recent: deque[float] = deque()
        self._device_last: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, device_id: str) -> None:
        now = self.clock()
        with self._lock:
            while self._recent and now - self._recent[0] >= 60:
                self._recent.popleft()
            retry_after = 0.0
            if len(self._recent) >= self.max_per_minute:
                retry_after = max(retry_after, 60 - (now - self._recent[0]))
            last = self._device_last.get(device_id)
            if last is not None:
                retry_after = max(
                    retry_after,
                    self.device_cooldown_seconds - (now - last),
                )
            if retry_after > 0:
                raise ApiError(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "ingest_rate_limited",
                    "This enrolled device submitted snapshots too quickly.",
                    headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
                )
            self._recent.append(now)
            self._device_last[device_id] = now


class SwarmSnapshotIngestor:
    def __init__(
        self,
        *,
        enrollments: Mapping[str, SwarmEnrollment],
        replay_state_path: Path,
        proof_hmac_key: bytes,
        history_max_entries_per_device: int = DEFAULT_HISTORY_MAX_ENTRIES_PER_DEVICE,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        rate_limiter: SwarmIngestRateLimiter | None = None,
    ) -> None:
        if (
            isinstance(history_max_entries_per_device, bool)
            or not isinstance(history_max_entries_per_device, int)
            or not 1
            <= history_max_entries_per_device
            <= MAX_HISTORY_MAX_ENTRIES_PER_DEVICE
        ):
            raise ValueError(
                "history_max_entries_per_device must be an integer from 1 "
                f"through {MAX_HISTORY_MAX_ENTRIES_PER_DEVICE}"
            )
        self.enrollments = dict(enrollments)
        self.replay_state_path = replay_state_path.resolve()
        replay_paths = {
            self.replay_state_path,
            *(
                self.replay_state_path.with_name(
                    self.replay_state_path.name + suffix
                )
                for suffix in SQLITE_AUXILIARY_SUFFIXES
            ),
        }
        for enrollment in self.enrollments.values():
            snapshot_path = enrollment.snapshot_path.resolve()
            proof_path = _proof_path(snapshot_path)
            history_path = _history_root(snapshot_path)
            for replay_path in replay_paths:
                for persisted_path in (snapshot_path, proof_path, history_path):
                    if (
                        replay_path == persisted_path
                        or replay_path.is_relative_to(persisted_path)
                        or persisted_path.is_relative_to(replay_path)
                    ):
                        raise ValueError(
                            "swarm replay database paths must not intersect "
                            "snapshot, proof, or history paths"
                        )
        validated_proof_key = validate_proof_hmac_key(
            proof_hmac_key,
            required=True,
        )
        assert validated_proof_key is not None
        self.proof_hmac_key = validated_proof_key
        self.history_max_entries_per_device = history_max_entries_per_device
        self.clock = clock
        self.rate_limiter = rate_limiter or SwarmIngestRateLimiter()
        self._device_locks = {
            device_id: threading.Lock() for device_id in self.enrollments
        }
        self._initialization_lock = threading.Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        self._initialize()
        connection = sqlite3.connect(
            self.replay_state_path,
            timeout=10,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        if self._initialized:
            return
        with self._initialization_lock:
            if self._initialized:
                return
            self._ensure_directory_durable(self.replay_state_path.parent)
            with sqlite3.connect(self.replay_state_path, timeout=10) as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS swarm_replay_state (
                        device_id TEXT PRIMARY KEY,
                        sequence INTEGER NOT NULL,
                        collected_at TEXT NOT NULL,
                        snapshot_sha256 TEXT NOT NULL,
                        received_at TEXT NOT NULL
                    )
                    """
                )
                columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(swarm_replay_state)"
                    )
                }
                if "received_at" not in columns:
                    connection.execute(
                        "ALTER TABLE swarm_replay_state ADD COLUMN received_at TEXT"
                    )
                self._migrate_replay_received_at(connection)
            try:
                self.replay_state_path.chmod(0o600)
            except OSError:
                pass
            self._fsync_directory(self.replay_state_path.parent)
            self._initialized = True

    def _migrate_replay_received_at(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            """
            SELECT device_id, sequence, collected_at, snapshot_sha256
            FROM swarm_replay_state
            WHERE received_at IS NULL OR received_at = ''
            """
        ).fetchall()
        for device_id, sequence, collected_at, snapshot_sha256 in rows:
            received_at = str(collected_at)
            enrollment = self.enrollments.get(str(device_id))
            if enrollment is not None:
                proof_path = _proof_path(enrollment.snapshot_path)
                proof_raw = self._read_optional_bounded_file(
                    proof_path,
                    MAX_PROOF_BYTES,
                )
                if proof_raw is not None:
                    try:
                        proof = parse_proof_json(proof_raw)
                    except ValueError:
                        proof = None
                    if (
                        isinstance(proof, dict)
                        and verify_proof_hmac(proof, self.proof_hmac_key)
                        and proof.get("device_id") == device_id
                        and proof.get("sequence") == sequence
                        and proof.get("payload_sha256") == snapshot_sha256
                        and isinstance(proof.get("received_at"), str)
                    ):
                        try:
                            _parse_timestamp(proof["received_at"])
                        except ApiError:
                            pass
                        else:
                            received_at = proof["received_at"]
            connection.execute(
                """
                UPDATE swarm_replay_state
                SET received_at = ?
                WHERE device_id = ?
                """,
                (received_at, device_id),
            )

    def ingest(
        self,
        envelope: Mapping[str, Any],
        bearer_token: str,
        *,
        preauthenticated_device_id: str | None = None,
    ) -> dict[str, Any]:
        if set(envelope) != ENVELOPE_FIELDS:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_envelope",
                "The signed snapshot envelope has unexpected or missing fields.",
            )
        schema_version = envelope.get("schema_version")
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != 1
        ):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "unsupported_schema",
                "Only signed snapshot envelope schema version 1 is accepted.",
            )
        device_id = envelope.get("device_id")
        if not isinstance(device_id, str):
            self._unauthorized()
        if (
            preauthenticated_device_id is not None
            and not hmac.compare_digest(device_id, preauthenticated_device_id)
        ):
            self._unauthorized()
        enrollment = self._authenticate(
            device_id,
            bearer_token,
            claim_rate=preauthenticated_device_id is None,
        )

        key_id = envelope.get("key_id")
        algorithm = envelope.get("algorithm")
        if (
            not isinstance(key_id, str)
            or not hmac.compare_digest(key_id, enrollment.key_id)
            or algorithm != ALGORITHM
        ):
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "invalid_signature",
                "The signed snapshot could not be authenticated.",
            )

        signed_payload = _decode_base64(
            envelope.get("signed_payload"),
            "signed_payload",
            max_bytes=MAX_SNAPSHOT_BYTES,
        )
        signature = _decode_base64(
            envelope.get("signature"),
            "signature",
            max_bytes=256,
        )
        try:
            enrollment.public_key.verify(
                signature,
                signed_payload,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "invalid_signature",
                "The signed snapshot could not be authenticated.",
            ) from exc

        snapshot = parse_canonical_snapshot(signed_payload)
        if snapshot.get("device_id") != device_id:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "device_mismatch",
                "The envelope and signed snapshot device ids must match.",
            )
        try:
            validate_verified_android_snapshot(
                snapshot,
                require_collected_at=True,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_snapshot",
                "The signed snapshot does not match Android schema version 1.",
            ) from exc
        sequence = snapshot.get("sequence")
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or not 1 <= sequence <= MAX_SEQUENCE
        ):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_snapshot",
                "sequence must be an integer from 1 through 2^63-1.",
            )
        collected_at = _parse_timestamp(snapshot.get("collected_at"))
        now = self.clock().astimezone(timezone.utc)
        snapshot_sha256 = hashlib.sha256(signed_payload).hexdigest()
        self._persist_if_newer(
            enrollment=enrollment,
            sequence=sequence,
            collected_at=collected_at,
            received_at=now,
            snapshot_sha256=snapshot_sha256,
            signed_payload=signed_payload,
            signature=signature,
        )
        return {
            "accepted": True,
            "device_id": device_id,
            "key_id": enrollment.key_id,
            "sequence": sequence,
            "snapshot_sha256": snapshot_sha256,
        }

    def preauthenticate(self, device_id: str, bearer_token: str) -> None:
        self._authenticate(device_id, bearer_token, claim_rate=True)

    def _authenticate(
        self,
        device_id: str,
        bearer_token: str,
        *,
        claim_rate: bool,
    ) -> SwarmEnrollment:
        enrollment = self.enrollments.get(device_id)
        token_valid = is_valid_device_token(bearer_token)
        supplied_token_hash = hashlib.sha256(
            bearer_token.encode("ascii") if token_valid else b"invalid-device-token"
        ).hexdigest()
        token_matches = hmac.compare_digest(
            supplied_token_hash,
            enrollment.token_sha256 if enrollment is not None else "0" * 64,
        )
        if (
            enrollment is None
            or not token_valid
            or not token_matches
        ):
            self._unauthorized()
        assert enrollment is not None
        if claim_rate:
            self.rate_limiter.claim(device_id)
        return enrollment

    @staticmethod
    def _unauthorized() -> None:
        raise ApiError(
            HTTPStatus.UNAUTHORIZED,
            "unauthorized_device",
            "A valid enrolled device and bearer token are required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _persist_if_newer(
        self,
        *,
        enrollment: SwarmEnrollment,
        sequence: int,
        collected_at: datetime,
        received_at: datetime,
        snapshot_sha256: str,
        signed_payload: bytes,
        signature: bytes,
    ) -> None:
        device_lock = self._device_locks[enrollment.device_id]
        with device_lock:
            connection = self._connect()
            accepted_received_at: str | None = None
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT sequence, snapshot_sha256, received_at
                    FROM swarm_replay_state
                    WHERE device_id = ?
                    """,
                    (enrollment.device_id,),
                ).fetchone()
                if row is not None:
                    accepted_sequence = int(row[0])
                    accepted_sha256 = str(row[1])
                    prior_received_at = self._validated_replay_received_at(row[2])
                    if (
                        sequence == accepted_sequence
                        and hmac.compare_digest(snapshot_sha256, accepted_sha256)
                    ):
                        accepted_received_at = prior_received_at
                        connection.rollback()
                    elif sequence <= accepted_sequence:
                        connection.rollback()
                        raise ApiError(
                            HTTPStatus.CONFLICT,
                            "replayed_snapshot",
                            "The signed snapshot sequence is older than, or "
                            "conflicts with, the last accepted sequence.",
                        )
                    elif not self._accepted_materialization_complete(
                        enrollment=enrollment,
                        sequence=accepted_sequence,
                        received_at=prior_received_at,
                        snapshot_sha256=accepted_sha256,
                    ):
                        connection.rollback()
                        raise ApiError(
                            HTTPStatus.CONFLICT,
                            "previous_snapshot_incomplete",
                            "The previously accepted snapshot must be retried "
                            "before a higher sequence can be accepted.",
                        )

                if accepted_received_at is None:
                    if (
                        self._history_entry_count(enrollment.snapshot_path)
                        >= self.history_max_entries_per_device
                    ):
                        connection.rollback()
                        raise ApiError(
                            HTTPStatus.INSUFFICIENT_STORAGE,
                            "history_capacity_exceeded",
                            "This device's accepted-history capacity is full.",
                        )
                    accepted_received_at = received_at.isoformat()
                    connection.execute(
                        """
                        INSERT INTO swarm_replay_state (
                            device_id,
                            sequence,
                            collected_at,
                            snapshot_sha256,
                            received_at
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(device_id) DO UPDATE SET
                            sequence = excluded.sequence,
                            collected_at = excluded.collected_at,
                            snapshot_sha256 = excluded.snapshot_sha256,
                            received_at = excluded.received_at
                        """,
                        (
                            enrollment.device_id,
                            sequence,
                            collected_at.isoformat(),
                            snapshot_sha256,
                            accepted_received_at,
                        ),
                    )
                    # The replay row is the write-ahead acceptance record. If a
                    # following file write fails, an exact retry repairs the
                    # materialized snapshot/proof with this original receipt time.
                    connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

            assert accepted_received_at is not None
            self._materialize_accepted_snapshot(
                enrollment=enrollment,
                sequence=sequence,
                received_at=accepted_received_at,
                snapshot_sha256=snapshot_sha256,
                signed_payload=signed_payload,
                signature=signature,
            )

    @staticmethod
    def _validated_replay_received_at(value: Any) -> str:
        if not isinstance(value, str):
            raise RuntimeError("Swarm replay state has an invalid receipt timestamp")
        try:
            _parse_timestamp(value)
        except ApiError as exc:
            raise RuntimeError(
                "Swarm replay state has an invalid receipt timestamp"
            ) from exc
        return value

    def _materialize_accepted_snapshot(
        self,
        *,
        enrollment: SwarmEnrollment,
        sequence: int,
        received_at: str,
        snapshot_sha256: str,
        signed_payload: bytes,
        signature: bytes,
    ) -> None:
        proof_path = _proof_path(enrollment.snapshot_path)
        proof = self._proof_record(
            enrollment=enrollment,
            sequence=sequence,
            received_at=received_at,
            snapshot_sha256=snapshot_sha256,
        )
        proof_bytes = (
            json.dumps(
                proof,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

        history_snapshot_path, history_proof_path, history_signature_path = _history_paths(
            enrollment.snapshot_path,
            sequence,
            snapshot_sha256,
        )
        self._ensure_immutable_file(history_snapshot_path, signed_payload)
        self._ensure_archived_signature(
            history_signature_path,
            signature,
            enrollment=enrollment,
            signed_payload=signed_payload,
        )
        self._ensure_immutable_file(history_proof_path, proof_bytes)

        proof_path = _proof_path(enrollment.snapshot_path)
        if not self._file_equals(enrollment.snapshot_path, signed_payload):
            self._atomic_write(enrollment.snapshot_path, signed_payload)
        if not self._proof_matches(proof_path, proof):
            self._atomic_write(proof_path, proof_bytes)

    def _proof_record(
        self,
        *,
        enrollment: SwarmEnrollment,
        sequence: int,
        received_at: str,
        snapshot_sha256: str,
    ) -> dict[str, Any]:
        proof: dict[str, Any] = {
            "algorithm": ALGORITHM,
            "device_id": enrollment.device_id,
            "key_id": enrollment.key_id,
            "payload_sha256": snapshot_sha256,
            "received_at": received_at,
            "schema_version": 1,
            "sequence": sequence,
            "signature_verified": True,
        }
        proof["proof_hmac_sha256"] = proof_hmac_sha256(
            proof,
            self.proof_hmac_key,
        )
        return proof

    def _accepted_materialization_complete(
        self,
        *,
        enrollment: SwarmEnrollment,
        sequence: int,
        received_at: str,
        snapshot_sha256: str,
    ) -> bool:
        history_snapshot, history_proof, history_signature = _history_paths(
            enrollment.snapshot_path,
            sequence,
            snapshot_sha256,
        )
        signed_payload = self._read_optional_bounded_file(
            history_snapshot,
            MAX_SWARM_REQUEST_BYTES,
        )
        if (
            signed_payload is None
            or not hmac.compare_digest(
                hashlib.sha256(signed_payload).hexdigest(),
                snapshot_sha256,
            )
            or not self._archived_signature_matches(
                history_signature,
                enrollment=enrollment,
                signed_payload=signed_payload,
            )
        ):
            return False
        proof = self._proof_record(
            enrollment=enrollment,
            sequence=sequence,
            received_at=received_at,
            snapshot_sha256=snapshot_sha256,
        )
        proof_bytes = self._read_optional_bounded_file(history_proof, MAX_PROOF_BYTES)
        if proof_bytes is None:
            return False
        try:
            archived_proof = parse_proof_json(proof_bytes)
        except ValueError:
            return False
        if archived_proof != proof or not verify_proof_hmac(
            archived_proof,
            self.proof_hmac_key,
        ):
            return False

        # The immutable archive is authoritative. Repair only the mutable latest
        # compatibility pair before advancing, so external damage cannot wedge a
        # device whose acknowledged prior outbox entry is already gone.
        if not self._file_equals(enrollment.snapshot_path, signed_payload):
            self._atomic_write(enrollment.snapshot_path, signed_payload)
        current_proof_path = _proof_path(enrollment.snapshot_path)
        if not self._proof_matches(current_proof_path, proof):
            self._atomic_write(current_proof_path, proof_bytes)
        return True

    @staticmethod
    def _archived_signature_matches(
        target: Path,
        *,
        enrollment: SwarmEnrollment,
        signed_payload: bytes,
    ) -> bool:
        signature = SwarmSnapshotIngestor._read_optional_bounded_file(target, 256)
        if signature is None or not signature:
            return False
        try:
            enrollment.public_key.verify(
                signature,
                signed_payload,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    @staticmethod
    def _ensure_archived_signature(
        target: Path,
        signature: bytes,
        *,
        enrollment: SwarmEnrollment,
        signed_payload: bytes,
    ) -> None:
        try:
            with target.open("rb") as handle:
                archived_signature = handle.read(257)
        except FileNotFoundError:
            SwarmSnapshotIngestor._ensure_immutable_file(target, signature)
            return
        except OSError as exc:
            raise RuntimeError(
                "Swarm accepted-history signature could not be verified"
            ) from exc
        if len(archived_signature) > 256 or not archived_signature:
            raise RuntimeError("Swarm accepted-history signature is invalid")
        try:
            enrollment.public_key.verify(
                archived_signature,
                signed_payload,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError) as exc:
            raise RuntimeError("Swarm accepted-history signature is invalid") from exc
        SwarmSnapshotIngestor._fsync_directory(target.parent)

    @staticmethod
    def _history_entry_count(snapshot_path: Path) -> int:
        history_root = _history_root(snapshot_path)
        count = 0
        try:
            with os.scandir(history_root) as entries:
                for entry in entries:
                    if HISTORY_SNAPSHOT_NAME_PATTERN.fullmatch(entry.name):
                        count += 1
        except FileNotFoundError:
            return 0
        except OSError as exc:
            raise RuntimeError(
                "Swarm accepted-history capacity could not be checked"
            ) from exc
        return count

    @staticmethod
    def _ensure_immutable_file(target: Path, expected: bytes) -> None:
        try:
            with target.open("rb") as handle:
                actual = handle.read(len(expected) + 1)
        except FileNotFoundError:
            actual = None
        except OSError as exc:
            raise RuntimeError(
                "Swarm accepted-history entry could not be verified"
            ) from exc
        if actual is not None:
            if actual == expected:
                SwarmSnapshotIngestor._fsync_directory(target.parent)
                return
            raise RuntimeError(
                "Swarm accepted-history entry conflicts with immutable evidence"
            )

        SwarmSnapshotIngestor._ensure_directory_durable(target.parent)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                os.chmod(temporary_name, 0o600)
                temporary.write(expected)
                temporary.flush()
                os.fsync(temporary.fileno())
            try:
                os.link(temporary_name, target)
            except FileExistsError:
                with target.open("rb") as handle:
                    concurrent = handle.read(len(expected) + 1)
                if concurrent != expected:
                    raise RuntimeError(
                        "Swarm accepted-history entry conflicts with immutable evidence"
                    )
            Path(temporary_name).unlink()
            temporary_name = None
            SwarmSnapshotIngestor._fsync_directory(target.parent)
        finally:
            if temporary_name is not None:
                try:
                    Path(temporary_name).unlink()
                except FileNotFoundError:
                    pass

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        directory_fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _ensure_directory_durable(path: Path) -> None:
        missing: list[Path] = []
        cursor = path
        while True:
            try:
                if cursor.is_dir():
                    break
                if cursor.exists():
                    raise NotADirectoryError(
                        f"Swarm storage parent is not a directory: {cursor}"
                    )
            except OSError as exc:
                raise RuntimeError(
                    "Swarm storage directory could not be inspected"
                ) from exc
            parent = cursor.parent
            if parent == cursor:
                raise RuntimeError("Swarm storage directory has no usable parent")
            missing.append(cursor)
            cursor = parent

        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                if not directory.is_dir():
                    raise RuntimeError(
                        "Swarm storage parent is not a directory"
                    )
            SwarmSnapshotIngestor._fsync_directory(directory)
            SwarmSnapshotIngestor._fsync_directory(directory.parent)

    def _proof_matches(
        self,
        path: Path,
        expected: Mapping[str, Any],
    ) -> bool:
        raw = self._read_optional_bounded_file(path, MAX_PROOF_BYTES)
        if raw is None:
            return False
        try:
            actual = parse_proof_json(raw)
        except ValueError:
            return False
        return (
            actual == expected
            and verify_proof_hmac(actual, self.proof_hmac_key)
        )

    @staticmethod
    def _file_equals(path: Path, expected: bytes) -> bool:
        try:
            with path.open("rb") as handle:
                actual = handle.read(len(expected) + 1)
        except (FileNotFoundError, IsADirectoryError, OSError):
            return False
        return actual == expected

    @staticmethod
    def _read_optional_bounded_file(path: Path, limit: int) -> bytes | None:
        try:
            with path.open("rb") as handle:
                payload = handle.read(limit + 1)
        except (FileNotFoundError, IsADirectoryError, OSError):
            return None
        return payload if len(payload) <= limit else None

    @staticmethod
    def _atomic_write(target: Path, data: bytes) -> None:
        SwarmSnapshotIngestor._ensure_directory_durable(target.parent)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                os.chmod(temporary_name, 0o600)
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, target)
            temporary_name = None
            SwarmSnapshotIngestor._fsync_directory(target.parent)
        finally:
            if temporary_name is not None:
                try:
                    Path(temporary_name).unlink()
                except FileNotFoundError:
                    pass
