from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any, Final, Mapping


PROOF_HMAC_ENV: Final[str] = "SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64"
PROOF_HMAC_KEY_BYTES: Final[int] = 32
PROOF_HMAC_DOMAIN: Final[bytes] = b"watch-dawg-swarm-proof-v1\0"
PROOF_SIGNED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "algorithm",
        "device_id",
        "key_id",
        "payload_sha256",
        "received_at",
        "schema_version",
        "sequence",
        "signature_verified",
    }
)
PROOF_FIELDS: Final[frozenset[str]] = PROOF_SIGNED_FIELDS | {
    "proof_hmac_sha256"
}


def load_proof_hmac_key(
    encoded: str | None,
    *,
    required: bool,
) -> bytes | None:
    if not encoded:
        if required:
            raise ValueError(
                f"{PROOF_HMAC_ENV} is required when Swarm enrollment is enabled"
            )
        return None
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(
            f"{PROOF_HMAC_ENV} must be valid base64 encoding exactly "
            f"{PROOF_HMAC_KEY_BYTES} bytes"
        ) from exc
    if len(key) != PROOF_HMAC_KEY_BYTES:
        raise ValueError(
            f"{PROOF_HMAC_ENV} must decode to exactly "
            f"{PROOF_HMAC_KEY_BYTES} bytes"
        )
    return key


def parse_proof_json(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate proof key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite proof value: {value}")

    try:
        proof = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Swarm proof must be strict UTF-8 JSON") from exc
    if not isinstance(proof, dict):
        raise ValueError("Swarm proof must contain a JSON object")
    return proof


def validate_proof_hmac_key(key: bytes | None, *, required: bool) -> bytes | None:
    if key is None:
        if required:
            raise ValueError("Swarm proof HMAC key is required")
        return None
    if not isinstance(key, bytes) or len(key) != PROOF_HMAC_KEY_BYTES:
        raise ValueError(
            f"Swarm proof HMAC key must contain exactly {PROOF_HMAC_KEY_BYTES} bytes"
        )
    return key


def canonical_proof_bytes(proof: Mapping[str, Any]) -> bytes:
    signed = {field: proof.get(field) for field in PROOF_SIGNED_FIELDS}
    return (
        PROOF_HMAC_DOMAIN
        + json.dumps(
            signed,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def proof_hmac_sha256(proof: Mapping[str, Any], key: bytes) -> str:
    validated_key = validate_proof_hmac_key(key, required=True)
    assert validated_key is not None
    return hmac.new(
        validated_key,
        canonical_proof_bytes(proof),
        hashlib.sha256,
    ).hexdigest()


def proof_structure_valid(proof: Mapping[str, Any]) -> bool:
    if set(proof) != PROOF_FIELDS:
        return False
    schema_version = proof.get("schema_version")
    sequence = proof.get("sequence")
    key_id = proof.get("key_id")
    payload_sha256 = proof.get("payload_sha256")
    proof_mac = proof.get("proof_hmac_sha256")
    received_at = proof.get("received_at")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
        or proof.get("signature_verified") is not True
        or proof.get("algorithm") != "SHA256withECDSA"
        or not isinstance(proof.get("device_id"), str)
        or not proof.get("device_id")
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
        or not _is_lower_hex_digest(key_id)
        or not _is_lower_hex_digest(payload_sha256)
        or not _is_lower_hex_digest(proof_mac)
        or not isinstance(received_at, str)
    ):
        return False
    return True


def verify_proof_hmac(proof: Mapping[str, Any], key: bytes | None) -> bool:
    if key is None or not proof_structure_valid(proof):
        return False
    try:
        expected = proof_hmac_sha256(proof, key)
    except (TypeError, ValueError):
        return False
    supplied = proof.get("proof_hmac_sha256")
    assert isinstance(supplied, str)
    return hmac.compare_digest(supplied, expected)


def _is_lower_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
