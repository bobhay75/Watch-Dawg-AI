from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .browser_capture import (
    BROWSER_PACKAGE_SCHEMA,
    BrowserCaptureError,
    verify_browser_package,
)
from .evidence_verify import (
    PACKAGE_SCHEMA,
    PackageVerificationError,
    read_verified_json,
    verify_package,
)


RECEIPT_SCHEMA: Final[str] = "proofpass-receipt/v1"
VERIFICATION_SCHEMA: Final[str] = "proofpass-receipt-verification/v1"
SIGNATURE_ALGORITHM: Final[str] = "Ed25519"
SIGNING_DOMAIN: Final[bytes] = b"proofpass-receipt-v1\0"
HTTP_SUBJECT_TYPE: Final[str] = "watch-dawg-website-evidence-package"
BROWSER_SUBJECT_TYPE: Final[str] = "watch-dawg-browser-evidence-package"
SUBJECT_TYPES: Final[frozenset[str]] = frozenset({HTTP_SUBJECT_TYPE, BROWSER_SUBJECT_TYPE})
EVIDENCE_STATUSES: Final[frozenset[str]] = frozenset(
    {"VERIFIED_INTEGRITY", "VERIFIED_BROWSER_EVIDENCE"}
)
MAX_KEY_FILE_BYTES: Final[int] = 16_384
MAX_RECEIPT_BYTES: Final[int] = 128_000
RECEIPT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "receipt_id",
        "attestation",
        "issuer",
        "subject",
        "coverage",
        "evidence",
        "issued_at",
        "limitations",
        "signature",
    }
)


class ProofPassError(RuntimeError):
    """Raised when a ProofPass receipt cannot be issued or verified safely."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProofPassError("receipt contains unsupported JSON values") from exc


def strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ProofPassError(f"{label} exceeds the maximum allowed size")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProofPassError(f"{label} must be strict UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ProofPassError(f"{label} must contain a JSON object")
    return payload


def _public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _read_bounded_file(path: Path, limit: int, *, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as exc:
        raise ProofPassError(f"could not read {label}") from exc
    if len(payload) > limit:
        raise ProofPassError(f"{label} exceeds the maximum allowed size")
    return payload


def _validate_private_key_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPassError("private signing key file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ProofPassError("private signing key file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise ProofPassError("private signing key path must be a regular file")
    if metadata.st_size > MAX_KEY_FILE_BYTES:
        raise ProofPassError("private signing key file is too large")
    if metadata.st_mode & 0o077:
        raise ProofPassError("private signing key permissions must deny group and other access")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ProofPassError("private signing key file must be owned by the current user")


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key_path = Path(path)
    _validate_private_key_file(key_path)
    payload = _read_bounded_file(key_path, MAX_KEY_FILE_BYTES, label="private signing key")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ProofPassError("private signing key is not valid unencrypted PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ProofPassError("ProofPass v1 requires an Ed25519 private key")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key_path = Path(path)
    payload = _read_bounded_file(key_path, MAX_KEY_FILE_BYTES, label="public verification key")
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as exc:
        raise ProofPassError("public verification key is not valid PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ProofPassError("ProofPass v1 requires an Ed25519 public key")
    return key


def generate_keypair(private_path: str | Path, public_path: str | Path) -> dict[str, Any]:
    private_target = Path(private_path)
    public_target = Path(public_path)
    if private_target.exists() or public_target.exists():
        raise ProofPassError("key generation refuses to overwrite existing key files")
    private_target.parent.mkdir(parents=True, exist_ok=True)
    public_target.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_fd = os.open(private_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(private_fd, "wb") as handle:
            handle.write(private_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        private_target.unlink(missing_ok=True)
        raise

    try:
        public_fd = os.open(public_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(public_fd, "wb") as handle:
            handle.write(public_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        private_target.unlink(missing_ok=True)
        public_target.unlink(missing_ok=True)
        raise

    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": _public_key_id(public_key),
        "private_key": str(private_target),
        "public_key": str(public_target),
        "warning": "Protect the private key outside source control and rotate/revoke it if exposure is suspected.",
    }


def _receipt_unsigned(receipt: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    return unsigned


def _signed_bytes(receipt: Mapping[str, Any]) -> bytes:
    return SIGNING_DOMAIN + canonical_json_bytes(_receipt_unsigned(receipt))


def _receipt_id_for(unsigned_without_id: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(SIGNING_DOMAIN + canonical_json_bytes(unsigned_without_id)).hexdigest()
    return f"pp1-{digest[:32]}"


def _verified_subject(
    evidence_root: str | Path,
    package_ref: str,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    root = Path(evidence_root)
    try:
        package = read_verified_json(root, package_ref)
    except PackageVerificationError as exc:
        raise ProofPassError(f"evidence package failed integrity verification: {exc}") from exc

    schema = package.get("schema")
    if schema == PACKAGE_SCHEMA:
        try:
            verification = verify_package(root, package_ref)
            capture = read_verified_json(root, verification["capture_ref"])
        except PackageVerificationError as exc:
            raise ProofPassError(f"evidence package failed integrity verification: {exc}") from exc
        return HTTP_SUBJECT_TYPE, verification, capture

    if schema == BROWSER_PACKAGE_SCHEMA:
        try:
            verification = verify_browser_package(root, package_ref)
            capture = read_verified_json(root, verification["capture_ref"])
        except (BrowserCaptureError, PackageVerificationError) as exc:
            raise ProofPassError(f"browser evidence package failed verification: {exc}") from exc
        return BROWSER_SUBJECT_TYPE, verification, capture

    raise ProofPassError("unsupported evidence package schema for ProofPass v1")


def issue_receipt(
    *,
    evidence_root: str | Path,
    package_ref: str,
    private_key: Ed25519PrivateKey,
    issuer_id: str,
    issued_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(issuer_id, str) or not issuer_id.strip() or len(issuer_id) > 200:
        raise ProofPassError("issuer_id must be non-empty text no longer than 200 characters")
    issuer_id = issuer_id.strip()

    subject_type, verification, capture = _verified_subject(evidence_root, package_ref)

    timestamp = issued_at or utc_now_iso()
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProofPassError("issued_at must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ProofPassError("issued_at must include a timezone")
    timestamp = parsed.astimezone(timezone.utc).isoformat()

    public_key = private_key.public_key()
    key_id = _public_key_id(public_key)
    evidence_status = verification.get("status")
    if evidence_status not in EVIDENCE_STATUSES:
        raise ProofPassError("evidence verifier returned an unsupported status")

    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "attestation": "EVIDENCE_INTEGRITY",
        "issuer": {
            "id": issuer_id,
            "key_id": key_id,
        },
        "subject": {
            "type": subject_type,
            "package_ref": package_ref,
            "target_id": verification.get("target_id"),
            "source": capture.get("final_url"),
            "observed_at": verification.get("observed_at"),
        },
        "coverage": verification.get("coverage"),
        "evidence": {
            "status": evidence_status,
            "verified_refs": verification.get("verified_refs", []),
        },
        "issued_at": timestamp,
        "limitations": [
            "This receipt attests to evidence-package integrity and issuer-key possession, not truth.",
            "Trust in the issuer identity depends on independently trusting the supplied public key.",
            "The receipt covers only the collection scope recorded in the evidence package.",
            "Hashes and signatures do not establish exploitability, intent, causation, or business impact.",
        ],
    }
    receipt_id = _receipt_id_for(core)
    receipt: dict[str, Any] = {**core, "receipt_id": receipt_id}
    signature = private_key.sign(_signed_bytes(receipt))
    receipt["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return receipt


def _validate_receipt_shape(receipt: Mapping[str, Any]) -> None:
    if set(receipt) != RECEIPT_FIELDS:
        raise ProofPassError("receipt has unexpected or missing top-level fields")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise ProofPassError("unsupported ProofPass receipt schema")
    if receipt.get("attestation") != "EVIDENCE_INTEGRITY":
        raise ProofPassError("unsupported ProofPass attestation type")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("pp1-") or len(receipt_id) != 36:
        raise ProofPassError("invalid ProofPass receipt_id")
    issuer = receipt.get("issuer")
    if not isinstance(issuer, dict) or set(issuer) != {"id", "key_id"}:
        raise ProofPassError("invalid issuer object")
    if not isinstance(issuer.get("id"), str) or not issuer.get("id"):
        raise ProofPassError("issuer id is missing")
    key_id = issuer.get("key_id")
    if not isinstance(key_id, str) or len(key_id) != 64 or any(c not in "0123456789abcdef" for c in key_id):
        raise ProofPassError("issuer key_id must be a lowercase SHA-256 digest")
    subject = receipt.get("subject")
    expected_subject = {"type", "package_ref", "target_id", "source", "observed_at"}
    if not isinstance(subject, dict) or set(subject) != expected_subject:
        raise ProofPassError("invalid receipt subject")
    if subject.get("type") not in SUBJECT_TYPES:
        raise ProofPassError("unsupported receipt subject type")
    if not isinstance(subject.get("package_ref"), str):
        raise ProofPassError("receipt package_ref is missing")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"status", "verified_refs"}:
        raise ProofPassError("invalid receipt evidence object")
    if evidence.get("status") not in EVIDENCE_STATUSES or not isinstance(evidence.get("verified_refs"), list):
        raise ProofPassError("receipt evidence status or references are invalid")
    if not isinstance(receipt.get("coverage"), dict):
        raise ProofPassError("receipt coverage must be an object")
    if not isinstance(receipt.get("limitations"), list) or not all(isinstance(item, str) for item in receipt["limitations"]):
        raise ProofPassError("receipt limitations must be a list of text")
    if not isinstance(receipt.get("issued_at"), str):
        raise ProofPassError("receipt issued_at is missing")
    signature = receipt.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value_base64"}:
        raise ProofPassError("invalid signature object")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM or signature.get("key_id") != key_id:
        raise ProofPassError("receipt signature metadata does not match issuer key")


def verify_receipt(
    *,
    evidence_root: str | Path,
    receipt: Mapping[str, Any],
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    _validate_receipt_shape(receipt)
    expected_key_id = _public_key_id(public_key)
    supplied_key_id = receipt["issuer"]["key_id"]
    if supplied_key_id != expected_key_id:
        raise ProofPassError("receipt issuer key_id does not match the trusted public key")

    signature_value = receipt["signature"]["value_base64"]
    if not isinstance(signature_value, str):
        raise ProofPassError("receipt signature is missing")
    try:
        signature = base64.b64decode(signature_value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProofPassError("receipt signature is not valid base64") from exc
    if len(signature) != 64:
        raise ProofPassError("Ed25519 receipt signature must be exactly 64 bytes")
    try:
        public_key.verify(signature, _signed_bytes(receipt))
    except InvalidSignature as exc:
        raise ProofPassError("receipt signature verification failed") from exc

    unsigned = _receipt_unsigned(receipt)
    receipt_id = unsigned.pop("receipt_id")
    expected_receipt_id = _receipt_id_for(unsigned)
    if receipt_id != expected_receipt_id:
        raise ProofPassError("receipt_id does not match the signed receipt content")

    subject = receipt["subject"]
    subject_type, verification, capture = _verified_subject(
        evidence_root,
        subject["package_ref"],
    )
    if subject.get("type") != subject_type:
        raise ProofPassError("receipt subject type does not match the evidence package schema")
    if subject.get("target_id") != verification.get("target_id"):
        raise ProofPassError("receipt target_id does not match the evidence package")
    if subject.get("observed_at") != verification.get("observed_at"):
        raise ProofPassError("receipt observed_at does not match the evidence package")
    if subject.get("source") != capture.get("final_url"):
        raise ProofPassError("receipt source does not match the evidence capture")
    if receipt.get("coverage") != verification.get("coverage"):
        raise ProofPassError("receipt coverage does not match the evidence package")
    if receipt["evidence"].get("status") != verification.get("status"):
        raise ProofPassError("receipt evidence status does not match independent verification")
    if receipt["evidence"].get("verified_refs") != verification.get("verified_refs"):
        raise ProofPassError("receipt evidence references do not match independently verified artifacts")

    return {
        "schema": VERIFICATION_SCHEMA,
        "status": "VERIFIED_RECEIPT",
        "receipt_id": receipt_id,
        "attestation": receipt.get("attestation"),
        "subject_type": subject_type,
        "issuer_id": receipt["issuer"]["id"],
        "issuer_key_id": supplied_key_id,
        "trusted_public_key_matched": True,
        "signature_valid": True,
        "evidence_integrity": verification.get("status"),
        "package_ref": subject["package_ref"],
        "target_id": subject.get("target_id"),
        "source": subject.get("source"),
        "observed_at": subject.get("observed_at"),
        "issued_at": receipt.get("issued_at"),
        "coverage": receipt.get("coverage"),
        "limitations": [
            "VERIFIED_RECEIPT means the signature and referenced evidence integrity verified; it does not mean the website claim is true.",
            "Issuer identity is trustworthy only to the extent the verifier independently trusts this public key.",
        ],
    }


def write_receipt(path: str | Path, receipt: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dict(receipt), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        with target.open("x", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ProofPassError("receipt output already exists; refusing to overwrite") from exc


def read_receipt(path: str | Path) -> dict[str, Any]:
    raw = _read_bounded_file(Path(path), MAX_RECEIPT_BYTES, label="ProofPass receipt")
    return strict_json_object(raw, label="ProofPass receipt")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Issue and verify ProofPass v1 evidence receipts")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate-key", help="Generate an Ed25519 ProofPass keypair")
    generate.add_argument("--private-key", required=True, type=Path)
    generate.add_argument("--public-key", required=True, type=Path)

    sign = subparsers.add_parser("sign", help="Issue a signed receipt for a verified evidence package")
    sign.add_argument("--evidence-root", required=True, type=Path)
    sign.add_argument("--package-ref", required=True)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--issuer", required=True)
    sign.add_argument("--out", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="Verify a signed receipt and its evidence package")
    verify.add_argument("--evidence-root", required=True, type=Path)
    verify.add_argument("--receipt", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "generate-key":
            result = generate_keypair(args.private_key, args.public_key)
        elif args.command == "sign":
            private_key = load_private_key(args.private_key)
            receipt = issue_receipt(
                evidence_root=args.evidence_root,
                package_ref=args.package_ref,
                private_key=private_key,
                issuer_id=args.issuer,
            )
            write_receipt(args.out, receipt)
            result = {
                "status": "RECEIPT_ISSUED",
                "receipt_id": receipt["receipt_id"],
                "subject_type": receipt["subject"]["type"],
                "package_ref": receipt["subject"]["package_ref"],
                "issuer_key_id": receipt["issuer"]["key_id"],
                "receipt_path": str(args.out),
            }
        else:
            receipt = read_receipt(args.receipt)
            public_key = load_public_key(args.public_key)
            result = verify_receipt(
                evidence_root=args.evidence_root,
                receipt=receipt,
                public_key=public_key,
            )
    except (OSError, ProofPassError) as exc:
        print(json.dumps({
            "schema": VERIFICATION_SCHEMA,
            "status": "FAILED",
            "error": str(exc),
        }, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
