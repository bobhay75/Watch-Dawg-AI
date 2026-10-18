from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


PACKAGE_SCHEMA = "watch-dawg-evidence-package/v1"
CAPTURE_SCHEMA = "watch-dawg-http-capture/v1"
REFERENCE_PREFIX = "sha256:"


class PackageVerificationError(RuntimeError):
    """Raised when a website evidence package cannot be independently verified."""


def parse_sha256_ref(reference: str) -> str:
    if not isinstance(reference, str) or not reference.startswith(REFERENCE_PREFIX):
        raise PackageVerificationError("reference must use sha256:<digest>")
    digest = reference[len(REFERENCE_PREFIX):]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise PackageVerificationError(f"invalid SHA-256 reference: {reference!r}")
    return digest


def artifact_path(evidence_root: Path, reference: str) -> Path:
    digest = parse_sha256_ref(reference)
    return evidence_root / "sha256" / digest[:2] / digest


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_verified_artifact(evidence_root: Path, reference: str) -> bytes:
    digest = parse_sha256_ref(reference)
    path = artifact_path(evidence_root, reference)
    if not path.is_file():
        raise PackageVerificationError(f"missing artifact: {reference}")
    payload = path.read_bytes()
    actual = sha256_bytes(payload)
    if actual != digest:
        raise PackageVerificationError(
            f"hash mismatch for {reference}: observed sha256:{actual}"
        )
    return payload


def read_verified_json(evidence_root: Path, reference: str) -> dict[str, Any]:
    payload = read_verified_artifact(evidence_root, reference)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageVerificationError(f"artifact is not valid UTF-8 JSON: {reference}") from exc
    if not isinstance(value, dict):
        raise PackageVerificationError(f"JSON artifact must be an object: {reference}")
    return value


def verify_package(evidence_root: str | Path, package_ref: str) -> dict[str, Any]:
    root = Path(evidence_root)
    package = read_verified_json(root, package_ref)
    if package.get("schema") != PACKAGE_SCHEMA:
        raise PackageVerificationError("unsupported or missing evidence package schema")

    capture_ref = package.get("capture_ref")
    if not isinstance(capture_ref, str):
        raise PackageVerificationError("package capture_ref is missing")
    capture = read_verified_json(root, capture_ref)
    if capture.get("schema") != CAPTURE_SCHEMA:
        raise PackageVerificationError("unsupported or missing HTTP capture schema")

    if capture.get("target_id") != package.get("target_id"):
        raise PackageVerificationError("package and capture target_id do not match")
    if capture.get("observed_at") != package.get("observed_at"):
        raise PackageVerificationError("package and capture observed_at do not match")
    if capture.get("coverage") != package.get("coverage"):
        raise PackageVerificationError("package and capture coverage do not match")

    body = capture.get("body")
    if not isinstance(body, dict):
        raise PackageVerificationError("capture body artifact metadata is missing")
    body_ref = body.get("ref")
    if not isinstance(body_ref, str):
        raise PackageVerificationError("capture body ref is missing")
    body_bytes = read_verified_artifact(root, body_ref)
    body_digest = parse_sha256_ref(body_ref)

    if body.get("sha256") != body_digest:
        raise PackageVerificationError("capture body sha256 metadata does not match its ref")
    if body.get("size_bytes") != len(body_bytes):
        raise PackageVerificationError("capture body size metadata does not match stored bytes")
    if body.get("source") != capture.get("final_url"):
        raise PackageVerificationError("capture body source does not match final_url")

    artifact_refs = package.get("artifact_refs")
    if not isinstance(artifact_refs, list) or any(not isinstance(item, str) for item in artifact_refs):
        raise PackageVerificationError("package artifact_refs must be a list of references")
    required_refs = {capture_ref, body_ref}
    if not required_refs.issubset(set(artifact_refs)):
        raise PackageVerificationError("package artifact_refs omit required capture or body evidence")

    verified_refs = [package_ref]
    for reference in artifact_refs:
        read_verified_artifact(root, reference)
        if reference not in verified_refs:
            verified_refs.append(reference)

    return {
        "schema": "watch-dawg-evidence-verification/v1",
        "status": "VERIFIED_INTEGRITY",
        "package_ref": package_ref,
        "target_id": package.get("target_id"),
        "observed_at": package.get("observed_at"),
        "capture_ref": capture_ref,
        "body_ref": body_ref,
        "verified_refs": verified_refs,
        "coverage": package.get("coverage"),
        "limitations": [
            "Hash verification establishes integrity of stored artifacts, not signer identity.",
            "Verification does not establish that the website or any business claim is truthful.",
            "The result covers only the collection scope recorded in the package.",
        ],
    }


def export_verified_package(
    evidence_root: str | Path,
    package_ref: str,
    destination: str | Path,
) -> dict[str, Any]:
    root = Path(evidence_root)
    verification = verify_package(root, package_ref)
    package = read_verified_json(root, package_ref)
    capture = read_verified_json(root, verification["capture_ref"])

    output = Path(destination)
    if output.exists() and any(output.iterdir()):
        raise PackageVerificationError("export destination must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)

    shutil.copyfile(artifact_path(root, package_ref), output / "package.json")
    shutil.copyfile(
        artifact_path(root, verification["capture_ref"]),
        output / "capture.json",
    )
    shutil.copyfile(
        artifact_path(root, verification["body_ref"]),
        output / "response-body.bin",
    )
    (output / "verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "README.txt").write_text(
        "Watch-Dawg evidence export\n"
        "\n"
        "This export passed SHA-256 integrity and manifest-linkage verification.\n"
        "It does not prove signer identity, exploitability, intent, or the truth of\n"
        "any business claim. Review verification.json and the recorded coverage.\n",
        encoding="utf-8",
    )
    return {
        **verification,
        "exported_to": str(output),
        "export_files": [
            "package.json",
            "capture.json",
            "response-body.bin",
            "verification.json",
            "README.txt",
        ],
        "source_final_url": capture.get("final_url"),
        "package_schema": package.get("schema"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently verify a content-addressed Watch-Dawg website evidence package"
    )
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--package-ref", required=True)
    parser.add_argument("--export", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.export:
            result = export_verified_package(args.evidence_root, args.package_ref, args.export)
        else:
            result = verify_package(args.evidence_root, args.package_ref)
    except (OSError, PackageVerificationError) as exc:
        print(json.dumps({
            "schema": "watch-dawg-evidence-verification/v1",
            "status": "FAILED",
            "error": str(exc),
        }, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
