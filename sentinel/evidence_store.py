from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


class EvidenceIntegrityError(RuntimeError):
    """Raised when content-addressed evidence does not match its digest."""


class ContentAddressedEvidenceStore:
    """Append-only SHA-256 evidence storage.

    Artifacts are addressed only by their content digest. Existing artifacts are
    never overwritten. If bytes already exist at a digest-derived path, they are
    re-hashed before reuse so silent corruption fails closed.
    """

    SCHEMA = "watch-dawg-evidence/v1"

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def put_bytes(
        self,
        payload: bytes,
        *,
        media_type: str,
        source: str,
        observed_at: str,
        artifact_type: str,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(payload).hexdigest()
        artifact_path = self._artifact_path(digest)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_once_verified(artifact_path, payload, digest)
        return {
            "schema": self.SCHEMA,
            "ref": f"sha256:{digest}",
            "sha256": digest,
            "size_bytes": len(payload),
            "media_type": media_type,
            "source": source,
            "observed_at": observed_at,
            "artifact_type": artifact_type,
        }

    def put_json(
        self,
        payload: dict[str, Any],
        *,
        source: str,
        observed_at: str,
        artifact_type: str,
    ) -> dict[str, Any]:
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
        return self.put_bytes(
            encoded,
            media_type="application/json",
            source=source,
            observed_at=observed_at,
            artifact_type=artifact_type,
        )

    def verify(self, reference: str) -> bool:
        digest = self._parse_reference(reference)
        path = self._artifact_path(digest)
        if not path.is_file():
            return False
        return self._sha256_file(path) == digest

    def read_bytes(self, reference: str) -> bytes:
        digest = self._parse_reference(reference)
        path = self._artifact_path(digest)
        payload = path.read_bytes()
        actual = hashlib.sha256(payload).hexdigest()
        if actual != digest:
            raise EvidenceIntegrityError(
                f"evidence integrity failure for {reference}: observed {actual}"
            )
        return payload

    def _artifact_path(self, digest: str) -> Path:
        return self.root / "sha256" / digest[:2] / digest

    @staticmethod
    def _parse_reference(reference: str) -> str:
        prefix = "sha256:"
        if not reference.startswith(prefix):
            raise ValueError("evidence reference must use sha256:<digest>")
        digest = reference[len(prefix):]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("invalid SHA-256 evidence reference")
        return digest

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(128 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _write_once_verified(self, path: Path, payload: bytes, digest: str) -> None:
        if path.exists():
            actual = self._sha256_file(path)
            if actual != digest:
                raise EvidenceIntegrityError(
                    f"existing evidence at {path} does not match digest {digest}"
                )
            return

        fd, temporary_name = tempfile.mkstemp(prefix=f".{digest}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary_path, path)
            except FileExistsError:
                actual = self._sha256_file(path)
                if actual != digest:
                    raise EvidenceIntegrityError(
                        f"concurrent evidence write corrupted digest {digest}"
                    )
        finally:
            temporary_path.unlink(missing_ok=True)
